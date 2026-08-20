use crate::hilog_writer::{HiLogWriter, MAX_TAG_LEN};
use crate::LogDomain;
use hilog_sys::{LogLevel, LogType};
use std::ffi::CString;
use std::fmt;
use std::io::{self, Write};

/// An [`io::Write`] sink that forwards written bytes to HiLog.
///
/// Use this to adapt code that writes to `stderr` so those messages appear in
/// HiLog at **WARN** or **ERROR**, depending on the situation.
///
/// Data is line-buffered: complete lines (terminated by `\n`) are emitted
/// immediately, and a trailing partial line is emitted on [`flush`](Write::flush)
/// or when the sink is dropped. Messages longer than HiLog's size limit are
/// split by the underlying writer.
///
/// # Examples
///
/// ```no_run
/// use hilog::{HiLogSink, LogDomain};
/// use std::io::Write;
///
/// let mut warn = HiLogSink::warn(LogDomain::new(0), "MyApp");
/// writeln!(warn, "unexpected value: {}", 42).unwrap();
///
/// let mut err = HiLogSink::error(LogDomain::new(0), "MyApp");
/// writeln!(err, "operation failed").unwrap();
/// ```
pub struct HiLogSink {
    level: LogLevel,
    domain: LogDomain,
    tag: CString,
    pending: Vec<u8>,
    #[cfg(test)]
    capture: Option<std::rc::Rc<std::cell::RefCell<Vec<CapturedLog>>>>,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CapturedLog {
    pub level: LogLevel,
    pub domain: LogDomain,
    pub tag: String,
    pub msg: String,
}

impl HiLogSink {
    /// Creates a sink that logs each emitted message at the WARN level.
    pub fn warn(domain: LogDomain, tag: &str) -> Self {
        Self::new(LogLevel::LOG_WARN, domain, tag)
    }

    /// Creates a sink that logs each emitted message at the ERROR level.
    pub fn error(domain: LogDomain, tag: &str) -> Self {
        Self::new(LogLevel::LOG_ERROR, domain, tag)
    }

    fn new(level: LogLevel, domain: LogDomain, tag: &str) -> Self {
        Self {
            level,
            domain,
            tag: tag_cstring(tag),
            pending: Vec::new(),
            #[cfg(test)]
            capture: None,
        }
    }

    #[cfg(test)]
    fn with_capture(
        level: LogLevel,
        domain: LogDomain,
        tag: &str,
        capture: std::rc::Rc<std::cell::RefCell<Vec<CapturedLog>>>,
    ) -> Self {
        Self {
            level,
            domain,
            tag: tag_cstring(tag),
            pending: Vec::new(),
            capture: Some(capture),
        }
    }

    fn emit_ready_lines(&mut self, flush_all: bool) {
        for line in drain_log_lines(&mut self.pending, flush_all) {
            self.emit_message(&line);
        }
    }

    fn emit_message(&self, msg: &[u8]) {
        if msg.is_empty() {
            return;
        }

        let text = String::from_utf8_lossy(msg);

        #[cfg(test)]
        if let Some(capture) = &self.capture {
            capture.borrow_mut().push(CapturedLog {
                level: self.level,
                domain: self.domain,
                tag: self.tag.to_string_lossy().into_owned(),
                msg: text.into_owned(),
            });
            return;
        }

        let mut writer = HiLogWriter::new(LogType::LOG_APP, self.level, self.domain, &self.tag);
        let _ = fmt::Write::write_str(&mut writer, &text);
        writer.flush();
    }
}

impl Write for HiLogSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        self.emit_ready_lines(false);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_ready_lines(true);
        Ok(())
    }
}

impl fmt::Write for HiLogSink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_all(s.as_bytes()).map_err(|_| fmt::Error)
    }
}

impl Drop for HiLogSink {
    fn drop(&mut self) {
        self.emit_ready_lines(true);
    }
}

/// Drain complete newline-terminated lines from `pending`.
///
/// The trailing `\n` is not included in the returned lines. When `flush_all`
/// is true, any remaining partial line is also returned.
pub(crate) fn drain_log_lines(pending: &mut Vec<u8>, flush_all: bool) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
        let mut line: Vec<u8> = pending.drain(..=pos).collect();
        line.pop();
        lines.push(line);
    }
    if flush_all && !pending.is_empty() {
        lines.push(std::mem::take(pending));
    }
    lines
}

fn tag_cstring(tag: &str) -> CString {
    let bytes = tag.as_bytes();
    let bytes = match bytes.iter().position(|&b| b == 0) {
        Some(i) => &bytes[..i],
        None => bytes,
    };
    let owned = if bytes.len() > MAX_TAG_LEN {
        let keep = MAX_TAG_LEN.saturating_sub(2);
        let mut v = bytes[..keep].to_vec();
        v.extend_from_slice(b"..");
        v
    } else {
        bytes.to_vec()
    };
    CString::new(owned).unwrap_or_else(|_| CString::new("unknown").expect("static tag"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LogDomain;
    use std::cell::RefCell;
    use std::io::Write;
    use std::rc::Rc;

    fn capture_pair(
        level: LogLevel,
        domain: LogDomain,
        tag: &str,
    ) -> (HiLogSink, Rc<RefCell<Vec<CapturedLog>>>) {
        let captured = Rc::new(RefCell::new(Vec::new()));
        let sink = HiLogSink::with_capture(level, domain, tag, captured.clone());
        (sink, captured)
    }

    #[test]
    fn drain_complete_lines_leaves_partial() {
        let mut pending = b"warn one\nwarn two\npartial".to_vec();
        let lines = drain_log_lines(&mut pending, false);
        assert_eq!(lines, vec![b"warn one".to_vec(), b"warn two".to_vec()]);
        assert_eq!(pending, b"partial");
    }

    #[test]
    fn drain_flush_all_takes_partial_line() {
        let mut pending = b"partial".to_vec();
        let lines = drain_log_lines(&mut pending, true);
        assert_eq!(lines, vec![b"partial".to_vec()]);
        assert!(pending.is_empty());
    }

    #[test]
    fn drain_flush_all_on_empty_is_empty() {
        let mut pending = Vec::new();
        assert!(drain_log_lines(&mut pending, true).is_empty());
    }

    #[test]
    fn constructors_select_warn_and_error_levels() {
        let warn = HiLogSink::warn(LogDomain::new(1), "tag");
        assert_eq!(warn.level, LogLevel::LOG_WARN);
        let error = HiLogSink::error(LogDomain::new(1), "tag");
        assert_eq!(error.level, LogLevel::LOG_ERROR);
    }

    #[test]
    fn write_macro_emits_warn_line() {
        let (mut sink, captured) =
            capture_pair(LogLevel::LOG_WARN, LogDomain::new(0x12), "WarnTag");
        write!(sink, "unexpected value: {}", 42).unwrap();
        sink.flush().unwrap();

        let logs = captured.borrow();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].level, LogLevel::LOG_WARN);
        assert_eq!(logs[0].domain, LogDomain::new(0x12));
        assert_eq!(logs[0].tag, "WarnTag");
        assert_eq!(logs[0].msg, "unexpected value: 42");
    }

    #[test]
    fn write_macro_emits_error_line() {
        let (mut sink, captured) = capture_pair(LogLevel::LOG_ERROR, LogDomain::new(0), "ErrTag");
        let detail = "disk full";
        writeln!(sink, "operation failed: {}", detail).unwrap();

        let logs = captured.borrow();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].level, LogLevel::LOG_ERROR);
        assert_eq!(logs[0].msg, "operation failed: disk full");
    }

    #[test]
    fn write_chunks_concatenate_until_newline() {
        let (mut sink, captured) = capture_pair(LogLevel::LOG_WARN, LogDomain::new(0), "T");
        write!(sink, "hel").unwrap();
        write!(sink, "lo ").unwrap();
        let name = "world";
        writeln!(sink, "{}", name).unwrap();

        let logs = captured.borrow();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].msg, "hello world");
    }

    #[test]
    fn multiple_lines_emit_separately() {
        let (mut sink, captured) = capture_pair(LogLevel::LOG_ERROR, LogDomain::new(0), "T");
        write!(sink, "first\nsecond\n").unwrap();

        let logs = captured.borrow();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].msg, "first");
        assert_eq!(logs[1].msg, "second");
    }

    #[test]
    fn drop_flushes_partial_line() {
        let captured = Rc::new(RefCell::new(Vec::new()));
        {
            let mut sink = HiLogSink::with_capture(
                LogLevel::LOG_WARN,
                LogDomain::new(0),
                "T",
                captured.clone(),
            );
            write!(sink, "no newline").unwrap();
        }
        let logs = captured.borrow();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].msg, "no newline");
    }

    #[test]
    fn long_tag_is_truncated() {
        let long = "abcdefghijklmnopqrstuvwxyz0123456789";
        let sink = HiLogSink::warn(LogDomain::new(0), long);
        let tag = sink.tag.as_bytes();
        assert_eq!(tag.len(), MAX_TAG_LEN);
        assert!(tag.ends_with(b".."));
    }
}
