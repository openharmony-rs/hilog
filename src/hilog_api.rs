//! Safe wrappers around HiLog NDK functions from [`hilog-sys`].
//!
//! Newer OpenHarmony APIs are gated behind `api-*` features that forward to the
//! matching [`hilog-sys`] features. API-19 itself adds no new HiLog symbols;
//! enabling `api-19` exposes the API-15/API-18 wrappers (`set_min_log_level`,
//! `print_msg`, `print_msg_by_len`).
//!
//! [`hilog-sys`]: https://docs.rs/hilog-sys

use crate::LogDomain;
use hilog_sys::{LogLevel, OH_LOG_IsLoggable};
use std::ffi::CStr;

#[cfg(feature = "api-18")]
use std::os::raw::c_char;

/// Checks whether logs of the specified service domain, tag, and level can be output.
///
/// Wraps [`OH_LOG_IsLoggable`](hilog_sys::OH_LOG_IsLoggable) (available since API-8).
#[must_use]
pub fn is_loggable(domain: LogDomain, tag: &CStr, level: LogLevel) -> bool {
    unsafe { OH_LOG_IsLoggable(domain.0.into(), tag.as_ptr(), level) }
}

/// Sets the lowest log level of the current application process.
///
/// Wraps [`OH_LOG_SetMinLogLevel`](hilog_sys::OH_LOG_SetMinLogLevel)
/// (available since API-15). Requires the `api-15` feature (also enabled by
/// `api-18` / `api-19`).
#[cfg(feature = "api-15")]
#[cfg_attr(docsrs, doc(cfg(feature = "api-15")))]
pub fn set_min_log_level(level: LogLevel) {
    unsafe { hilog_sys::OH_LOG_SetMinLogLevel(level) }
}

/// Outputs a log message without a `printf` format string.
///
/// Wraps [`OH_LOG_PrintMsg`](hilog_sys::OH_LOG_PrintMsg) (available since
/// API-18). Requires the `api-18` feature (also enabled by `api-19`).
///
/// Returns `0` or a larger value on success, or a negative value on failure.
#[cfg(feature = "api-18")]
#[cfg_attr(docsrs, doc(cfg(feature = "api-18")))]
pub fn print_msg(
    log_type: hilog_sys::LogType,
    level: LogLevel,
    domain: LogDomain,
    tag: &CStr,
    message: &CStr,
) -> i32 {
    unsafe {
        hilog_sys::OH_LOG_PrintMsg(
            log_type,
            level,
            domain.0.into(),
            tag.as_ptr(),
            message.as_ptr(),
        )
    }
}

/// Pointer + length for `OH_LOG_PrintMsgByLen`.
///
/// Empty `&str` slices may have a dangling (non-null) pointer; the NDK still
/// receives a valid pointer to a static empty string in that case.
#[cfg(feature = "api-18")]
pub(crate) fn str_to_hilog_ptr(s: &str) -> (*const c_char, usize) {
    if s.is_empty() {
        (c"".as_ptr(), 0)
    } else {
        (s.as_ptr().cast(), s.len())
    }
}

/// Outputs a log message from Rust `&str` values, passing explicit lengths.
///
/// Wraps [`OH_LOG_PrintMsgByLen`](hilog_sys::OH_LOG_PrintMsgByLen) (available
/// since API-18). Requires the `api-18` feature (also enabled by `api-19`).
///
/// Unlike [`print_msg`], this does not require a trailing NUL on `tag` or
/// `message`.
///
/// Returns `0` or a larger value on success, or a negative value on failure.
#[cfg(feature = "api-18")]
#[cfg_attr(docsrs, doc(cfg(feature = "api-18")))]
pub fn print_msg_by_len(
    log_type: hilog_sys::LogType,
    level: LogLevel,
    domain: LogDomain,
    tag: &str,
    message: &str,
) -> i32 {
    let (tag_ptr, tag_len) = str_to_hilog_ptr(tag);
    let (message_ptr, message_len) = str_to_hilog_ptr(message);
    unsafe {
        hilog_sys::OH_LOG_PrintMsgByLen(
            log_type,
            level,
            domain.0.into(),
            tag_ptr,
            tag_len,
            message_ptr,
            message_len,
        )
    }
}

/// Sets the lowest log level of the current application process with a
/// preference strategy.
///
/// Wraps [`OH_LOG_SetLogLevel`](hilog_sys::OH_LOG_SetLogLevel) (available since
/// API-21). Requires the `api-21` feature.
#[cfg(feature = "api-21")]
#[cfg_attr(docsrs, doc(cfg(feature = "api-21")))]
pub fn set_log_level(level: LogLevel, prefer: hilog_sys::PreferStrategy) {
    unsafe { hilog_sys::OH_LOG_SetLogLevel(level, prefer) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hilog_sys::LogLevel;

    #[test]
    fn log_level_from_log_crate() {
        assert_eq!(LogLevel::from(log::Level::Error), LogLevel::LOG_ERROR);
        assert_eq!(LogLevel::from(log::Level::Warn), LogLevel::LOG_WARN);
        assert_eq!(LogLevel::from(log::Level::Info), LogLevel::LOG_INFO);
        assert_eq!(LogLevel::from(log::Level::Debug), LogLevel::LOG_DEBUG);
        assert_eq!(LogLevel::from(log::Level::Trace), LogLevel::LOG_DEBUG);
    }

    #[test]
    fn log_domain_roundtrip() {
        assert_eq!(LogDomain::new(0).0, 0);
        assert_eq!(LogDomain::new(0xFFFF).0, 0xFFFF);
        assert_eq!(LogDomain::new(0x1234), LogDomain::new(0x1234));
    }

    #[cfg(feature = "api-18")]
    #[test]
    fn empty_str_uses_non_null_ptr() {
        let (ptr, len) = str_to_hilog_ptr("");
        assert!(!ptr.is_null());
        assert_eq!(len, 0);
    }

    #[cfg(feature = "api-18")]
    #[test]
    fn nonempty_str_preserves_bytes() {
        let s = "hi";
        let (ptr, len) = str_to_hilog_ptr(s);
        assert_eq!(len, 2);
        unsafe {
            assert_eq!(*ptr, b'h' as c_char);
            assert_eq!(*ptr.add(1), b'i' as c_char);
        }
    }

    #[cfg(feature = "api-21")]
    #[test]
    fn prefer_strategy_constants() {
        use hilog_sys::PreferStrategy;
        assert_ne!(
            PreferStrategy::UNSET_LOGLEVEL,
            PreferStrategy::PREFER_CLOSE_LOG
        );
        assert_ne!(
            PreferStrategy::PREFER_CLOSE_LOG,
            PreferStrategy::PREFER_OPEN_LOG
        );
    }
}
