//! Experimental re-implementation of `hilog-base`
//!
//! Directly sends logs to `hilogd` to improve performance

use hilog_sys::hilog_base::{HILOG_SOCKET_PATH, MAX_LOG_LEN, MAX_TAG_LEN};
use crate::{LogLevel, LogType};
use nix::errno::Errno;
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
use nix::sys::time::TimeSpec;
use nix::sys::uio::writev;
use nix::time;
use nix::time::ClockId;
use nix::unistd::getpid;
use std::ffi::CStr;
use std::io::IoSlice;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use nix::errno::Errno::EINTR;

#[repr(C, packed)]
struct RawHilogMsg {
    len: u16,
    meta: u16,
    tv_sec: u32,
    tv_nsec: u32,
    mono_sec: u32,
    pid: u32,
    tid: u32,
    domain: u32,
}

impl RawHilogMsg {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `RawHilogMsg` is plain old data and can be viewed as bytes.
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

const VERSION_BITS: u16 = 3;
const TYPE_BITS: u16 = 4;
const LEVEL_BITS: u16 = 3;
const TAG_LEN_BITS: u16 = 6;
const VERSION_SHIFT: u16 = 0;
const TYPE_SHIFT: u16 = VERSION_SHIFT + VERSION_BITS;
const LEVEL_SHIFT: u16 = TYPE_SHIFT + TYPE_BITS;
const TAG_LEN_SHIFT: u16 = LEVEL_SHIFT + LEVEL_BITS;
const VERSION: u16 = 0;

fn raw_type(log_type: LogType) -> u16 {
    if log_type == LogType::LOG_APP {
        0
    } else {
        0
    }
}

fn raw_level(level: LogLevel) -> u16 {
    if level == LogLevel::LOG_DEBUG {
        3
    } else if level == LogLevel::LOG_INFO {
        4
    } else if level == LogLevel::LOG_WARN {
        5
    } else if level == LogLevel::LOG_ERROR {
        6
    } else if level == LogLevel::LOG_FATAL {
        7
    } else {
        4
    }
}

#[derive(Debug)]
#[allow(unused)]
pub(crate) enum LogError {
    CreateSocketFailed(Errno),
    ConnectFailed(Errno),
    GetTimeFailed(Errno),
    WritevFailed(Errno),
    TagTooLong(usize),
    MessageTooLong(usize),
    MessageMetaOverflow,
}

pub(crate) fn send_message(
    log_type: LogType,
    level: LogLevel,
    domain: u32,
    tag: &CStr,
    message: &CStr,
) -> Result<(), LogError> {
    let socket_flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;

    let socket_fd = loop {
        match socket(
            AddressFamily::Unix,
            SockType::Datagram,
            socket_flags,
            None,
        ) {
            Ok(fd) => break fd,
            Err(errno) if errno == Errno::EINTR => continue,
            Err(errno) => return Err(LogError::CreateSocketFailed(errno)),
        }
    };

    // Comment from hilogbase code:
    // > The hilogbase interface cannot has mutex, so need to re-open and connect to the socketof the hilogd
    // > server each time you write logs. Although there is some overhead, you can only do this.
    // I think we could also consider making a pool of sockets, and checking the performance.
    loop {
        match connect(
            socket_fd.as_raw_fd(),
            &UnixAddr::new(HILOG_SOCKET_PATH).unwrap(),
        ) {
            Ok(()) => break,
            Err(errno) if errno == Errno::EINTR => continue,
            Err(errno) => return Err(LogError::ConnectFailed(errno)),
        }
    }

    let ts = time::clock_gettime(ClockId::CLOCK_REALTIME).unwrap_or(TimeSpec::new(0, 0));
    let ts_mono = time::clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap_or(TimeSpec::new(0, 0));

    let raw_tag = tag.to_bytes_with_nul();
    let raw_message = message.to_bytes_with_nul();
    if raw_tag.len() > MAX_TAG_LEN {
        return Err(LogError::TagTooLong(raw_tag.len()))
    }
    if raw_message.len() > MAX_LOG_LEN {
        return Err(LogError::MessageTooLong(raw_message.len()))

    }
    let tag_len = raw_tag.len() as u16;
    if tag_len >= (1 << TAG_LEN_BITS) {
        return Err(LogError::MessageMetaOverflow);
    }

    let len = size_of::<RawHilogMsg>() + raw_tag.len() + raw_message.len();
    let meta = (VERSION << VERSION_SHIFT)
        | (raw_type(log_type) << TYPE_SHIFT)
        | (raw_level(level) << LEVEL_SHIFT)
        | (tag_len << TAG_LEN_SHIFT);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let tid = nix::unistd::gettid().as_raw() as u32;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let tid = getpid().as_raw() as u32;

    let header = RawHilogMsg {
        len: len as u16,
        meta,
        tv_sec: ts.tv_sec() as u32,
        tv_nsec: ts.tv_nsec() as u32,
        mono_sec: ts_mono.tv_sec() as u32,
        pid: getpid().as_raw() as u32,
        tid,
        domain,
    };

    let io_vec = [
        IoSlice::new(header.as_bytes()),
        IoSlice::new(&raw_tag),
        IoSlice::new(&raw_message),
    ];
    let socket = socket_fd.as_fd();
    loop {
        match writev(socket, &io_vec) {
            Ok(_written_bytes) => return Ok(()),
            Err(errno) if errno == Errno::EAGAIN || errno == EINTR => continue,
            Err(errno) => return Err(LogError::WritevFailed(errno)),
        }
    }

}
