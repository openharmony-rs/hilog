//! `log` compatible logger to the `HiLog` logging system on OpenHarmony
//!
//! This crate is in its very early stages and still under development,
//! it was partially inspired by [`env_logger`].
//! 
//! ## Features
//! - Permits filtering based on the [`env_filter`] spec via the crate.
//! - Permits dynamic replacement of filters in an atomic manner, making changes
//!  available to subsequent invocations on other threads without
//!  invalidating the state of any running threads.
//!
//! [`env_logger`]: https://docs.rs/env_logger/latest/env_logger/
//! [`env_filter`]: https://docs.rs/env_filter/latest/env_filter/
//! 

mod hilog_writer;

use arc_swap::ArcSwap;
use env_filter::Filter;
use hilog_sys::{LogLevel, LogType, OH_LOG_IsLoggable};
use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::ffi::CStr;
use std::fmt;
use std::fmt::Write;
use std::mem::MaybeUninit;
use std::sync::Arc;

pub(crate) type FormatFn = Box<dyn Fn(&mut dyn fmt::Write, &Record) -> fmt::Result + Sync + Send>;

/// Service domain of logs
///
/// The user can set this value as required. The value can be used
/// when filtering `hilog` logs.
#[derive(Copy, Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct LogDomain(u16);

impl LogDomain {
    /// Creates a new LogDomain
    ///
    /// Valid values are 0-0xFFFF.
    pub fn new(domain: u16) -> Self {
        Self(domain)
    }
}

#[derive(Default)]
pub struct Builder {
    filter: env_filter::Builder,
    log_domain: LogDomain,
    log_tag: Option<String>,
    custom_format: Option<FormatFn>,
    built: bool,
}

impl Builder {
    pub fn new() -> Builder {
        Default::default()
    }

    /// Sets the Service domain for the logs
    ///
    /// Users can set a custom domain, which allows filtering by hilogd.
    pub fn set_domain(&mut self, domain: LogDomain) -> &mut Self {
        self.log_domain = domain;
        self
    }

    /// Sets the tag for the logs. Maximum length is 31 bytes.
    ///
    /// If not set, the module path will be used as the tag.
    /// If the provided tag is longer than 31 bytes it will be truncated.
    pub fn set_tag(&mut self, tag: &str) -> &mut Self {
        self.log_tag = Some(tag.to_string());
        self
    }

    /// Adds a directive to the filter for a specific module.
    ///
    /// # Examples
    ///
    /// Only include messages for info and above for logs in `path::to::module`:
    ///
    /// ```
    /// use hilog::Builder;
    /// use log::LevelFilter;
    ///
    /// let mut builder = Builder::new();
    ///
    /// builder.filter_module("path::to::module", LevelFilter::Info);
    /// ```
    pub fn filter_module(&mut self, module: &str, level: LevelFilter) -> &mut Self {
        self.filter.filter_module(module, level);
        self
    }

    /// Adds a directive to the filter for all modules.
    ///
    /// # Examples
    ///
    /// Only include messages for info and above for logs globally:
    ///
    /// ```
    /// use hilog::Builder;
    /// use log::LevelFilter;
    ///
    /// let mut builder = Builder::new();
    ///
    /// builder.filter_level(LevelFilter::Info);
    /// ```
    pub fn filter_level(&mut self, level: LevelFilter) -> &mut Self {
        self.filter.filter_level(level);
        self
    }

    /// Adds filters to the logger.
    ///
    /// The given module (if any) will log at most the specified level provided.
    /// If no module is provided then the filter will apply to all log messages.
    ///
    /// # Examples
    ///
    /// Only include messages for info and above for logs in `path::to::module`:
    ///
    /// ```
    /// use hilog::Builder;
    /// use log::LevelFilter;
    ///
    /// let mut builder = Builder::new();
    ///
    /// builder.filter(Some("path::to::module"), LevelFilter::Info);
    /// ```
    pub fn filter(&mut self, module: Option<&str>, level: LevelFilter) -> &mut Self {
        self.filter.filter(module, level);
        self
    }

    /// Adds a custom format function to the logger.
    ///
    /// The format function will be called for each log message that would be output.
    /// It should write the formatted log message to the provided writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use hilog::Builder;
    /// use log::{Record, Level};
    ///
    /// let mut builder = Builder::new();
    ///
    /// builder.format(|buf, record| {
    ///     writeln!(buf, "{}:{} - {}",
    ///     record.file().unwrap_or("unknown"),
    ///     record.line().unwrap_or(0),
    ///     record.args())
    ///  });
    /// ```
    pub fn format<F>(&mut self, format: F) -> &mut Self
    where
        F: Fn(&mut dyn fmt::Write, &Record) -> fmt::Result + Sync + Send + 'static,
    {
        self.custom_format = Some(Box::new(format));
        self
    }

    /// Initializes the global logger with the built env logger.
    ///
    /// This should be called early in the execution of a Rust program. Any log
    /// events that occur before initialization will be ignored.
    ///
    /// # Errors
    ///
    /// This function will fail if it is called more than once, or if another
    /// library has already initialized a global logger.
    pub fn try_init(&mut self) -> Result<(), SetLoggerError> {
        let logger = self.build();

        let max_level = logger.filter();
        let r = log::set_boxed_logger(Box::new(logger));

        if r.is_ok() {
            log::set_max_level(max_level);
        }

        r
    }

    /// Initializes the global logger with the built env logger.
    ///
    /// This should be called early in the execution of a Rust program. Any log
    /// events that occur before initialization will be ignored.
    ///
    /// # Panics
    ///
    /// This function will panic if it is called more than once, or if another
    /// library has already initialized a global logger.
    pub fn init(&mut self) {
        self.try_init()
            .expect("Builder::init should not be called after logger initialized");
    }

    /// Build an env logger.
    ///
    /// The returned logger implements the `Log` trait and can be installed manually
    /// or nested within another logger.
    pub fn build(&mut self) -> Logger {
        assert!(!self.built, "attempt to re-use consumed builder");
        self.built = true;

        Logger {
            domain: self.log_domain,
            tag: self.log_tag.take(),
            filter: ArcSwap::from_pointee(self.filter.build()),
            custom_format: self.custom_format.take(),
        }
    }
}

pub struct Logger {
    domain: LogDomain,
    tag: Option<String>,
    filter: ArcSwap<Filter>,
    custom_format: Option<FormatFn>,
}

use hilog_writer::HiLogWriter;
use hilog_writer::MAX_TAG_LEN;

fn uninit_array<const N: usize, T>() -> [MaybeUninit<T>; N] {
    [const { MaybeUninit::uninit() }; N]
}

impl Logger {
    /// Returns the maximum `LevelFilter` that this env logger instance is
    /// configured to output.
    pub fn filter(&self) -> LevelFilter {
        self.filter.load().filter()
    }

    pub fn set_filter(&self, filter: Filter) {
        self.filter.store(filter.into());
    }

    fn is_loggable(&self, tag: &CStr, level: LogLevel) -> bool {
        unsafe { OH_LOG_IsLoggable(self.domain.0.into(), tag.as_ptr(), level) }
    }

    fn fill_tag_bytes(&self, tag_bytes: &mut [MaybeUninit<u8>], tag: &[u8]) {
        if tag.len() > MAX_TAG_LEN {
            for (input, output) in tag
                .iter()
                .take(MAX_TAG_LEN - 2)
                .chain(b"..\0".iter())
                .zip(tag_bytes.iter_mut())
            {
                output.write(*input);
            }
        } else {
            for (input, output) in tag.iter().chain(b"\0".iter()).zip(tag_bytes.iter_mut()) {
                output.write(*input);
            }
        }
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.filter.load().enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // truncate the tag to MAX_TAG_LEN bytes
        let mut tag_bytes: [MaybeUninit<u8>; MAX_TAG_LEN + 1] = uninit_array();

        let tag = self
            .tag
            .as_ref()
            .map(|tag| tag.as_bytes())
            .unwrap_or_else(|| {
                record
                    .module_path()
                    .map(|path| path.as_bytes())
                    .unwrap_or(b"unknown")
            });
        self.fill_tag_bytes(&mut tag_bytes, tag);
        let tag: &CStr = unsafe { CStr::from_ptr(tag_bytes.as_ptr().cast()) };

        let mut writer =
            HiLogWriter::new(LogType::LOG_APP, record.level().into(), self.domain, tag);
        let _ = match &self.custom_format {
            Some(custom_format) => custom_format(&mut writer, record),
            None => write!(&mut writer, "{}", record.args()),
        };

        writer.flush();
    }

    fn flush(&self) {}
}
