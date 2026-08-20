# Hilog

This crate provides a `log` compatible logger that writes messages to the `HiLog` logging system on OpenHarmony
devices.

This crate is partially based on [`env_logger`] and [`android_logger`].

## Writing to HiLog with `write!`

Code that writes diagnostics to `stderr` can be pointed at HiLog instead via
`HiLogSink`, an `std::io::Write` implementation. Choose WARN or ERROR depending
on the situation:

```rust
use hilog::{HiLogSink, LogDomain};
use std::io::Write;

fn report_warning(details: &str) {
    let mut sink = HiLogSink::warn(LogDomain::new(0), "MyApp");
    let _ = writeln!(sink, "warning: {details}");
}

fn report_error(err: &str) {
    let mut sink = HiLogSink::error(LogDomain::new(0), "MyApp");
    let _ = writeln!(sink, "error: {err}");
}
```

[`env_logger`]: https://docs.rs/env_logger/latest/env_logger/
[`android_logger`]: https://github.com/rust-mobile/android_logger-rs

## License

This crate is licensed under the Apache-2.0 license.
