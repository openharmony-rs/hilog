# Hilog

This crate provides a `log` compatible logger that writes messages to the `HiLog` logging system on OpenHarmony
devices.

This crate is partially based on [`env_logger`] and [`android_logger`].

[`env_logger`]: https://docs.rs/env_logger/latest/env_logger/
[`android_logger`]: https://github.com/rust-mobile/android_logger-rs

## Native HiLog APIs

In addition to the `log` facade sink, the crate exposes small safe wrappers around
useful HiLog NDK functions from [`hilog-sys`] 0.1.8+. Newer functions are gated
behind `api-*` features that match `hilog-sys`. API-19 itself adds no new HiLog
symbols; enabling `api-19` exposes the API-15/API-18 wrappers.

| Feature | Wrappers | OpenHarmony API |
| --- | --- | --- |
| *(always)* | `is_loggable` | 8 |
| `api-15` | `set_min_log_level` | 15 |
| `api-18` | `print_msg`, `print_msg_by_len` | 18 |
| `api-19` | *(forwards to API-18; no extra symbols)* | 19 |
| `api-21` | `set_log_level` | 21 |

`LogType` and `LogLevel` are re-exported from `hilog-sys`. `OH_LOG_SetCallback`
is left unwrapped; use `hilog-sys` directly if you need the raw C callback.

Host `cargo test` links a stub `libhilog_ndk.z` (non-`ohos` targets only). The
real NDK library is used when `target_env = "ohos"`.

```toml
[dependencies]
hilog = { version = "0.2.3", features = ["api-19"] }
```

```rust,ignore
use hilog::{is_loggable, print_msg, set_min_log_level, LogDomain, LogLevel, LogType};
use std::ffi::CStr;

let domain = LogDomain::new(0x0000);
let tag = CStr::from_bytes_with_nul(b"MyApp\0").unwrap();

set_min_log_level(LogLevel::LOG_INFO);

if is_loggable(domain, tag, LogLevel::LOG_INFO) {
    print_msg(
        LogType::LOG_APP,
        LogLevel::LOG_INFO,
        domain,
        tag,
        c"hello from hilog",
    );
}
```

[`hilog-sys`]: https://docs.rs/hilog-sys

## License

This crate is licensed under the Apache-2.0 license.
