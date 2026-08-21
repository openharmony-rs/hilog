# Changelog

## v0.2.3

- Bump `hilog-sys` from 0.1.1 to 0.1.8.
- Add safe wrappers for newer HiLog NDK APIs (see latest `hilog-sys`):
  - `is_loggable` — always available (`OH_LOG_IsLoggable`, API-8).
  - `set_min_log_level` — feature `api-15` (`OH_LOG_SetMinLogLevel`).
  - `print_msg` / `print_msg_by_len` — feature `api-18` (`OH_LOG_PrintMsg*`).
  - `set_log_level` — feature `api-21` (`OH_LOG_SetLogLevel`).
- Add `api-19` feature. API-19 adds no new HiLog symbols in `hilog-sys`; the
  feature forwards to the API-18 print wrappers and `set_min_log_level`.
- Re-export `LogType` and `LogLevel` (and `PreferStrategy` with `api-21`).
- Use `OH_LOG_PrintMsg` internally when the `api-18` feature is enabled.
- `OH_LOG_SetCallback` is not wrapped: it is an unsafe C function-pointer API
  with no additional safe surface beyond the raw `hilog-sys` binding.
- Host `cargo test` links against a stub `libhilog_ndk.z` (non-`ohos` only).

## v0.2.2

- Add an option to additionally save logs to a file.

## v0.2.0
- Filterlevel can be changed safely and dynamically.
