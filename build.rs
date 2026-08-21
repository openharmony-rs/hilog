//! On non-OpenHarmony targets, compile a stub `libhilog_ndk.z` so host
//! `cargo test` can link. Device / `target_env = "ohos"` builds use the real NDK.

fn main() {
    println!("cargo:rerun-if-changed=host_stubs/hilog_ndk.c");

    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "ohos" {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let obj = std::path::Path::new(&out_dir).join("hilog_ndk.o");
    let lib = std::path::Path::new(&out_dir).join("libhilog_ndk.z.a");

    let status = std::process::Command::new("cc")
        .args(["-c", "-fPIC", "-o"])
        .arg(&obj)
        .arg("host_stubs/hilog_ndk.c")
        .status()
        .expect("failed to spawn cc for hilog host stubs");
    if !status.success() {
        panic!("cc failed to compile host_stubs/hilog_ndk.c");
    }

    let status = std::process::Command::new("ar")
        .arg("crus")
        .arg(&lib)
        .arg(&obj)
        .status()
        .expect("failed to spawn ar for hilog host stubs");
    if !status.success() {
        panic!("ar failed to create libhilog_ndk.z.a");
    }

    println!("cargo:rustc-link-search=native={out_dir}");
}
