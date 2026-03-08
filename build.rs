fn main() {
    let mut builder = cc::Build::new();
    builder.includes(
        [
            "hilog_C/frameworks/libhilog/include",
            "hilog_C/frameworks/include",
          //  "$libhilog_root/include",
            "hilog_C/frameworks/libhilog/ioctl/include",
            "hilog_C/frameworks/libhilog/param/include",
            "hilog_C/frameworks/libhilog/socket/include",
            "hilog_C/frameworks/libhilog/utils/include",
            "hilog_C/frameworks/libhilog/vsnprintf/include",
            "hilog_C/interfaces/native/innerkits/include",     
        ]
    );
    builder.files(
        [ 
            "hilog_C/frameworks/libhilog/hilog.cpp",
            "hilog_C/frameworks/libhilog/hilog_printf.cpp",
           // "hilog_C/frameworks/libhilog/param/properties.cpp",
            "hilog_C/frameworks/libhilog/ioctl/log_ioctl.cpp",
            "hilog_C/frameworks/libhilog/socket/dgram_socket_client.cpp",
            "hilog_C/frameworks/libhilog/socket/hilog_input_socket_client.cpp",
            "hilog_C/frameworks/libhilog/socket/seq_packet_socket_client.cpp",
            "hilog_C/frameworks/libhilog/socket/socket.cpp",
            "hilog_C/frameworks/libhilog/socket/socket_client.cpp",
            "hilog_C/frameworks/libhilog/utils/log_print.cpp",
            "hilog_C/frameworks/libhilog/utils/log_utils.cpp",
            "hilog_C/frameworks/libhilog/vsnprintf/vsnprintf_s_p.cpp",
            "hilog_C/frameworks/libhilog/vsnprintf/vsprintf_p.cpp",
        ]
    );
    builder
        .cpp(true)
        .define("__RECV_MSG_WITH_UCRED_", "")
        .define("snprintf_s(dest, len, something, fmt, ...)", "snprintf(dest, len, fmt, __VA_ARGS__)")
        .define("memcpy_s(dest, destlen, s, s_len)", "memcpy(dest, s, s_len)")
        .define("memset_s(dest, destlen, ch, count)", "0")
        .flag("-includestdio.h")
        .std("c++17")
    ;
    builder.compile("libhilog.a");
    
}