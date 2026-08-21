/* Host-only stubs so `cargo test` / host link checks work without OpenHarmony. */
#include <stdbool.h>
#include <stddef.h>

int OH_LOG_Print(unsigned type, unsigned level, unsigned domain, const char *tag,
                 const char *fmt, ...) {
    (void)type;
    (void)level;
    (void)domain;
    (void)tag;
    (void)fmt;
    return 0;
}

int OH_LOG_PrintMsg(unsigned type, unsigned level, unsigned domain, const char *tag,
                    const char *message) {
    (void)type;
    (void)level;
    (void)domain;
    (void)tag;
    (void)message;
    return 0;
}

int OH_LOG_PrintMsgByLen(unsigned type, unsigned level, unsigned domain, const char *tag,
                         size_t tag_len, const char *message, size_t message_len) {
    (void)type;
    (void)level;
    (void)domain;
    (void)tag;
    (void)tag_len;
    (void)message;
    (void)message_len;
    return 0;
}

bool OH_LOG_IsLoggable(unsigned domain, const char *tag, unsigned level) {
    (void)domain;
    (void)tag;
    (void)level;
    return true;
}

void OH_LOG_SetMinLogLevel(unsigned level) { (void)level; }

void OH_LOG_SetLogLevel(unsigned level, unsigned prefer) {
    (void)level;
    (void)prefer;
}

void OH_LOG_SetCallback(void *callback) { (void)callback; }
