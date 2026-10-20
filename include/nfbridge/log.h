/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NFBRIDGE_LOG_H
#define NFBRIDGE_LOG_H

enum nfb_log_level {
    NFB_LOG_ERROR = 0,
    NFB_LOG_WARN = 1,
    NFB_LOG_INFO = 2,
    NFB_LOG_DEBUG = 3,
};

void nfb_log_set_level(enum nfb_log_level level);
enum nfb_log_level nfb_log_get_level(void);

/* Parses "error", "warn", "info" or "debug". Returns 0 on success, -1 otherwise. */
int nfb_log_parse_level(const char *s, enum nfb_log_level *out);

void nfb_log(enum nfb_log_level level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define LOG_ERROR(...) nfb_log(NFB_LOG_ERROR, __VA_ARGS__)
#define LOG_WARN(...) nfb_log(NFB_LOG_WARN, __VA_ARGS__)
#define LOG_INFO(...) nfb_log(NFB_LOG_INFO, __VA_ARGS__)
#define LOG_DEBUG(...)                                                                             \
    do {                                                                                           \
        if (nfb_log_get_level() >= NFB_LOG_DEBUG)                                                  \
            nfb_log(NFB_LOG_DEBUG, __VA_ARGS__);                                                   \
    } while (0)

#endif /* NFBRIDGE_LOG_H */
