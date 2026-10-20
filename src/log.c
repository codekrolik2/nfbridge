/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "nfbridge/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static enum nfb_log_level g_level = NFB_LOG_INFO;

static const char *const level_names[] = {"error", "warn", "info", "debug"};

void nfb_log_set_level(enum nfb_log_level level)
{
    g_level = level;
}

enum nfb_log_level nfb_log_get_level(void)
{
    return g_level;
}

int nfb_log_parse_level(const char *s, enum nfb_log_level *out)
{
    for (size_t i = 0; i < sizeof(level_names) / sizeof(level_names[0]); i++) {
        if (strcmp(s, level_names[i]) == 0) {
            *out = (enum nfb_log_level)i;
            return 0;
        }
    }
    if (strcmp(s, "warning") == 0) {
        *out = NFB_LOG_WARN;
        return 0;
    }
    return -1;
}

void nfb_log(enum nfb_log_level level, const char *fmt, ...)
{
    if (level > g_level)
        return;

    struct timespec ts;
    struct tm tm;
    char tbuf[32];
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Single fprintf so concurrent writers to stderr do not interleave mid-line. */
    fprintf(stderr, "%s.%03ld nfbridge[%s]: %s\n", tbuf, ts.tv_nsec / 1000000L, level_names[level],
            msg);
}
