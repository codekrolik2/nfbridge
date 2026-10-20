/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "nfbridge/config.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef NFBRIDGE_VERSION
#define NFBRIDGE_VERSION "unknown"
#endif

static void usage(FILE *out, const char *prog)
{
    fprintf(out,
            "Usage: %s [options]\n"
            "\n"
            "Thin NFQUEUE packet interceptor: forwards each queued packet to a Java\n"
            "decision process over a Unix socket and applies its ALLOW/DROP verdict.\n"
            "\n"
            "Options:\n"
            "  -q, --queue NUM        NFQUEUE number to bind (0-65535, default %d)\n"
            "  -s, --socket PATH      Unix socket of the Java process (default %s)\n"
            "  -t, --timeout-ms MS    max time to wait for a verdict (default %d)\n"
            "  -o, --fail-open        ACCEPT packets when Java is unavailable\n"
            "                         (default: fail-closed, i.e. DROP)\n"
            "  -l, --log-level LEVEL  error, warn, info or debug (default info)\n"
            "  -v, --verbose          shortcut for --log-level debug\n"
            "  -h, --help             show this help and exit\n"
            "  -V, --version          show version and exit\n",
            prog, NFB_DEFAULT_QUEUE, NFB_DEFAULT_SOCKET, NFB_DEFAULT_TIMEOUT_MS);
}

static int parse_long(const char *s, long min, long max, long *out)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

enum nfb_config_result nfb_config_parse(struct nfb_config *cfg, int argc, char **argv)
{
    static const struct option opts[] = {
        {"queue", required_argument, NULL, 'q'},
        {"socket", required_argument, NULL, 's'},
        {"timeout-ms", required_argument, NULL, 't'},
        {"fail-open", no_argument, NULL, 'o'},
        {"log-level", required_argument, NULL, 'l'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    const char *prog = argc > 0 ? argv[0] : "nfbridge";

    cfg->queue_num = NFB_DEFAULT_QUEUE;
    cfg->socket_path = NFB_DEFAULT_SOCKET;
    cfg->timeout_ms = NFB_DEFAULT_TIMEOUT_MS;
    cfg->fail_open = false;
    cfg->log_level = NFB_LOG_INFO;

    int c;
    long v;
    while ((c = getopt_long(argc, argv, "q:s:t:ol:vhV", opts, NULL)) != -1) {
        switch (c) {
        case 'q':
            if (parse_long(optarg, 0, 65535, &v) != 0) {
                fprintf(stderr, "%s: invalid queue number '%s' (expected 0-65535)\n", prog, optarg);
                return NFB_CONFIG_EXIT_USAGE;
            }
            cfg->queue_num = (uint16_t)v;
            break;
        case 's':
            cfg->socket_path = optarg;
            break;
        case 't':
            if (parse_long(optarg, 1, 600000, &v) != 0) {
                fprintf(stderr, "%s: invalid timeout '%s' (expected 1-600000 ms)\n", prog, optarg);
                return NFB_CONFIG_EXIT_USAGE;
            }
            cfg->timeout_ms = (int)v;
            break;
        case 'o':
            cfg->fail_open = true;
            break;
        case 'l':
            if (nfb_log_parse_level(optarg, &cfg->log_level) != 0) {
                fprintf(stderr, "%s: invalid log level '%s'\n", prog, optarg);
                return NFB_CONFIG_EXIT_USAGE;
            }
            break;
        case 'v':
            cfg->log_level = NFB_LOG_DEBUG;
            break;
        case 'h':
            usage(stdout, prog);
            return NFB_CONFIG_EXIT_OK;
        case 'V':
            printf("nfbridge %s\n", NFBRIDGE_VERSION);
            return NFB_CONFIG_EXIT_OK;
        default:
            usage(stderr, prog);
            return NFB_CONFIG_EXIT_USAGE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "%s: unexpected argument '%s'\n", prog, argv[optind]);
        usage(stderr, prog);
        return NFB_CONFIG_EXIT_USAGE;
    }
    return NFB_CONFIG_OK;
}
