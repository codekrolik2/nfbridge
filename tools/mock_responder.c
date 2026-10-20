/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Minimal stand-in for the Java decision process, for manual testing of nfbridge.
 * Listens on a Unix socket, logs a one-line summary of every packet and answers
 * according to the selected mode.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "nfbridge/protocol.h"

enum mode { MODE_ALLOW, MODE_DROP, MODE_ALTERNATE, MODE_DROP_ICMP };

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n == 0)
            return 0;
        if (n < 0) {
            if (errno == EINTR && !g_stop)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 1;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Returns the IP protocol number (TCP=6, UDP=17, ICMP=1, ICMPv6=58) or -1. */
static int describe(const uint8_t *p, uint32_t len, char *out, size_t outlen)
{
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    if (len >= 20 && (p[0] >> 4) == 4) {
        inet_ntop(AF_INET, p + 12, src, sizeof(src));
        inet_ntop(AF_INET, p + 16, dst, sizeof(dst));
        snprintf(out, outlen, "IPv4 %s -> %s proto=%u", src, dst, p[9]);
        return p[9];
    }
    if (len >= 40 && (p[0] >> 4) == 6) {
        inet_ntop(AF_INET6, p + 8, src, sizeof(src));
        inet_ntop(AF_INET6, p + 24, dst, sizeof(dst));
        snprintf(out, outlen, "IPv6 %s -> %s next=%u", src, dst, p[6]);
        return p[6];
    }
    snprintf(out, outlen, "non-IP/short packet");
    return -1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -s PATH [-m allow|drop|alternate|drop-icmp] [-d DELAY_MS]\n"
            "  -s, --socket PATH   Unix socket path to listen on (required)\n"
            "  -m, --mode MODE     decision mode (default allow)\n"
            "  -d, --delay-ms MS   artificial delay before each reply (default 0)\n",
            prog);
}

static void serve(int cfd, enum mode mode, long delay_ms)
{
    static uint8_t payload[NFB_MAX_PAYLOAD];
    uint64_t count = 0;
    while (!g_stop) {
        uint8_t hbuf[NFB_REQ_HDR_LEN];
        struct nfb_request_hdr hdr;
        int r = read_full(cfd, hbuf, sizeof(hbuf));
        if (r <= 0)
            return;
        int prc = nfb_decode_request_hdr(hbuf, &hdr);
        if (prc != NFB_PROTO_OK) {
            fprintf(stderr, "mock: bad request header: %s\n", nfb_proto_strerror(prc));
            return;
        }
        if (hdr.payload_len > 0 && read_full(cfd, payload, hdr.payload_len) <= 0)
            return;

        char desc[160];
        int proto = describe(payload, hdr.payload_len, desc, sizeof(desc));

        enum nfb_decision d = NFB_DECISION_ALLOW;
        switch (mode) {
        case MODE_ALLOW:
            break;
        case MODE_DROP:
            d = NFB_DECISION_DROP;
            break;
        case MODE_ALTERNATE:
            d = (count % 2) ? NFB_DECISION_DROP : NFB_DECISION_ALLOW;
            break;
        case MODE_DROP_ICMP:
            d = (proto == 1 || proto == 58) ? NFB_DECISION_DROP : NFB_DECISION_ALLOW;
            break;
        }
        count++;

        printf("corr=%" PRIu64 " id=%" PRIu32 " hook=%u mark=%" PRIu32 " in=%" PRIu32
               " out=%" PRIu32 " len=%" PRIu32 " %s => %s\n",
               hdr.correlation_id, hdr.packet_id, hdr.hook, hdr.mark, hdr.indev, hdr.outdev,
               hdr.payload_len, desc, nfb_decision_str(d));
        fflush(stdout);

        if (delay_ms > 0) {
            struct timespec ts = {.tv_sec = delay_ms / 1000,
                                  .tv_nsec = (delay_ms % 1000) * 1000000L};
            nanosleep(&ts, NULL);
        }

        uint8_t rbuf[NFB_RESP_LEN];
        struct nfb_response resp = {.correlation_id = hdr.correlation_id, .decision = d};
        nfb_encode_response(rbuf, &resp);
        if (write_full(cfd, rbuf, sizeof(rbuf)) != 0)
            return;
    }
}

int main(int argc, char **argv)
{
    static const struct option opts[] = {
        {"socket", required_argument, NULL, 's'},
        {"mode", required_argument, NULL, 'm'},
        {"delay-ms", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    const char *path = NULL;
    enum mode mode = MODE_ALLOW;
    long delay_ms = 0;
    int c;
    while ((c = getopt_long(argc, argv, "s:m:d:h", opts, NULL)) != -1) {
        switch (c) {
        case 's':
            path = optarg;
            break;
        case 'm':
            if (strcmp(optarg, "allow") == 0)
                mode = MODE_ALLOW;
            else if (strcmp(optarg, "drop") == 0)
                mode = MODE_DROP;
            else if (strcmp(optarg, "alternate") == 0)
                mode = MODE_ALTERNATE;
            else if (strcmp(optarg, "drop-icmp") == 0)
                mode = MODE_DROP_ICMP;
            else {
                usage(argv[0]);
                return 2;
            }
            break;
        case 'd':
            delay_ms = strtol(optarg, NULL, 10);
            if (delay_ms < 0 || delay_ms > 600000) {
                usage(argv[0]);
                return 2;
            }
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (path == NULL || strlen(path) == 0 || strlen(path) >= sizeof(addr.sun_path)) {
        usage(argv[0]);
        return 2;
    }
    memcpy(addr.sun_path, path, strlen(path) + 1);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }
    unlink(path);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(lfd, 4) < 0) {
        fprintf(stderr, "mock: cannot listen on %s: %s\n", path, strerror(errno));
        close(lfd);
        return 1;
    }
    fprintf(stderr, "mock: listening on %s\n", path);

    while (!g_stop) {
        int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }
        fprintf(stderr, "mock: client connected\n");
        serve(cfd, mode, delay_ms);
        close(cfd);
        fprintf(stderr, "mock: client disconnected\n");
    }

    close(lfd);
    unlink(path);
    return 0;
}
