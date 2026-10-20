/* SPDX-License-Identifier: Apache-2.0 */
/* IPC client tests against forked fake Java servers on a temporary Unix socket. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "nfbridge/ipc.h"
#include "nfbridge/log.h"
#include "nfbridge/protocol.h"

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);               \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

enum behaviour {
    B_ALLOW,          /* answer ALLOW to every request */
    B_DROP,           /* answer DROP to every request */
    B_TRICKLE,        /* answer DROP, one byte at a time */
    B_WRONG_CORR,     /* answer with a wrong correlation id */
    B_BAD_DECISION,   /* answer with decision value 0 */
    B_SILENT,         /* never answer */
    B_CLOSE,          /* close right after reading the request */
    B_ALLOW_ONE_EXIT, /* answer ALLOW once, then close */
};

static char g_dir[64];
static char g_path[128];

static int make_listener(void)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, g_path);
    unlink(g_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, 4) < 0) {
        perror("listener");
        exit(2);
    }
    return fd;
}

static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Child: serve one connection. Exit 0 if every received request was well-formed. */
static void server_child(int lfd, enum behaviour b)
{
    static uint8_t payload[NFB_MAX_PAYLOAD];
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0)
        _exit(10);
    for (;;) {
        uint8_t hbuf[NFB_REQ_HDR_LEN];
        struct nfb_request_hdr hdr;
        if (read_full(cfd, hbuf, sizeof(hbuf)) != 0)
            _exit(0); /* client closed */
        if (nfb_decode_request_hdr(hbuf, &hdr) != NFB_PROTO_OK)
            _exit(11);
        if (hdr.payload_len > 0 && read_full(cfd, payload, hdr.payload_len) != 0)
            _exit(12);
        for (uint32_t i = 0; i < hdr.payload_len; i++)
            if (payload[i] != (uint8_t)(i * 7u + hdr.packet_id))
                _exit(13);

        struct nfb_response resp = {.correlation_id = hdr.correlation_id,
                                    .decision = NFB_DECISION_ALLOW};
        uint8_t rbuf[NFB_RESP_LEN];
        switch (b) {
        case B_ALLOW:
        case B_ALLOW_ONE_EXIT:
            break;
        case B_DROP:
        case B_TRICKLE:
            resp.decision = NFB_DECISION_DROP;
            break;
        case B_WRONG_CORR:
            resp.correlation_id += 1000;
            break;
        case B_BAD_DECISION:
            break;
        case B_SILENT:
            while (read(cfd, rbuf, sizeof(rbuf)) > 0) {
            }
            _exit(0);
        case B_CLOSE:
            close(cfd);
            _exit(0);
        }
        nfb_encode_response(rbuf, &resp);
        if (b == B_BAD_DECISION)
            rbuf[19] = 0;

        if (b == B_TRICKLE) {
            for (size_t i = 0; i < sizeof(rbuf); i++) {
                if (write(cfd, rbuf + i, 1) != 1)
                    _exit(14);
                sleep_ms(2);
            }
        } else if (write(cfd, rbuf, sizeof(rbuf)) != (ssize_t)sizeof(rbuf)) {
            _exit(14);
        }
        if (b == B_ALLOW_ONE_EXIT) {
            close(cfd);
            _exit(0);
        }
    }
}

static pid_t spawn_server(int lfd, enum behaviour b)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0)
        server_child(lfd, b);
    return pid;
}

static void expect_child_ok(pid_t pid)
{
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void init_ipc(struct nfb_ipc *ipc, int timeout_ms)
{
    CHECK(nfb_ipc_init(ipc, g_path, timeout_ms) == 0);
    ipc->backoff_initial_ms = 0; /* deterministic: always retry immediately */
    ipc->backoff_max_ms = 0;
    ipc->backoff_ms = 0;
}

static int decide(struct nfb_ipc *ipc, uint32_t packet_id, uint32_t len, enum nfb_decision *d)
{
    static uint8_t payload[NFB_MAX_PAYLOAD];
    for (uint32_t i = 0; i < len; i++)
        payload[i] = (uint8_t)(i * 7u + packet_id);
    struct nfb_request_hdr hdr = {
        .packet_id = packet_id, .hw_protocol = 0x0800, .payload_len = len};
    return nfb_ipc_decide(ipc, &hdr, payload, d);
}

static struct nfb_ipc g_ipc;

static void test_init_validation(void)
{
    char longpath[200];
    memset(longpath, 'a', sizeof(longpath) - 1);
    longpath[sizeof(longpath) - 1] = '\0';
    CHECK(nfb_ipc_init(&g_ipc, longpath, 100) == -1);
    CHECK(nfb_ipc_init(&g_ipc, "", 100) == -1);
}

static void test_no_server(void)
{
    enum nfb_decision d;
    unlink(g_path);
    init_ipc(&g_ipc, 200);
    CHECK(decide(&g_ipc, 1, 10, &d) == -1);
    CHECK(!nfb_ipc_is_connected(&g_ipc));
}

static void test_simple(enum behaviour b, enum nfb_decision expected, uint32_t len)
{
    enum nfb_decision d = 0;
    int lfd = make_listener();
    pid_t pid = spawn_server(lfd, b);
    init_ipc(&g_ipc, 1000);
    CHECK(decide(&g_ipc, 5, len, &d) == 0);
    CHECK(d == expected);
    CHECK(decide(&g_ipc, 6, len, &d) == 0); /* same connection, next correlation id */
    CHECK(d == expected);
    nfb_ipc_close(&g_ipc);
    expect_child_ok(pid);
    close(lfd);
}

static void test_failure(enum behaviour b, int timeout_ms)
{
    enum nfb_decision d;
    int lfd = make_listener();
    pid_t pid = spawn_server(lfd, b);
    init_ipc(&g_ipc, timeout_ms);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK(decide(&g_ipc, 9, 100, &d) == -1);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long elapsed = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    CHECK(elapsed < timeout_ms + 500);
    CHECK(!nfb_ipc_is_connected(&g_ipc)); /* connection dropped to resync the stream */
    nfb_ipc_close(&g_ipc);
    expect_child_ok(pid);
    close(lfd);
}

static void test_reconnect_after_server_start(void)
{
    enum nfb_decision d;
    unlink(g_path);
    init_ipc(&g_ipc, 1000);
    CHECK(decide(&g_ipc, 1, 10, &d) == -1);

    int lfd = make_listener();
    pid_t pid = spawn_server(lfd, B_DROP);
    CHECK(decide(&g_ipc, 2, 10, &d) == 0);
    CHECK(d == NFB_DECISION_DROP);
    nfb_ipc_close(&g_ipc);
    expect_child_ok(pid);
    close(lfd);
}

static void test_resend_after_server_restart(void)
{
    enum nfb_decision d;
    int lfd = make_listener();
    init_ipc(&g_ipc, 1000);

    pid_t pid = spawn_server(lfd, B_ALLOW_ONE_EXIT);
    CHECK(decide(&g_ipc, 1, 10, &d) == 0);
    CHECK(d == NFB_DECISION_ALLOW);
    expect_child_ok(pid); /* server is gone, client still holds the stale connection */

    pid = spawn_server(lfd, B_DROP);
    CHECK(decide(&g_ipc, 2, 10, &d) == 0); /* EPIPE on stale fd -> transparent resend */
    CHECK(d == NFB_DECISION_DROP);
    nfb_ipc_close(&g_ipc);
    expect_child_ok(pid);
    close(lfd);
}

static void test_backoff(void)
{
    enum nfb_decision d;
    unlink(g_path);
    CHECK(nfb_ipc_init(&g_ipc, g_path, 100) == 0); /* default backoff */
    CHECK(decide(&g_ipc, 1, 0, &d) == -1);

    int lfd = make_listener();
    pid_t pid = spawn_server(lfd, B_ALLOW);
    /* Still inside the backoff window: no connection attempt is made. */
    CHECK(decide(&g_ipc, 2, 0, &d) == -1);
    sleep_ms(g_ipc.backoff_initial_ms + 50);
    CHECK(decide(&g_ipc, 3, 0, &d) == 0);
    CHECK(d == NFB_DECISION_ALLOW);
    nfb_ipc_close(&g_ipc);
    expect_child_ok(pid);
    close(lfd);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    nfb_log_set_level(NFB_LOG_ERROR);

    strcpy(g_dir, "/tmp/nfbridge-test-XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        perror("mkdtemp");
        return 2;
    }
    snprintf(g_path, sizeof(g_path), "%s/java.sock", g_dir);

    test_init_validation();
    test_no_server();
    test_simple(B_ALLOW, NFB_DECISION_ALLOW, 64);
    test_simple(B_DROP, NFB_DECISION_DROP, 0);
    test_simple(B_ALLOW, NFB_DECISION_ALLOW, NFB_MAX_PAYLOAD);
    test_simple(B_TRICKLE, NFB_DECISION_DROP, 1500);
    test_failure(B_WRONG_CORR, 1000);
    test_failure(B_BAD_DECISION, 1000);
    test_failure(B_CLOSE, 1000);
    test_failure(B_SILENT, 200);
    test_reconnect_after_server_start();
    test_resend_after_server_restart();
    test_backoff();

    unlink(g_path);
    rmdir(g_dir);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("ipc tests passed\n");
    return 0;
}
