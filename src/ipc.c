/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "nfbridge/ipc.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nfbridge/log.h"

#define BACKOFF_INITIAL_MS 100
#define BACKOFF_MAX_MS 5000

enum io_result {
    IO_OK = 0,
    IO_ERROR = -1, /* errno is set */
    IO_TIMEOUT = -2,
    IO_EOF = -3,
};

static void ts_now(struct timespec *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
}

static void ts_add_ms(struct timespec *ts, int ms)
{
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

static int ts_before(const struct timespec *a, const struct timespec *b)
{
    return a->tv_sec < b->tv_sec || (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
}

/* Milliseconds remaining until deadline, rounded up; 0 if already passed. */
static int ms_until(const struct timespec *deadline)
{
    struct timespec now;
    ts_now(&now);
    if (!ts_before(&now, deadline))
        return 0;
    int64_t ns =
        (int64_t)(deadline->tv_sec - now.tv_sec) * 1000000000LL + (deadline->tv_nsec - now.tv_nsec);
    return (int)((ns + 999999) / 1000000);
}

static enum io_result wait_fd(int fd, short events, const struct timespec *deadline)
{
    for (;;) {
        int remaining = ms_until(deadline);
        if (remaining == 0)
            return IO_TIMEOUT;
        struct pollfd pfd = {.fd = fd, .events = events};
        int rc = poll(&pfd, 1, remaining);
        if (rc > 0)
            return IO_OK; /* readable/writable or error/hangup: let send/recv report it */
        if (rc == 0)
            return IO_TIMEOUT;
        if (errno != EINTR)
            return IO_ERROR;
    }
}

static enum io_result send_all(int fd, const uint8_t *buf, size_t len,
                               const struct timespec *deadline)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            enum io_result rc = wait_fd(fd, POLLOUT, deadline);
            if (rc != IO_OK)
                return rc;
            continue;
        }
        return IO_ERROR;
    }
    return IO_OK;
}

static enum io_result recv_all(int fd, uint8_t *buf, size_t len, const struct timespec *deadline)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, MSG_DONTWAIT);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0)
            return IO_EOF;
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            enum io_result rc = wait_fd(fd, POLLIN, deadline);
            if (rc != IO_OK)
                return rc;
            continue;
        }
        return IO_ERROR;
    }
    return IO_OK;
}

static const char *io_strerror(enum io_result rc, int err)
{
    switch (rc) {
    case IO_TIMEOUT:
        return "timed out waiting for Java process";
    case IO_EOF:
        return "connection closed by Java process";
    case IO_ERROR:
        return strerror(err);
    default:
        return "ok";
    }
}

int nfb_ipc_init(struct nfb_ipc *ipc, const char *path, int timeout_ms)
{
    size_t len = path ? strlen(path) : 0;
    if (len == 0 || len >= sizeof(ipc->path))
        return -1;
    memcpy(ipc->path, path, len + 1);
    ipc->fd = -1;
    ipc->timeout_ms = timeout_ms;
    ipc->backoff_initial_ms = BACKOFF_INITIAL_MS;
    ipc->backoff_max_ms = BACKOFF_MAX_MS;
    ipc->backoff_ms = BACKOFF_INITIAL_MS;
    ipc->next_attempt.tv_sec = 0;
    ipc->next_attempt.tv_nsec = 0;
    ipc->down_logged = false;
    ipc->next_correlation_id = 1;
    return 0;
}

bool nfb_ipc_is_connected(const struct nfb_ipc *ipc)
{
    return ipc->fd >= 0;
}

static void schedule_retry(struct nfb_ipc *ipc)
{
    ts_now(&ipc->next_attempt);
    ts_add_ms(&ipc->next_attempt, ipc->backoff_ms);
    if (ipc->backoff_ms < ipc->backoff_max_ms / 2)
        ipc->backoff_ms *= 2;
    else
        ipc->backoff_ms = ipc->backoff_max_ms;
}

int nfb_ipc_ensure_connected(struct nfb_ipc *ipc)
{
    if (ipc->fd >= 0)
        return 0;

    struct timespec now;
    ts_now(&now);
    if (ts_before(&now, &ipc->next_attempt))
        return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        LOG_ERROR("socket(AF_UNIX): %s", strerror(errno));
        schedule_retry(ipc);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, ipc->path, strlen(ipc->path) + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = errno;
        close(fd);
        schedule_retry(ipc);
        if (!ipc->down_logged) {
            LOG_WARN("cannot connect to Java process at %s: %s (will keep retrying, "
                     "packets get the fail policy verdict meanwhile)",
                     ipc->path, strerror(err));
            ipc->down_logged = true;
        } else {
            LOG_DEBUG("reconnect to %s failed: %s", ipc->path, strerror(err));
        }
        return -1;
    }

    ipc->fd = fd;
    ipc->backoff_ms = ipc->backoff_initial_ms;
    ipc->down_logged = false;
    LOG_INFO("connected to Java process at %s", ipc->path);
    return 0;
}

static void drop_connection(struct nfb_ipc *ipc, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void drop_connection(struct nfb_ipc *ipc, const char *fmt, ...)
{
    char reason[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);

    LOG_WARN("closing connection to Java process at %s: %s", ipc->path, reason);
    nfb_ipc_close(ipc);
    /* Allow an immediate reconnect attempt; backoff applies only if it fails. */
    ipc->next_attempt.tv_sec = 0;
    ipc->next_attempt.tv_nsec = 0;
}

int nfb_ipc_decide(struct nfb_ipc *ipc, const struct nfb_request_hdr *hdr, const uint8_t *payload,
                   enum nfb_decision *decision)
{
    if (hdr->payload_len > NFB_MAX_PAYLOAD || (hdr->payload_len > 0 && payload == NULL)) {
        LOG_ERROR("refusing to send packet %" PRIu32 ": invalid payload length %" PRIu32,
                  hdr->packet_id, hdr->payload_len);
        return -1;
    }

    struct timespec deadline;
    ts_now(&deadline);
    ts_add_ms(&deadline, ipc->timeout_ms);

    /*
     * Two attempts: if the Java process restarted while we were idle, the first
     * send on the stale connection fails with EPIPE/ECONNRESET. In that case the
     * request was never processed, so it is safe to resend it on a new connection.
     */
    for (int attempt = 0; attempt < 2; attempt++) {
        if (nfb_ipc_ensure_connected(ipc) != 0)
            return -1;

        struct nfb_request_hdr h = *hdr;
        h.correlation_id = ipc->next_correlation_id++;
        nfb_encode_request_hdr(ipc->buf, &h);
        if (h.payload_len > 0)
            memcpy(ipc->buf + NFB_REQ_HDR_LEN, payload, h.payload_len);

        enum io_result rc = send_all(ipc->fd, ipc->buf, NFB_REQ_HDR_LEN + h.payload_len, &deadline);
        if (rc != IO_OK) {
            int err = errno;
            drop_connection(ipc, "send failed: %s", io_strerror(rc, err));
            if (attempt == 0 && rc == IO_ERROR && (err == EPIPE || err == ECONNRESET))
                continue;
            return -1;
        }

        uint8_t rbuf[NFB_RESP_LEN];
        rc = recv_all(ipc->fd, rbuf, sizeof(rbuf), &deadline);
        if (rc != IO_OK) {
            drop_connection(ipc, "receive failed: %s", io_strerror(rc, errno));
            return -1;
        }

        struct nfb_response resp;
        int prc = nfb_decode_response(rbuf, &resp);
        if (prc != NFB_PROTO_OK) {
            drop_connection(ipc, "malformed response: %s", nfb_proto_strerror(prc));
            return -1;
        }
        if (resp.correlation_id != h.correlation_id) {
            drop_connection(ipc, "correlation id mismatch: expected %" PRIu64 ", got %" PRIu64,
                            h.correlation_id, resp.correlation_id);
            return -1;
        }

        *decision = resp.decision;
        return 0;
    }
    return -1;
}

void nfb_ipc_close(struct nfb_ipc *ipc)
{
    if (ipc->fd >= 0) {
        close(ipc->fd);
        ipc->fd = -1;
    }
}
