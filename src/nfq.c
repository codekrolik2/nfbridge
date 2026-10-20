/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "nfbridge/nfq.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netfilter.h> /* NF_ACCEPT, NF_DROP */
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "nfbridge/log.h"

/* Large enough for one netlink message carrying a full 64 KiB packet copy plus attributes. */
#define NFQ_RECV_BUF_SIZE (NFB_MAX_PAYLOAD + 4096)
#define NFQ_POLL_INTERVAL_MS 500

static int on_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa,
                     void *data)
{
    (void)nfmsg;
    struct nfb_nfq *q = data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph == NULL) {
        /* Without an id no verdict can be issued; the kernel keeps the packet queued. */
        LOG_ERROR("queued packet without packet header, ignoring");
        return 0;
    }
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *payload = NULL;
    int len = nfq_get_payload(nfa, &payload);
    if (len < 0) {
        len = 0;
        payload = NULL;
    }

    struct nfb_request_hdr hdr = {
        .packet_id = id,
        .hw_protocol = ntohs(ph->hw_protocol),
        .hook = ph->hook,
        .mark = nfq_get_nfmark(nfa),
        .indev = nfq_get_indev(nfa),
        .outdev = nfq_get_outdev(nfa),
        .payload_len = (uint32_t)len,
    };

    enum nfb_decision decision;
    const char *source = "java";
    if (nfb_ipc_decide(q->ipc, &hdr, payload, &decision) != 0) {
        decision = q->fail_open ? NFB_DECISION_ALLOW : NFB_DECISION_DROP;
        source = q->fail_open ? "fail-open" : "fail-closed";
    }

    uint32_t verdict = decision == NFB_DECISION_ALLOW ? NF_ACCEPT : NF_DROP;
    LOG_DEBUG("packet id=%" PRIu32 " len=%d hook=%u -> %s (%s)", id, len, (unsigned)ph->hook,
              nfb_decision_str(decision), source);

    if (nfq_set_verdict(qh, id, verdict, 0, NULL) < 0)
        LOG_ERROR("nfq_set_verdict(id=%" PRIu32 "): %s", id, strerror(errno));
    return 0;
}

int nfb_nfq_open(struct nfb_nfq *q, uint16_t queue_num, bool fail_open, struct nfb_ipc *ipc)
{
    memset(q, 0, sizeof(*q));
    q->fd = -1;
    q->queue_num = queue_num;
    q->fail_open = fail_open;
    q->ipc = ipc;

    q->h = nfq_open();
    if (q->h == NULL) {
        LOG_ERROR("nfq_open: %s (are you root / do you have CAP_NET_ADMIN?)", strerror(errno));
        return -1;
    }

    /*
     * Per-family (un)binding is a no-op on kernels >= 3.8 but required on older ones.
     * Failures are therefore only fatal for AF_INET binding.
     */
    if (nfq_unbind_pf(q->h, AF_INET) < 0)
        LOG_DEBUG("nfq_unbind_pf(AF_INET): %s (ignored)", strerror(errno));
    if (nfq_bind_pf(q->h, AF_INET) < 0) {
        LOG_ERROR("nfq_bind_pf(AF_INET): %s (requires root or CAP_NET_ADMIN)", strerror(errno));
        goto fail;
    }
    if (nfq_unbind_pf(q->h, AF_INET6) < 0)
        LOG_DEBUG("nfq_unbind_pf(AF_INET6): %s (ignored)", strerror(errno));
    if (nfq_bind_pf(q->h, AF_INET6) < 0)
        LOG_WARN("nfq_bind_pf(AF_INET6): %s (IPv6 may not be intercepted)", strerror(errno));

    q->qh = nfq_create_queue(q->h, queue_num, on_packet, q);
    if (q->qh == NULL) {
        LOG_ERROR("nfq_create_queue(%u): %s (is another process bound to this queue?)",
                  (unsigned)queue_num, strerror(errno));
        goto fail;
    }

    if (nfq_set_mode(q->qh, NFQNL_COPY_PACKET, NFB_MAX_PAYLOAD) < 0) {
        LOG_ERROR("nfq_set_mode(NFQNL_COPY_PACKET): %s", strerror(errno));
        goto fail;
    }

    if (fail_open) {
        /* Also let the kernel accept packets instead of dropping them when the queue is full. */
        if (nfq_set_queue_flags(q->qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) < 0)
            LOG_WARN("kernel does not support NFQA_CFG_F_FAIL_OPEN: %s", strerror(errno));
    }

    q->fd = nfq_fd(q->h);
    LOG_INFO("bound to NFQUEUE %u (fail-%s)", (unsigned)queue_num, fail_open ? "open" : "closed");
    return 0;

fail:
    nfb_nfq_close(q);
    return -1;
}

int nfb_nfq_run(struct nfb_nfq *q, volatile sig_atomic_t *stop)
{
    static char buf[NFQ_RECV_BUF_SIZE] __attribute__((aligned));

    while (!*stop) {
        struct pollfd pfd = {.fd = q->fd, .events = POLLIN};
        int rc = poll(&pfd, 1, NFQ_POLL_INTERVAL_MS);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            LOG_ERROR("poll(nfqueue fd): %s", strerror(errno));
            return -1;
        }
        if (rc == 0)
            continue;

        ssize_t n = recv(q->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            if (errno == ENOBUFS) {
                /* Netlink buffer overran: the kernel could not deliver some packets to us. */
                LOG_WARN("nfqueue receive buffer overrun (ENOBUFS): verdicts are too slow, "
                         "some packets were not delivered to nfbridge");
                continue;
            }
            LOG_ERROR("recv(nfqueue fd): %s", strerror(errno));
            return -1;
        }
        if (n == 0)
            continue;
        nfq_handle_packet(q->h, buf, (int)n);
    }
    return 0;
}

void nfb_nfq_close(struct nfb_nfq *q)
{
    if (q->qh != NULL) {
        nfq_destroy_queue(q->qh);
        q->qh = NULL;
    }
    if (q->h != NULL) {
        nfq_close(q->h);
        q->h = NULL;
    }
    q->fd = -1;
}
