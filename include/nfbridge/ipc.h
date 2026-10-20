/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NFBRIDGE_IPC_H
#define NFBRIDGE_IPC_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/un.h>
#include <time.h>

#include "nfbridge/protocol.h"

/*
 * Synchronous client for the Java decision process over a Unix stream socket.
 *
 * The connection is established lazily and re-established automatically with
 * exponential backoff after any failure. Any I/O error, timeout or malformed
 * response closes the connection so that the stream can never get out of sync.
 */
struct nfb_ipc {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    int fd;
    int timeout_ms;
    int backoff_initial_ms;
    int backoff_max_ms;
    int backoff_ms;
    struct timespec next_attempt;
    bool down_logged;
    uint64_t next_correlation_id;
    uint8_t buf[NFB_REQ_HDR_LEN + NFB_MAX_PAYLOAD];
};

/* Returns 0 on success, -1 if the path is empty or does not fit into sockaddr_un. */
int nfb_ipc_init(struct nfb_ipc *ipc, const char *path, int timeout_ms);

/* Connects if not connected and the backoff period has elapsed. Returns 0 if connected. */
int nfb_ipc_ensure_connected(struct nfb_ipc *ipc);

bool nfb_ipc_is_connected(const struct nfb_ipc *ipc);

/*
 * Sends one request (hdr->correlation_id is assigned internally) and waits for
 * the matching response. Returns 0 and stores the decision on success, -1 on any
 * failure (not connected, I/O error, timeout, malformed response). On failure the
 * caller must apply its fail-open / fail-closed policy.
 */
int nfb_ipc_decide(struct nfb_ipc *ipc, const struct nfb_request_hdr *hdr, const uint8_t *payload,
                   enum nfb_decision *decision);

void nfb_ipc_close(struct nfb_ipc *ipc);

#endif /* NFBRIDGE_IPC_H */
