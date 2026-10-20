/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NFBRIDGE_NFQ_H
#define NFBRIDGE_NFQ_H

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "nfbridge/ipc.h"

struct nfq_handle;
struct nfq_q_handle;

struct nfb_nfq {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    uint16_t queue_num;
    bool fail_open;
    struct nfb_ipc *ipc;
};

/* Opens the NFQUEUE handle, binds the queue and sets packet copy mode. Returns 0 on success. */
int nfb_nfq_open(struct nfb_nfq *q, uint16_t queue_num, bool fail_open, struct nfb_ipc *ipc);

/* Processes packets until *stop becomes non-zero. Returns 0 on clean stop, -1 on fatal error. */
int nfb_nfq_run(struct nfb_nfq *q, volatile sig_atomic_t *stop);

void nfb_nfq_close(struct nfb_nfq *q);

#endif /* NFBRIDGE_NFQ_H */
