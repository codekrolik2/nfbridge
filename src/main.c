/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nfbridge/config.h"
#include "nfbridge/ipc.h"
#include "nfbridge/log.h"
#include "nfbridge/nfq.h"

/* Exit codes */
#define EXIT_FATAL 1
#define EXIT_USAGE 2

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    /* No SA_RESTART: blocking calls return EINTR so the loop notices the stop flag quickly. */
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0)
        return -1;

    /* Writes to a closed Java socket must surface as EPIPE, not kill the process. */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    struct nfb_config cfg;
    switch (nfb_config_parse(&cfg, argc, argv)) {
    case NFB_CONFIG_OK:
        break;
    case NFB_CONFIG_EXIT_OK:
        return EXIT_SUCCESS;
    default:
        return EXIT_USAGE;
    }
    nfb_log_set_level(cfg.log_level);

    /* Static: the IPC context embeds a 64 KiB frame buffer. */
    static struct nfb_ipc ipc;
    if (nfb_ipc_init(&ipc, cfg.socket_path, cfg.timeout_ms) != 0) {
        fprintf(stderr, "nfbridge: invalid socket path '%s' (empty or longer than %zu bytes)\n",
                cfg.socket_path, sizeof(ipc.path) - 1);
        return EXIT_USAGE;
    }

    if (install_signal_handlers() != 0) {
        LOG_ERROR("failed to install signal handlers");
        return EXIT_FATAL;
    }

    LOG_INFO("starting: queue=%u socket=%s timeout=%dms policy=fail-%s", (unsigned)cfg.queue_num,
             cfg.socket_path, cfg.timeout_ms, cfg.fail_open ? "open" : "closed");

    /* Try to connect early so misconfiguration is visible at startup; not fatal. */
    nfb_ipc_ensure_connected(&ipc);

    struct nfb_nfq q;
    if (nfb_nfq_open(&q, cfg.queue_num, cfg.fail_open, &ipc) != 0) {
        nfb_ipc_close(&ipc);
        return EXIT_FATAL;
    }

    int rc = nfb_nfq_run(&q, &g_stop);

    LOG_INFO("shutting down");
    nfb_nfq_close(&q);
    nfb_ipc_close(&ipc);
    return rc == 0 ? EXIT_SUCCESS : EXIT_FATAL;
}
