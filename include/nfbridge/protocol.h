/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NFBRIDGE_PROTOCOL_H
#define NFBRIDGE_PROTOCOL_H

/*
 * Binary protocol between nfbridge (C helper) and the Java decision process.
 * All multi-byte integers are big-endian (network byte order).
 * See README.md ("IPC protocol") for the full description.
 *
 * Request frame (helper -> Java), 40-byte header followed by payload:
 *   off  size  field
 *     0     4  magic          0x4E464252 ("NFBR")
 *     4     2  version        1
 *     6     2  type           1 (REQUEST)
 *     8     8  correlation_id unique per request on a connection
 *    16     4  packet_id      NFQUEUE packet id (informational)
 *    20     2  hw_protocol    EtherType (0x0800 IPv4, 0x86DD IPv6)
 *    22     1  hook           netfilter hook number
 *    23     1  flags          reserved, 0
 *    24     4  mark           packet mark (nfmark)
 *    28     4  indev          input interface index (0 if none)
 *    32     4  outdev         output interface index (0 if none)
 *    36     4  payload_len    number of payload bytes that follow (<= 65535)
 *    40     N  payload        raw packet bytes, starting at the L3 (IP) header
 *
 * Response frame (Java -> helper), fixed 20 bytes:
 *     0     4  magic          0x4E464252 ("NFBR")
 *     4     2  version        1
 *     6     2  type           2 (RESPONSE)
 *     8     8  correlation_id must match the outstanding request
 *    16     4  decision       1 = ALLOW, 2 = DROP
 */

#include <stddef.h>
#include <stdint.h>

#define NFB_PROTO_MAGIC 0x4E464252u
#define NFB_PROTO_VERSION 1u
#define NFB_MSG_REQUEST 1u
#define NFB_MSG_RESPONSE 2u

#define NFB_REQ_HDR_LEN 40u
#define NFB_RESP_LEN 20u
#define NFB_MAX_PAYLOAD 65535u

enum nfb_decision {
    NFB_DECISION_ALLOW = 1,
    NFB_DECISION_DROP = 2,
};

enum nfb_proto_err {
    NFB_PROTO_OK = 0,
    NFB_PROTO_EMAGIC = -1,
    NFB_PROTO_EVERSION = -2,
    NFB_PROTO_ETYPE = -3,
    NFB_PROTO_EDECISION = -4,
    NFB_PROTO_ELENGTH = -5,
    NFB_PROTO_EFLAGS = -6,
};

struct nfb_request_hdr {
    uint64_t correlation_id;
    uint32_t packet_id;
    uint16_t hw_protocol;
    uint8_t hook;
    uint32_t mark;
    uint32_t indev;
    uint32_t outdev;
    uint32_t payload_len;
};

struct nfb_response {
    uint64_t correlation_id;
    enum nfb_decision decision;
};

/* Encodes a request header. Returns NFB_PROTO_ELENGTH if payload_len is too large. */
int nfb_encode_request_hdr(uint8_t out[NFB_REQ_HDR_LEN], const struct nfb_request_hdr *hdr);
int nfb_decode_request_hdr(const uint8_t in[NFB_REQ_HDR_LEN], struct nfb_request_hdr *hdr);

int nfb_encode_response(uint8_t out[NFB_RESP_LEN], const struct nfb_response *resp);
int nfb_decode_response(const uint8_t in[NFB_RESP_LEN], struct nfb_response *resp);

const char *nfb_proto_strerror(int err);
const char *nfb_decision_str(enum nfb_decision d);

#endif /* NFBRIDGE_PROTOCOL_H */
