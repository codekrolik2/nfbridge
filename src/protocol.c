/* SPDX-License-Identifier: Apache-2.0 */
#include "nfbridge/protocol.h"

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u64(uint8_t *p, uint64_t v)
{
    put_u32(p, (uint32_t)(v >> 32));
    put_u32(p + 4, (uint32_t)v);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get_u64(const uint8_t *p)
{
    return ((uint64_t)get_u32(p) << 32) | get_u32(p + 4);
}

static int check_preamble(const uint8_t *in, uint16_t expected_type)
{
    if (get_u32(in) != NFB_PROTO_MAGIC)
        return NFB_PROTO_EMAGIC;
    if (get_u16(in + 4) != NFB_PROTO_VERSION)
        return NFB_PROTO_EVERSION;
    if (get_u16(in + 6) != expected_type)
        return NFB_PROTO_ETYPE;
    return NFB_PROTO_OK;
}

int nfb_encode_request_hdr(uint8_t out[NFB_REQ_HDR_LEN], const struct nfb_request_hdr *hdr)
{
    if (hdr->payload_len > NFB_MAX_PAYLOAD)
        return NFB_PROTO_ELENGTH;
    put_u32(out + 0, NFB_PROTO_MAGIC);
    put_u16(out + 4, NFB_PROTO_VERSION);
    put_u16(out + 6, NFB_MSG_REQUEST);
    put_u64(out + 8, hdr->correlation_id);
    put_u32(out + 16, hdr->packet_id);
    put_u16(out + 20, hdr->hw_protocol);
    out[22] = hdr->hook;
    out[23] = 0;
    put_u32(out + 24, hdr->mark);
    put_u32(out + 28, hdr->indev);
    put_u32(out + 32, hdr->outdev);
    put_u32(out + 36, hdr->payload_len);
    return NFB_PROTO_OK;
}

int nfb_decode_request_hdr(const uint8_t in[NFB_REQ_HDR_LEN], struct nfb_request_hdr *hdr)
{
    int rc = check_preamble(in, NFB_MSG_REQUEST);
    if (rc != NFB_PROTO_OK)
        return rc;
    if (in[23] != 0)
        return NFB_PROTO_EFLAGS;
    uint32_t len = get_u32(in + 36);
    if (len > NFB_MAX_PAYLOAD)
        return NFB_PROTO_ELENGTH;
    hdr->correlation_id = get_u64(in + 8);
    hdr->packet_id = get_u32(in + 16);
    hdr->hw_protocol = get_u16(in + 20);
    hdr->hook = in[22];
    hdr->mark = get_u32(in + 24);
    hdr->indev = get_u32(in + 28);
    hdr->outdev = get_u32(in + 32);
    hdr->payload_len = len;
    return NFB_PROTO_OK;
}

int nfb_encode_response(uint8_t out[NFB_RESP_LEN], const struct nfb_response *resp)
{
    if (resp->decision != NFB_DECISION_ALLOW && resp->decision != NFB_DECISION_DROP)
        return NFB_PROTO_EDECISION;
    put_u32(out + 0, NFB_PROTO_MAGIC);
    put_u16(out + 4, NFB_PROTO_VERSION);
    put_u16(out + 6, NFB_MSG_RESPONSE);
    put_u64(out + 8, resp->correlation_id);
    put_u32(out + 16, (uint32_t)resp->decision);
    return NFB_PROTO_OK;
}

int nfb_decode_response(const uint8_t in[NFB_RESP_LEN], struct nfb_response *resp)
{
    int rc = check_preamble(in, NFB_MSG_RESPONSE);
    if (rc != NFB_PROTO_OK)
        return rc;
    uint32_t d = get_u32(in + 16);
    if (d != NFB_DECISION_ALLOW && d != NFB_DECISION_DROP)
        return NFB_PROTO_EDECISION;
    resp->correlation_id = get_u64(in + 8);
    resp->decision = (enum nfb_decision)d;
    return NFB_PROTO_OK;
}

const char *nfb_proto_strerror(int err)
{
    switch (err) {
    case NFB_PROTO_OK:
        return "ok";
    case NFB_PROTO_EMAGIC:
        return "bad magic";
    case NFB_PROTO_EVERSION:
        return "unsupported protocol version";
    case NFB_PROTO_ETYPE:
        return "unexpected message type";
    case NFB_PROTO_EDECISION:
        return "invalid decision value";
    case NFB_PROTO_ELENGTH:
        return "invalid payload length";
    case NFB_PROTO_EFLAGS:
        return "non-zero reserved flags";
    default:
        return "unknown protocol error";
    }
}

const char *nfb_decision_str(enum nfb_decision d)
{
    switch (d) {
    case NFB_DECISION_ALLOW:
        return "ALLOW";
    case NFB_DECISION_DROP:
        return "DROP";
    default:
        return "INVALID";
    }
}
