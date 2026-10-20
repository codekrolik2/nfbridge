/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <string.h>

#include "nfbridge/protocol.h"

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);               \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static void test_request_roundtrip(void)
{
    struct nfb_request_hdr in = {
        .correlation_id = 0x0102030405060708ULL,
        .packet_id = 0xA1B2C3D4u,
        .hw_protocol = 0x86DD,
        .hook = 3,
        .mark = 0xDEADBEEFu,
        .indev = 2,
        .outdev = 7,
        .payload_len = 1500,
    };
    uint8_t buf[NFB_REQ_HDR_LEN];
    CHECK(nfb_encode_request_hdr(buf, &in) == NFB_PROTO_OK);

    /* Wire layout is big-endian at fixed offsets. */
    static const uint8_t expected_prefix[] = {0x4E, 0x46, 0x42, 0x52, 0x00, 0x01, 0x00, 0x01,
                                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                              0xA1, 0xB2, 0xC3, 0xD4, 0x86, 0xDD, 0x03, 0x00};
    CHECK(memcmp(buf, expected_prefix, sizeof(expected_prefix)) == 0);
    CHECK(buf[36] == 0x00 && buf[37] == 0x00 && buf[38] == 0x05 && buf[39] == 0xDC);

    struct nfb_request_hdr out;
    CHECK(nfb_decode_request_hdr(buf, &out) == NFB_PROTO_OK);
    CHECK(out.correlation_id == in.correlation_id);
    CHECK(out.packet_id == in.packet_id);
    CHECK(out.hw_protocol == in.hw_protocol);
    CHECK(out.hook == in.hook);
    CHECK(out.mark == in.mark);
    CHECK(out.indev == in.indev);
    CHECK(out.outdev == in.outdev);
    CHECK(out.payload_len == in.payload_len);
}

static void test_request_validation(void)
{
    struct nfb_request_hdr in = {.payload_len = NFB_MAX_PAYLOAD + 1};
    uint8_t buf[NFB_REQ_HDR_LEN];
    CHECK(nfb_encode_request_hdr(buf, &in) == NFB_PROTO_ELENGTH);

    in.payload_len = NFB_MAX_PAYLOAD;
    CHECK(nfb_encode_request_hdr(buf, &in) == NFB_PROTO_OK);
    struct nfb_request_hdr out;
    buf[23] = 1;
    CHECK(nfb_decode_request_hdr(buf, &out) == NFB_PROTO_EFLAGS);
    buf[23] = 0;
    buf[37] = 0x01; /* payload_len = 0x0001FFFF */
    CHECK(nfb_decode_request_hdr(buf, &out) == NFB_PROTO_ELENGTH);
}

static void test_response_roundtrip(void)
{
    uint8_t buf[NFB_RESP_LEN];
    struct nfb_response in = {.correlation_id = 42, .decision = NFB_DECISION_DROP};
    CHECK(nfb_encode_response(buf, &in) == NFB_PROTO_OK);
    static const uint8_t expected[NFB_RESP_LEN] = {0x4E, 0x46, 0x42, 0x52, 0, 1,  0, 2, 0, 0,
                                                   0,    0,    0,    0,    0, 42, 0, 0, 0, 2};
    CHECK(memcmp(buf, expected, sizeof(expected)) == 0);

    struct nfb_response out;
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_OK);
    CHECK(out.correlation_id == 42);
    CHECK(out.decision == NFB_DECISION_DROP);

    in.decision = NFB_DECISION_ALLOW;
    CHECK(nfb_encode_response(buf, &in) == NFB_PROTO_OK);
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_OK);
    CHECK(out.decision == NFB_DECISION_ALLOW);

    in.decision = (enum nfb_decision)7;
    CHECK(nfb_encode_response(buf, &in) == NFB_PROTO_EDECISION);
}

static void test_response_validation(void)
{
    uint8_t good[NFB_RESP_LEN];
    struct nfb_response r = {.correlation_id = 1, .decision = NFB_DECISION_ALLOW};
    nfb_encode_response(good, &r);

    uint8_t buf[NFB_RESP_LEN];
    struct nfb_response out;

    memcpy(buf, good, sizeof(buf));
    buf[0] = 'X';
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_EMAGIC);

    memcpy(buf, good, sizeof(buf));
    buf[5] = 2;
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_EVERSION);

    memcpy(buf, good, sizeof(buf));
    buf[7] = NFB_MSG_REQUEST;
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_ETYPE);

    memcpy(buf, good, sizeof(buf));
    buf[19] = 0;
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_EDECISION);

    memcpy(buf, good, sizeof(buf));
    buf[19] = 3;
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_EDECISION);

    memcpy(buf, good, sizeof(buf));
    buf[16] = 1; /* 0x01000001 */
    CHECK(nfb_decode_response(buf, &out) == NFB_PROTO_EDECISION);
}

int main(void)
{
    test_request_roundtrip();
    test_request_validation();
    test_response_roundtrip();
    test_response_validation();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("protocol tests passed\n");
    return 0;
}
