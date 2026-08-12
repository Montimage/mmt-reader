/**
 * test_wifi.c — Unit tests for capture_wifi_to_ethernet()
 *
 * Drives the 802.11 to Ethernet conversion with synthetic frames built
 * as byte arrays: valid data frames for each ToDS/FromDS combination,
 * plus malformed, truncated and non-convertible frames.
 *
 * Compile: gcc -g -o test_wifi tests/test_wifi.c capture.c flows.c \
 *              -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
 *              -L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capture.h"

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define ASSERT_EQ(expected, actual, msg) do { \
    tests_run++; \
    if ((expected) == (actual)) { tests_pass++; } \
    else { printf("FAIL: %s (expected=%d, actual=%d)\n", msg, expected, actual); tests_fail++; } \
} while(0)

#define ASSERT_MEM_EQ(expected, actual, len, msg) do { \
    tests_run++; \
    if (memcmp((expected), (actual), (size_t)(len)) == 0) { tests_pass++; } \
    else { printf("FAIL: %s (%d bytes differ)\n", msg, len); tests_fail++; } \
} while(0)

/* ------------------------------------------------------------------ */
/* Synthetic frame helpers                                             */
/* ------------------------------------------------------------------ */

/* Address field offsets inside the 802.11 MAC header */
#define A1 4
#define A2 10
#define A3 16
#define A4 24

/* Recognisable first byte of each address so DA/SA mix-ups are visible */
#define TAG1 0x10
#define TAG2 0x20
#define TAG3 0x30
#define TAG4 0x40

#define FRAME_MAX 256

/** Fill a 6-byte address field with a recognisable pattern */
static void set_addr(u_char *buf, int off, u_char tag) {
    int i;
    for (i = 0; i < 6; i++) {
        buf[off + i] = (u_char)(tag + i);
    }
}

/** Build the expected 6-byte address for a given tag */
static void expect_addr(u_char *out, u_char tag) {
    int i;
    for (i = 0; i < 6; i++) {
        out[i] = (u_char)(tag + i);
    }
}

/**
 * Build a synthetic 802.11 frame.
 *
 * Writes the Frame Control bytes, the four address fields, an LLC/SNAP
 * header with the given EtherType and a payload of payload_len bytes.
 *
 * @param buf         Frame buffer (at least FRAME_MAX bytes)
 * @param fc0         Frame Control byte 0 (type/subtype)
 * @param fc1         Frame Control byte 1 (ToDS/FromDS/Protected/Order)
 * @param hdr_len     MAC header length the frame should have
 * @param ethertype   EtherType to place in the SNAP header
 * @param payload_len Number of payload bytes after the SNAP header
 * @return            Total frame length
 */
static int build_frame(u_char *buf, u_char fc0, u_char fc1, int hdr_len,
                       uint16_t ethertype, int payload_len) {
    int i;

    memset(buf, 0, FRAME_MAX);
    buf[0] = fc0;
    buf[1] = fc1;
    set_addr(buf, A1, TAG1);
    set_addr(buf, A2, TAG2);
    set_addr(buf, A3, TAG3);
    set_addr(buf, A4, TAG4);

    /* LLC/SNAP: AA AA 03 00 00 00 <ethertype> */
    buf[hdr_len + 0] = 0xAA;
    buf[hdr_len + 1] = 0xAA;
    buf[hdr_len + 2] = 0x03;
    buf[hdr_len + 3] = 0x00;
    buf[hdr_len + 4] = 0x00;
    buf[hdr_len + 5] = 0x00;
    buf[hdr_len + 6] = (u_char)(ethertype >> 8);
    buf[hdr_len + 7] = (u_char)(ethertype & 0xFF);

    for (i = 0; i < payload_len; i++) {
        buf[hdr_len + 8 + i] = (u_char)(0xC0 + i);
    }

    return hdr_len + 8 + payload_len;
}

/* ------------------------------------------------------------------ */
/* Valid frames                                                        */
/* ------------------------------------------------------------------ */

/* QoS data, FromDS=1 (AP -> STA): DA = Addr1, SA = Addr3, hdr_len 26 */
static void test_qos_fromds_ipv4(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    u_char expected[6];
    int out_len = 0;
    int payload_len = 20;
    int caplen = build_frame(frame, 0x88, 0x02, 26, 0x0800, payload_len);

    int rc = capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len);
    ASSERT_EQ(1, rc, "QoS FromDS frame converts");
    ASSERT_EQ(14 + payload_len, out_len, "QoS FromDS out_len is 14 + payload");

    expect_addr(expected, TAG1);
    ASSERT_MEM_EQ(expected, &eth[0], 6, "QoS FromDS DA is Addr1");
    expect_addr(expected, TAG3);
    ASSERT_MEM_EQ(expected, &eth[6], 6, "QoS FromDS SA is Addr3");

    ASSERT_EQ(0x08, eth[12], "QoS FromDS EtherType high byte is 0x08");
    ASSERT_EQ(0x00, eth[13], "QoS FromDS EtherType low byte is 0x00");
    ASSERT_MEM_EQ(&frame[26 + 8], &eth[14], payload_len, "QoS FromDS payload copied verbatim");
}

/* Non-QoS data, ToDS=1 (STA -> AP): DA = Addr3, SA = Addr2, hdr_len 24 */
static void test_nonqos_tods(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    u_char expected[6];
    int out_len = 0;
    int payload_len = 16;
    int caplen = build_frame(frame, 0x08, 0x01, 24, 0x0800, payload_len);

    int rc = capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len);
    ASSERT_EQ(1, rc, "non-QoS ToDS frame converts");
    ASSERT_EQ(14 + payload_len, out_len, "non-QoS ToDS out_len is 14 + payload");

    expect_addr(expected, TAG3);
    ASSERT_MEM_EQ(expected, &eth[0], 6, "non-QoS ToDS DA is Addr3");
    expect_addr(expected, TAG2);
    ASSERT_MEM_EQ(expected, &eth[6], 6, "non-QoS ToDS SA is Addr2");
}

/* Non-QoS data, IBSS (ToDS=0, FromDS=0): DA = Addr1, SA = Addr2 */
static void test_nonqos_ibss(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    u_char expected[6];
    int out_len = 0;
    int caplen = build_frame(frame, 0x08, 0x00, 24, 0x0800, 12);

    int rc = capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len);
    ASSERT_EQ(1, rc, "IBSS frame converts");

    expect_addr(expected, TAG1);
    ASSERT_MEM_EQ(expected, &eth[0], 6, "IBSS DA is Addr1");
    expect_addr(expected, TAG2);
    ASSERT_MEM_EQ(expected, &eth[6], 6, "IBSS SA is Addr2");
}

/* 4-address WDS frame (ToDS=1, FromDS=1): DA = Addr3, SA = Addr4, hdr_len 30 */
static void test_wds_four_address(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    u_char expected[6];
    int out_len = 0;
    int payload_len = 24;
    int caplen = build_frame(frame, 0x08, 0x03, 30, 0x0800, payload_len);

    int rc = capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len);
    ASSERT_EQ(1, rc, "WDS frame converts");
    ASSERT_EQ(14 + payload_len, out_len, "WDS out_len is 14 + payload");

    expect_addr(expected, TAG3);
    ASSERT_MEM_EQ(expected, &eth[0], 6, "WDS DA is Addr3");
    expect_addr(expected, TAG4);
    ASSERT_MEM_EQ(expected, &eth[6], 6, "WDS SA is Addr4");
    /* A 30-byte header means the payload starts at 38, not 32 */
    ASSERT_MEM_EQ(&frame[38], &eth[14], payload_len, "WDS payload starts after 30-byte header");
}

/* QoS data with the Order bit set carries an extra 4-byte HT Control field */
static void test_qos_ht_control(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int payload_len = 10;
    int caplen = build_frame(frame, 0x88, 0x82, 30, 0x0800, payload_len);

    int rc = capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len);
    ASSERT_EQ(1, rc, "QoS+HT frame converts");
    ASSERT_EQ(14 + payload_len, out_len, "QoS+HT out_len is 14 + payload");
    ASSERT_MEM_EQ(&frame[38], &eth[14], payload_len, "QoS+HT payload starts after 30-byte header");
}

/* IPv6 SNAP frame: EtherType 0x86DD is preserved verbatim */
static void test_ipv6_ethertype(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int caplen = build_frame(frame, 0x88, 0x02, 26, 0x86DD, 40);

    int rc = capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len);
    ASSERT_EQ(1, rc, "IPv6 SNAP frame converts");
    ASSERT_EQ(0x86, eth[12], "IPv6 EtherType high byte is 0x86");
    ASSERT_EQ(0xDD, eth[13], "IPv6 EtherType low byte is 0xDD");
}

/* ------------------------------------------------------------------ */
/* Rejected frame types                                                */
/* ------------------------------------------------------------------ */

/* Management frame (type 0, beacon subtype 8) */
static void test_management_frame(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int caplen = build_frame(frame, 0x80, 0x00, 24, 0x0800, 20);

    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len),
              "management frame rejected");
}

/* Control frame (type 1, ACK subtype 13) */
static void test_control_frame(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int caplen = build_frame(frame, 0xD4, 0x00, 24, 0x0800, 20);

    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len),
              "control frame rejected");
}

/* Null data (subtype 4) and QoS Null (subtype 12) carry no payload */
static void test_null_data_frames(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int caplen;

    caplen = build_frame(frame, 0x48, 0x01, 24, 0x0800, 20);
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len),
              "Null data frame rejected");

    caplen = build_frame(frame, 0xC8, 0x01, 26, 0x0800, 20);
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len),
              "QoS Null frame rejected");
}

/* Protected bit set — the payload is encrypted */
static void test_protected_frame(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int caplen = build_frame(frame, 0x08, 0x41, 24, 0x0800, 20);

    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len),
              "protected frame rejected");
}

/* ------------------------------------------------------------------ */
/* Malformed and truncated frames                                      */
/* ------------------------------------------------------------------ */

static void test_truncated_frames(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;

    build_frame(frame, 0x08, 0x01, 24, 0x0800, 20);

    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, 0, eth, (int)sizeof(eth), &out_len),
              "caplen 0 rejected");
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, 4, eth, (int)sizeof(eth), &out_len),
              "caplen 4 rejected");
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, 23, eth, (int)sizeof(eth), &out_len),
              "caplen 23 rejected");
    /* hdr_len + 4: the SNAP header is truncated */
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, 24 + 4, eth, (int)sizeof(eth), &out_len),
              "truncated SNAP header rejected");
    /* hdr_len + 8: SNAP header complete but no payload */
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, 24 + 8, eth, (int)sizeof(eth), &out_len),
              "zero-length payload rejected");
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, -1, eth, (int)sizeof(eth), &out_len),
              "negative caplen rejected");
}

static void test_bad_snap_header(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int caplen = build_frame(frame, 0x08, 0x01, 24, 0x0800, 20);

    frame[24] = 0x45;   /* not AA AA 03 — looks like a bare IPv4 header */
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len),
              "non-SNAP payload rejected");

    frame[24] = 0xAA;
    frame[26] = 0x00;   /* AA AA 00 — wrong control byte */
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), &out_len),
              "wrong SNAP control byte rejected");
}

static void test_output_buffer_too_small(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int payload_len = 40;
    int caplen = build_frame(frame, 0x08, 0x01, 24, 0x0800, payload_len);

    /* One byte short of the 14 + payload_len needed */
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, 14 + payload_len - 1, &out_len),
              "undersized output buffer rejected");
    ASSERT_EQ(1, capture_wifi_to_ethernet(frame, caplen, eth, 14 + payload_len, &out_len),
              "exactly-sized output buffer accepted");
}

static void test_null_arguments(void) {
    u_char frame[FRAME_MAX];
    u_char eth[FRAME_MAX];
    int out_len = 0;
    int caplen = build_frame(frame, 0x08, 0x01, 24, 0x0800, 20);

    ASSERT_EQ(0, capture_wifi_to_ethernet(NULL, caplen, eth, (int)sizeof(eth), &out_len),
              "NULL frame rejected");
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, NULL, (int)sizeof(eth), &out_len),
              "NULL output buffer rejected");
    ASSERT_EQ(0, capture_wifi_to_ethernet(frame, caplen, eth, (int)sizeof(eth), NULL),
              "NULL out_len rejected");
}

/* ---- Main ---- */

int main(void) {
    printf("=== 802.11 conversion Unit Tests ===\n\n");

    test_qos_fromds_ipv4();
    test_nonqos_tods();
    test_nonqos_ibss();
    test_wds_four_address();
    test_qos_ht_control();
    test_ipv6_ethertype();
    test_management_frame();
    test_control_frame();
    test_null_data_frames();
    test_protected_frame();
    test_truncated_frames();
    test_bad_snap_header();
    test_output_buffer_too_small();
    test_null_arguments();

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
