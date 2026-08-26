/**
 * test_capture_dispatch.c — Unit tests for the capture packet dispatch
 *
 * capture_callback() must hand every captured frame to the processor
 * registered with capture_set_processor(), on the Ethernet path and on
 * both 802.11 paths (converted and raw fallback). That processor is
 * where the engine counts packets and stamps the capture window, so a
 * missing dispatch silently zeroes every INPUT STATISTICS figure.
 *
 * A stub processor records the invocations; the frames are synthetic
 * byte arrays, so no interface and no privileges are needed.
 *
 * Compile: gcc -g -o test_capture_dispatch tests/test_capture_dispatch.c \
 *              capture.c \
 *              -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
 *              -L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capture.h"

/* Some older libpcap headers do not expose these datalink constants */
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11 105
#endif

#include "test_util.h"

/* ------------------------------------------------------------------ */
/* Stub processor                                                      */
/* ------------------------------------------------------------------ */

#define SNIFF_LEN 16

static int            g_calls = 0;          /**< Number of invocations      */
static unsigned int   g_last_caplen = 0;    /**< caplen of the last frame   */
static unsigned int   g_last_len = 0;       /**< len of the last frame      */
static struct timeval g_last_ts;            /**< ts of the last frame       */
static void          *g_last_ctx = NULL;    /**< ctx of the last invocation */
static u_char         g_first_bytes[SNIFF_LEN]; /**< head of the last frame */
static int            g_return_value = 1;   /**< What the stub returns      */

/** Record the dispatch and return the configured result */
static int stub_processor(void *ctx, const struct pkthdr *hdr, const u_char *data) {
    g_calls++;
    g_last_ctx    = ctx;
    g_last_caplen = hdr->caplen;
    g_last_len    = hdr->len;
    g_last_ts     = hdr->ts;
    memset(g_first_bytes, 0, sizeof(g_first_bytes));
    if (data != NULL) {
        unsigned int n = hdr->caplen < SNIFF_LEN ? hdr->caplen : SNIFF_LEN;
        memcpy(g_first_bytes, data, (size_t)n);
    }
    return g_return_value;
}

/** Reset the recorder before each scenario */
static void stub_reset(void) {
    g_calls = 0;
    g_last_caplen = 0;
    g_last_len = 0;
    g_last_ctx = NULL;
    g_last_ts.tv_sec = 0;
    g_last_ts.tv_usec = 0;
    g_return_value = 1;
    memset(g_first_bytes, 0, sizeof(g_first_bytes));
}

/* ------------------------------------------------------------------ */
/* Synthetic frame helpers                                             */
/* ------------------------------------------------------------------ */

#define FRAME_MAX 256

/* Address field offsets inside the 802.11 MAC header */
#define A1 4
#define A2 10
#define A3 16
#define A4 24

/* Recognisable first byte of each address */
#define TAG1 0x10
#define TAG2 0x20
#define TAG3 0x30
#define TAG4 0x40

/** Fill a 6-byte address field with a recognisable pattern */
static void set_addr(u_char *buf, int off, u_char tag) {
    int i;
    for (i = 0; i < 6; i++) {
        buf[off + i] = (u_char)(tag + i);
    }
}

/**
 * Build a synthetic 802.11 frame with an LLC/SNAP encapsulated payload.
 * Mirrors the builder used by tests/test_wifi.c.
 */
static int build_wifi_frame(u_char *buf, u_char fc0, u_char fc1, int hdr_len,
                            uint16_t ethertype, int payload_len) {
    int i;

    memset(buf, 0, FRAME_MAX);
    buf[0] = fc0;
    buf[1] = fc1;
    set_addr(buf, A1, TAG1);
    set_addr(buf, A2, TAG2);
    set_addr(buf, A3, TAG3);
    set_addr(buf, A4, TAG4);

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

/**
 * Build a minimal Ethernet/IPv4/UDP frame.
 * @return the frame length
 */
static int build_eth_frame(u_char *buf, u_char tag) {
    int i;

    memset(buf, 0, FRAME_MAX);
    for (i = 0; i < 6; i++) {
        buf[i]     = (u_char)(0xAA + i);   /* destination MAC */
        buf[6 + i] = (u_char)(0xB0 + i);   /* source MAC      */
    }
    buf[12] = 0x08;                        /* EtherType IPv4  */
    buf[13] = 0x00;
    buf[14] = 0x45;                        /* IPv4, IHL 5     */
    buf[17] = 50;                          /* total length    */
    buf[23] = 17;                          /* protocol UDP    */
    buf[30] = tag;                         /* recognisable    */

    return 64;
}

/** Build a pcap header for a frame of the given length */
static struct pcap_pkthdr make_hdr(unsigned int caplen, unsigned int len,
                                   long sec, long usec) {
    struct pcap_pkthdr h;
    memset(&h, 0, sizeof(h));
    h.ts.tv_sec  = sec;
    h.ts.tv_usec = usec;
    h.caplen     = (bpf_u_int32)caplen;
    h.len        = (bpf_u_int32)len;
    return h;
}

/* ------------------------------------------------------------------ */
/* Ethernet dispatch                                                   */
/* ------------------------------------------------------------------ */

/* One Ethernet frame reaches the processor exactly once, unchanged */
static void test_ethernet_single_dispatch(void) {
    u_char frame[FRAME_MAX];
    int frame_len = build_eth_frame(frame, 0x77);
    struct pcap_pkthdr hdr = make_hdr((unsigned int)frame_len, 90, 1234, 5678);
    int marker = 0;

    stub_reset();
    /* No MMT handler is needed: the processor replaces packet_process() */
    capture_set_context(NULL, DLT_EN10MB);
    capture_set_processor(stub_processor, &marker);

    capture_callback(NULL, &hdr, frame);

    ASSERT_EQ(1, g_calls, "Ethernet frame dispatched exactly once");
    ASSERT_EQ(frame_len, (int)g_last_caplen, "Ethernet caplen forwarded verbatim");
    ASSERT_EQ(90, (int)g_last_len, "Ethernet wire len forwarded verbatim");
    ASSERT_EQ(1, g_last_ctx == &marker, "processor receives the registered context");
    ASSERT_MEM_EQ(frame, g_first_bytes, SNIFF_LEN, "Ethernet frame bytes forwarded verbatim");
}

/* N frames in a row produce exactly N dispatches — the regression made 0 */
static void test_every_frame_dispatched(void) {
    u_char frame[FRAME_MAX];
    int frame_len = build_eth_frame(frame, 0x01);
    int i;
    const int n = 17;

    stub_reset();
    capture_set_context(NULL, DLT_EN10MB);
    capture_set_processor(stub_processor, NULL);

    for (i = 0; i < n; i++) {
        struct pcap_pkthdr hdr = make_hdr((unsigned int)frame_len,
                                          (unsigned int)frame_len, 100 + i, 0);
        capture_callback(NULL, &hdr, frame);
    }

    ASSERT_EQ(n, g_calls, "every frame reaches the processor");
}

/* The MMT header carries the pcap timestamp — the capture window depends on it */
static void test_timestamp_forwarded(void) {
    u_char frame[FRAME_MAX];
    int frame_len = build_eth_frame(frame, 0x02);
    struct pcap_pkthdr hdr = make_hdr((unsigned int)frame_len,
                                      (unsigned int)frame_len, 1700000123, 456789);

    stub_reset();
    capture_set_context(NULL, DLT_EN10MB);
    capture_set_processor(stub_processor, NULL);

    capture_callback(NULL, &hdr, frame);

    ASSERT_EQ(1, g_calls, "timestamped frame dispatched once");
    ASSERT_EQ((int)hdr.ts.tv_sec, (int)g_last_ts.tv_sec, "tv_sec forwarded to the processor");
    ASSERT_EQ((int)hdr.ts.tv_usec, (int)g_last_ts.tv_usec, "tv_usec forwarded to the processor");
}

/* ------------------------------------------------------------------ */
/* 802.11 dispatch                                                     */
/* ------------------------------------------------------------------ */

/* A convertible 802.11 frame is dispatched once with the converted length */
static void test_wifi_converted_dispatch(void) {
    u_char frame[FRAME_MAX];
    int payload_len = 20;
    /* QoS data, FromDS=1, 26-byte MAC header */
    int caplen = build_wifi_frame(frame, 0x88, 0x02, 26, 0x0800, payload_len);
    struct pcap_pkthdr hdr = make_hdr((unsigned int)caplen, (unsigned int)caplen, 300, 42);

    stub_reset();
    capture_set_context(NULL, DLT_IEEE802_11);
    capture_set_processor(stub_processor, NULL);

    capture_callback(NULL, &hdr, frame);

    ASSERT_EQ(1, g_calls, "converted 802.11 frame dispatched exactly once");
    ASSERT_EQ(14 + payload_len, (int)g_last_caplen, "converted caplen is 14 + payload");
    ASSERT_EQ(14 + payload_len, (int)g_last_len, "converted wire len is 14 + payload");
    /* Ethernet header rebuilt from Addr1 (DA) and Addr3 (SA) */
    ASSERT_EQ(TAG1, (int)g_first_bytes[0], "converted DA taken from Addr1");
    ASSERT_EQ(TAG3, (int)g_first_bytes[6], "converted SA taken from Addr3");
    ASSERT_EQ(0x08, (int)g_first_bytes[12], "converted EtherType high byte preserved");
    ASSERT_EQ(0x00, (int)g_first_bytes[13], "converted EtherType low byte preserved");
    ASSERT_MEM_EQ(&frame[26 + 8], &g_first_bytes[14], 2, "converted payload follows the header");
}

/* An unconvertible 802.11 frame still reaches the processor, raw */
static void test_wifi_raw_fallback_dispatch(void) {
    u_char frame[FRAME_MAX];
    /* Management frame (type 0) — capture_wifi_to_ethernet() rejects it */
    int caplen = build_wifi_frame(frame, 0x80, 0x00, 24, 0x0800, 20);
    struct pcap_pkthdr hdr = make_hdr((unsigned int)caplen, (unsigned int)caplen, 301, 7);

    stub_reset();
    capture_set_context(NULL, DLT_IEEE802_11);
    capture_set_processor(stub_processor, NULL);

    capture_callback(NULL, &hdr, frame);

    ASSERT_EQ(1, g_calls, "unconvertible 802.11 frame still dispatched once");
    ASSERT_EQ(caplen, (int)g_last_caplen, "raw fallback keeps the original caplen");
    ASSERT_EQ(caplen, (int)g_last_len, "raw fallback keeps the original wire len");
    ASSERT_MEM_EQ(frame, g_first_bytes, SNIFF_LEN, "raw fallback forwards the frame verbatim");
}

/* ------------------------------------------------------------------ */
/* Failure handling                                                    */
/* ------------------------------------------------------------------ */

/* A processor reporting failure must not stop the following frames */
static void test_processor_failure_does_not_stop_dispatch(void) {
    u_char frame[FRAME_MAX];
    int frame_len = build_eth_frame(frame, 0x04);
    int i;
    const int n = 3;

    stub_reset();
    capture_set_context(NULL, DLT_EN10MB);
    capture_set_processor(stub_processor, NULL);
    g_return_value = 0;   /* every frame reports an extraction failure */

    printf("(expecting %d 'Packet data extraction failure.' messages below)\n", n);
    fflush(stdout);
    for (i = 0; i < n; i++) {
        struct pcap_pkthdr hdr = make_hdr((unsigned int)frame_len,
                                          (unsigned int)frame_len, 400 + i, 0);
        capture_callback(NULL, &hdr, frame);
    }

    ASSERT_EQ(n, g_calls, "a failing processor keeps receiving later frames");
}

/* ------------------------------------------------------------------ */
/* Fallback path                                                       */
/* ------------------------------------------------------------------ */

/**
 * Clearing the processor restores the packet_process() fallback.
 *
 * A real MMT handler is needed here: the fallback dereferences it.
 */
static void test_fallback_when_processor_cleared(void) {
    u_char frame[FRAME_MAX];
    int frame_len = build_eth_frame(frame, 0x05);
    struct pcap_pkthdr hdr = make_hdr((unsigned int)frame_len,
                                      (unsigned int)frame_len, 500, 0);
    char errbuf[1024];
    mmt_handler_t *mmt;

    init_extraction();
    mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (mmt == NULL) {
        printf("FAIL: mmt_init_handler failed: %s\n", errbuf);
        tests_run++;
        tests_fail++;
        close_extraction();
        return;
    }

    stub_reset();
    capture_set_context(mmt, DLT_EN10MB);
    capture_set_processor(NULL, NULL);

    capture_callback(NULL, &hdr, frame);

    ASSERT_EQ(0, g_calls, "cleared processor is no longer called");

    /* Re-installing the processor takes precedence again */
    capture_set_processor(stub_processor, NULL);
    capture_callback(NULL, &hdr, frame);
    ASSERT_EQ(1, g_calls, "re-installed processor takes precedence over the fallback");

    capture_set_processor(NULL, NULL);
    mmt_close_handler(mmt);
    close_extraction();
}

/* ---- Main ---- */

int main(void) {
    printf("=== Capture dispatch Unit Tests ===\n\n");

    test_ethernet_single_dispatch();
    test_every_frame_dispatched();
    test_timestamp_forwarded();
    test_wifi_converted_dispatch();
    test_wifi_raw_fallback_dispatch();
    test_processor_failure_does_not_stop_dispatch();
    test_fallback_when_processor_cleared();

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
