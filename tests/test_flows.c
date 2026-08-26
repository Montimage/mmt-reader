/**
 * test_flows.c — Unit tests for the top-talker report in flows.c
 *
 * flows.c no longer parses packets: it records the sessions MMT-DPI
 * opens and ranks them by the DPI's own byte counters. The tests
 * therefore drive a real MMT handler with synthetic Ethernet frames
 * (plain IPv4/IPv6, VLAN-tagged, TCP/UDP, ARP) and assert on the report
 * rendered by flows_print_top() into an in-memory stream.
 *
 * Compile: gcc -g -o test_flows tests/test_flows.c flows.c \
 *              -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
 *              -L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include "mmt_core.h"
#include "flows.h"

#include "test_util.h"

/* ------------------------------------------------------------------ */
/* Synthetic frame helpers                                             */
/* ------------------------------------------------------------------ */

#define FRAME_MAX 512

/* Ethernet header: 6 DA + 6 SA + 2 EtherType */
#define ETH_HDR_LEN 14

static void put_be16(u_char *buf, int off, uint16_t v) {
    buf[off]     = (u_char)(v >> 8);
    buf[off + 1] = (u_char)(v & 0xFF);
}

/**
 * Write the Ethernet header and any VLAN tags.
 *
 * Each tag is 4 bytes: a 2-byte TCI followed by the EtherType of
 * whatever comes next (the following tag, or the L3 protocol).
 *
 * @param buf      Frame buffer (at least FRAME_MAX bytes)
 * @param tpids    Tag protocol IDs, outermost first (NULL for none)
 * @param ntags    Number of tags in tpids
 * @param l3_type  EtherType of the L3 header that follows the tags
 * @return         Offset of the L3 header
 */
static int build_eth(u_char *buf, const uint16_t *tpids, int ntags, uint16_t l3_type) {
    int i;

    memset(buf, 0, FRAME_MAX);
    for (i = 0; i < 6; i++) {
        buf[i]     = (u_char)(0xAA + i);   /* destination MAC */
        buf[6 + i] = (u_char)(0xBB + i);   /* source MAC      */
    }

    put_be16(buf, 12, (ntags > 0) ? tpids[0] : l3_type);

    for (i = 0; i < ntags; i++) {
        int off = ETH_HDR_LEN + 4 * i;
        put_be16(buf, off, 0x0064);        /* TCI: VLAN id 100 */
        put_be16(buf, off + 2, (i + 1 < ntags) ? tpids[i + 1] : l3_type);
    }

    return ETH_HDR_LEN + 4 * ntags;
}

/** Write a TCP or UDP header with the given ports. Returns its length. */
static int build_l4(u_char *buf, int off, uint8_t proto, uint16_t sport, uint16_t dport) {
    if (proto == IPPROTO_TCP) {
        put_be16(buf, off, sport);
        put_be16(buf, off + 2, dport);
        buf[off + 12] = 0x50;              /* data offset 5, no options */
        buf[off + 13] = 0x02;              /* SYN                       */
        return 20;
    }
    if (proto == IPPROTO_UDP) {
        put_be16(buf, off, sport);
        put_be16(buf, off + 2, dport);
        put_be16(buf, off + 4, 8);         /* length */
        return 8;
    }
    return 0;
}

/**
 * Build an Ethernet + optional VLAN + IPv4 + L4 frame.
 *
 * @param buf    Frame buffer
 * @param tpids  VLAN tag protocol IDs, outermost first (NULL for none)
 * @param ntags  Number of VLAN tags
 * @param proto  IP protocol number
 * @param src    Source address in dotted-quad form
 * @param dst    Destination address in dotted-quad form
 * @param sport  Source port (TCP/UDP only)
 * @param dport  Destination port (TCP/UDP only)
 * @return       Total frame length
 */
static int build_ipv4(u_char *buf, const uint16_t *tpids, int ntags, uint8_t proto,
                      const char *src, const char *dst,
                      uint16_t sport, uint16_t dport) {
    int l3 = build_eth(buf, tpids, ntags, 0x0800);
    int l4 = l3 + 20;
    int l4_len;

    buf[l3]     = 0x45;                    /* version 4, IHL 5 */
    buf[l3 + 8] = 64;                      /* TTL   */
    buf[l3 + 9] = proto;
    inet_pton(AF_INET, src, &buf[l3 + 12]);
    inet_pton(AF_INET, dst, &buf[l3 + 16]);

    l4_len = build_l4(buf, l4, proto, sport, dport);
    put_be16(buf, l3 + 2, (uint16_t)(20 + l4_len));

    return l4 + l4_len;
}

/**
 * Build an Ethernet + IPv6 + L4 frame.
 *
 * @param buf    Frame buffer
 * @param src    Source address in presentation form
 * @param dst    Destination address in presentation form
 * @param proto  L4 protocol number
 * @param sport  Source port
 * @param dport  Destination port
 * @return       Total frame length
 */
static int build_ipv6(u_char *buf, const char *src, const char *dst,
                      uint8_t proto, uint16_t sport, uint16_t dport) {
    int l3 = build_eth(buf, NULL, 0, 0x86DD);
    int off = l3 + 40;
    int l4_len;

    buf[l3]     = 0x60;                    /* version 6 */
    buf[l3 + 6] = proto;                   /* next header */
    buf[l3 + 7] = 64;                      /* hop limit */
    inet_pton(AF_INET6, src, &buf[l3 + 8]);
    inet_pton(AF_INET6, dst, &buf[l3 + 24]);

    l4_len = build_l4(buf, off, proto, sport, dport);
    put_be16(buf, l3 + 4, (uint16_t)l4_len);

    return off + l4_len;
}

/* ------------------------------------------------------------------ */
/* Test fixture: an MMT handler with an attached aggregator            */
/* ------------------------------------------------------------------ */

typedef struct {
    mmt_handler_t *mmt;
    flows_t *flows;
    uint32_t seconds;    /**< Timestamp of the next frame fed */
} fixture_t;

static int fixture_init(fixture_t *fx) {
    char errbuf[1024];

    fx->mmt = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (fx->mmt == NULL) {
        printf("FAIL: mmt_init_handler: %s\n", errbuf);
        return 0;
    }
    fx->flows = flows_create();
    if (fx->flows == NULL) {
        printf("FAIL: flows_create returned NULL\n");
        return 0;
    }
    fx->seconds = 1000;
    return flows_attach(fx->flows, fx->mmt);
}

static void fixture_close(fixture_t *fx) {
    flows_destroy(fx->flows);
    mmt_close_handler(fx->mmt);
}

/** Feed one frame with explicit caplen and wire length. */
static void feed(fixture_t *fx, const u_char *frame, uint32_t caplen, uint32_t wire_len) {
    struct pkthdr hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = fx->seconds++;
    hdr.ts.tv_usec = 0;
    hdr.caplen = caplen;
    hdr.len    = wire_len;
    packet_process(fx->mmt, &hdr, (u_char *)frame);
}

/** Render the top flows into a heap buffer. Caller frees. */
static char *render(flows_t *f, int top_n) {
    char *buf = NULL;
    size_t len = 0;
    FILE *fp = open_memstream(&buf, &len);

    if (fp == NULL) return NULL;
    flows_print_top(f, fp, top_n);
    fclose(fp);
    if (buf == NULL) buf = strdup("");
    return buf;
}

/** Count the data rows in rendered output (header rows are skipped). */
static int count_rows(const char *out) {
    int n = 0;
    const char *p = out;

    while (p != NULL && *p != '\0') {
        const char *eol = strchr(p, '\n');
        size_t len = (eol != NULL) ? (size_t)(eol - p) : strlen(p);
        char line[256];

        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        /* A data row carries an endpoint, which the headers never do */
        if (strchr(line, ':') != NULL && strstr(line, "TOP FLOWS") == NULL) n++;
        p = (eol != NULL) ? eol + 1 : NULL;
    }
    return n;
}

/**
 * Test whether the report contains a flow between these endpoints with
 * exactly these counters. The protocol column is left to the DPI's
 * classifier and is not part of the match.
 */
static int has_flow(const char *out, const char *client, const char *server,
                    unsigned long bytes, unsigned long pkts) {
    char want[256];

    snprintf(want, sizeof(want), "%-24s %-24s %12lu %10lu\n",
             client, server, bytes, pkts);
    return strstr(out, want) != NULL;
}

/* ------------------------------------------------------------------ */
/* Sessions                                                            */
/* ------------------------------------------------------------------ */

/* One IPv4/TCP packet: one flow, client first, counters from the DPI */
static void test_ipv4_tcp_basic(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "flows_attach registers with the handler");
    caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP, "10.0.0.1", "10.0.0.2", 1234, 80);
    feed(&fx, frame, (uint32_t)caplen, 100);

    out = render(fx.flows, 10);
    ASSERT_EQ(1, count_rows(out), "IPv4/TCP packet opens one session");
    ASSERT_TRUE(has_flow(out, "10.0.0.1:1234", "10.0.0.2:80", 100, 1),
                "endpoints and counters come from the session");

    free(out);
    fixture_close(&fx);
}

/* Byte counters follow the wire length, not the captured length */
static void test_bytes_use_wire_length(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");
    caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP, "10.0.0.1", "10.0.0.2", 1234, 80);
    /* Snapshot length 1500 while only caplen bytes were captured */
    feed(&fx, frame, (uint32_t)caplen, 1500);

    out = render(fx.flows, 10);
    ASSERT_TRUE(has_flow(out, "10.0.0.1:1234", "10.0.0.2:80", 1500, 1),
                "byte counter uses the wire length, not caplen");

    free(out);
    fixture_close(&fx);
}

/* Both directions of a conversation are one session, counted together */
static void test_both_directions_are_one_flow(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");

    caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP,
                        "192.168.1.10", "192.168.1.20", 40000, 443);
    feed(&fx, frame, (uint32_t)caplen, 100);
    caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP,
                        "192.168.1.20", "192.168.1.10", 443, 40000);
    feed(&fx, frame, (uint32_t)caplen, 250);

    out = render(fx.flows, 10);
    ASSERT_EQ(1, count_rows(out), "the reply joins the session, not a second flow");
    ASSERT_TRUE(has_flow(out, "192.168.1.10:40000", "192.168.1.20:443", 350, 2),
                "both directions are summed, client stays the session opener");

    free(out);
    fixture_close(&fx);
}

/* Repeated packets on one session keep aggregating */
static void test_same_session_aggregates(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");
    caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP,
                        "192.168.1.10", "192.168.1.20", 40000, 443);
    feed(&fx, frame, (uint32_t)caplen, 100);
    feed(&fx, frame, (uint32_t)caplen, 250);

    out = render(fx.flows, 10);
    ASSERT_EQ(1, count_rows(out), "two packets on one session make one flow");
    ASSERT_TRUE(has_flow(out, "192.168.1.10:40000", "192.168.1.20:443", 350, 2),
                "packets and bytes accumulate on the session");

    free(out);
    fixture_close(&fx);
}

/* UDP ports are reported just like TCP ports */
static void test_ipv4_udp(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");
    caplen = build_ipv4(frame, NULL, 0, IPPROTO_UDP, "172.16.0.5", "8.8.8.8", 5353, 53);
    feed(&fx, frame, (uint32_t)caplen, 80);

    out = render(fx.flows, 10);
    ASSERT_EQ(1, count_rows(out), "IPv4/UDP packet opens one session");
    ASSERT_TRUE(has_flow(out, "172.16.0.5:5353", "8.8.8.8:53", 80, 1),
                "UDP ports are reported");

    free(out);
    fixture_close(&fx);
}

/* Distinct 5-tuples are distinct sessions */
static void test_distinct_sessions(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");
    caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP, "10.0.0.1", "10.0.0.2", 1111, 80);
    feed(&fx, frame, (uint32_t)caplen, 100);
    caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP, "10.0.0.1", "10.0.0.2", 2222, 80);
    feed(&fx, frame, (uint32_t)caplen, 200);

    out = render(fx.flows, 10);
    ASSERT_EQ(2, count_rows(out), "a different source port is a different session");
    ASSERT_TRUE(has_flow(out, "10.0.0.1:1111", "10.0.0.2:80", 100, 1),
                "the first session keeps its own counters");
    ASSERT_TRUE(has_flow(out, "10.0.0.1:2222", "10.0.0.2:80", 200, 1),
                "the second session keeps its own counters");

    free(out);
    fixture_close(&fx);
}

/* The DPI strips VLAN tags, so the endpoints are unchanged by them */
static void test_vlan_tagged(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    uint16_t tpids[2] = { 0x88A8, 0x8100 };
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");
    caplen = build_ipv4(frame, tpids, 2, IPPROTO_TCP, "10.2.0.1", "10.2.0.2", 1111, 22);
    feed(&fx, frame, (uint32_t)caplen, 120);

    out = render(fx.flows, 10);
    ASSERT_EQ(1, count_rows(out), "a QinQ frame opens one session");
    ASSERT_TRUE(has_flow(out, "10.2.0.1:1111", "10.2.0.2:22", 120, 1),
                "VLAN tags do not disturb the endpoints");

    free(out);
    fixture_close(&fx);
}

/* IPv6 sessions are reported with their addresses in presentation form */
static void test_ipv6_tcp(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");
    caplen = build_ipv6(frame, "2001:db8::1", "2001:db8::2", IPPROTO_TCP, 9999, 443);
    feed(&fx, frame, (uint32_t)caplen, 300);

    out = render(fx.flows, 10);
    ASSERT_EQ(1, count_rows(out), "IPv6/TCP packet opens one session");
    ASSERT_TRUE(has_flow(out, "[2001:db8::1]:9999", "[2001:db8::2]:443", 300, 1),
                "IPv6 endpoints are reported, bracketed before the port");

    free(out);
    fixture_close(&fx);
}

/* Traffic with no session behind it (ARP) is not a flow */
static void test_non_ip_traffic(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");
    build_eth(frame, NULL, 0, 0x0806);            /* ARP */
    feed(&fx, frame, 60, 60);

    out = render(fx.flows, 10);
    ASSERT_EQ(0, count_rows(out), "ARP traffic records no flow");

    free(out);
    fixture_close(&fx);
}

/* ------------------------------------------------------------------ */
/* Reporting                                                           */
/* ------------------------------------------------------------------ */

/* flows_print_top prints at most top_n rows, largest flow first */
static void test_print_top_n_and_ordering(void) {
    u_char frame[FRAME_MAX];
    fixture_t fx;
    char *out;
    int caplen;
    int i;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");

    /* Three sessions with increasing volume: port 1002 is the biggest */
    for (i = 0; i < 3; i++) {
        caplen = build_ipv4(frame, NULL, 0, IPPROTO_TCP,
                            "10.30.0.1", "10.30.0.2", (uint16_t)(1000 + i), 80);
        feed(&fx, frame, (uint32_t)caplen, (uint32_t)(100 * (i + 1)));
    }

    out = render(fx.flows, 10);
    ASSERT_EQ(3, count_rows(out), "three source ports make three sessions");
    free(out);

    out = render(fx.flows, 2);
    ASSERT_EQ(2, count_rows(out), "top_n caps the number of printed rows");
    ASSERT_TRUE(has_flow(out, "10.30.0.1:1002", "10.30.0.2:80", 300, 1),
                "the largest flow is printed");
    ASSERT_TRUE(!has_flow(out, "10.30.0.1:1000", "10.30.0.2:80", 100, 1),
                "the smallest flow is dropped by top_n");

    free(out);
    fixture_close(&fx);
}

/* Degenerate arguments are handled without dereferencing them */
static void test_null_arguments(void) {
    fixture_t fx;
    flows_t *f;
    char *out;

    ASSERT_TRUE(fixture_init(&fx), "fixture is ready");

    /* An aggregator that saw nothing prints nothing at all */
    out = render(fx.flows, 10);
    ASSERT_EQ(0, (int)strlen(out), "an empty aggregator prints nothing");
    free(out);

    out = render(fx.flows, 0);
    ASSERT_EQ(0, (int)strlen(out), "top_n of zero prints nothing");
    free(out);

    fixture_close(&fx);

    f = flows_create();
    ASSERT_TRUE(f != NULL, "flows_create returns a handle");
    ASSERT_EQ(0, flows_attach(f, NULL), "attaching to a NULL handler fails");
    ASSERT_EQ(0, flows_attach(NULL, NULL), "attaching a NULL aggregator fails");
    flows_print_top(NULL, stdout, 10);
    flows_destroy(f);
    flows_destroy(NULL);
    tests_run++; tests_pass++;   /* reached here without crashing */
}

/* ---- Main ---- */

int main(void) {
    printf("=== Flow reporting Unit Tests ===\n\n");

    init_extraction();

    test_ipv4_tcp_basic();
    test_bytes_use_wire_length();
    test_both_directions_are_one_flow();
    test_same_session_aggregates();
    test_ipv4_udp();
    test_distinct_sessions();
    test_vlan_tagged();
    test_ipv6_tcp();
    test_non_ip_traffic();
    test_print_top_n_and_ordering();
    test_null_arguments();

    close_extraction();

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
