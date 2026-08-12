/**
 * test_flows.c — Unit tests for the flow aggregator in flows.c
 *
 * Drives flows_packet() with synthetic Ethernet frames built as byte
 * arrays: plain IPv4/IPv6, single and stacked VLAN tags, IPv4 options,
 * TCP and UDP, plus malformed and truncated frames that must be
 * rejected without reading out of bounds.
 *
 * struct flows is opaque, so every assertion is made against the text
 * rendered by flows_print_top() into an in-memory stream.
 *
 * Compile: gcc -g -o test_flows tests/test_flows.c flows.c \
 *              -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
 *              -L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "flows.h"

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define ASSERT_EQ(expected, actual, msg) do { \
    tests_run++; \
    if ((expected) == (actual)) { tests_pass++; } \
    else { printf("FAIL: %s (expected=%d, actual=%d)\n", msg, expected, actual); tests_fail++; } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    tests_run++; \
    if (cond) { tests_pass++; } \
    else { printf("FAIL: %s\n", msg); tests_fail++; } \
} while(0)

/* ------------------------------------------------------------------ */
/* Synthetic frame helpers                                             */
/* ------------------------------------------------------------------ */

#define FRAME_MAX 512

/* Ethernet header: 6 DA + 6 SA + 2 EtherType */
#define ETH_HDR_LEN 14

/* Flow-table cap: FLOW_TABLE_SIZE (1 << 11) * 4, see flows.c */
#define EXPECTED_FLOW_CAP 8192

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
 * @param buf        Frame buffer (at least FRAME_MAX bytes)
 * @param tpids      Tag protocol IDs, outermost first (NULL for none)
 * @param ntags      Number of tags in tpids
 * @param l3_type    EtherType of the L3 header that follows the tags
 * @return           Offset of the L3 header
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
 * @param buf       Frame buffer
 * @param tpids     VLAN tag protocol IDs, outermost first (NULL for none)
 * @param ntags     Number of VLAN tags
 * @param ihl_words IPv4 IHL field, in 32-bit words (5 = no options)
 * @param proto     IP protocol number
 * @param src       Source address in dotted-quad form
 * @param dst       Destination address in dotted-quad form
 * @param sport     Source port (TCP/UDP only)
 * @param dport     Destination port (TCP/UDP only)
 * @return          Total frame length
 */
static int build_ipv4(u_char *buf, const uint16_t *tpids, int ntags,
                      uint8_t ihl_words, uint8_t proto,
                      const char *src, const char *dst,
                      uint16_t sport, uint16_t dport) {
    int l3 = build_eth(buf, tpids, ntags, 0x0800);
    int ip_len = ihl_words * 4;
    int l4 = l3 + ip_len;
    int l4_len;

    buf[l3]     = (u_char)(0x40 | ihl_words);
    buf[l3 + 8] = 64;                      /* TTL   */
    buf[l3 + 9] = proto;
    inet_pton(AF_INET, src, &buf[l3 + 12]);
    inet_pton(AF_INET, dst, &buf[l3 + 16]);

    l4_len = build_l4(buf, l4, proto, sport, dport);
    put_be16(buf, l3 + 2, (uint16_t)(ip_len + l4_len));

    return l4 + l4_len;
}

/**
 * Build an Ethernet + IPv6 + optional extension headers + L4 frame.
 *
 * Every extension header written is 8 bytes long.
 *
 * @param buf     Frame buffer
 * @param src     Source address in presentation form
 * @param dst     Destination address in presentation form
 * @param exts    Extension header protocol numbers, in chain order
 * @param nexts   Number of extension headers
 * @param proto   Final (L4) protocol number
 * @param sport   Source port (TCP/UDP only)
 * @param dport   Destination port (TCP/UDP only)
 * @return        Total frame length
 */
static int build_ipv6(u_char *buf, const char *src, const char *dst,
                      const uint8_t *exts, int nexts, uint8_t proto,
                      uint16_t sport, uint16_t dport) {
    int l3 = build_eth(buf, NULL, 0, 0x86DD);
    int off = l3 + 40;
    int i;
    int l4_len;

    buf[l3]     = 0x60;                    /* version 6 */
    buf[l3 + 6] = (nexts > 0) ? exts[0] : proto;
    buf[l3 + 7] = 64;                      /* hop limit */
    inet_pton(AF_INET6, src, &buf[l3 + 8]);
    inet_pton(AF_INET6, dst, &buf[l3 + 24]);

    for (i = 0; i < nexts; i++) {
        buf[off]     = (i + 1 < nexts) ? exts[i + 1] : proto;
        buf[off + 1] = 0;                  /* (0 + 1) * 8 = 8 bytes */
        off += 8;
    }

    l4_len = build_l4(buf, off, proto, sport, dport);
    put_be16(buf, l3 + 4, (uint16_t)(off - (l3 + 40) + l4_len));

    return off + l4_len;
}

/* ------------------------------------------------------------------ */
/* Output capture & inspection                                         */
/* ------------------------------------------------------------------ */

/** Feed one frame with explicit caplen and wire length. */
static void feed(flows_t *f, const u_char *frame, uint32_t caplen, uint32_t wire_len) {
    struct pcap_pkthdr hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = caplen;
    hdr.len    = wire_len;
    flows_packet(f, &hdr, frame);
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

static int is_proto_name(const char *tok) {
    return strcmp(tok, "tcp") == 0 || strcmp(tok, "udp") == 0 ||
           strcmp(tok, "icmp") == 0 || strcmp(tok, "icmpv6") == 0 ||
           strcmp(tok, "ip") == 0;
}

/** Count the data rows in rendered output (the header row is skipped). */
static int count_rows(const char *out) {
    int n = 0;
    const char *p = out;

    while (p != NULL && *p != '\0') {
        const char *eol = strchr(p, '\n');
        size_t len = (eol != NULL) ? (size_t)(eol - p) : strlen(p);
        char line[256];
        char tok[16];

        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        if (sscanf(line, "%15s", tok) == 1 && is_proto_name(tok)) n++;
        p = (eol != NULL) ? eol + 1 : NULL;
    }
    return n;
}

/**
 * Test whether the rendered output contains exactly this flow row.
 *
 * The row is rebuilt with the same format string flows_print_top() uses,
 * so a mismatch in any field — including byte and packet counters —
 * fails the lookup.
 */
static int has_flow(const char *out, const char *proto,
                    const char *src, const char *sport,
                    const char *dst, const char *dport,
                    unsigned long bytes, unsigned long pkts) {
    char want[512];

    snprintf(want, sizeof(want), "%6s %12s %-7s %12s %-7s %12lu %10lu\n",
             proto, src, sport, dst, dport, bytes, pkts);
    return strstr(out, want) != NULL;
}

/* ------------------------------------------------------------------ */
/* Plain Ethernet frames                                               */
/* ------------------------------------------------------------------ */

/* Ethernet + IPv4 + TCP: one flow with the expected 5-tuple and counters */
static void test_ipv4_tcp_basic(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.0.0.1", "10.0.0.2", 1234, 80);

    ASSERT_TRUE(f != NULL, "flows_create returns a handle");
    feed(f, frame, (uint32_t)caplen, 100);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "IPv4/TCP frame records one flow");
    ASSERT_TRUE(has_flow(out, "tcp", "10.0.0.1", "1234", "10.0.0.2", "80", 100, 1),
                "IPv4/TCP 5-tuple, bytes and packets are correct");

    free(out);
    flows_destroy(f);
}

/* Byte counters use the wire length (hdr->len), not the captured length */
static void test_bytes_use_wire_length(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.0.0.1", "10.0.0.2", 1234, 80);

    /* Snapshot length 1500 while only caplen bytes were captured */
    feed(f, frame, (uint32_t)caplen, 1500);

    out = render(f, 10);
    ASSERT_TRUE(has_flow(out, "tcp", "10.0.0.1", "1234", "10.0.0.2", "80", 1500, 1),
                "byte counter uses the wire length, not caplen");
    ASSERT_TRUE(!has_flow(out, "tcp", "10.0.0.1", "1234", "10.0.0.2", "80",
                          (unsigned long)caplen, 1),
                "byte counter is not the captured length");

    free(out);
    flows_destroy(f);
}

/* Two packets on the same 5-tuple aggregate into one flow */
static void test_same_tuple_aggregates(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "192.168.1.10", "192.168.1.20", 40000, 443);

    feed(f, frame, (uint32_t)caplen, 100);
    feed(f, frame, (uint32_t)caplen, 250);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "two packets on one 5-tuple make one flow");
    ASSERT_TRUE(has_flow(out, "tcp", "192.168.1.10", "40000", "192.168.1.20", "443", 350, 2),
                "aggregated flow has packets=2 and the summed byte count");

    free(out);
    flows_destroy(f);
}

/* Flows are unidirectional: the reverse 5-tuple is a separate flow */
static void test_reverse_tuple_is_separate(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen;

    caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                        "10.0.0.1", "10.0.0.2", 1234, 80);
    feed(f, frame, (uint32_t)caplen, 100);
    caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                        "10.0.0.2", "10.0.0.1", 80, 1234);
    feed(f, frame, (uint32_t)caplen, 200);

    out = render(f, 10);
    ASSERT_EQ(2, count_rows(out), "reverse direction is tracked as its own flow");
    ASSERT_TRUE(has_flow(out, "tcp", "10.0.0.1", "1234", "10.0.0.2", "80", 100, 1),
                "forward direction keeps its own counters");
    ASSERT_TRUE(has_flow(out, "tcp", "10.0.0.2", "80", "10.0.0.1", "1234", 200, 1),
                "reverse direction keeps its own counters");

    free(out);
    flows_destroy(f);
}

/* UDP ports are resolved just like TCP ports */
static void test_ipv4_udp(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_UDP,
                            "172.16.0.5", "8.8.8.8", 5353, 53);

    feed(f, frame, (uint32_t)caplen, 80);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "IPv4/UDP frame records one flow");
    ASSERT_TRUE(has_flow(out, "udp", "172.16.0.5", "5353", "8.8.8.8", "53", 80, 1),
                "IPv4/UDP ports are parsed");

    free(out);
    flows_destroy(f);
}

/* ICMP has no ports: it aggregates per IP pair and prints "-" */
static void test_ipv4_icmp_has_no_ports(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_ICMP,
                            "10.1.1.1", "10.1.1.2", 0, 0);

    feed(f, frame, (uint32_t)caplen, 98);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "ICMP frame records one flow");
    ASSERT_TRUE(has_flow(out, "icmp", "10.1.1.1", "-", "10.1.1.2", "-", 98, 1),
                "ICMP flow prints \"-\" for both ports");

    free(out);
    flows_destroy(f);
}

/* ------------------------------------------------------------------ */
/* VLAN tags                                                           */
/* ------------------------------------------------------------------ */

/* A single 802.1Q tag (0x8100) shifts the IPv4 header by 4 bytes */
static void test_single_vlan(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint16_t tpids[1] = { 0x8100 };
    int caplen = build_ipv4(frame, tpids, 1, 5, IPPROTO_TCP,
                            "10.2.0.1", "10.2.0.2", 1111, 22);

    feed(f, frame, (uint32_t)caplen, 120);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "802.1Q frame records one flow");
    ASSERT_TRUE(has_flow(out, "tcp", "10.2.0.1", "1111", "10.2.0.2", "22", 120, 1),
                "802.1Q tag is skipped and the 5-tuple is correct");

    free(out);
    flows_destroy(f);
}

/* QinQ: an 802.1ad (0x88A8) outer tag with an 802.1Q inner tag */
static void test_qinq_88a8_8100(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint16_t tpids[2] = { 0x88A8, 0x8100 };
    int caplen = build_ipv4(frame, tpids, 2, 5, IPPROTO_UDP,
                            "10.3.0.1", "10.3.0.2", 2222, 161);

    feed(f, frame, (uint32_t)caplen, 140);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "QinQ 0x88A8+0x8100 frame records one flow");
    ASSERT_TRUE(has_flow(out, "udp", "10.3.0.1", "2222", "10.3.0.2", "161", 140, 1),
                "both QinQ tags are skipped and the 5-tuple is correct");

    free(out);
    flows_destroy(f);
}

/* Stacked 802.1Q tags (0x8100 twice) */
static void test_stacked_8100_8100(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint16_t tpids[2] = { 0x8100, 0x8100 };
    int caplen = build_ipv4(frame, tpids, 2, 5, IPPROTO_TCP,
                            "10.4.0.1", "10.4.0.2", 3333, 8080);

    feed(f, frame, (uint32_t)caplen, 160);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "stacked 0x8100+0x8100 frame records one flow");
    ASSERT_TRUE(has_flow(out, "tcp", "10.4.0.1", "3333", "10.4.0.2", "8080", 160, 1),
                "both stacked 802.1Q tags are skipped");

    free(out);
    flows_destroy(f);
}

/* Three stacked tags, including the legacy 0x9100 TPID */
static void test_triple_vlan_9100(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint16_t tpids[3] = { 0x9100, 0x88A8, 0x8100 };
    int caplen = build_ipv4(frame, tpids, 3, 5, IPPROTO_TCP,
                            "10.5.0.1", "10.5.0.2", 4444, 25);

    feed(f, frame, (uint32_t)caplen, 180);

    out = render(f, 10);
    ASSERT_TRUE(has_flow(out, "tcp", "10.5.0.1", "4444", "10.5.0.2", "25", 180, 1),
                "three stacked VLAN tags (incl. 0x9100) are skipped");

    free(out);
    flows_destroy(f);
}

/* A VLAN tag with no room for the tag itself leaves the ethertype unresolved */
static void test_vlan_truncated_tag(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint16_t tpids[1] = { 0x8100 };

    build_ipv4(frame, tpids, 1, 5, IPPROTO_TCP, "10.6.0.1", "10.6.0.2", 1, 2);

    /* Only 2 of the tag's 4 bytes captured — parse_vlan must not read them */
    feed(f, frame, ETH_HDR_LEN + 2, 200);

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "truncated VLAN tag records no flow");

    free(out);
    flows_destroy(f);
}

/* ------------------------------------------------------------------ */
/* IPv4 header-length handling                                         */
/* ------------------------------------------------------------------ */

/* IHL 8 (20 bytes of options): ports must be read 12 bytes further along */
static void test_ipv4_options_ihl8(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 8, IPPROTO_TCP,
                            "10.7.0.1", "10.7.0.2", 5555, 993);

    feed(f, frame, (uint32_t)caplen, 220);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "IPv4 with options records one flow");
    ASSERT_TRUE(has_flow(out, "tcp", "10.7.0.1", "5555", "10.7.0.2", "993", 220, 1),
                "ports are read at the IHL-derived offset, not a fixed 20");

    free(out);
    flows_destroy(f);
}

/* IHL 15 (60 bytes), the maximum, with UDP behind the options */
static void test_ipv4_options_ihl15(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 15, IPPROTO_UDP,
                            "10.8.0.1", "10.8.0.2", 6666, 123);

    feed(f, frame, (uint32_t)caplen, 240);

    out = render(f, 10);
    ASSERT_TRUE(has_flow(out, "udp", "10.8.0.1", "6666", "10.8.0.2", "123", 240, 1),
                "maximum IHL of 15 words is honoured");

    free(out);
    flows_destroy(f);
}

/* IHL below 5 is illegal — the frame must be dropped, not parsed */
static void test_ipv4_ihl_too_small(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.9.0.1", "10.9.0.2", 7777, 80);
    int i;

    for (i = 0; i <= 4; i++) {
        frame[ETH_HDR_LEN] = (u_char)(0x40 | i);
        feed(f, frame, (uint32_t)caplen, 100);
    }

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "IPv4 with IHL < 5 is rejected");

    free(out);
    flows_destroy(f);
}

/* IHL pointing past the captured bytes must be rejected */
static void test_ipv4_ihl_past_caplen(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.10.0.1", "10.10.0.2", 8888, 80);

    /* Claim a 60-byte header inside a 54-byte frame */
    frame[ETH_HDR_LEN] = 0x4F;
    feed(f, frame, (uint32_t)caplen, 100);

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "IPv4 whose IHL runs past caplen is rejected");

    free(out);
    flows_destroy(f);
}

/* ------------------------------------------------------------------ */
/* IPv6                                                                */
/* ------------------------------------------------------------------ */

/* IPv6 with TCP directly in the next-header field */
static void test_ipv6_tcp(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv6(frame, "2001:db8::1", "2001:db8::2", NULL, 0,
                            IPPROTO_TCP, 9999, 443);

    feed(f, frame, (uint32_t)caplen, 300);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "IPv6/TCP frame records one flow");
    ASSERT_TRUE(has_flow(out, "tcp", "2001:db8::1", "9999", "2001:db8::2", "443", 300, 1),
                "IPv6/TCP 5-tuple is correct");

    free(out);
    flows_destroy(f);
}

/* IPv6 with UDP */
static void test_ipv6_udp(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv6(frame, "fe80::1", "fe80::2", NULL, 0,
                            IPPROTO_UDP, 546, 547);

    feed(f, frame, (uint32_t)caplen, 90);

    out = render(f, 10);
    ASSERT_TRUE(has_flow(out, "udp", "fe80::1", "546", "fe80::2", "547", 90, 1),
                "IPv6/UDP ports are parsed");

    free(out);
    flows_destroy(f);
}

/* A Hop-by-Hop extension header is walked before the TCP header */
static void test_ipv6_hopopts_chain(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint8_t exts[1] = { IPPROTO_HOPOPTS };
    int caplen = build_ipv6(frame, "2001:db8::10", "2001:db8::20", exts, 1,
                            IPPROTO_TCP, 1010, 8443);

    feed(f, frame, (uint32_t)caplen, 320);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "IPv6 with Hop-by-Hop records one flow");
    ASSERT_TRUE(has_flow(out, "tcp", "2001:db8::10", "1010", "2001:db8::20", "8443", 320, 1),
                "Hop-by-Hop header is skipped and TCP ports are found");

    free(out);
    flows_destroy(f);
}

/* A longer chain: Hop-by-Hop, Routing, Destination Options, then UDP */
static void test_ipv6_multi_ext_chain(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint8_t exts[3] = { IPPROTO_HOPOPTS, IPPROTO_ROUTING, IPPROTO_DSTOPTS };
    int caplen = build_ipv6(frame, "2001:db8::30", "2001:db8::40", exts, 3,
                            IPPROTO_UDP, 2020, 4500);

    feed(f, frame, (uint32_t)caplen, 340);

    out = render(f, 10);
    ASSERT_TRUE(has_flow(out, "udp", "2001:db8::30", "2020", "2001:db8::40", "4500", 340, 1),
                "a three-header extension chain is walked to the UDP header");

    free(out);
    flows_destroy(f);
}

/*
 * A Fragment header is a fixed 8 bytes; its second byte is reserved.
 *
 * flows.c derives every extension header's length from that byte as
 * (l4[1] + 1) * 8, which is only correct for a Fragment header when the
 * reserved byte happens to be 0. These assertions pin the ACTUAL
 * behaviour of both cases.
 *
 * TODO: flows.c:213 should special-case IPPROTO_FRAGMENT as 8 bytes
 * rather than reading the reserved byte as a header length.
 */
static void test_ipv6_fragment_reserved_byte(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint8_t exts[1] = { IPPROTO_FRAGMENT };
    int caplen = build_ipv6(frame, "2001:db8::50", "2001:db8::60", exts, 1,
                            IPPROTO_TCP, 3030, 80);

    /* Reserved byte 0: the (len + 1) * 8 arithmetic lands on 8 by luck */
    feed(f, frame, (uint32_t)caplen, 360);
    out = render(f, 10);
    ASSERT_TRUE(has_flow(out, "tcp", "2001:db8::50", "3030", "2001:db8::60", "80", 360, 1),
                "Fragment header with a zero reserved byte parses correctly");
    free(out);
    flows_destroy(f);

    /* Reserved byte 1: the header length is misread as 16, skipping the ports */
    f = flows_create();
    frame[ETH_HDR_LEN + 40 + 1] = 1;
    feed(f, frame, (uint32_t)caplen, 360);
    out = render(f, 10);
    ASSERT_TRUE(has_flow(out, "tcp", "2001:db8::50", "0", "2001:db8::60", "0", 360, 1),
                "Fragment header with a non-zero reserved byte loses the ports");
    free(out);
    flows_destroy(f);
}

/* An extension header claiming to run past the captured bytes is dropped */
static void test_ipv6_ext_past_caplen(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    uint8_t exts[1] = { IPPROTO_HOPOPTS };
    int caplen = build_ipv6(frame, "2001:db8::70", "2001:db8::80", exts, 1,
                            IPPROTO_TCP, 4040, 80);

    /* Claim (31 + 1) * 8 = 256 bytes of options in a 82-byte frame */
    frame[ETH_HDR_LEN + 40 + 1] = 31;
    feed(f, frame, (uint32_t)caplen, 380);

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "IPv6 extension header past caplen is rejected");

    free(out);
    flows_destroy(f);
}

/* An IPv6 header cut short of its 40 bytes is dropped */
static void test_ipv6_truncated_header(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;

    build_ipv6(frame, "2001:db8::90", "2001:db8::a0", NULL, 0, IPPROTO_TCP, 1, 2);
    feed(f, frame, ETH_HDR_LEN + 39, 400);

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "IPv6 header shorter than 40 bytes is rejected");

    free(out);
    flows_destroy(f);
}

/* ------------------------------------------------------------------ */
/* Non-IP, truncated and malformed frames                              */
/* ------------------------------------------------------------------ */

/* ARP and other non-IP EtherTypes are ignored without crashing */
static void test_non_ip_ethertype(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;

    build_eth(frame, NULL, 0, 0x0806);            /* ARP  */
    feed(f, frame, 60, 60);
    build_eth(frame, NULL, 0, 0x8847);            /* MPLS */
    feed(f, frame, 60, 60);
    build_eth(frame, NULL, 0, 0x0000);
    feed(f, frame, 60, 60);

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "non-IP EtherTypes record no flow");

    free(out);
    flows_destroy(f);
}

/* Frames shorter than a full Ethernet header, or cut off mid-IP-header */
static void test_truncated_frames(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.20.0.1", "10.20.0.2", 1234, 80);
    int i;

    feed(f, frame, 0, 100);                       /* nothing captured      */
    feed(f, frame, 13, 100);                      /* one byte short of L2  */
    feed(f, frame, ETH_HDR_LEN, 100);             /* L2 only, no L3        */

    /* Every cut inside the IPv4 header must be rejected */
    for (i = 1; i < 20; i++) {
        feed(f, frame, (uint32_t)(ETH_HDR_LEN + i), 100);
    }

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "truncated frames record no flow");
    free(out);

    /* The same frame at full length is still accepted afterwards */
    feed(f, frame, (uint32_t)caplen, 100);
    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "a complete frame is still parsed after truncated ones");
    ASSERT_TRUE(has_flow(out, "tcp", "10.20.0.1", "1234", "10.20.0.2", "80", 100, 1),
                "the complete frame's 5-tuple is correct");

    free(out);
    flows_destroy(f);
}

/*
 * A frame carrying a complete IPv4 header but a partial TCP header is
 * still counted, with both ports left at 0 — flows.c only reads the
 * ports when the whole 20-byte TCP header was captured, even though the
 * ports themselves are in the first 4 bytes.
 */
static void test_truncated_l4_keeps_flow_without_ports(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;

    build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP, "10.21.0.1", "10.21.0.2", 1234, 80);
    /* IPv4 header complete, only 4 of the 20 TCP header bytes captured */
    feed(f, frame, ETH_HDR_LEN + 20 + 4, 100);

    out = render(f, 10);
    ASSERT_EQ(1, count_rows(out), "partial TCP header still records the IP pair");
    ASSERT_TRUE(has_flow(out, "tcp", "10.21.0.1", "0", "10.21.0.2", "0", 100, 1),
                "partial TCP header leaves both ports at 0");

    free(out);
    flows_destroy(f);
}

/* NULL arguments are handled without dereferencing them */
static void test_null_arguments(void) {
    u_char frame[FRAME_MAX];
    struct pcap_pkthdr hdr;
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.22.0.1", "10.22.0.2", 1234, 80);

    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = (uint32_t)caplen;
    hdr.len    = 100;

    flows_packet(NULL, &hdr, frame);
    flows_packet(f, NULL, frame);
    flows_packet(f, &hdr, NULL);
    flows_destroy(NULL);

    out = render(f, 10);
    ASSERT_EQ(0, count_rows(out), "NULL arguments record no flow");
    free(out);

    /* An empty aggregator prints nothing at all */
    out = render(f, 10);
    ASSERT_EQ(0, (int)strlen(out), "an empty aggregator prints nothing");

    free(out);
    flows_destroy(f);
}

/* ------------------------------------------------------------------ */
/* Reporting and capacity                                              */
/* ------------------------------------------------------------------ */

/* flows_print_top prints at most top_n rows, largest flow first */
static void test_print_top_n_and_ordering(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen;
    int i;

    /* Three flows with increasing volume: port 1002 is the biggest */
    for (i = 0; i < 3; i++) {
        caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.30.0.1", "10.30.0.2", (uint16_t)(1000 + i), 80);
        feed(f, frame, (uint32_t)caplen, (uint32_t)(100 * (i + 1)));
    }

    out = render(f, 10);
    ASSERT_EQ(3, count_rows(out), "three distinct source ports make three flows");
    free(out);

    out = render(f, 2);
    ASSERT_EQ(2, count_rows(out), "top_n caps the number of printed rows");
    ASSERT_TRUE(has_flow(out, "tcp", "10.30.0.1", "1002", "10.30.0.2", "80", 300, 1),
                "the largest flow is printed");
    ASSERT_TRUE(!has_flow(out, "tcp", "10.30.0.1", "1000", "10.30.0.2", "80", 100, 1),
                "the smallest flow is dropped by top_n");

    free(out);
    flows_destroy(f);
}

/* The flow table stops growing at its cap instead of overflowing */
static void test_flow_table_cap(void) {
    u_char frame[FRAME_MAX];
    flows_t *f = flows_create();
    char *out;
    int caplen = build_ipv4(frame, NULL, 0, 5, IPPROTO_TCP,
                            "10.40.0.1", "10.40.0.2", 1234, 80);
    int total = EXPECTED_FLOW_CAP + 500;
    int i;

    /* Walk the destination address to create distinct 5-tuples */
    for (i = 0; i < total; i++) {
        frame[ETH_HDR_LEN + 16] = 10;
        frame[ETH_HDR_LEN + 17] = (u_char)((i >> 16) & 0xFF);
        frame[ETH_HDR_LEN + 18] = (u_char)((i >> 8) & 0xFF);
        frame[ETH_HDR_LEN + 19] = (u_char)(i & 0xFF);
        feed(f, frame, (uint32_t)caplen, 100);
    }

    out = render(f, total + 100);
    ASSERT_EQ(EXPECTED_FLOW_CAP, count_rows(out),
              "the flow table stops at its cap instead of overflowing");
    free(out);

    /* Flows already in the table keep aggregating once the cap is hit */
    frame[ETH_HDR_LEN + 16] = 10;
    frame[ETH_HDR_LEN + 17] = 0;
    frame[ETH_HDR_LEN + 18] = 0;
    frame[ETH_HDR_LEN + 19] = 0;
    feed(f, frame, (uint32_t)caplen, 100);

    out = render(f, 5);
    ASSERT_TRUE(has_flow(out, "tcp", "10.40.0.1", "1234", "10.0.0.0", "80", 200, 2),
                "an existing flow still aggregates after the cap is reached");

    free(out);
    flows_destroy(f);
}

/* ---- Main ---- */

int main(void) {
    printf("=== Flow aggregation Unit Tests ===\n\n");

    test_ipv4_tcp_basic();
    test_bytes_use_wire_length();
    test_same_tuple_aggregates();
    test_reverse_tuple_is_separate();
    test_ipv4_udp();
    test_ipv4_icmp_has_no_ports();
    test_single_vlan();
    test_qinq_88a8_8100();
    test_stacked_8100_8100();
    test_triple_vlan_9100();
    test_vlan_truncated_tag();
    test_ipv4_options_ihl8();
    test_ipv4_options_ihl15();
    test_ipv4_ihl_too_small();
    test_ipv4_ihl_past_caplen();
    test_ipv6_tcp();
    test_ipv6_udp();
    test_ipv6_hopopts_chain();
    test_ipv6_multi_ext_chain();
    test_ipv6_fragment_reserved_byte();
    test_ipv6_ext_past_caplen();
    test_ipv6_truncated_header();
    test_non_ip_ethertype();
    test_truncated_frames();
    test_truncated_l4_keeps_flow_without_ports();
    test_null_arguments();
    test_print_top_n_and_ordering();
    test_flow_table_cap();

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
