/**
 * flows.c — Live flow aggregation (top talkers by volume)
 *
 * Maintains a hash map of 5-tuple flows (src IP, dst IP, proto,
 * src port, dst port) with byte/packet counters. Reports the top
 * flows by transferred volume via flows_print_top().
 *
 * The packet parser walks Ethernet → (VLAN) → IPv4/IPv6 → (IPv6
 * extension headers) → TCP/UDP headers and resolves ports only for
 * TCP/UDP. ICMP/ICMPv6, ESP and other L4 protocols are aggregated per
 * IP pair with ports set to 0.
 */
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "flows.h"

/* ------------------------------------------------------------------ */
/* Internal types                                                      */
/* ------------------------------------------------------------------ */

/*
 * Header sizes, in bytes. Every header is read by explicit byte offset
 * rather than through a struct pointer: an Ethernet frame leaves the IP
 * header at an odd alignment (14 bytes of L2, plus 4 per VLAN tag), so
 * casting to struct ip / ip6_hdr / tcphdr is undefined behaviour even
 * where the hardware tolerates it.
 */
#define IPV4_MIN_HDR_LEN 20            /* IPv4 header without options  */
#define IPV6_HDR_LEN     40            /* IPv6 fixed header            */
#define L4_PORTS_LEN      4            /* src + dst port, TCP and UDP  */

#define FLOW_TABLE_BITS  11            /* 2048 buckets                 */
#define FLOW_TABLE_SIZE  (1U << FLOW_TABLE_BITS)
#define FLOW_MAX_FLOWS   (FLOW_TABLE_SIZE * 4)

typedef struct flow_entry {
    uint32_t hash;
    uint32_t src4;
    uint32_t dst4;
    uint8_t  src6[16];
    uint8_t  dst6[16];
    uint8_t  is_ipv6;
    uint8_t  proto;
    uint16_t sport;
    uint16_t dport;
    uint64_t bytes;
    uint64_t pkts;
    struct flow_entry *next;
} flow_entry_t;

struct flows {
    flow_entry_t *buckets[FLOW_TABLE_SIZE];
    flow_entry_t *flows[FLOW_MAX_FLOWS];
    size_t nflows;
};

/* ------------------------------------------------------------------ */
/* Hash helpers                                                        */
/* ------------------------------------------------------------------ */

static uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t flow_hash(uint8_t is_v6, const void *src, const void *dst,
                          uint8_t proto, uint16_t sport, uint16_t dport) {
    size_t addr_len = is_v6 ? 16 : 4;
    uint32_t h = fnv1a((const uint8_t *)src, addr_len);
    h ^= fnv1a((const uint8_t *)dst, addr_len);
    h ^= ((uint32_t)proto << 16) | ((uint32_t)sport << 8) | dport;
    return h;
}

static int flow_key_eq(const flow_entry_t *e, uint8_t is_v6,
                       const void *src, const void *dst,
                       uint8_t proto, uint16_t sport, uint16_t dport) {
    if (e->is_ipv6 != is_v6 || e->proto != proto ||
        e->sport != sport || e->dport != dport) {
        return 0;
    }
    size_t addr_len = is_v6 ? sizeof(e->src6) : sizeof(e->src4);
    const void *esrc = is_v6 ? (const void *)e->src6 : (const void *)&e->src4;
    const void *edst = is_v6 ? (const void *)e->dst6 : (const void *)&e->dst4;
    return memcmp(esrc, src, addr_len) == 0 &&
           memcmp(edst, dst, addr_len) == 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

flows_t *flows_create(void) {
    return (flows_t *)calloc(1, sizeof(flows_t));
}

void flows_destroy(flows_t *f) {
    if (f == NULL) return;
    for (size_t i = 0; i < FLOW_TABLE_SIZE; i++) {
        flow_entry_t *e = f->buckets[i];
        while (e != NULL) {
            flow_entry_t *next = e->next;
            free(e);
            e = next;
        }
    }
    free(f);
}

/* ------------------------------------------------------------------ */
/* Packet parsing & aggregation                                        */
/* ------------------------------------------------------------------ */

static void agg_packet(flows_t *f, uint8_t is_v6, const void *src, const void *dst,
                       uint8_t proto, uint16_t sport, uint16_t dport,
                       uint32_t wire_len) {
    uint32_t hash = flow_hash(is_v6, src, dst, proto, sport, dport);
    uint32_t bidx = hash & (FLOW_TABLE_SIZE - 1);

    flow_entry_t *e = f->buckets[bidx];
    while (e != NULL) {
        if (e->hash == hash &&
            flow_key_eq(e, is_v6, src, dst, proto, sport, dport)) {
            e->bytes += wire_len;
            e->pkts++;
            return;
        }
        e = e->next;
    }

    if (f->nflows >= FLOW_MAX_FLOWS) return; /* table full — drop */

    flow_entry_t *ne = (flow_entry_t *)calloc(1, sizeof(flow_entry_t));
    if (ne == NULL) return;
    ne->hash  = hash;
    ne->is_ipv6 = is_v6;
    ne->proto = proto;
    ne->sport = sport;
    ne->dport = dport;
    ne->bytes = wire_len;
    ne->pkts  = 1;
    if (is_v6) {
        memcpy(ne->src6, src, 16);
        memcpy(ne->dst6, dst, 16);
    } else {
        /* Raw network-order bytes, as consumed by flows_print_top() */
        memcpy(&ne->src4, src, 4);
        memcpy(&ne->dst4, dst, 4);
    }
    ne->next = f->buckets[bidx];
    f->buckets[bidx] = ne;
    f->flows[f->nflows++] = ne;
}

static uint16_t parse_vlan(const u_char **data, size_t *rem, uint16_t ethertype) {
    /* Skip one or more 802.1Q/802.1ad tags until a non-tag type */
    while (rem[0] >= 4 &&
           (ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100)) {
        ethertype = ((const uint8_t *)data[0])[2] << 8 |
                    ((const uint8_t *)data[0])[3];
        *data += 4;
        *rem  -= 4;
    }
    return ethertype;
}

/**
 * True for the IPv6 extension headers this parser knows how to skip.
 *
 * ESP (50) is deliberately absent: its payload is encrypted, so there
 * are no readable ports behind it and stopping there is correct.
 */
static int is_ext_header(uint8_t proto) {
    return proto == IPPROTO_HOPOPTS  || proto == IPPROTO_ROUTING ||
           proto == IPPROTO_DSTOPTS  || proto == IPPROTO_FRAGMENT ||
           proto == IPPROTO_AH;
}

/**
 * Read the TCP/UDP source and destination ports.
 *
 * Both protocols carry the two ports in the first 4 bytes of the header,
 * so a snaplen-truncated header still yields them. Ports are left
 * untouched for any other protocol, or if fewer than 4 bytes remain.
 */
static void read_ports(uint8_t proto, const u_char *l4, size_t l4rem,
                       uint16_t *sport, uint16_t *dport) {
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return;
    if (l4rem < L4_PORTS_LEN) return;
    *sport = ((uint16_t)l4[0] << 8) | l4[1];
    *dport = ((uint16_t)l4[2] << 8) | l4[3];
}

void flows_packet(flows_t *f, const struct pcap_pkthdr *hdr, const u_char *data) {
    if (f == NULL || hdr == NULL || data == NULL) return;
    if (hdr->caplen < 14) return;

    size_t rem = (size_t)hdr->caplen;
    uint16_t ethertype = ((uint16_t)data[12] << 8) | data[13];
    data += 14;
    rem  -= 14;

    ethertype = parse_vlan(&data, &rem, ethertype);

    if (ethertype == 0x0800) {      /* IPv4 */
        if (rem < IPV4_MIN_HDR_LEN) return;
        size_t ihl = (size_t)(data[0] & 0x0F) * 4;   /* IHL, in 32-bit words */
        if (ihl < IPV4_MIN_HDR_LEN || rem < ihl) return;

        uint8_t proto = data[9];
        uint16_t sport = 0, dport = 0;
        const u_char *l4 = data + ihl;
        size_t l4rem = rem - ihl;

        read_ports(proto, l4, l4rem, &sport, &dport);

        /* Addresses at offsets 12 (src) and 16 (dst), 4 bytes each */
        agg_packet(f, 0, data + 12, data + 16, proto, sport, dport,
                   hdr->len);

    } else if (ethertype == 0x86dd) { /* IPv6 */
        if (rem < IPV6_HDR_LEN) return;

        uint8_t proto = data[6];                     /* next header */
        uint16_t sport = 0, dport = 0;
        const u_char *l4 = data + IPV6_HDR_LEN;
        size_t l4rem = rem - IPV6_HDR_LEN;

        /* Skip IPv6 extension headers (basic handling) */
        while (is_ext_header(proto) && l4rem >= 8) {
            uint8_t nxt = l4[0];
            uint16_t ext_len;
            uint16_t min_len;

            if (proto == IPPROTO_FRAGMENT) {
                /* Fixed 8 bytes; the second byte is reserved, not a length */
                ext_len = 8;
                min_len = 8;
            } else if (proto == IPPROTO_AH) {
                /* Payload Len counts 4-byte units, biased by 2 */
                ext_len = ((uint16_t)l4[1] + 2) * 4;
                min_len = 4;
            } else {
                /* Hdr Ext Len counts 8-byte units, biased by 1 */
                ext_len = ((uint16_t)l4[1] + 1) * 8;
                min_len = 8;
            }
            /* min_len also guarantees the walk makes progress */
            if (ext_len < min_len || ext_len > l4rem) return;

            l4 += ext_len;
            l4rem -= ext_len;
            proto = nxt;
        }

        read_ports(proto, l4, l4rem, &sport, &dport);

        /* Addresses at offsets 8 (src) and 24 (dst), 16 bytes each */
        agg_packet(f, 1, data + 8, data + 24, proto, sport, dport,
                   hdr->len);
    }
    /* Non-IP (ARP, etc.) — ignored */
}

/* ------------------------------------------------------------------ */
/* Reporting                                                           */
/* ------------------------------------------------------------------ */

static int cmp_bytes_desc(const void *a, const void *b) {
    const flow_entry_t *fa = *(flow_entry_t *const *)a;
    const flow_entry_t *fb = *(flow_entry_t *const *)b;
    if (fb->bytes != fa->bytes) {
        return fb->bytes > fa->bytes ? 1 : -1;
    }
    return 0;
}

static const char *proto_name(uint8_t proto) {
    switch (proto) {
    case IPPROTO_TCP: return "tcp";
    case IPPROTO_UDP: return "udp";
    case IPPROTO_ICMP: return "icmp";
    case IPPROTO_ICMPV6: return "icmpv6";
    default: return "ip";
    }
}

void flows_print_top(flows_t *f, FILE *fp, int top_n) {
    if (f == NULL || fp == NULL || f->nflows == 0) return;

    qsort(f->flows, f->nflows, sizeof(flow_entry_t *), cmp_bytes_desc);

    size_t count = f->nflows < (size_t)top_n ? f->nflows : (size_t)top_n;

    fprintf(fp, "\n- - - - - - TOP FLOWS BY VOLUME - - - - - -\n\n");
    fprintf(fp, "%6s %12s %-7s %12s %-7s %12s %10s\n",
            "proto", "src", "sport", "dst", "dport", "bytes", "pkts");

    for (size_t i = 0; i < count; i++) {
        const flow_entry_t *e = f->flows[i];
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        if (e->is_ipv6) {
            inet_ntop(AF_INET6, e->src6, src, sizeof(src));
            inet_ntop(AF_INET6, e->dst6, dst, sizeof(dst));
        } else {
            struct in_addr sa, da;
            sa.s_addr = e->src4;
            da.s_addr = e->dst4;
            inet_ntop(AF_INET, &sa, src, sizeof(src));
            inet_ntop(AF_INET, &da, dst, sizeof(dst));
        }

        char sport[8], dport[8];
        if (e->proto == IPPROTO_TCP || e->proto == IPPROTO_UDP) {
            snprintf(sport, sizeof(sport), "%u", e->sport);
            snprintf(dport, sizeof(dport), "%u", e->dport);
        } else {
            snprintf(sport, sizeof(sport), "-");
            snprintf(dport, sizeof(dport), "-");
        }
        fprintf(fp, "%6s %12s %-7s %12s %-7s %12lu %10lu\n",
                proto_name(e->proto), src, sport, dst, dport,
                e->bytes, e->pkts);
    }
    fprintf(fp, "\n");
}