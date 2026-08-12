/**
 * flows.h — Live flow aggregation (top talkers by volume)
 *
 * Tracks per-5-tuple byte/packet counters and reports the top flows
 * by transferred volume. Used with the --flows capture option to
 * identify which host (and port) consumes the most traffic.
 */
#ifndef FLOWS_H
#define FLOWS_H

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

/** Opaque flow-aggregation state. */
typedef struct flows flows_t;

/**
 * Create a new flow aggregator.
 * @return Aggregator handle, or NULL on allocation failure
 */
flows_t *flows_create(void);

/**
 * Destroy a flow aggregator and release its resources.
 * @param f Aggregator handle (NULL is safe)
 */
void flows_destroy(flows_t *f);

/**
 * Feed one Ethernet frame to the aggregator.
 *
 * Parses IPv4/IPv6 (with optional VLAN tag) and TCP/UDP/ICMP/ICMPv6
 * headers, updating the matching 5-tuple bucket.
 * @param f     Aggregator handle
 * @param hdr   libpcap packet header
 * @param data  Raw frame bytes
 */
void flows_packet(flows_t *f, const struct pcap_pkthdr *hdr, const u_char *data);

/**
 * Print the top flows by bytes to the given stream.
 * @param f        Aggregator handle
 * @param fp       Output stream (stdout/stderr)
 * @param top_n    Maximum number of flows to print
 */
void flows_print_top(flows_t *f, FILE *fp, int top_n);

#endif /* FLOWS_H */