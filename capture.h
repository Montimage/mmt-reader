/**
 * capture.h — PCAP capture operations
 *
 * Handles pcap handle creation and live capture callback.
 * Supports both Ethernet (DLT_EN10MB) and WiFi (DLT_IEEE802_11) interfaces.
 */
#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>
#include <pcap.h>
#include "mmt_core.h"
#include "flows.h"

/**
 * Initialize a pcap handle for live capture.
 * Accepts both Ethernet and WiFi interfaces.
 * @param iname       interface name
 * @param buffer_size buffer size in MB
 * @param snaplen     packet snaplen
 * @return            pcap handle, or NULL on error
 */
pcap_t *capture_init(const char *iname, uint16_t buffer_size, uint16_t snaplen);

/**
 * Close a handle created by capture_init().
 * Clears the cached capture handle before closing it, so a signal
 * arriving during/after the close cannot call pcap_breakloop() on
 * freed memory. Passing NULL is a no-op.
 * @param p  pcap handle returned by capture_init(), or NULL
 */
void capture_close(pcap_t *p);

/**
 * Request the active capture loop to stop at the next opportunity.
 * Safe to call from a signal handler (only sets a flag via pcap_breakloop()).
 * May be called when no capture is active — it is a no-op in that case.
 */
void capture_breakloop(void);

/**
 * Set the datalink type and MMT handler for the capture callback.
 * Must be called after capture_init() and before starting capture.
 * @param mmt       MMT handler pointer
 * @param datalink  Interface datalink type (DLT_EN10MB, DLT_IEEE802_11, etc.)
 */
void capture_set_context(mmt_handler_t *mmt, int datalink);

/**
 * Set the flow aggregator fed by the capture callback.
 * May be NULL to disable flow tracking. The aggregator receives the
 * Ethernet-converted frames (WiFi 802.11 frames are converted first).
 * @param flows  Flow aggregator, or NULL
 */
void capture_set_flows(flows_t *flows);

/**
 * Live capture callback — passes packets to MMT.
 * Handles both Ethernet and WiFi (802.11) frame conversion.
 * @param user    u_char pointer (reserved, not used)
 * @param p_pkthdr pcap header
 * @param data    packet data
 */
void capture_callback(u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data);

#endif /* CAPTURE_H */
