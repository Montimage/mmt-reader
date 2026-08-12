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
 * Packet processor invoked by the capture callback for every frame.
 *
 * Lets the capture layer hand each frame to a higher-level owner (the
 * DPI engine) without depending on it, so packet accounting happens in
 * exactly one place.
 *
 * @param ctx   Opaque context registered with capture_set_processor()
 * @param hdr   MMT packet header (timestamp, captured/wire length)
 * @param data  Frame bytes (Ethernet-converted when applicable)
 * @return      Non-zero on success, 0 on extraction failure
 */
typedef int (*capture_processor_fn)(void *ctx,
                                    const struct pkthdr *hdr,
                                    const u_char *data);

/**
 * Set the packet processor used by the capture callback.
 *
 * When no processor is set (or it is cleared with NULL), the callback
 * falls back to calling packet_process() on the handler registered with
 * capture_set_context().
 *
 * @param fn   Processor function, or NULL to restore the fallback
 * @param ctx  Opaque context passed back to the processor
 */
void capture_set_processor(capture_processor_fn fn, void *ctx);

/**
 * Convert an IEEE 802.11 data frame to an Ethernet frame.
 *
 * Accepts only data frames (type 2) that are unencrypted, carry a
 * payload and are LLC/SNAP encapsulated. The MAC header length is
 * derived from the ToDS/FromDS pair and the QoS/HT Control fields, and
 * DA/SA are taken from the address fields that match that pair. The
 * EtherType is read from the SNAP header, which is then skipped.
 *
 * Every read is bounded by caplen and every write by out_cap, so the
 * frame may be attacker-controlled.
 *
 * @param data     Pointer to the 802.11 frame (no radiotap header)
 * @param caplen   Captured length of the frame in bytes
 * @param out_buf  Output buffer receiving the Ethernet frame
 * @param out_cap  Capacity of out_buf in bytes
 * @param out_len  Set to the converted length on success
 * @return         1 on success, 0 when the frame cannot be converted
 */
int capture_wifi_to_ethernet(const u_char *data, int caplen,
                             u_char *out_buf, int out_cap, int *out_len);

/**
 * Live capture callback — passes packets to MMT.
 * Handles both Ethernet and WiFi (802.11) frame conversion.
 * @param user    u_char pointer (reserved, not used)
 * @param p_pkthdr pcap header
 * @param data    packet data
 */
void capture_callback(u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data);

#endif /* CAPTURE_H */
