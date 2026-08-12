/**
 * capture.h — PCAP capture operations
 *
 * Handles pcap handle creation and live capture callback.
 */
#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include "mmt_core.h"

/**
 * Initialize a pcap handle for live capture.
 * @param iname       interface name
 * @param buffer_size buffer size in MB
 * @param snaplen     packet snaplen
 * @return            pcap handle, or NULL on error
 */
pcap_t *capture_init(const char *iname, uint16_t buffer_size, uint16_t snaplen);

/**
 * Live capture callback — passes packets to MMT.
 * @param user    MMT handler pointer
 * @param p_pkthdr pcap header
 * @param data    packet data
 */
void capture_callback(u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data);

#endif /* CAPTURE_H */
