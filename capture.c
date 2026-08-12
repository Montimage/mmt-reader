/**
 * capture.c — PCAP capture implementation
 *
 * Supports Ethernet (DLT_EN10MB) and WiFi (DLT_IEEE802_11) interfaces.
 * WiFi frames are converted to Ethernet format before passing to MMT.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

/* ------------------------------------------------------------------ */
/* Internal state                                                      */
/* ------------------------------------------------------------------ */

/** Context set by capture_set_context() — used by capture_callback() */
static mmt_handler_t *g_mmt = NULL;
static int             g_datalink = DLT_EN10MB;

/** Active pcap handle — used by capture_breakloop() to stop the loop */
static pcap_t         *g_capture_pcap = NULL;

/** Flow aggregator fed with Ethernet-converted frames (may be NULL) */
static flows_t        *g_flows = NULL;

/* ------------------------------------------------------------------ */
/* WiFi (802.11) to Ethernet conversion                                */
/* ------------------------------------------------------------------ */

/**
 * Convert an 802.11 data frame to Ethernet format.
 *
 * Parses the 802.11 MAC header (managed mode, data subtypes 0-7),
 * extracts the payload, and prepends a 14-byte Ethernet header.
 *
 * @param data      Pointer to the 802.11 frame data
 * @param caplen    Captured length of the frame
 * @param out_buf   Output buffer (must be >= caplen + 14)
 * @param out_len   Pointer to store the output length
 * @return          1 on success, 0 on failure
 */
static int convert_wifi_to_ethernet(const u_char *data, int caplen,
                                    u_char *out_buf, int *out_len) {
    /* Minimum 802.11 MAC header is 16 bytes (no addresses) */
    if (caplen < 16) {
        return 0;
    }

    /* Parse 802.11 Frame Control field (2 bytes, little-endian) */
    uint16_t fc = (uint16_t)data[0] | ((uint16_t)data[1] << 8);

    /* Extract subtype (bits 4-1 of FC) */
    uint8_t subtype = (fc >> 4) & 0x0F;

    /* Check for data frame (subtypes 0-7) */
    if (subtype > 7) {
        return 0;
    }

    /* Extract address count (bits 1-0 of FC) */
    uint8_t addr_count = fc & 0x03;

    /* Determine MAC header length based on address count */
    int hdr_len;
    switch (addr_count) {
    case 3:  /* Managed mode: DA, SA, BSSID */
        hdr_len = 24;
        break;
    case 2:  /* Mesh mode: DA, SA */
        hdr_len = 22;
        break;
    default:
        /* to-DS or from-DS: not supported for conversion */
        return 0;
    }

    /* Account for QoS Control field (2 bytes) in QoS data frames */
    if (subtype >= 4 && subtype <= 7) {
        hdr_len += 2;
    }

    /* Calculate payload offset and verify we have enough data */
    int payload_offset = hdr_len;
    if (payload_offset >= caplen) {
        return 0;
    }
    int payload_len = caplen - payload_offset;

    /* Need room for Ethernet header (14 bytes) + at least 2 bytes payload */
    if (payload_len < 2) {
        return 0;
    }

    /* Build Ethernet header */
    out_buf[0]  = data[payload_offset - 6]; /* DA[0] = 802.11 SA */
    out_buf[1]  = data[payload_offset - 5]; /* DA[1] */
    out_buf[2]  = data[payload_offset - 4]; /* DA[2] */
    out_buf[3]  = data[payload_offset - 3]; /* DA[3] */
    out_buf[4]  = data[payload_offset - 2]; /* DA[4] */
    out_buf[5]  = data[payload_offset - 1]; /* DA[5] */
    out_buf[6]  = data[payload_offset - 18]; /* SA[0] = 802.11 BSSID */
    out_buf[7]  = data[payload_offset - 17]; /* SA[1] */
    out_buf[8]  = data[payload_offset - 16]; /* SA[2] */
    out_buf[9]  = data[payload_offset - 15]; /* SA[3] */
    out_buf[10] = data[payload_offset - 14]; /* SA[4] */
    out_buf[11] = data[payload_offset - 13]; /* SA[5] */
    out_buf[12] = 0x08; /* EtherType high byte (set below) */
    out_buf[13] = 0x00; /* EtherType low byte */

    /* Copy payload after Ethernet header */
    memcpy(&out_buf[14], &data[payload_offset], (size_t)payload_len);

    /* Determine EtherType from first payload byte */
    if (payload_len >= 2 && data[payload_offset] == 0x45) {
        /* IPv4: EtherType = 0x0800 */
        out_buf[12] = 0x08;
        out_buf[13] = 0x00;
    } else if (payload_len >= 2 && (data[payload_offset] & 0xF0) == 0x60) {
        /* IPv6: EtherType = 0x86DD */
        out_buf[12] = 0x86;
        out_buf[13] = 0xDD;
    } else {
        /* Unknown protocol — use 0x0000 */
        out_buf[12] = 0x00;
        out_buf[13] = 0x00;
    }

    *out_len = 14 + payload_len;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

pcap_t *capture_init(const char *iname, uint16_t buffer_size, uint16_t snaplen) {
    pcap_t *my_pcap;
    char errbuf[1024];

    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s: %s\n", iname, errbuf);
        return NULL;
    }

    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 200);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);

    int act_rc = pcap_activate(my_pcap);
    if (act_rc < 0) {
        fprintf(stderr, "[error] Couldn't activate device %s: %s\n",
                iname, pcap_geterr(my_pcap));
        pcap_close(my_pcap);
        return NULL;
    }
    if (act_rc > 0) {
        /* Non-fatal warning (e.g. promisc mode not available) */
        fprintf(stderr, "[warning] %s: %s\n", iname, pcap_geterr(my_pcap));
    }

    /* Accept any datalink type — some WiFi drivers report non-standard values */
    int dlt = pcap_datalink(my_pcap);

    g_capture_pcap = my_pcap;
    return my_pcap;
}

void capture_breakloop(void) {
    if (g_capture_pcap != NULL) {
        pcap_breakloop(g_capture_pcap);
    }
}

void capture_set_context(mmt_handler_t *mmt, int datalink) {
    g_mmt = mmt;
    g_datalink = datalink;
}

void capture_set_flows(flows_t *flows) {
    g_flows = flows;
}

void capture_callback(u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data) {
    (void)user;
    struct pkthdr header;

    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;

    if (g_datalink == DLT_EN10MB) {
        /* Ethernet — pass directly to MMT */
        if (g_flows != NULL) {
            flows_packet(g_flows, p_pkthdr, data);
        }
        if (!packet_process(g_mmt, &header, data)) {
            fprintf(stderr, "Packet data extraction failure.\n");
        }
    } else {
        /* WiFi or non-standard datalink — try 802.11 conversion first,
         * then fall back to raw processing (some drivers prepend Ethernet headers) */
        u_char eth_buf[65555]; /* Max Ethernet frame + header */
        int eth_len = 0;

        if (convert_wifi_to_ethernet(data, p_pkthdr->caplen, eth_buf, &eth_len)) {
            header.caplen = eth_len;
            header.len = eth_len;
            if (g_flows != NULL) {
                struct pcap_pkthdr eth_hdr = *p_pkthdr;
                eth_hdr.caplen = eth_len;
                eth_hdr.len = eth_len;
                flows_packet(g_flows, &eth_hdr, eth_buf);
            }
            if (!packet_process(g_mmt, &header, eth_buf)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        } else {
            /* Conversion failed — try raw processing (driver may prepend Ethernet header) */
            if (g_flows != NULL) {
                flows_packet(g_flows, p_pkthdr, data);
            }
            if (!packet_process(g_mmt, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
    }
}
