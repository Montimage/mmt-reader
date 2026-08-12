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

/* Some older libpcap headers do not expose these datalink constants */
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11 105
#endif
#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO 127
#endif

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

/** Packet processor set by capture_set_processor() (may be NULL) */
static capture_processor_fn g_processor = NULL;
static void                *g_processor_ctx = NULL;

/* ------------------------------------------------------------------ */
/* WiFi (802.11) to Ethernet conversion                                */
/* ------------------------------------------------------------------ */

/** Fixed offsets of the 802.11 address fields inside the MAC header */
#define WIFI_ADDR1_OFF  4
#define WIFI_ADDR2_OFF 10
#define WIFI_ADDR3_OFF 16
#define WIFI_ADDR4_OFF 24

/** Base 802.11 MAC header: FC 2 + Duration 2 + Addr1/2/3 18 + SeqCtl 2 */
#define WIFI_HDR_BASE  24

/** LLC/SNAP header prefixed to an 802.11 data payload */
#define SNAP_HDR_LEN    8

/**
 * Strip a radiotap header from a captured frame.
 *
 * The radiotap header starts with it_version(1), it_pad(1) and
 * it_len(2, little-endian); the 802.11 frame begins it_len bytes in.
 *
 * @param data    In/out pointer to the frame, advanced past the header
 * @param caplen  In/out captured length, reduced by the header length
 * @return        1 when a sane radiotap header was stripped, 0 otherwise
 */
static int strip_radiotap(const u_char **data, int *caplen) {
    if (*caplen < 4) {
        return 0;
    }

    int it_len = (int)(*data)[2] | ((int)(*data)[3] << 8);
    if (it_len < 8 || it_len >= *caplen) {
        return 0;
    }

    *data   += it_len;
    *caplen -= it_len;
    return 1;
}

int capture_wifi_to_ethernet(const u_char *data, int caplen,
                             u_char *out_buf, int out_cap, int *out_len) {
    if (data == NULL || out_buf == NULL || out_len == NULL) {
        return 0;
    }

    /* The shortest convertible frame is a 24-byte MAC header plus a
     * SNAP header plus at least one payload byte */
    if (caplen < 0 || caplen < WIFI_HDR_BASE) {
        return 0;
    }

    /* Frame Control field (2 bytes, little-endian) */
    uint16_t fc = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    uint8_t type          = (fc >> 2) & 0x03;
    uint8_t subtype       = (fc >> 4) & 0x0F;
    uint8_t toDS          = (data[1] >> 0) & 0x01;
    uint8_t fromDS        = (data[1] >> 1) & 0x01;
    uint8_t protected_bit = (data[1] >> 6) & 0x01;
    uint8_t order_bit     = (data[1] >> 7) & 0x01;

    /* Only data frames (type 2) carry a convertible payload */
    if (type != 2) {
        return 0;
    }

    /* Null (4) and QoS Null (12) data subtypes carry no payload */
    if (subtype == 4 || subtype == 12) {
        return 0;
    }

    /* An encrypted payload (WEP/WPA/CCMP) cannot be converted */
    if (protected_bit) {
        return 0;
    }

    /* MAC header length: base + Addr4 (WDS) + QoS Control + HT Control */
    int hdr_len = WIFI_HDR_BASE;
    if (toDS && fromDS) {
        hdr_len += 6;   /* 4-address WDS frame carries Addr4 */
    }
    if ((subtype & 0x08) != 0) {
        hdr_len += 2;   /* QoS data frames carry a QoS Control field */
        if (order_bit) {
            hdr_len += 4;   /* ...followed by an HT Control field */
        }
    }

    /* Must be able to read the whole MAC header and the SNAP header */
    if (caplen < hdr_len + SNAP_HDR_LEN) {
        return 0;
    }

    /* DA/SA live in different address fields depending on ToDS/FromDS */
    int da_off, sa_off;
    if (!toDS && !fromDS) {         /* IBSS / ad-hoc */
        da_off = WIFI_ADDR1_OFF;
        sa_off = WIFI_ADDR2_OFF;
    } else if (!toDS && fromDS) {   /* AP -> STA */
        da_off = WIFI_ADDR1_OFF;
        sa_off = WIFI_ADDR3_OFF;
    } else if (toDS && !fromDS) {   /* STA -> AP */
        da_off = WIFI_ADDR3_OFF;
        sa_off = WIFI_ADDR2_OFF;
    } else {                        /* WDS (4-address) */
        da_off = WIFI_ADDR3_OFF;
        sa_off = WIFI_ADDR4_OFF;
    }

    /* The payload starts with an LLC/SNAP header carrying the EtherType:
     * AA AA 03 00 00 00 <ethertype_hi> <ethertype_lo> */
    const u_char *snap = data + hdr_len;
    if (snap[0] != 0xAA || snap[1] != 0xAA || snap[2] != 0x03) {
        return 0;
    }

    int payload_offset = hdr_len + SNAP_HDR_LEN;
    int payload_len    = caplen - payload_offset;
    if (payload_len <= 0) {
        return 0;
    }

    /* Never write past the caller's buffer */
    if (14 + payload_len > out_cap) {
        return 0;
    }

    /* Build the Ethernet header, then copy the payload after it */
    memcpy(&out_buf[0], &data[da_off], 6);
    memcpy(&out_buf[6], &data[sa_off], 6);
    out_buf[12] = snap[6];  /* EtherType high byte */
    out_buf[13] = snap[7];  /* EtherType low byte */
    memcpy(&out_buf[14], &data[payload_offset], (size_t)payload_len);

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

    g_capture_pcap = my_pcap;
    return my_pcap;
}

void capture_close(pcap_t *p) {
    /* Clear the cached handle FIRST so a signal arriving mid-close sees
     * NULL and skips pcap_breakloop() on an already-freed handle. */
    g_capture_pcap = NULL;
    if (p != NULL) {
        pcap_close(p);
    }
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

void capture_set_processor(capture_processor_fn fn, void *ctx) {
    g_processor = fn;
    g_processor_ctx = ctx;
}

/**
 * Feed a frame to the flow aggregator and to the packet processor.
 *
 * The processor owns the packet accounting (counters, timestamps); when
 * none is registered the frame goes straight to MMT as before.
 */
static void process_frame(const struct pcap_pkthdr *p_pkthdr, const u_char *data) {
    struct pkthdr header;
    int ok;

    header.ts     = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len    = p_pkthdr->len;

    if (g_flows != NULL) {
        flows_packet(g_flows, p_pkthdr, data);
    }

    if (g_processor != NULL) {
        ok = g_processor(g_processor_ctx, &header, data);
    } else {
        ok = packet_process(g_mmt, &header, data) ? 1 : 0;
    }

    if (!ok) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

void capture_callback(u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data) {
    (void)user;

    if (g_datalink == DLT_IEEE802_11 || g_datalink == DLT_IEEE802_11_RADIO) {
        /* WiFi — try 802.11 conversion first, then fall back to raw
         * processing (some drivers prepend Ethernet headers) */
        u_char eth_buf[65555]; /* Max Ethernet frame + header */
        int eth_len = 0;
        const u_char *frame = data;
        int frame_len = (int)p_pkthdr->caplen;
        int have_frame = 1;

        if (g_datalink == DLT_IEEE802_11_RADIO) {
            /* Each frame is prefixed by a radiotap header */
            have_frame = strip_radiotap(&frame, &frame_len);
        }

        if (have_frame && capture_wifi_to_ethernet(frame, frame_len, eth_buf,
                                                   (int)sizeof(eth_buf), &eth_len)) {
            struct pcap_pkthdr eth_hdr = *p_pkthdr;
            eth_hdr.caplen = (bpf_u_int32)eth_len;
            eth_hdr.len    = (bpf_u_int32)eth_len;
            process_frame(&eth_hdr, eth_buf);
            return;
        }
        /* Conversion failed — fall through to raw processing */
    }

    /* Ethernet, or any datalink we do not convert — pass directly to MMT */
    process_frame(p_pkthdr, data);
}
