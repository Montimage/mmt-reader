/**
 * dispatch.c — Command dispatch implementation
 *
 * Routes to analyze (pcap file) or capture (live interface) commands.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include "dispatch.h"
#include "argparse.h"
#include "mmt_handler.h"
#include "capture.h"
#include "display.h"
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

/* Shared state between modules */
char filename[MAX_FILENAME_SIZE + 1];
int proto_path_detail = 1;

static int cmd_analyze(const mmt_config_t *cfg) {
    mmt_handler_t *mmt = mmt_get_handler();
    char errbuf[1024];
    pcap_t *pcap;
    const u_char *data;
    struct pcap_pkthdr p_pkthdr;
    struct pkthdr header;

    pcap = pcap_open_offline(cfg->source, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open failed: %s\n", errbuf);
        return 1;
    }

    while ((data = pcap_next(pcap, &p_pkthdr))) {
        header.ts = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len = p_pkthdr.len;
        if (!packet_process(mmt, &header, data)) {
            fprintf(stderr, "Packet data extraction failure.\n");
        }
    }

    pcap_close(pcap);
    return 0;
}

static int cmd_capture(const mmt_config_t *cfg) {
    mmt_handler_t *mmt = mmt_get_handler();
    pcap_t *pcap;
    uint16_t snaplen = 65535;
    uint16_t buf_size = cfg->buffer_size > 0 ? (uint16_t)cfg->buffer_size : 50;

    if (cfg->buffer_size == 0) {
        printf("INFO: Use default buffer size: 50 (MB)\n");
    } else {
        printf("INFO: Use buffer size: %d (MB)\n", cfg->buffer_size);
    }

    pcap = capture_init(cfg->source, buf_size, snaplen);
    if (!pcap) {
        fprintf(stderr, "[error] creating pcap failed\n");
        return 1;
    }

    /* Set callback context: MMT handler + interface datalink type */
    capture_set_context(mmt, pcap_datalink(pcap));

    if (pcap_loop(pcap, -1, &capture_callback, NULL) < 0) {
        fprintf(stderr, "[error] pcap_loop failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return 1;
    }
    pcap_close(pcap);
    return 0;
}

int dispatch(const mmt_config_t *cfg) {
    char mmt_errbuf[1024];
    mmt_handler_t *mmt;

    /* Copy source to shared filename */
    strncpy(filename, cfg->source, MAX_FILENAME_SIZE);
    filename[MAX_FILENAME_SIZE] = '\0';

    /* Set protocol path detail from config */
    proto_path_detail = cfg->proto_path_detail;

    /* Initialize MMT */
    mmt_init_extraction();

    /* Create MMT handler */
    mmt = mmt_create_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt) {
        fprintf(stderr, "[error] MMT handler init failed: %s\n", mmt_errbuf);
        return 1;
    }

    /* Setup classification */
    mmt_setup_classification(mmt,
                             cfg->ip_address_classify,
                             cfg->hostname_classify,
                             cfg->port_classify);

    /* Register handlers */
    mmt_register_handlers(mmt);

    /* Setup signal handling */
    mmt_setup_signals();

    /* Dispatch to command */
    if (cfg->source_type == TRACE_FILE) {
        return cmd_analyze(cfg);
    } else if (cfg->source_type == LIVE_INTERFACE) {
        return cmd_capture(cfg);
    }

    return 1;
}
