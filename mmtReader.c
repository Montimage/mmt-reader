/**
 * mmtReader.c — MMT-READER CLI entry point
 *
 * Thin main: banner → parse → engine init → dispatch → cleanup
 *
 * Core DPI logic (handler init, packet processing, statistics)
 * is encapsulated in core/engine.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include "core/engine.h"

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2

static char filename[MAX_FILENAME_SIZE + 1];
static int pcap_bs = 50; /* default 50 MB buffer */
static int ip_address_classify = 1;
static int hostname_classify = 1;
static int port_classify = 1;
static volatile sig_atomic_t got_signal = 0;

/* ------------------------------------------------------------------ */
/* Help / usage                                                        */
/* ------------------------------------------------------------------ */

static void usage(const char *prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-b <value>     : Set buffer for pcap handler (MB, default 50).\n");
    fprintf(stderr, "\t-a             : Show protocol statistic for each protocol path.\n");
    fprintf(stderr, "\t-x <0|1>       : IP address classification (default 1).\n");
    fprintf(stderr, "\t-y <0|1>       : Hostname classification (default 1).\n");
    fprintf(stderr, "\t-z <0|1>       : Port number classification (default 1).\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/* ------------------------------------------------------------------ */
/* Signal handler                                                      */
/* ------------------------------------------------------------------ */

static void signal_handler(int type) {
    printf("\nINFO: reception of signal %d\n", type);
    got_signal = 1;
    fflush(stderr);
}

/* ------------------------------------------------------------------ */
/* Argument parsing                                                    */
/* ------------------------------------------------------------------ */

static int parseOptions(int argc, char **argv, int *type) {
    int opt;
    int optcount = 0;

    while ((opt = getopt(argc, argv, "t:i:b:x:y:z:ha")) != EOF) {
        switch (opt) {
            case 't':
                optcount++;
                if (optcount > 6) usage(argv[0]);
                strncpy(filename, optarg, MAX_FILENAME_SIZE);
                *type = TRACE_FILE;
                break;
            case 'i':
                optcount++;
                if (optcount > 6) usage(argv[0]);
                strncpy(filename, optarg, MAX_FILENAME_SIZE);
                *type = LIVE_INTERFACE;
                break;
            case 'b':
                optcount++;
                if (optcount > 6) usage(argv[0]);
                pcap_bs = atoi(optarg);
                if (pcap_bs <= 0) pcap_bs = 50;
                break;
            case 'a':
                optcount++;
                if (optcount > 6) usage(argv[0]);
                /* proto_path_detail is handled by engine */
                break;
            case 'x':
                optcount++;
                if (optcount > 9) usage(argv[0]);
                ip_address_classify = atoi(optarg);
                break;
            case 'y':
                optcount++;
                if (optcount > 9) usage(argv[0]);
                hostname_classify = atoi(optarg);
                break;
            case 'z':
                optcount++;
                if (optcount > 9) usage(argv[0]);
                port_classify = atoi(optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }

    if (filename[0] == '\0') {
        if (*type == TRACE_FILE) {
            fprintf(stderr, "Missing trace file name\n");
        }
        if (*type == LIVE_INTERFACE) {
            fprintf(stderr, "Missing network interface name\n");
        }
        usage(argv[0]);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* PCAP helpers                                                        */
/* ------------------------------------------------------------------ */

static pcap_t *init_pcap(const char *iname, uint16_t buffer_size, uint16_t snaplen) {
    pcap_t *my_pcap;
    char errbuf[1024];

    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s\n", errbuf);
        return NULL;
    }

    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 0);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    pcap_activate(my_pcap);

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission!)\n",
                iname);
        pcap_close(my_pcap);
        return NULL;
    }

    return my_pcap;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    /* Banner */
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("|\t\t MONTIMAGE\n");
    printf("|\t MMT-SDK version: %s\n", mmt_version());
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");

    int type = -1; /* TRACE_FILE or LIVE_INTERFACE */

    /* Parse options */
    parseOptions(argc, argv, &type);

    /* Create engine */
    char mmt_errbuf[1024];
    engine_t *eng = engine_create(DLT_EN10MB, 0, mmt_errbuf);
    if (!eng) {
        fprintf(stderr, "[error] Failed to create MMT engine\n");
        return EXIT_FAILURE;
    }

    /* Configure classification */
    engine_set_ip_classify(eng, ip_address_classify);
    engine_set_hostname_classify(eng, hostname_classify);
    engine_set_port_classify(eng, port_classify);

    /* Set up signal handling */
    signal(SIGINT, signal_handler);

    /* Process packets */
    if (type == TRACE_FILE) {
        /* OFFLINE mode: read from pcap file */
        struct pcap_pkthdr p_pkthdr;
        const u_char *data;
        struct pkthdr header;

        pcap_t *pcap = pcap_open_offline(filename, mmt_errbuf);
        if (!pcap) {
            fprintf(stderr, "[error] pcap_open failed: %s\n", mmt_errbuf);
            engine_destroy(eng);
            return EXIT_FAILURE;
        }

        while ((data = pcap_next(pcap, &p_pkthdr)) != NULL && !got_signal) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!engine_process_packet(eng, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
        pcap_close(pcap);

    } else if (type == LIVE_INTERFACE) {
        /* ONLINE mode: live capture from interface */
        pcap_t *pcap;

        if (pcap_bs == 50) {
            printf("INFO: Use default buffer size: 50 (MB)\n");
        } else {
            printf("INFO: Use buffer size: %d (MB)\n", pcap_bs);
        }

        pcap = init_pcap(filename, (uint16_t)pcap_bs, 65535);
        if (!pcap) {
            fprintf(stderr, "[error] Creating pcap handle failed\n");
            engine_destroy(eng);
            return EXIT_FAILURE;
        }

        (void)pcap_loop(pcap, -1, engine_live_callback, (u_char *)eng);
        pcap_close(pcap);

    } else {
        usage(argv[0]);
    }

    /* Cleanup */
    engine_destroy(eng);

    return EXIT_SUCCESS;
}
