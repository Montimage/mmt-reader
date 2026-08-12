/**
 * engine.c — MMT-DPI engine implementation
 *
 * Encapsulates MMT-DPI handler initialization, packet processing,
 * and statistics collection. Provides a clean API for the CLI layer.
 * Output formatting is delegated to cli/output.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/time.h>
#include "engine.h"
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "output.h"

/* ------------------------------------------------------------------ */
/* Internal state                                                      */
/* ------------------------------------------------------------------ */

struct engine {
    mmt_handler_t *mmt;           /**< MMT handler                   */
    engine_stats_t stats;         /**< Accumulated statistics        */
};

/* Module-level proto_path_detail (shared by output_print_stats) */
static int proto_path_detail = 1;



/* ------------------------------------------------------------------ */
/* Packet handler (internal)                                           */
/* ------------------------------------------------------------------ */

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    engine_t *eng = (engine_t *)user_args;

    uint64_t *packet_count = (uint64_t *)get_attribute_extracted_data(
        ipacket, PROTO_META, PROTO_PACKET_COUNT);
    if (packet_count != NULL) {
        eng->stats.nb_packets = *packet_count;
    }

    uint64_t *data_count = (uint64_t *)get_attribute_extracted_data(
        ipacket, PROTO_META, PROTO_DATA_VOLUME);
    if (data_count != NULL) {
        eng->stats.data_volume = *data_count;
    }

    if (ipacket->packet_id == 1) {
        struct timeval *first_time = (struct timeval *)get_attribute_extracted_data(
            ipacket, PROTO_META, PROTO_FIRST_PACKET_TIME);
        if (first_time != NULL) {
            eng->stats.init_time = *first_time;
        }
    }

    struct timeval *last_time = (struct timeval *)get_attribute_extracted_data(
        ipacket, PROTO_META, PROTO_LAST_PACKET_TIME);
    if (last_time != NULL) {
        eng->stats.end_time = *last_time;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Session handlers (internal)                                         */
/* ------------------------------------------------------------------ */

static void new_ipv4_session_handler(const ipacket_t *ipacket,
                                     attribute_t *attribute,
                                     void *user_args) {
    (void)ipacket;
    (void)attribute;
    engine_t *eng = (engine_t *)user_args;
    eng->stats.nb_ipv4_sessions++;
}

static void new_ipv6_session_handler(const ipacket_t *ipacket,
                                     attribute_t *attribute,
                                     void *user_args) {
    (void)ipacket;
    (void)attribute;
    engine_t *eng = (engine_t *)user_args;
    eng->stats.nb_ipv6_sessions++;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

engine_t *engine_create(int dlt, int flags, char *errbuf) {
    engine_t *eng = (engine_t *)calloc(1, sizeof(engine_t));
    if (eng == NULL) {
        fprintf(stderr, "[error] Failed to allocate engine\n");
        return NULL;
    }

    /* Initialize MMT extraction */
    init_extraction();

    /* Initialize MMT handler */
    eng->mmt = mmt_init_handler(dlt, flags, errbuf);
    if (!eng->mmt) {
        fprintf(stderr, "[error] MMT handler init failed: %s\n", errbuf);
        free(eng);
        return NULL;
    }

    /* Default settings */
    proto_path_detail = 1;

    /* Zero out stats */
    memset(&eng->stats, 0, sizeof(eng->stats));

    return eng;
}

void engine_destroy(engine_t *eng) {
    if (eng == NULL) return;

    /* Print final stats (delegated to output module) */
    engine_print_stats(eng);

    /* Close MMT handler */
    if (eng->mmt) {
        mmt_close_handler(eng->mmt);
        close_extraction();
    }

    free(eng);
}

void engine_set_ip_classify(engine_t *eng, int on) {
    if (eng == NULL) return;
    if (on) {
        printf("Enable classification by IP address");
        enable_ip_address_classify(eng->mmt);
    } else {
        disable_ip_address_classify(eng->mmt);
    }
}

void engine_set_hostname_classify(engine_t *eng, int on) {
    if (eng == NULL) return;
    if (on) {
        printf("Enable classification by Hostname");
        enable_hostname_classify(eng->mmt);
    } else {
        disable_hostname_classify(eng->mmt);
    }
}

void engine_set_port_classify(engine_t *eng, int on) {
    if (eng == NULL) return;
    if (on) {
        printf("Enable classification by Port number");
        enable_port_classify(eng->mmt);
    } else {
        disable_port_classify(eng->mmt);
    }
}

void engine_set_proto_path_detail(engine_t *eng, int on) {
    (void)eng;
    proto_path_detail = on;
}

int engine_process_packet(engine_t *eng,
                          const struct pkthdr *hdr,
                          const u_char *data) {
    if (eng == NULL || hdr == NULL || data == NULL) return 0;
    /* Cast away const — packet_process expects non-const per MMT-DPI API */
    return packet_process(eng->mmt, (struct pkthdr *)hdr, (u_char *)data) ? 1 : 0;
}

void engine_live_callback(u_char *user,
                          const struct pcap_pkthdr *p_pkthdr,
                          const u_char *data) {
    engine_t *eng = (engine_t *)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;

    if (!engine_process_packet(eng, &header, data)) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

void engine_get_stats(const engine_t *eng, engine_stats_t *out) {
    if (eng == NULL || out == NULL) return;
    *out = eng->stats;
}

void engine_print_stats(const engine_t *eng) {
    if (eng == NULL) return;

    /* Delegate output formatting to the output module */
    output_print_stats(stdout, eng->mmt, proto_path_detail, &eng->stats);
}

void engine_print_pcap_stats(const struct pcap_stat *pcs) {
    if (pcs == NULL) return;

    if (pcs->ps_recv == 0) return;

    printf(">>>> PCAP STATISTICS <<<< \n\n");
    printf("%12d Received\n", pcs->ps_recv);
    printf("%12d Dropped by kernel (%3.2f%%)\n",
           pcs->ps_drop, pcs->ps_drop * 100.0 / pcs->ps_recv);
    printf("%12d Dropped by driver (%3.2f%%)\n",
           pcs->ps_ifdrop, pcs->ps_ifdrop * 100.0 / pcs->ps_recv);
    fflush(stderr);
}
