/**
 * engine.c — MMT-DPI engine implementation
 *
 * Encapsulates MMT-DPI handler initialization, packet processing,
 * and statistics collection. Provides a clean API for the CLI layer.
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

/* ------------------------------------------------------------------ */
/* Internal state                                                      */
/* ------------------------------------------------------------------ */

struct engine {
    mmt_handler_t *mmt;           /**< MMT handler                   */
    engine_stats_t stats;         /**< Accumulated statistics        */
};

/* Module-level proto_path_detail (shared by protocols_stats) */
static int proto_path_detail = 1;

/* ------------------------------------------------------------------ */
/* Protocol statistics helpers (linked-list sorting)                   */
/* ------------------------------------------------------------------ */

typedef struct proto_info {
    const char *name;
    uint64_t pkts;
    uint64_t volume;
    uint64_t payload;
    struct proto_info *prev;
    struct proto_info *next;
} proto_info_t;

static proto_info_t *proto_head = NULL;

static void proto_info_free_all(void) {
    proto_info_t *current = proto_head;
    while (current != NULL) {
        proto_info_t *next = current->next;
        free(current);
        current = next;
    }
    proto_head = NULL;
}

static void proto_info_insert(proto_info_t *p_info) {
    if (proto_head == NULL) {
        proto_head = p_info;
        return;
    }
    proto_info_t *current = proto_head;
    while (current != NULL) {
        if (p_info->pkts > current->pkts) {
            p_info->next = current;
            p_info->prev = current->prev;
            if (current->prev != NULL) {
                current->prev->next = p_info;
            } else {
                proto_head = p_info;
            }
            current->prev = p_info;
            return;
        }
        if (current->next == NULL) {
            current->next = p_info;
            p_info->prev = current;
            return;
        }
        current = current->next;
    }
}

/* ------------------------------------------------------------------ */
/* Protocol path string conversion                                     */
/* ------------------------------------------------------------------ */

static int proto_hierarchy_ids_to_str(const proto_hierarchy_t *proto_hierarchy,
                                       char *dest) {
    int offset = 0;
    if (proto_hierarchy->len < 1) {
        offset += sprintf(dest, ".");
    } else {
        int index = 1;
        offset += sprintf(dest, "%s",
                          get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        index++;
        for (; index < proto_hierarchy->len && index < 16; index++) {
            offset += sprintf(&dest[offset], ".%s",
                              get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        }
    }
    return offset;
}

/* ------------------------------------------------------------------ */
/* Attribute / protocol iterators                                      */
/* ------------------------------------------------------------------ */

static void attributes_iterator(attribute_metadata_t *attribute,
                                uint32_t proto_id,
                                void *args) {
    register_extraction_attribute(args, proto_id, attribute->id);
}

static void protocols_iterator(uint32_t proto_id, void *args) {
    iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
}

/* ------------------------------------------------------------------ */
/* Protocol stats iterator (uses static proto_path_detail)             */
/* ------------------------------------------------------------------ */

static void protocols_stats(uint32_t proto_id, void *args) {
    if (proto_id == 1) return; /* Ignore PROTO_META */

    proto_statistics_t *proto_stats = get_protocol_stats((mmt_handler_t *)args, proto_id);
    if (proto_stats != NULL) {
        proto_info_t *p_info = (proto_info_t *)malloc(sizeof(proto_info_t));
        if (p_info == NULL) return;
        memset(p_info, 0, sizeof(proto_info_t));

        const char *proto_name = get_protocol_name_by_id(proto_id);
        p_info->name = proto_name;

        while (proto_stats != NULL) {
            if (proto_stats->touched) {
                p_info->pkts += proto_stats->packets_count;
                p_info->volume += proto_stats->data_volume;
                p_info->payload += proto_stats->payload_volume;
                if (proto_path_detail) {
                    proto_hierarchy_t proto_hierarchy = {0};
                    get_protocol_stats_path((mmt_handler_t *)args, proto_stats,
                                            &proto_hierarchy);
                    char path[128];
                    proto_hierarchy_ids_to_str(&proto_hierarchy, path);
                    printf("%10lu %10lu %10lu %60s\n",
                           proto_stats->packets_count,
                           proto_stats->data_volume,
                           proto_stats->payload_volume,
                           path);
                }
            }
            proto_stats = proto_stats->next;
        }
        proto_info_insert(p_info);
    }
}

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

    /* Print final stats */
    engine_print_stats(eng);

    /* Close MMT handler */
    if (eng->mmt) {
        mmt_close_handler(eng->mmt);
        close_extraction();
    }

    /* Free protocol info list */
    proto_info_free_all();

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

    const engine_stats_t *s = &eng->stats;

    printf("\n- - - - - - MMT-READER STATS - - - - -\n\n");
    if (proto_path_detail) {
        printf("Protocol statistics with the protocol path:\n\n");
    }
    printf("\t#pkts\t#volume\t#payload\t#proto_path\n");
    iterate_through_protocols(protocols_stats, eng->mmt);

    printf("\nProtocol statistics:\n\n");
    printf("\t#pkts\t#volume\t#payload\t#proto_name\n");

    proto_info_t *current = proto_head;
    while (current != NULL) {
        printf("%10lu %10lu %10lu %20s\n",
               current->pkts, current->volume, current->payload, current->name);
        proto_info_t *next = current->next;
        free(current);
        current = next;
    }
    proto_head = NULL;

    printf(">>>>>> INPUT STATISTICS <<<<<< \n\n");

    /* Calculate duration */
    double duration = 0;
    if (s->end_time.tv_sec > s->init_time.tv_sec) {
        duration = (double)(s->end_time.tv_sec - s->init_time.tv_sec);
    } else {
        duration = 1.0; /* avoid division by zero */
    }

    printf("\tPackets: %lu\n", s->nb_packets);
    printf("\tData: %lu bytes\n", s->data_volume);
    printf("\tSessions: %lu\n", s->nb_ipv4_sessions + s->nb_ipv6_sessions);
    printf("\tProtocols: %lu\n", s->nb_protocols);
    printf("\tDuration: %.0f seconds\n", duration);
    printf("\tBandwidth: %.2f bytes/second\n",
           s->data_volume / duration);
    printf("\tpps: %.2f packets/second\n",
           (double)s->nb_packets / duration);
    printf("\tfps: %.2f sessions/second\n\n",
           (double)(s->nb_ipv4_sessions + s->nb_ipv6_sessions) / duration);
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
