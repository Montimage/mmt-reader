/**
 * output.c — Text table rendering for protocol statistics
 *
 * Implements formatted output for MMT-DPI statistics, including
 * protocol tables (with/without paths) and input statistics.
 *
 * All printf-based formatting has been extracted from core/engine.c
 * into this dedicated module, giving the engine a clean API that
 * delegates presentation to the output layer.
 *
 * Color output is controlled by the colors module (colors_init(),
 * colors_set_enabled()) which respects the NO_COLOR environment
 * variable and the --no-color command-line flag.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "output.h"
#include "colors.h"

/* ------------------------------------------------------------------ */
/* Internal types                                                      */
/* ------------------------------------------------------------------ */

/**
 * Aggregated protocol information (sorted by packet count).
 */
typedef struct proto_info {
    const char *name;
    uint64_t pkts;
    uint64_t volume;
    uint64_t payload;
    struct proto_info *prev;
    struct proto_info *next;
} proto_info_t;

/**
 * Context passed to the protocol stats iterator callback.
 */
typedef struct {
    void *mmt;
    int proto_path;
    proto_info_t **agg_head;
    FILE *fp;
} proto_iter_ctx_t;

/* ------------------------------------------------------------------ */
/* Protocol info list helpers                                          */
/* ------------------------------------------------------------------ */

static void proto_info_insert(proto_info_t **head, proto_info_t *p_info) {
    if (*head == NULL) {
        *head = p_info;
        return;
    }
    proto_info_t *current = *head;
    while (current != NULL) {
        if (p_info->pkts > current->pkts) {
            p_info->next = current;
            p_info->prev = current->prev;
            if (current->prev != NULL) {
                current->prev->next = p_info;
            } else {
                *head = p_info;
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
/* Protocol stats iterator (uses proto_path flag)                      */
/* ------------------------------------------------------------------ */

static void protocols_stats_iterator(uint32_t proto_id, void *args) {
    if (proto_id == 1) return; /* Ignore PROTO_META */

    proto_iter_ctx_t *ctx = (proto_iter_ctx_t *)args;

    proto_statistics_t *proto_stats = get_protocol_stats((mmt_handler_t *)ctx->mmt, proto_id);
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
                if (ctx->proto_path) {
                    proto_hierarchy_t proto_hierarchy = {0};
                    get_protocol_stats_path((mmt_handler_t *)ctx->mmt, proto_stats,
                                            &proto_hierarchy);
                    char path[128];
                    proto_hierarchy_ids_to_str(&proto_hierarchy, path);
                    fprintf(ctx->fp, "%10lu %10lu %10lu %60s\n",
                            proto_stats->packets_count,
                            proto_stats->data_volume,
                            proto_stats->payload_volume,
                            path);
                }
            }
            proto_stats = proto_stats->next;
        }
        proto_info_insert(ctx->agg_head, p_info);
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void output_print_stats(FILE *fp,
                        void *mmt,
                        int proto_path,
                        const engine_stats_t *stats) {
    if (fp == NULL || stats == NULL) return;

    proto_info_t *agg_head = NULL;

    /* Main header — bold yellow */
    colors_fprintf(fp, COLOR_BOLD, "\n- - - - - - MMT-READER STATS - - - - -\n\n");

    if (proto_path) {
        fprintf(fp, "Protocol statistics with the protocol path:\n\n");
    }
    /* Column headers — bold */
    colors_fprintf(fp, COLOR_BOLD, "\t#pkts\t#volume\t#payload\t#proto_path\n");
    {
        proto_iter_ctx_t ctx = { mmt, proto_path, &agg_head, fp };
        iterate_through_protocols(protocols_stats_iterator, &ctx);
    }

    /* Section header — bold yellow */
    colors_fprintf(fp, COLOR_BOLD, "\nProtocol statistics:\n\n");
    colors_fprintf(fp, COLOR_BOLD, "\t#pkts\t#volume\t#payload\t#proto_name\n");

    proto_info_t *current = agg_head;
    while (current != NULL) {
        /* Protocol name in cyan */
        fprintf(fp, "%10lu %10lu %10lu ",
                current->pkts, current->volume, current->payload);
        colors_fprintf_fmt(fp, COLOR_CYAN, "%s\n", current->name);
        proto_info_t *next = current->next;
        free(current);
        current = next;
    }

    /* Input statistics header — bold green */
    colors_fprintf_fmt(fp, COLOR_BOLD_GREEN, ">>>>>> INPUT STATISTICS <<<<<< \n\n");

    /* Calculate duration */
    double duration = 0;
    if (stats->end_time.tv_sec > stats->init_time.tv_sec) {
        duration = (double)(stats->end_time.tv_sec - stats->init_time.tv_sec);
    } else {
        duration = 1.0; /* avoid division by zero */
    }

    /* Label/value pairs — labels in bold */
    colors_fprintf(fp, COLOR_BOLD, "\tPackets: ");
    fprintf(fp, "%lu\n", stats->nb_packets);

    colors_fprintf(fp, COLOR_BOLD, "\tData: ");
    fprintf(fp, "%lu bytes\n", stats->data_volume);

    colors_fprintf(fp, COLOR_BOLD, "\tSessions: ");
    fprintf(fp, "%lu\n", stats->nb_ipv4_sessions + stats->nb_ipv6_sessions);

    colors_fprintf(fp, COLOR_BOLD, "\tProtocols: ");
    fprintf(fp, "%lu\n", stats->nb_protocols);

    colors_fprintf(fp, COLOR_BOLD, "\tDuration: ");
    fprintf(fp, "%.0f seconds\n", duration);

    fprintf(fp, "\tBandwidth: %.2f bytes/second\n",
            stats->data_volume / duration);
    fprintf(fp, "\tpps: %.2f packets/second\n",
            (double)stats->nb_packets / duration);
    fprintf(fp, "\tfps: %.2f sessions/second\n\n",
            (double)(stats->nb_ipv4_sessions + stats->nb_ipv6_sessions) / duration);
}
