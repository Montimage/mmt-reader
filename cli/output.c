/**
 * output.c — Text table rendering and JSON output for protocol statistics
 *
 * Implements formatted output for MMT-DPI statistics, including
 * protocol tables (with/without paths), JSON output, and input
 * statistics.  Supports per-protocol session breakdown via the
 * --sessions flag.
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
#include "../utils/version.h"

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
    uint64_t sessions;    /**< Per-protocol session count (for --sessions) */
    struct proto_info *prev;
    struct proto_info *next;
} proto_info_t;

/**
 * Protocol path entry for JSON output.
 */
typedef struct proto_path_entry {
    uint64_t pkts;
    uint64_t volume;
    uint64_t payload;
    char path[128];
    struct proto_path_entry *next;
} proto_path_entry_t;

/**
 * Context passed to the protocol stats iterator callback.
 */
typedef struct {
    void *mmt;
    int proto_path;
    int show_sessions;
    int is_json;
    proto_info_t **agg_head;
    proto_path_entry_t **path_head;
    FILE *fp;
} proto_iter_ctx_t;

/* ------------------------------------------------------------------ */
/* JSON string escaping helper                                         */
/* ------------------------------------------------------------------ */

/**
 * Escape a string for JSON output. Writes to a caller-allocated buffer.
 * Returns the length of the escaped string.
 */
static size_t json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 5 < dst_size; i++) {
        switch (src[i]) {
        case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
        case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
        case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
        case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
        case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
        default:   dst[j++] = src[i]; break;
        }
    }
    dst[j] = '\0';
    return j;
}

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
/* Protocol path helpers                                               */
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

static void proto_path_insert(proto_path_entry_t **head, proto_path_entry_t *entry) {
    /* Append to end of list */
    if (*head == NULL) {
        *head = entry;
        return;
    }
    proto_path_entry_t *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = entry;
}

/* ------------------------------------------------------------------ */
/* Protocol stats iterator (uses proto_path and show_sessions flags)   */
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
                if (ctx->show_sessions) {
                    p_info->sessions += proto_stats->sessions_count;
                }
                if (ctx->proto_path) {
                    proto_hierarchy_t proto_hierarchy = {0};
                    get_protocol_stats_path((mmt_handler_t *)ctx->mmt, proto_stats,
                                            &proto_hierarchy);
                    char path[128];
                    proto_hierarchy_ids_to_str(&proto_hierarchy, path);

                    if (ctx->is_json) {
                        /* Collect for JSON output */
                        proto_path_entry_t *entry =
                            (proto_path_entry_t *)malloc(sizeof(proto_path_entry_t));
                        if (entry != NULL) {
                            entry->pkts = proto_stats->packets_count;
                            entry->volume = proto_stats->data_volume;
                            entry->payload = proto_stats->payload_volume;
                            strncpy(entry->path, path, sizeof(entry->path) - 1);
                            entry->path[sizeof(entry->path) - 1] = '\0';
                            entry->next = NULL;
                            proto_path_insert(ctx->path_head, entry);
                        }
                    } else {
                        /* Text output */
                        fprintf(ctx->fp, "%10lu %10lu %10lu %60s\n",
                                proto_stats->packets_count,
                                proto_stats->data_volume,
                                proto_stats->payload_volume,
                                path);
                    }
                }
            }
            proto_stats = proto_stats->next;
        }
        proto_info_insert(ctx->agg_head, p_info);
    }
}

/* ------------------------------------------------------------------ */
/* Helper: calculate duration from stats                               */
/* ------------------------------------------------------------------ */

static double calc_duration(const engine_stats_t *stats) {
    double duration = 0;
    if (stats->end_time.tv_sec > stats->init_time.tv_sec) {
        duration = (double)(stats->end_time.tv_sec - stats->init_time.tv_sec);
    } else {
        duration = 1.0; /* avoid division by zero */
    }
    return duration;
}

/* ------------------------------------------------------------------ */
/* Text output helpers                                                 */
/* ------------------------------------------------------------------ */

static void output_text_stats(FILE *fp,
                              void *mmt,
                              int proto_path,
                              int show_sessions,
                              const engine_stats_t *stats) {
    proto_info_t *agg_head = NULL;

    /* Main header — bold yellow */
    colors_fprintf(fp, COLOR_BOLD, "\n- - - - - - MMT-READER STATS - - - - -\n\n");

    if (proto_path) {
        fprintf(fp, "Protocol statistics with the protocol path:\n\n");
    }
    /* Column headers — bold */
    colors_fprintf(fp, COLOR_BOLD, "\t#pkts\t#volume\t#payload\t#proto_path\n");
    {
        proto_iter_ctx_t ctx = { mmt, proto_path, show_sessions, 0, &agg_head, NULL, fp };
        iterate_through_protocols(protocols_stats_iterator, &ctx);
    }

    /* Section header — bold yellow */
    colors_fprintf(fp, COLOR_BOLD, "\nProtocol statistics:\n\n");
    colors_fprintf(fp, COLOR_BOLD, "\t#pkts\t#volume\t#payload\t#proto_name");
    if (show_sessions) {
        fprintf(fp, "\t#sessions");
    }
    fprintf(fp, "\n");

    proto_info_t *current = agg_head;
    while (current != NULL) {
        /* Protocol name in cyan */
        fprintf(fp, "%10lu %10lu %10lu ",
                current->pkts, current->volume, current->payload);
        colors_fprintf_fmt(fp, COLOR_CYAN, "%s", current->name);
        if (show_sessions) {
            fprintf(fp, "    %lu", current->sessions);
        }
        fprintf(fp, "\n");
        proto_info_t *next = current->next;
        free(current);
        current = next;
    }

    /* Input statistics header — bold green */
    colors_fprintf_fmt(fp, COLOR_BOLD_GREEN, ">>>>>> INPUT STATISTICS <<<<<< \n\n");

    /* Calculate duration */
    double duration = calc_duration(stats);

    /* Label/value pairs — labels in bold */
    colors_fprintf(fp, COLOR_BOLD, "\tPackets: ");
    fprintf(fp, "%lu\n", stats->nb_packets);

    colors_fprintf(fp, COLOR_BOLD, "\tData: ");
    fprintf(fp, "%lu bytes\n", stats->data_volume);

    if (show_sessions) {
        colors_fprintf(fp, COLOR_BOLD, "\tIPv4 Sessions: ");
        fprintf(fp, "%lu\n", stats->nb_ipv4_sessions);
        colors_fprintf(fp, COLOR_BOLD, "\tIPv6 Sessions: ");
        fprintf(fp, "%lu\n", stats->nb_ipv6_sessions);
    }

    colors_fprintf(fp, COLOR_BOLD, "\tTotal Sessions: ");
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

/* ------------------------------------------------------------------ */
/* JSON output helpers                                                 */
/* ------------------------------------------------------------------ */

static void output_json_stats(FILE *fp,
                              void *mmt,
                              int proto_path,
                              int show_sessions,
                              const engine_stats_t *stats) {
    proto_info_t *agg_head = NULL;
    proto_path_entry_t *path_head = NULL;

    /* Calculate duration */
    double duration = calc_duration(stats);

    /* Open JSON object */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"version\": \"%s\",\n", version());
    fprintf(fp, "  \"input_stats\": {\n");
    fprintf(fp, "    \"packets\": %lu,\n", stats->nb_packets);
    fprintf(fp, "    \"data_volume\": %lu,\n", stats->data_volume);
    fprintf(fp, "    \"duration_seconds\": %.2f,\n", duration);
    fprintf(fp, "    \"bandwidth_bytes_per_sec\": %.2f,\n",
            stats->data_volume / duration);
    fprintf(fp, "    \"packets_per_sec\": %.2f,\n",
            (double)stats->nb_packets / duration);
    if (show_sessions) {
        fprintf(fp, "    \"ipv4_sessions\": %lu,\n", stats->nb_ipv4_sessions);
        fprintf(fp, "    \"ipv6_sessions\": %lu,\n", stats->nb_ipv6_sessions);
    }
    fprintf(fp, "    \"total_sessions\": %lu,\n",
            stats->nb_ipv4_sessions + stats->nb_ipv6_sessions);
    fprintf(fp, "    \"protocols\": %lu\n", stats->nb_protocols);
    fprintf(fp, "  },\n");

    /* Protocol paths section (if enabled) */
    if (proto_path) {
        fprintf(fp, "  \"protocol_paths\": [\n");
        {
            proto_iter_ctx_t ctx = { mmt, proto_path, show_sessions, 1,
                                     &agg_head, &path_head, fp };
            iterate_through_protocols(protocols_stats_iterator, &ctx);
        }
        /* Output collected paths as JSON array */
        proto_path_entry_t *entry = path_head;
        while (entry != NULL) {
            char escaped[128];
            json_escape(entry->path, escaped, sizeof(escaped));
            fprintf(fp, "    {\n");
            fprintf(fp, "      \"packets\": %lu,\n", entry->pkts);
            fprintf(fp, "      \"data_volume\": %lu,\n", entry->volume);
            fprintf(fp, "      \"payload_volume\": %lu,\n", entry->payload);
            fprintf(fp, "      \"path\": \"%s\"\n", escaped);
            fprintf(fp, "    }");
            proto_path_entry_t *next = entry->next;
            free(entry);
            entry = next;
            if (next != NULL) {
                fprintf(fp, ",\n");
            }
        }
        fprintf(fp, "\n  ],\n");
    }

    /* Aggregated protocol statistics */
    fprintf(fp, "  \"protocols\": [\n");

    proto_info_t *current = agg_head;
    while (current != NULL) {
        char escaped_name[256];
        json_escape(current->name, escaped_name, sizeof(escaped_name));
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"name\": \"%s\",\n", escaped_name);
        fprintf(fp, "      \"packets\": %lu,\n", current->pkts);
        fprintf(fp, "      \"data_volume\": %lu,\n", current->volume);
        fprintf(fp, "      \"payload_volume\": %lu", current->payload);
        if (show_sessions) {
            fprintf(fp, ",\n      \"sessions\": %lu", current->sessions);
        }
        fprintf(fp, "\n    }");
        proto_info_t *next = current->next;
        free(current);
        current = next;
        if (next != NULL) {
            fprintf(fp, ",\n");
        }
    }
    fprintf(fp, "\n  ]\n");

    /* Close JSON object */
    fprintf(fp, "}\n");
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void output_print_stats_ex(FILE *fp,
                           void *mmt,
                           int proto_path,
                           output_format_t format,
                           int show_sessions,
                           const engine_stats_t *stats) {
    if (stats == NULL) return;
    if (fp == NULL) fp = stdout;

    if (format == OUTPUT_FORMAT_JSON) {
        output_json_stats(fp, mmt, proto_path, show_sessions, stats);
    } else {
        output_text_stats(fp, mmt, proto_path, show_sessions, stats);
    }
}

void output_print_stats(FILE *fp,
                        void *mmt,
                        int proto_path,
                        const engine_stats_t *stats) {
    output_print_stats_ex(fp, mmt, proto_path, OUTPUT_FORMAT_TEXT, 0, stats);
}
