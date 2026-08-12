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
/* Anomaly detection default implementation                            */
/* ------------------------------------------------------------------ */

/**
 * Default no-op anomaly detection context.
 * Future implementations can extend this struct with detection state.
 */
struct anomaly_ctx {
    int enabled;  /**< Whether anomaly detection is active */
};

anomaly_ctx_t *anomaly_ctx_create(void) {
    anomaly_ctx_t *ctx = (anomaly_ctx_t *)calloc(1, sizeof(anomaly_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->enabled = 0;  /* Disabled by default */
    return ctx;
}

void anomaly_ctx_destroy(anomaly_ctx_t *ctx) {
    if (ctx != NULL) {
        free(ctx);
    }
}

void anomaly_detect(anomaly_ctx_t *ctx,
                    const struct pkthdr *hdr,
                    const u_char *data,
                    anomaly_result_t *out) {
    (void)ctx;
    (void)hdr;
    (void)data;
    (void)out;
    /* Default: no anomaly detection. Future implementations
     * can inspect packets and populate the anomaly_result_t. */
    if (out != NULL) {
        out->type = ANOMALY_NONE;
        out->severity = 0;
        out->description[0] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* Internal state                                                      */
/* ------------------------------------------------------------------ */

struct engine {
    mmt_handler_t *mmt;           /**< MMT handler                   */
    engine_stats_t stats;         /**< Accumulated statistics        */
    output_format_t output_format;/**< Output format (TEXT/JSON)     */
    int show_sessions;            /**< Show per-protocol sessions    */
    anomaly_ctx_t *anomaly_ctx;   /**< Anomaly detection context     */
};

/* Module-level proto_path_detail (shared by output_print_stats) */
static int proto_path_detail = 1;



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

    /* Initialize anomaly detection context */
    eng->anomaly_ctx = anomaly_ctx_create();

    return eng;
}

mmt_handler_t *engine_get_mmt(const engine_t *eng) {
    if (eng == NULL) return NULL;
    return eng->mmt;
}

void engine_set_ip_classify(engine_t *eng, int on) {
    if (eng == NULL) return;
    if (on) {
        fprintf(stderr, "Enable classification by IP address\n");
        enable_ip_address_classify(eng->mmt);
    } else {
        disable_ip_address_classify(eng->mmt);
    }
}

void engine_set_hostname_classify(engine_t *eng, int on) {
    if (eng == NULL) return;
    if (on) {
        fprintf(stderr, "Enable classification by Hostname\n");
        enable_hostname_classify(eng->mmt);
    } else {
        disable_hostname_classify(eng->mmt);
    }
}

void engine_set_port_classify(engine_t *eng, int on) {
    if (eng == NULL) return;
    if (on) {
        fprintf(stderr, "Enable classification by Port number\n");
        enable_port_classify(eng->mmt);
    } else {
        disable_port_classify(eng->mmt);
    }
}

void engine_set_proto_path_detail(engine_t *eng, int on) {
    (void)eng;
    proto_path_detail = on;
}

void engine_set_output_format(engine_t *eng, output_format_t format) {
    if (eng == NULL) return;
    eng->output_format = format;
}

void engine_set_show_sessions(engine_t *eng, int on) {
    if (eng == NULL) return;
    eng->show_sessions = on;
}

int engine_process_packet(engine_t *eng,
                          const struct pkthdr *hdr,
                          const u_char *data) {
    if (eng == NULL || hdr == NULL || data == NULL) return 0;

    /* Track packet count and timestamps */
    eng->stats.nb_packets++;
    if (eng->stats.nb_packets == 1) {
        eng->stats.init_time = hdr->ts;
    }
    eng->stats.end_time = hdr->ts;

    /* Cast away const — packet_process expects non-const per MMT-DPI API */
    int result = packet_process(eng->mmt, (struct pkthdr *)hdr, (u_char *)data) ? 1 : 0;

    /* Run anomaly detection hook after packet processing */
    if (eng->anomaly_ctx != NULL && result) {
        anomaly_result_t anomaly;
        anomaly_detect(eng->anomaly_ctx, hdr, data, &anomaly);
        (void)anomaly; /* Future: log or store anomaly results */
    }

    return result;
}

int engine_process_packet_cb(void *ctx,
                             const struct pkthdr *hdr,
                             const u_char *data) {
    return engine_process_packet((engine_t *)ctx, hdr, data);
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

    /* Populate session counts from MMT-DPI */
    uint64_t total_sessions = get_active_session_count(eng->mmt);
    /* MMT-DPI does not expose per-IP-version session counts.
     * Report the total in nb_ipv4_sessions for backward compatibility */
    out->nb_ipv4_sessions = total_sessions;
    out->nb_ipv6_sessions = 0;
}

void engine_print_stats_ex(const engine_t *eng, FILE *fp,
                           output_format_t format, int show_sessions) {
    if (eng == NULL) return;

    /* Get fresh stats from MMT-DPI */
    engine_get_stats(eng, (engine_stats_t *)&eng->stats);

    /* Delegate output formatting to the output module */
    output_print_stats_ex(fp, eng->mmt, proto_path_detail,
                          format, show_sessions, &eng->stats);
}

void engine_print_stats(const engine_t *eng) {
    if (eng == NULL) return;
    engine_print_stats_ex(eng, stdout, OUTPUT_FORMAT_TEXT, 0);
}

void engine_destroy(engine_t *eng) {
    if (eng == NULL) return;

    /* Print final stats (delegated to output module) */
    engine_print_stats_ex(eng, stdout, eng->output_format, eng->show_sessions);

    /* Close MMT handler */
    if (eng->mmt) {
        mmt_close_handler(eng->mmt);
        close_extraction();
    }

    /* Destroy anomaly detection context */
    anomaly_ctx_destroy(eng->anomaly_ctx);

    free(eng);
}


