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
    unsigned long extract_failures; /**< Packets the DPI could not parse */
};

/* Module-level proto_path_detail (shared by output_print_stats) */
static int proto_path_detail = 1;

/* ------------------------------------------------------------------ */
/* MMT-DPI statistics helpers                                          */
/* ------------------------------------------------------------------ */

/**
 * Totals summed over every statistics instance of one protocol.
 *
 * MMT-DPI keeps one instance per protocol path a protocol appears in
 * (eth.ip.tcp.http and eth.ip.tcp.ssl.http are separate), so a protocol
 * total is the sum over the instance list returned by get_protocol_stats().
 */
typedef struct {
    uint64_t packets;
    uint64_t volume;
    uint64_t sessions;
} proto_totals_t;

static proto_totals_t sum_proto_stats(mmt_handler_t *mmt, uint32_t proto_id) {
    proto_totals_t totals = { 0, 0, 0 };
    proto_statistics_t *stats = get_protocol_stats(mmt, proto_id);

    for (; stats != NULL; stats = stats->next) {
        if (!stats->touched) continue;
        totals.packets  += stats->packets_count;
        totals.volume   += stats->data_volume;
        totals.sessions += stats->sessions_count;
    }
    return totals;
}

/** Context for the distinct-protocol counter below. */
typedef struct {
    mmt_handler_t *mmt;
    uint64_t count;
} proto_count_ctx_t;

/**
 * Count a protocol if the DPI saw at least one packet of it.
 * PROTO_META is the path root, not a protocol on the wire.
 */
static void count_touched_protocols(uint32_t proto_id, void *args) {
    proto_count_ctx_t *ctx = (proto_count_ctx_t *)args;

    if (proto_id == PROTO_META) return;
    if (sum_proto_stats(ctx->mmt, proto_id).packets > 0) {
        ctx->count++;
    }
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

    /* Count failures instead of logging per packet: under random or
     * hostile traffic a per-packet fprintf floods the logs (#69). The
     * total is reported once at shutdown. */
    if (!result) {
        eng->extract_failures++;
    }

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

    /* Failures are counted by engine_process_packet() and reported
     * once at shutdown (issue #69) */
    (void)engine_process_packet(eng, &header, data);
}

void engine_get_stats(const engine_t *eng, engine_stats_t *out) {
    if (eng == NULL || out == NULL) return;
    *out = eng->stats;

    /* Everything below is read from MMT-DPI's own accounting rather than
     * recomputed here. PROTO_META is the root of every protocol path, so
     * its statistics cover every packet the engine handed to the DPI. */
    proto_totals_t meta = sum_proto_stats(eng->mmt, PROTO_META);
    out->data_volume = meta.volume;

    /* Sessions, per IP version, from the IP/IPv6 protocol statistics */
    out->nb_ipv4_sessions = sum_proto_stats(eng->mmt, PROTO_IP).sessions;
    out->nb_ipv6_sessions = sum_proto_stats(eng->mmt, PROTO_IPV6).sessions;

    /* Sessions still alive (the rest have timed out) */
    out->nb_active_sessions = get_active_session_count(eng->mmt);

    /* Distinct protocols seen */
    proto_count_ctx_t ctx = { eng->mmt, 0 };
    iterate_through_protocols(count_touched_protocols, &ctx);
    out->nb_protocols = ctx.count;
}

void engine_print_stats_ex(const engine_t *eng, FILE *fp,
                           output_format_t format, int show_sessions) {
    if (eng == NULL) return;

    /* Get fresh stats from MMT-DPI */
    engine_stats_t stats;
    engine_get_stats(eng, &stats);

    /* Delegate output formatting to the output module */
    output_print_stats_ex(fp, eng->mmt, proto_path_detail,
                          format, show_sessions, &stats);
}

unsigned long engine_extraction_failures(const engine_t *eng) {
    return (eng == NULL) ? 0 : eng->extract_failures;
}

void engine_print_extraction_summary(const engine_t *eng) {
    if (eng == NULL) return;

    /* Silent on clean runs; one line total otherwise. Goes to stderr
     * so stdout stays a single document under --json. */
    if (eng->extract_failures > 0) {
        fprintf(stderr,
                "INFO: Packet data extraction failure for %lu packet(s)\n",
                eng->extract_failures);
    }
}

void engine_print_stats(const engine_t *eng) {
    if (eng == NULL) return;
    engine_print_stats_ex(eng, stdout, eng->output_format, eng->show_sessions);

    /* Shutdown summary: exactly one line per run, in both the analyze
     * and capture paths, since both print statistics exactly once */
    engine_print_extraction_summary(eng);
}

void engine_destroy(engine_t *eng) {
    if (eng == NULL) return;

    /* Close MMT handler */
    if (eng->mmt) {
        mmt_close_handler(eng->mmt);
        close_extraction();
    }

    /* Destroy anomaly detection context */
    anomaly_ctx_destroy(eng->anomaly_ctx);

    free(eng);
}


