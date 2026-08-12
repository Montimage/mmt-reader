/**
 * engine.h — MMT-DPI engine API
 *
 * Provides a clean interface for MMT-DPI handler initialization,
 * packet processing, and statistics collection. Separates core DPI
 * logic from CLI concerns.
 */
#ifndef ENGINE_H
#define ENGINE_H

#include <stdint.h>
#include <sys/time.h>
#include <pcap.h>
#include "mmt_core.h"

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

/**
 * Output format for statistics display.
 */
typedef enum {
    OUTPUT_FORMAT_TEXT,   /**< Human-readable text table (default) */
    OUTPUT_FORMAT_JSON    /**< Machine-readable JSON               */
} output_format_t;

/**
 * Engine statistics snapshot (read-only after processing).
 */
typedef struct {
    uint64_t nb_packets;          /**< Total packets processed            */
    uint64_t nb_ipv4_sessions;    /**< IPv4 sessions created              */
    uint64_t nb_ipv6_sessions;    /**< IPv6 sessions created              */
    uint64_t nb_protocols;        /**< Distinct protocols seen            */
    uint64_t data_volume;         /**< Total data volume in bytes         */
    struct timeval init_time;     /**< First packet timestamp             */
    struct timeval end_time;      /**< Last packet timestamp              */
} engine_stats_t;

/**
 * Opaque engine handle.
 */
typedef struct engine engine_t;

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

/**
 * Create and initialize a new MMT-DPI engine.
 *
 * @param dlt         Data-link type (e.g. DLT_EN10MB)
 * @param flags       Handler flags (reserved, pass 0)
 * @param errbuf      Error buffer (caller-allocated, ≥1024 bytes)
 * @return Opaque engine pointer, or NULL on failure
 */
engine_t *engine_create(int dlt, int flags, char *errbuf);

/**
 * Get the underlying MMT handler from an engine.
 * Used internally by capture callbacks.
 * @param eng  Engine handle
 * @return     MMT handler pointer
 */
mmt_handler_t *engine_get_mmt(const engine_t *eng);

/**
 * Destroy the engine and release all internal resources.
 * @param eng Engine handle (NULL is safe)
 */
void engine_destroy(engine_t *eng);

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/**
 * Enable or disable IP-address-based classification.
 * @param eng  Engine handle
 * @param on   1 = enable, 0 = disable
 */
void engine_set_ip_classify(engine_t *eng, int on);

/**
 * Enable or disable hostname-based classification.
 * @param eng  Engine handle
 * @param on   1 = enable, 0 = disable
 */
void engine_set_hostname_classify(engine_t *eng, int on);

/**
 * Enable or disable port-number-based classification.
 * @param eng  Engine handle
 * @param on   1 = enable, 0 = disable
 */
void engine_set_port_classify(engine_t *eng, int on);

/**
 * Enable or disable per-protocol-path detail in statistics output.
 * @param eng  Engine handle
 * @param on   1 = enable, 0 = disable
 */
void engine_set_proto_path_detail(engine_t *eng, int on);

/**
 * Set the output format for statistics display.
 * @param eng    Engine handle
 * @param format OUTPUT_FORMAT_TEXT or OUTPUT_FORMAT_JSON
 */
void engine_set_output_format(engine_t *eng, output_format_t format);

/**
 * Enable per-protocol session count display.
 * @param eng  Engine handle
 * @param on   1 = enable, 0 = disable
 */
void engine_set_show_sessions(engine_t *eng, int on);

/* ------------------------------------------------------------------ */
/* Packet processing                                                   */
/* ------------------------------------------------------------------ */

/**
 * Process a single packet through the DPI engine.
 *
 * @param eng   Engine handle
 * @param hdr   MMT packet header (timestamp, length)
 * @param data  Raw packet bytes
 * @return 1 on success, 0 on failure
 */
int engine_process_packet(engine_t *eng,
                          const struct pkthdr *hdr,
                          const u_char *data);

/**
 * Process a packet via the legacy callback interface.
 * Used internally by pcap_loop callbacks.
 *
 * @param user  Opaque user data (engine_t pointer)
 * @param p_pkthdr  libpcap packet header
 * @param data  Raw packet bytes
 */
void engine_live_callback(u_char *user,
                          const struct pcap_pkthdr *p_pkthdr,
                          const u_char *data);

/* ------------------------------------------------------------------ */
/* Statistics                                                          */
/* ------------------------------------------------------------------ */

/**
 * Retrieve a snapshot of accumulated statistics.
 * @param eng  Engine handle
 * @param out  Caller-allocated stats struct (filled in)
 */
void engine_get_stats(const engine_t *eng, engine_stats_t *out);

/**
 * Print accumulated statistics to the given file descriptor.
 *
 * @param eng        Engine handle
 * @param fp         File descriptor to write to (stdout, stderr, or NULL for stdout)
 * @param format     Output format (TEXT or JSON)
 * @param show_sessions  1 to include per-protocol session breakdown
 */
void engine_print_stats_ex(const engine_t *eng, FILE *fp,
                           output_format_t format, int show_sessions);

/**
 * Print accumulated statistics to stdout (legacy API).
 * @param eng  Engine handle
 */
void engine_print_stats(const engine_t *eng);

/**
 * Print pcap capture statistics (received, dropped, etc.).
 * @param pcs  pcap_stat structure from pcap_stats()
 */
void engine_print_pcap_stats(const struct pcap_stat *pcs);

/* ------------------------------------------------------------------ */
/* Anomaly detection (future extension)                                */
/* ------------------------------------------------------------------ */

/**
 * Opaque anomaly detection context.
 */
typedef struct anomaly_ctx anomaly_ctx_t;

/**
 * Anomaly type classification.
 */
typedef enum {
    ANOMALY_NONE = 0,           /**< No anomaly detected             */
    ANOMALY_UNUSUAL_TRAFFIC,    /**< Unusual traffic pattern         */
    ANOMALY_PROTOCOL_VIOLATION, /**< Protocol violation detected     */
    ANOMALY_SECURITY_THREAT     /**< Security threat detected        */
} anomaly_type_t;

/**
 * Anomaly detection result for a single packet.
 */
typedef struct {
    anomaly_type_t type;        /**< Type of anomaly (ANOMALY_NONE = no anomaly) */
    int severity;               /**< Severity level (0-100, higher = more severe) */
    char description[128];      /**< Human-readable description                */
} anomaly_result_t;

/**
 * Create an anomaly detection context.
 *
 * This hook is called during engine creation to initialize the anomaly
 * detection subsystem. The default implementation returns a no-op context.
 *
 * @return Opaque anomaly context pointer, or NULL if disabled
 */
anomaly_ctx_t *anomaly_ctx_create(void);

/**
 * Destroy an anomaly detection context and release resources.
 * @param ctx Anomaly context (NULL is safe)
 */
void anomaly_ctx_destroy(anomaly_ctx_t *ctx);

/**
 * Run anomaly detection on a processed packet.
 *
 * This hook is called after each packet is processed by the DPI engine.
 * The default implementation returns ANOMALY_NONE for all packets.
 *
 * @param ctx  Anomaly context (may be NULL if detection is disabled)
 * @param hdr  Packet header (timestamp, length)
 * @param data Raw packet bytes
 * @param out  Caller-allocated anomaly result (filled in on detection)
 */
void anomaly_detect(anomaly_ctx_t *ctx,
                    const struct pkthdr *hdr,
                    const u_char *data,
                    anomaly_result_t *out);

#endif /* ENGINE_H */
