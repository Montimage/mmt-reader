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
 * Print accumulated statistics to stdout.
 * @param eng  Engine handle
 */
void engine_print_stats(const engine_t *eng);

/**
 * Print pcap capture statistics (received, dropped, etc.).
 * @param pcs  pcap_stat structure from pcap_stats()
 */
void engine_print_pcap_stats(const struct pcap_stat *pcs);

#endif /* ENGINE_H */
