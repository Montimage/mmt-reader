/**
 * mmt_handler.h — MMT handler setup and packet processing
 *
 * Handles MMT initialization, attribute registration, and packet handling.
 */
#ifndef MMT_HANDLER_H
#define MMT_HANDLER_H

#include <stdint.h>
#include <signal.h>
#include "mmt_core.h"

/* Global statistics */
extern uint64_t nb_packets;
extern uint64_t nb_ipv4_sessions;
extern uint64_t nb_ipv6_sessions;
extern uint64_t nb_protocols;
extern uint64_t data_volume;
extern struct timeval *init_time;
extern struct timeval *end_time;

/**
 * Initialize MMT extraction.
 */
void mmt_init_extraction(void);

/**
 * Initialize the MMT handler.
 * @param dlt       data link type
 * @param flags     handler flags
 * @param errbuf    error buffer (1024 bytes)
 * @return MMT handler, or NULL on error
 */
mmt_handler_t *mmt_create_handler(int dlt, int flags, char *errbuf);

/**
 * Set up classification options on the MMT handler.
 */
void mmt_setup_classification(mmt_handler_t *mmt,
                               int ip_classify,
                               int hostname_classify,
                               int port_classify);

/**
 * Register all protocol attributes and packet handlers.
 */
void mmt_register_handlers(mmt_handler_t *mmt);

/**
 * Set up signal handling (SIGINT → clean exit).
 */
void mmt_setup_signals(void);

/**
 * Clean up all resources and print final statistics.
 */
void mmt_cleanup(void);

/**
 * Get the current MMT handler pointer.
 * @return MMT handler, or NULL if not initialized
 */
mmt_handler_t *mmt_get_handler(void);

#endif /* MMT_HANDLER_H */
