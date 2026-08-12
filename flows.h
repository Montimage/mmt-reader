/**
 * flows.h — Top talkers, reported from MMT-DPI sessions
 *
 * Ranks the sessions MMT-DPI tracks by transferred volume. Used with the
 * --flows capture option to identify which host (and application)
 * consumes the most traffic.
 */
#ifndef FLOWS_H
#define FLOWS_H

#include <stdio.h>
#include <stdint.h>
#include "mmt_core.h"

/** Opaque flow-aggregation state. */
typedef struct flows flows_t;

/**
 * Create a new flow aggregator.
 * @return Aggregator handle, or NULL on allocation failure
 */
flows_t *flows_create(void);

/**
 * Attach the aggregator to an MMT-DPI handler.
 *
 * Registers the session attributes the report needs (client/server
 * address and port, for IPv4 and IPv6) and a packet handler that records
 * every session the DPI opens. Must be called before the first packet is
 * processed; one aggregator attaches to one handler.
 *
 * @param f    Aggregator handle
 * @param mmt  MMT handler to observe
 * @return     1 on success, 0 if a registration failed
 */
int flows_attach(flows_t *f, mmt_handler_t *mmt);

/**
 * Destroy a flow aggregator and release its resources.
 * Detaches from the MMT handler it was attached to, if any.
 * @param f Aggregator handle (NULL is safe)
 */
void flows_destroy(flows_t *f);

/**
 * Print the top flows by bytes to the given stream.
 * @param f        Aggregator handle
 * @param fp       Output stream (stdout/stderr)
 * @param top_n    Maximum number of flows to print
 */
void flows_print_top(flows_t *f, FILE *fp, int top_n);

#endif /* FLOWS_H */
