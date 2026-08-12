/**
 * output.h — Text table rendering for protocol statistics
 *
 * Provides formatted output functions for MMT-DPI statistics,
 * including protocol tables (with/without paths), JSON output,
 * and input statistics.  Separates presentation concerns from the
 * core engine so the engine API stays clean and output can be
 * redirected or extended independently.
 *
 * Replaces the inline printf-based formatting in
 * core/engine.c with dedicated output functions.
 */
#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdio.h>
#include "../core/engine.h"

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * Print all statistics to the given file descriptor.
 *
 * Renders three sections:
 *   1. Protocol statistics with per-path detail (if enabled)
 *   2. Aggregated protocol statistics (sorted by packet count)
 *   3. Input statistics (packets, volume, sessions, duration, etc.)
 *
 * @param fp             File descriptor to write to (e.g. stdout, NULL for stdout)
 * @param mmt            MMT handler for protocol iteration
 * @param proto_path     1 to include per-protocol-path detail
 * @param format         Output format (TEXT or JSON)
 * @param show_sessions  1 to include per-protocol session breakdown
 * @param stats          Accumulated engine statistics
 */
void output_print_stats_ex(FILE *fp,
                           void *mmt,
                           int proto_path,
                           output_format_t format,
                           int show_sessions,
                           const engine_stats_t *stats);

/**
 * Print all statistics to the given file descriptor (text format only).
 *
 * @param fp             File descriptor to write to (e.g. stdout)
 * @param mmt            MMT handler for protocol iteration
 * @param proto_path     1 to include per-protocol-path detail
 * @param stats          Accumulated engine statistics
 */
void output_print_stats(FILE *fp,
                        void *mmt,
                        int proto_path,
                        const engine_stats_t *stats);

#endif /* OUTPUT_H */
