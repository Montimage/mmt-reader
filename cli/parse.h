/**
 * parse.h — CLI argument parsing and subcommand dispatch
 *
 * Provides getopt_long-based parsing for both short and long options,
 * subcommand dispatch (analyze / capture), and per-command help text.
 *
 * Replaces the inline getopt() parsing in mmtReader.c with a
 * dedicated module that supports long options and structured output.
 */
#ifndef PARSE_H
#define PARSE_H

#include <stdio.h>
#include "config.h"

/* Output format constants — defined here to avoid transitive dependency on core/engine.h */
#define OUTPUT_FORMAT_TEXT  0
#define OUTPUT_FORMAT_JSON  1

/* ------------------------------------------------------------------ */
/* Exit codes                                                          */
/* ------------------------------------------------------------------ */

#define PARSE_EXIT_OK       0   /**< --help or successful parse       */
#define PARSE_EXIT_ERROR    2   /**< usage / parsing error            */

/* ------------------------------------------------------------------ */
/* Parsed options                                                      */
/* ------------------------------------------------------------------ */

/**
 * Parsed CLI options shared across subcommands.
 *
 * All fields are initialized to defaults before parsing; the caller
 * inspects them after parse_options() returns.
 */
typedef struct {
    const char *input;          /**< trace file (-t) or interface (-i)    */
    int         mode;           /**< TRACE_FILE or LIVE_INTERFACE         */
    int         buffer_mb;      /**< pcap buffer size in MB (default 50)  */
    int         proto_path;     /**< per-protocol-path detail (-a)        */
    int         ip_classify;    /**< IP address classification (-x)       */
    int         hostname_classify; /**< hostname classification (-y)      */
    int         port_classify;    /**< port number classification (-z)    */
    int         show_help;      /**< 1 if --help was shown              */
    int         no_color;       /**< 1 if --no-color is set             */
    int         output_format;  /**< 0=text (default), 1=json           */
    int         show_sessions;  /**< 1 to show per-session breakdown (-s) */

    int         quiet;          /**< 1 if --quiet / MMTREADER_QUIET=1   */
    int         verbose;        /**< 1 if --verbose / -v                */
    int         json;           /**< 1 if --json / MMTREADER_JSON=1     */

    int         flows_seconds;  /**< capture duration + top-flow report (-F) */

    const char *config_path;    /**< 1 if --config flag was passed      */

} cli_options_t;

/* ------------------------------------------------------------------ */
/* Subcommand constants                                                  */
/* ------------------------------------------------------------------ */

#define SUBCMD_ANALYZE  1
#define SUBCMD_CAPTURE  2

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

/**
 * Initialize all cli_options_t fields to their default values.
 * @param opts  Pointer to uninitialized cli_options_t
 */
void parse_init(cli_options_t *opts);

/**
 * Parse command-line arguments using getopt_long.
 *
 * Supports both short flags (-t, -i, -a, etc.) and long options
 * (--trace, --interface, --proto-path, etc.). Handles subcommand
 * dispatch: the first non-option argument selects the subcommand
 * (analyze or capture).
 *
 * On --help: prints per-command help text and returns PARSE_EXIT_OK
 *           without modifying opts.
 * On error:  prints usage to stderr and returns PARSE_EXIT_ERROR.
 * On success: returns PARSE_EXIT_OK and fills opts.
 *
 * @param argc  Argument count (from main)
 * @param argv  Argument vector (from main)
 * @param opts  Pointer to cli_options_t to fill
 * @return PARSE_EXIT_OK on success/--help, PARSE_EXIT_ERROR on failure
 */
int parse_options(int argc, char *argv[], cli_options_t *opts);

/**
 * Print usage error to stderr and exit.
 * @param prog_name Program name (argv[0])
 */
void parse_error(const char *prog_name) __attribute__((noreturn));

/**
 * Print a validation error to stderr with usage hint.
 * @param prog_name Program name (argv[0])
 * @param msg       Error message (without trailing newline)
 */
void parse_validate_error(const char *prog_name, const char *msg);

#endif /* PARSE_H */
