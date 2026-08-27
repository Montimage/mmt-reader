/**
 * parse.c — CLI argument parsing and subcommand dispatch
 *
 * Implements getopt_long-based parsing for short and long options,
 * subcommand dispatch (analyze / capture), and structured help output.
 *
 * Replaces the inline getopt() parsing in mmtReader.c with a dedicated
 * module that supports long options and per-command help text.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include "parse.h"
#include "../config.h"

/* ------------------------------------------------------------------ */
/* Environment variable helpers                                        */
/* ------------------------------------------------------------------ */

/**
 * Apply an integer-valued environment override only when the variable
 * is actually set to a non-empty value.
 *
 * Unset variables leave *out untouched: values loaded from the config
 * file must survive when no override exists (the previous helper
 * returned 0 for unset variables, silently clobbering the config).
 *
 * @param name  Environment variable name
 * @param out   Destination receiving the parsed value when applied
 * @return      1 when an override was applied, 0 otherwise
 */
static int env_apply_int(const char *name, int *out) {
    const char *val = getenv(name);
    if (val == NULL || val[0] == '\0') {
        return 0;
    }
    *out = atoi(val) ? 1 : 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define MAX_FILENAME_SIZE 256

/* ------------------------------------------------------------------ */
/* Help / usage                                                        */
/* ------------------------------------------------------------------ */

static const char *analyze_help =
"Usage: %s analyze [OPTIONS] -t <trace.pcap>\n"
"\n"
"Analyze a PCAP trace file for protocol identification.\n"
"\n"
"Options:\n"
"  -t, --trace <file>       Trace file to analyze (required)\n"
"  -i, --interface <iface>  Live network interface (alternative to -t)\n"
"  -b, --buffer <MB>        PCAP buffer size in MB (1-10000, default: 50)\n"
"  -a, --proto-path         Show per-protocol-path statistics\n"
"  -s, --sessions           Show per-protocol session counts\n"
"  -j, --json               Output statistics in JSON format\n"
"  -T, --text               Explicitly set text output format (default)\n"

"  -q, --quiet              Suppress progress output\n"
"  -v, --verbose            Show verbose debug output\n"

"  -C, --no-color           Disable ANSI color output\n"
"  -h, --help               Show this help message\n"
"  -V, --version            Print version information\n"
"\n"
"  -c, --config <file>      Use config file for default options\n"
"                           (default: ~/.mmtreader.conf)\n"
"                           CLI flags override config file values.\n"
"\n"
"Environment variables:\n"
"  MMTREADER_JSON=1         Force JSON output\n"
"  MMTREADER_NO_COLOR=1     Disable color output\n"
"  MMTREADER_QUIET=1        Enable quiet mode\n"
"\n"
"Hidden flags:\n"
"  -x, --ip-classify <0|1>  IP address classification (default: 1)\n"
"  -y, --hostname-classify <0|1>  Hostname classification (default: 1)\n"
"  -z, --port-classify <0|1>    Port number classification (default: 1)\n"
"\n"
"Exit codes:\n"
"  0  Success or --help requested\n"
"  2  Usage error\n";

static const char *capture_help =
"Usage: %s capture [OPTIONS] -i <interface>\n"
"\n"
"Capture and analyze live network traffic from an interface.\n"
"\n"
"Options:\n"
"  -i, --interface <iface>  Network interface to capture from (required)\n"
"  -b, --buffer <MB>        PCAP buffer size in MB (1-10000, default: 50)\n"
"  -a, --proto-path         Show per-protocol-path statistics\n"
"  -s, --sessions           Show per-protocol session counts\n"
"  -F, --flows <seconds>    Capture for <seconds>, then report top flows by volume\n"
"  -j, --json               Output statistics in JSON format\n"
"  -T, --text               Explicitly set text output format (default)\n"

"  -q, --quiet              Suppress progress output\n"
"  -v, --verbose            Show verbose debug output\n"

"  -C, --no-color           Disable ANSI color output\n"
"  -h, --help               Show this help message\n"
"  -V, --version            Print version information\n"
"\n"
"  -c, --config <file>      Use config file for default options\n"
"                           (default: ~/.mmtreader.conf)\n"
"                           CLI flags override config file values.\n"
"\n"
"Environment variables:\n"
"  MMTREADER_JSON=1         Force JSON output\n"
"  MMTREADER_NO_COLOR=1     Disable color output\n"
"  MMTREADER_QUIET=1        Enable quiet mode\n"
"\n"
"Exit codes:\n"
"  0  Success or --help requested\n"
"  2  Usage error\n";

static const char *general_help =
"Usage: %s <command> [OPTIONS]\n"
"\n"
"MMT-READER — Network protocol analyzer\n"
"\n"
"Commands:\n"
"  analyze   Analyze a PCAP trace file\n"
"  capture   Capture and analyze live network traffic\n"
"\n"
"Use \"%s <command> --help\" for command-specific help.\n"
"\n"
"General options:\n"
"  -q, --quiet              Suppress progress output\n"
"  -v, --verbose            Show verbose debug output\n"
"  -b, --buffer <MB>        PCAP buffer size in MB (1-10000, default: 50)\n"
"  -h, --help       Show this help message\n"
"  -V, --version    Print version information\n"
"\n"
"  -c, --config <file>      Use config file for default options\n"
"                           (default: ~/.mmtreader.conf)\n"
"                           CLI flags override config file values.\n"
"\n"
"Environment variables:\n"
"  MMTREADER_JSON=1         Force JSON output\n"
"  MMTREADER_NO_COLOR=1     Disable color output\n"
"  MMTREADER_QUIET=1        Enable quiet mode\n"
"\n"
"Hidden flags (available with any command):\n"
"  -x, --ip-classify <0|1>         IP address classification (default: 1)\n"
"  -y, --hostname-classify <0|1>   Hostname classification (default: 1)\n"
"  -z, --port-classify <0|1>       Port number classification (default: 1)\n"
"\n"
"Exit codes:\n"
"  0  Success or --help requested\n"
"  2  Usage error\n";

/* ------------------------------------------------------------------ */
/* Parsing helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * Early-return sentinel used by the helpers below that can terminate
 * parsing on their own (--help, --version):
 *
 *   PARSE_CONTINUE  — nothing to report, the caller keeps going
 *   any other value — the caller must return that value immediately
 *
 * PARSE_EXIT_OK (0) and PARSE_EXIT_ERROR (2) are both distinct from the
 * sentinel, so either can be propagated unchanged.
 */
#define PARSE_CONTINUE (-1)

/**
 * Copy the five config-file-backed fields onto the parsed options.
 *
 * Shared by the default (~/.mmtreader.conf) and the custom (--config)
 * load paths so the two stay in lockstep; an absent/zero buffer falls
 * back to the built-in 50 MB default.
 */
static void parse_copy_config_fields(cli_options_t *opts, const config_t *cfg) {
    opts->json      = cfg->json;
    opts->quiet     = cfg->quiet;
    opts->verbose   = cfg->verbose;
    opts->no_color  = cfg->no_color;
    opts->buffer_mb = cfg->buffer[CONFIG_SECTION_GLOBAL];
    if (opts->buffer_mb == 0) opts->buffer_mb = 50;
}

/**
 * Load the default config file, then re-apply the environment overrides.
 *
 * Precedence: built-in defaults < ~/.mmtreader.conf < environment.
 * Only json / no_color / quiet are environment-overridable (there is no
 * MMTREADER_VERBOSE), and unset or empty variables leave the values just
 * loaded from the config file untouched.
 */
static void parse_load_default_config(cli_options_t *opts) {
    config_t file_cfg;
    config_init(&file_cfg);
    if (config_load(&file_cfg, NULL) == 0 && file_cfg.loaded) {
        parse_copy_config_fields(opts, &file_cfg);
    }

    /* Environment variables (medium priority — CLI flags override these).
     * Applied only when actually set: unset variables must not overwrite
     * the values just loaded from the config file. */
    env_apply_int("MMTREADER_JSON", &opts->json);
    env_apply_int("MMTREADER_NO_COLOR", &opts->no_color);
    env_apply_int("MMTREADER_QUIET", &opts->quiet);
}

/**
 * Re-apply a config file named with -c/--config, after the option loop.
 *
 * NOTE: the five shared fields are overwritten unconditionally, so a
 * custom config silently wins over CLI flags, and no environment
 * override is re-applied on this path. That is pre-existing, intentional
 * behavior and is preserved here verbatim.
 */
static void parse_reload_custom_config(cli_options_t *opts) {
    if (opts->config_path == NULL) {
        return;
    }
    config_t custom_cfg;
    config_init(&custom_cfg);
    if (config_load(&custom_cfg, opts->config_path) == 0 && custom_cfg.loaded) {
        parse_copy_config_fields(opts, &custom_cfg);
    }
}

/**
 * Select the subcommand from the first non-option argument and shift it
 * out of argv so getopt_long never sees it.
 *
 * With no subcommand the only accepted arguments are the global --help /
 * --version, and anything else prints the general help; all three cases
 * end parsing here.
 *
 * @param argc      In/out argument count (decremented by the shift)
 * @param argv      In/out argument vector (advanced by the shift)
 * @param opts      Options being filled
 * @param prog_name Program name captured before the shift
 * @param subcmd    Out: SUBCMD_ANALYZE, SUBCMD_CAPTURE or 0
 * @return PARSE_CONTINUE, or a status the caller must return as-is
 */
static int parse_dispatch_subcommand(int *argc, char ***argv, cli_options_t *opts,
                                     const char *prog_name, int *subcmd) {
    *subcmd = 0;

    /* Determine subcommand from first non-option argument */
    if (*argc > 1) {
        if (strcmp((*argv)[1], "analyze") == 0) {
            *subcmd = SUBCMD_ANALYZE;
            /* Shift argv to skip the subcommand for getopt */
            (*argc)--;
            (*argv)++;
        } else if (strcmp((*argv)[1], "capture") == 0) {
            *subcmd = SUBCMD_CAPTURE;
            (*argc)--;
            (*argv)++;
        }
    }
    if (*subcmd != 0) {
        return PARSE_CONTINUE;
    }

    /* If no subcommand, check for global options (--help, --version)
     * then show general help if neither is found. */
    if (*argc > 1) {
        if (strcmp((*argv)[1], "--help") == 0 || strcmp((*argv)[1], "-h") == 0) {
            opts->show_help = 1;
            fprintf(stdout, general_help, prog_name, prog_name);
            return PARSE_EXIT_OK;
        }
        if (strcmp((*argv)[1], "--version") == 0 || strcmp((*argv)[1], "-V") == 0) {
            opts->mode = MODE_VERSION;
            return PARSE_EXIT_OK;
        }
    }
    /* No subcommand and no global option — show general help */
    opts->show_help = 1;
    fprintf(stdout, general_help, prog_name, prog_name);
    return PARSE_EXIT_OK;
}

/**
 * Parse a strictly positive integer option argument bounded by max.
 *
 * Shared by -b/--buffer (max 10000) and -F/--flows (LONG_MAX, i.e. the
 * lower bound only). Rejected values print err_msg and exit through the
 * noreturn parse_error().
 *
 * @param arg       Option argument (valid only within this getopt round)
 * @param max       Largest accepted value
 * @param err_msg   Message printed after the "Error: " prefix
 * @param prog_name Program name for the usage hint
 * @return The accepted value
 */
static int parse_bounded_int_arg(const char *arg, long max, const char *err_msg,
                                 const char *prog_name) {
    long val = strtol(arg, NULL, 10);
    if (val <= 0 || val > max) {
        fprintf(stderr, "Error: %s\n", err_msg);
        parse_error(prog_name);
    }
    return (int)val;
}

/**
 * Parse an option argument that must be exactly 0 or 1.
 *
 * Shared by the hidden -x/-y/-z classification switches; rejected values
 * print err_msg and exit through the noreturn parse_error().
 */
static int parse_flag01_arg(const char *arg, const char *err_msg,
                            const char *prog_name) {
    int val = atoi(arg);
    if (val != 0 && val != 1) {
        fprintf(stderr, "Error: %s\n", err_msg);
        parse_error(prog_name);
    }
    return val;
}

/**
 * Validate and store the -t/--trace or -i/--interface argument.
 *
 * Each option is rejected on the wrong subcommand; -t additionally
 * requires an existing file. Both set opts->input and opts->mode.
 *
 * @param opt 't' for a trace file, 'i' for a live interface
 */
static void parse_input_arg(int opt, const char *arg, cli_options_t *opts,
                            int subcmd, const char *prog_name) {
    if (opt == 't') {
        if (subcmd == SUBCMD_CAPTURE) {
            fprintf(stderr, "Error: -t/--trace is for 'analyze' only\n");
            parse_error(prog_name);
        }
        if (strlen(arg) >= MAX_FILENAME_SIZE) {
            fprintf(stderr, "Error: trace file path too long\n");
            parse_error(prog_name);
        }
        if (access(arg, F_OK) != 0) {
            fprintf(stderr, "Error: file not found: %s\n", arg);
            parse_error(prog_name);
        }
        opts->mode = MODE_TRACE_FILE;
    } else {
        if (subcmd == SUBCMD_ANALYZE) {
            fprintf(stderr, "Error: -i/--interface is for 'capture' only\n");
            parse_error(prog_name);
        }
        if (strlen(arg) >= MAX_FILENAME_SIZE) {
            fprintf(stderr, "Error: interface name too long\n");
            parse_error(prog_name);
        }
        opts->mode = MODE_LIVE_INTERFACE;
    }
    opts->input = arg;
}

/**
 * Store one of the hidden -x/-y/-z classification switches.
 */
static void parse_classify_arg(int opt, const char *arg, cli_options_t *opts,
                               const char *prog_name) {
    if (opt == 'x') {
        opts->ip_classify = parse_flag01_arg(arg,
            "--ip-classify must be 0 or 1", prog_name);
    } else if (opt == 'y') {
        opts->hostname_classify = parse_flag01_arg(arg,
            "--hostname-classify must be 0 or 1", prog_name);
    } else {
        opts->port_classify = parse_flag01_arg(arg,
            "--port-classify must be 0 or 1", prog_name);
    }
}

/**
 * Handle the two flags that stop parsing immediately: -V/--version
 * selects the version mode, -h/--help prints the subcommand help.
 *
 * @return always PARSE_EXIT_OK — the caller must return it
 */
static int parse_early_exit_flag(int opt, cli_options_t *opts, int subcmd,
                                 const char *prog_name) {
    if (opt == 'V') {
        /* Delegate to version module — caller handles exit */
        opts->mode = MODE_VERSION;
        return PARSE_EXIT_OK;
    }
    opts->show_help = 1;
    if (subcmd == SUBCMD_ANALYZE) {
        fprintf(stdout, analyze_help, prog_name);
    } else if (subcmd == SUBCMD_CAPTURE) {
        fprintf(stdout, capture_help, prog_name);
    }
    return PARSE_EXIT_OK;
}

/**
 * Reject the option combinations that only become invalid once every
 * argument has been seen, and require an input for both subcommands.
 *
 * Every rejection path here exits through the noreturn parse_error().
 */
static void parse_validate_final(const cli_options_t *opts, int subcmd,
                                 int has_input, const char *prog_name) {
    /* --flows drives a timed live capture, so it only applies to the
     * 'capture' subcommand — reject it on the offline trace-file path */
    if (opts->mode == MODE_TRACE_FILE && opts->flows_seconds > 0) {
        fprintf(stderr, "Error: --flows is only supported by the 'capture' subcommand (live interfaces).\n");
        parse_error(prog_name);
    }

    /* Validate: input is required for both subcommands */
    if (!has_input) {
        if (subcmd == SUBCMD_ANALYZE) {
            parse_validate_error(prog_name, "missing --trace file path");
        } else if (subcmd == SUBCMD_CAPTURE) {
            parse_validate_error(prog_name, "missing --interface name");
        } else {
            parse_validate_error(prog_name, "missing required option");
        }
        parse_error(prog_name);
    }
}

/* ------------------------------------------------------------------ */
/* getopt_long setup                                                   */
/* ------------------------------------------------------------------ */

static const struct option long_options[] = {
    { "trace",           required_argument, NULL, 't' },
    { "interface",       required_argument, NULL, 'i' },
    { "buffer",          required_argument, NULL, 'b' },
    { "proto-path",      no_argument,       NULL, 'a' },
    { "sessions",        no_argument,       NULL, 's' },
    { "flows",           required_argument, NULL, 'F' },
    { "json",            no_argument,       NULL, 'j' },
    { "text",            no_argument,       NULL, 'T' },
    { "quiet",           no_argument,       NULL, 'q' },
    { "verbose",         no_argument,       NULL, 'v' },
    { "ip-classify",     required_argument, NULL, 'x' },
    { "hostname-classify", required_argument, NULL, 'y' },
    { "port-classify",   required_argument, NULL, 'z' },
    { "config",          required_argument, NULL, 'c' },
    { "help",            no_argument,       NULL, 'h' },
    { "version",         no_argument,       NULL, 'V' },
    { "no-color",        no_argument,       NULL, 'C' },
    { NULL, 0, NULL, 0 }
};

/**
 * Run the getopt_long loop over the (already shifted) argument vector.
 *
 * optind is reset on every call: parse_options() may run several times
 * in one process (the unit suite does), and a stale optind would skip
 * arguments of the next parse. optarg is consumed inside the iteration
 * that produced it — helpers take it by value, never by reference.
 *
 * @param has_input Out: set to 1 once -t or -i supplied an input
 * @return PARSE_CONTINUE, or a status the caller must return as-is
 */
static int parse_option_loop(int argc, char *argv[], cli_options_t *opts, int subcmd,
                             const char *prog_name, int *has_input) {
    int opt;

    /* Reset getopt state after argv shift */
    optind = 1;

    while ((opt = getopt_long(argc, argv, "t:i:b:haVsqjTCx:y:z:c:vF:",
                              long_options, NULL)) != EOF) {
        switch (opt) {
        case 't':
        case 'i':
            parse_input_arg(opt, optarg, opts, subcmd, prog_name);
            *has_input = 1;
            break;

        case 'b':
            opts->buffer_mb = parse_bounded_int_arg(optarg, 10000,
                "buffer size must be a positive integer (1-10000)", prog_name);
            break;

        case 'F':
            opts->flows_seconds = parse_bounded_int_arg(optarg, LONG_MAX,
                "--flows must be a positive number of seconds", prog_name);
            break;

        case 'x':
        case 'y':
        case 'z':
            parse_classify_arg(opt, optarg, opts, prog_name);
            break;

        case 'j':
        case 'J':
            opts->json          = 1;
            opts->output_format = OUTPUT_FORMAT_JSON;
            break;

        case 'a':
            opts->proto_path = 1;
            break;
        case 's':
            opts->show_sessions = 1;
            break;
        case 'T':
            opts->output_format = OUTPUT_FORMAT_TEXT;
            break;
        case 'C':
            opts->no_color = 1;
            break;
        case 'q':
            opts->quiet = 1;
            break;
        case 'v':
            opts->verbose = 1;
            break;
        case 'c':
            opts->config_path = optarg;
            break;

        case 'V':
        case 'h':
            return parse_early_exit_flag(opt, opts, subcmd, prog_name);

        default:
            parse_error(prog_name);
            break;
        }
    }

    return PARSE_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void parse_init(cli_options_t *opts) {
    opts->input           = NULL;
    opts->mode            = MODE_NONE;
    opts->buffer_mb       = 50;
    opts->proto_path      = 0;
    opts->ip_classify     = 1;
    opts->hostname_classify = 1;
    opts->port_classify   = 1;
    opts->show_help       = 0;
    opts->no_color        = 0;
    opts->output_format   = OUTPUT_FORMAT_TEXT;
    opts->show_sessions   = 0;

    opts->quiet           = 0;
    opts->verbose         = 0;
    opts->json            = 0;
    opts->flows_seconds   = 0;
    opts->config_path     = NULL;

    /* Environment variables (lowest priority — CLI flags override these) */
    env_apply_int("MMTREADER_JSON", &opts->json);
    env_apply_int("MMTREADER_NO_COLOR", &opts->no_color);
    env_apply_int("MMTREADER_QUIET", &opts->quiet);

}

int parse_options(int argc, char *argv[], cli_options_t *opts) {
    int subcmd = 0;   /* 0 = none, SUBCMD_ANALYZE, SUBCMD_CAPTURE */
    int has_input = 0;
    const char *prog_name = argv[0];  /* Save before argv shift */
    int early;

    /* Initialize options to defaults */
    parse_init(opts);

    /* Config file, then environment (lowest priority — CLI flags override) */
    parse_load_default_config(opts);

    early = parse_dispatch_subcommand(&argc, &argv, opts, prog_name, &subcmd);
    if (early != PARSE_CONTINUE) {
        return early;
    }

    early = parse_option_loop(argc, argv, opts, subcmd, prog_name, &has_input);
    if (early != PARSE_CONTINUE) {
        return early;
    }

    /* Apply custom config file (highest priority after CLI flags) */
    parse_reload_custom_config(opts);

    /* Support positional argument: "capture eth0" without -i */
    if (subcmd == SUBCMD_CAPTURE && !has_input && optind < argc) {
        opts->input = argv[optind];
        opts->mode  = MODE_LIVE_INTERFACE;
        has_input   = 1;
    }

    parse_validate_final(opts, subcmd, has_input, prog_name);

    return PARSE_EXIT_OK;
}

void parse_error(const char *prog_name) {
    fprintf(stderr, "Use \"%s --help\" for usage information\n", prog_name);
    exit(PARSE_EXIT_ERROR);
}

void parse_validate_error(const char *prog_name, const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    fprintf(stderr, "Use \"%s --help\" for usage information\n", prog_name);
}
