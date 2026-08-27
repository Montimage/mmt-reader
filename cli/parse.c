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
"  -d, --duration <seconds> Capture for <seconds>, auto-save to /tmp/mmtreader-<pid>.pcap\n"
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

/*
 * Config-key audit (issue #96). Of the five fields copied below:
 *
 *   json      — was DEAD for behavior: it fed only a debug printf, while
 *               every output decision reads output_format. That is the bug
 *               this issue fixes; the copy now writes output_format, the
 *               single carrier of the output format.
 *   quiet     — live, but only on the live-capture path (mmtReader.c:173,
 *               :244). `analyze` emits no INFO lines either way, so -q has
 *               no observable effect there.
 *   verbose   — live and general (mmtReader.c:91, :149, :160, :181, :269).
 *               Config- and CLI-only: there is no MMTREADER_VERBOSE.
 *   no_color  — live and general (mmtReader.c:67).
 *   buffer_mb — live, but only on the live-capture path (mmtReader.c:174,
 *               :177, :183, :186); `analyze` uses pcap_open_offline() and
 *               ignores it.
 *
 * Config keys nothing reads at all: proto_path, sessions, output_format,
 * ip_classify, hostname_classify, port_classify, and the per-section
 * [analyze]/[capture] buffer overrides — see docs/CONFIG.md.
 */

/**
 * Copy the five config-file-backed fields onto the parsed options.
 *
 * Shared by the default (~/.mmtreader.conf) and the custom (--config)
 * load paths so the two stay in lockstep; an absent/zero buffer falls
 * back to the built-in 50 MB default. All five are written
 * unconditionally, so a --config file replaces — rather than merges
 * with — whatever the default config supplied.
 */
static void parse_copy_config_fields(cli_options_t *opts, const config_t *cfg) {
    opts->output_format = cfg->json ? OUTPUT_FORMAT_JSON : OUTPUT_FORMAT_TEXT;
    opts->quiet     = cfg->quiet;
    opts->verbose   = cfg->verbose;
    opts->no_color  = cfg->no_color;
    opts->buffer_mb = cfg->buffer[CONFIG_SECTION_GLOBAL];
    if (opts->buffer_mb == 0) opts->buffer_mb = 50;
}

/**
 * Apply the environment overrides on top of the current option values.
 *
 * Only json / no_color / quiet are environment-overridable (there is no
 * MMTREADER_VERBOSE), and unset or empty variables leave the values
 * untouched so config-file settings survive when no override exists.
 *
 * MMTREADER_JSON feeds output_format rather than a boolean of its own:
 * it is read into a local flag and mapped explicitly onto
 * OUTPUT_FORMAT_TEXT/JSON, so an out-of-range MMTREADER_JSON=5 can never
 * leave a bogus format behind.
 */
static void parse_apply_env(cli_options_t *opts) {
    int json = (opts->output_format == OUTPUT_FORMAT_JSON);

    if (env_apply_int("MMTREADER_JSON", &json)) {
        opts->output_format = json ? OUTPUT_FORMAT_JSON : OUTPUT_FORMAT_TEXT;
    }
    env_apply_int("MMTREADER_NO_COLOR", &opts->no_color);
    env_apply_int("MMTREADER_QUIET", &opts->quiet);
}

/**
 * Load both config files, then re-apply the environment overrides.
 *
 * Precedence: built-in defaults < ~/.mmtreader.conf < --config file <
 * environment < CLI flags. Both files run through the same copy helper
 * and both are loaded *before* the getopt loop, so the flags parsed
 * afterwards always have the last word. Until issue #96 the --config
 * file was instead re-applied *after* the loop, which silently beat
 * explicit flags and skipped the environment entirely — the two config
 * paths had opposite precedence.
 *
 * opts->config_path is filled by parse_prescan_config_path() before this
 * runs; an unreadable path is ignored, exactly as for the default file.
 */
static void parse_load_config_files(cli_options_t *opts) {
    config_t cfg;

    config_init(&cfg);
    if (config_load(&cfg, NULL) == 0 && cfg.loaded) {
        parse_copy_config_fields(opts, &cfg);
    }

    if (opts->config_path != NULL) {
        config_init(&cfg);
        if (config_load(&cfg, opts->config_path) == 0 && cfg.loaded) {
            parse_copy_config_fields(opts, &cfg);
        }
    }

    parse_apply_env(opts);
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
    { "duration",        required_argument, NULL, 'd' },
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

/* ------------------------------------------------------------------ */
/* Config-file pre-scan                                                */
/* ------------------------------------------------------------------ */

/**
 * Resolve a long-option name to its long_options entry, accepting the
 * unambiguous abbreviations getopt_long() accepts.
 *
 * @param name Option name without the leading "--"
 * @param len  Length of the name (stops at '=' for --name=value)
 * @return The matching entry, or NULL when unknown or ambiguous
 */
static const struct option *long_opt_lookup(const char *name, size_t len) {
    const struct option *match = NULL;

    for (const struct option *o = long_options; o->name != NULL; o++) {
        if (strncmp(o->name, name, len) != 0) {
            continue;
        }
        if (o->name[len] == '\0') {
            return o;            /* exact match beats any abbreviation */
        }
        if (match != NULL) {
            return NULL;         /* ambiguous abbreviation */
        }
        match = o;
    }
    return match;
}

/* Short options that consume an argument — the ':' entries of the
 * optstring used by parse_option_loop(). The scan below skips those
 * arguments so a value merely containing 'c' is never read as -c. */
#define SHORT_OPTS_WITH_ARG "tibxyzcF"

/**
 * Find the -c/--config value before getopt_long() ever runs.
 *
 * The named config file has to be loaded *before* the option loop for
 * CLI flags to win over it (issue #96), but the path is only known once
 * the arguments have been read — hence this minimal pre-pass. It mirrors
 * getopt semantics: all four spellings (-c path, -cpath, --config path,
 * --config=path) plus clustered short options are recognized, "--" ends
 * option processing, and the last occurrence wins, exactly as the
 * repeated `opts->config_path = optarg` assignment in the loop does.
 *
 * Runs on the unshifted argv: the subcommand token in argv[1] is never
 * an option, so scanning from index 1 sees the same arguments getopt
 * will see after parse_dispatch_subcommand() shifts them.
 *
 * @return A pointer into argv, or NULL when no --config was given
 */
static const char *parse_prescan_config_path(int argc, char *argv[]) {
    const char *found = NULL;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--") == 0) {
            break;
        }
        if (arg[0] != '-' || arg[1] == '\0') {
            continue;                    /* operand, or a bare "-" */
        }

        if (arg[1] == '-') {             /* long option */
            const char *body = arg + 2;
            const char *eq   = strchr(body, '=');
            size_t      len  = eq ? (size_t)(eq - body) : strlen(body);
            const struct option *o = long_opt_lookup(body, len);

            if (o == NULL) {
                continue;
            }
            if (o->val == 'c') {
                if (eq != NULL) {
                    found = eq + 1;
                } else if (i + 1 < argc) {
                    found = argv[++i];
                }
            } else if (eq == NULL && o->has_arg == required_argument) {
                i++;                     /* skip the separate argument */
            }
            continue;
        }

        for (const char *p = arg + 1; *p != '\0'; p++) {   /* short cluster */
            if (*p == 'c') {
                if (p[1] != '\0') {
                    found = p + 1;
                } else if (i + 1 < argc) {
                    found = argv[++i];
                }
                break;
            }
            if (strchr(SHORT_OPTS_WITH_ARG, *p) != NULL) {
                if (p[1] == '\0') {
                    i++;                 /* argument is the next element */
                }
                break;
            }
        }
    }
    return found;
}

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

    while ((opt = getopt_long(argc, argv, "t:i:b:haVsqjTCx:y:z:c:vF:d",
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

        case 'd':
            opts->duration_seconds = parse_bounded_int_arg(optarg, LONG_MAX,
                "--duration must be a positive number of seconds", prog_name);
            break;

        case 'x':
        case 'y':
        case 'z':
            parse_classify_arg(opt, optarg, opts, prog_name);
            break;

        case 'j':
        case 'J':
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
    opts->flows_seconds   = 0;
    opts->duration_seconds = 0;
    opts->config_path     = NULL;

    /* Environment variables (lowest priority — CLI flags override these).
     * parse_options() re-applies them once the config files have loaded,
     * so the net order stays defaults < config < environment < CLI. */
    parse_apply_env(opts);
}

int parse_options(int argc, char *argv[], cli_options_t *opts) {
    int subcmd = 0;   /* 0 = none, SUBCMD_ANALYZE, SUBCMD_CAPTURE */
    int has_input = 0;
    const char *prog_name = argv[0];  /* Save before argv shift */
    int early;

    /* Initialize options to defaults */
    parse_init(opts);

    /* One precedence rule for both config files (issue #96): pre-scan for
     * -c/--config, load ~/.mmtreader.conf and then that file, re-apply the
     * environment, and only then run the option loop — so the CLI flags
     * are written last and win. */
    opts->config_path = parse_prescan_config_path(argc, argv);
    parse_load_config_files(opts);

    early = parse_dispatch_subcommand(&argc, &argv, opts, prog_name, &subcmd);
    if (early != PARSE_CONTINUE) {
        return early;
    }

    early = parse_option_loop(argc, argv, opts, subcmd, prog_name, &has_input);
    if (early != PARSE_CONTINUE) {
        return early;
    }

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
