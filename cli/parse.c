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
#include <getopt.h>
#include <unistd.h>
#include "parse.h"

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
"  -b, --buffer <MB>        PCAP buffer size in MB (default: 50)\n"
"  -a, --proto-path         Show per-protocol-path statistics\n"
"  -C, --no-color           Disable ANSI color output\n"
"  -h, --help               Show this help message\n"
"  -V, --version            Print version information\n"
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
"  -b, --buffer <MB>        PCAP buffer size in MB (default: 50)\n"
"  -a, --proto-path         Show per-protocol-path statistics\n"
"  -C, --no-color           Disable ANSI color output\n"
"  -h, --help               Show this help message\n"
"  -V, --version            Print version information\n"
"\n"
"Hidden flags:\n"
"  -x, --ip-classify <0|1>  IP address classification (default: 1)\n"
"  -y, --hostname-classify <0|1>  Hostname classification (default: 1)\n"
"  -z, --port-classify <0|1>    Port number classification (default: 1)\n"
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
"  -h, --help       Show this help message\n"
"  -V, --version    Print version information\n"
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
/* getopt_long setup                                                   */
/* ------------------------------------------------------------------ */

static const struct option long_options[] = {
    { "trace",       required_argument, NULL, 't' },
    { "interface",   required_argument, NULL, 'i' },
    { "buffer",      required_argument, NULL, 'b' },
    { "proto-path",  no_argument,       NULL, 'a' },
    { "ip-classify", required_argument, NULL, 'x' },
    { "hostname-classify", required_argument, NULL, 'y' },
    { "port-classify", required_argument, NULL, 'z' },
    { "help",        no_argument,       NULL, 'h' },
    { "version",     no_argument,       NULL, 'V' },
    { "no-color",    no_argument,       NULL, 'C' },
    { NULL, 0, NULL, 0 }
};

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void parse_init(cli_options_t *opts) {
    opts->input         = NULL;
    opts->mode          = 0;
    opts->buffer_mb     = 50;
    opts->proto_path    = 0;
    opts->ip_classify   = 1;
    opts->hostname_classify = 1;
    opts->port_classify   = 1;
    opts->show_help       = 0;
    opts->no_color        = 0;
}

int parse_options(int argc, char *argv[], cli_options_t *opts) {
    int opt;
    int subcmd = 0;   /* 0 = none, SUBCMD_ANALYZE, SUBCMD_CAPTURE */
    int has_input = 0;
    const char *prog_name = argv[0];  /* Save before argv shift */

    /* Initialize options to defaults */
    parse_init(opts);

    /* Determine subcommand from first non-option argument */
    if (argc > 1) {
        if (strcmp(argv[1], "analyze") == 0) {
            subcmd = SUBCMD_ANALYZE;
            /* Shift argv to skip the subcommand for getopt */
            argc--;
            argv++;
        } else if (strcmp(argv[1], "capture") == 0) {
            subcmd = SUBCMD_CAPTURE;
            argc--;
            argv++;
        }
    }

    /* If no subcommand, check for global options (--help, --version)
     * then show general help if neither is found. */
    if (subcmd == 0) {
        /* Check for global options at argv[1] (no subcommand prefix) */
        if (argc > 1) {
            if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
                opts->show_help = 1;
                fprintf(stdout, general_help, prog_name, prog_name);
                return PARSE_EXIT_OK;
            }
            if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
                opts->mode = 3; /* VERSION */
                return PARSE_EXIT_OK;
            }
        }
        /* No subcommand and no global option — show general help */
        opts->show_help = 1;
        fprintf(stdout, general_help, prog_name, prog_name);
        return PARSE_EXIT_OK;
    }

    /* Reset getopt state after argv shift */
    optind = 1;

    while ((opt = getopt_long(argc, argv, "t:i:b:x:y:z:haVC",
                              long_options, NULL)) != EOF) {
        switch (opt) {
        case 't':
            if (subcmd == SUBCMD_CAPTURE) {
                fprintf(stderr, "Error: -t/--trace is for 'analyze' only\n");
                parse_error(prog_name);
            }
            if (strlen(optarg) >= MAX_FILENAME_SIZE) {
                fprintf(stderr, "Error: trace file path too long\n");
                parse_error(prog_name);
            }
            opts->input = optarg;
            opts->mode  = 1; /* TRACE_FILE */
            has_input   = 1;
            break;

        case 'i':
            if (subcmd == SUBCMD_ANALYZE) {
                fprintf(stderr, "Error: -i/--interface is for 'capture' only\n");
                parse_error(prog_name);
            }
            if (strlen(optarg) >= MAX_FILENAME_SIZE) {
                fprintf(stderr, "Error: interface name too long\n");
                parse_error(prog_name);
            }
            opts->input = optarg;
            opts->mode  = 2; /* LIVE_INTERFACE */
            has_input   = 1;
            break;

        case 'b': {
            long val = strtol(optarg, NULL, 10);
            if (val <= 0 || val > 10000) {
                fprintf(stderr, "Error: buffer size must be a positive integer (1-10000)\n");
                parse_error(prog_name);
            }
            opts->buffer_mb = (int)val;
            break;
        }

        case 'a':
            opts->proto_path = 1;
            break;

        case 'x': {
            int val = atoi(optarg);
            if (val != 0 && val != 1) {
                fprintf(stderr, "Error: --ip-classify must be 0 or 1\n");
                parse_error(prog_name);
            }
            opts->ip_classify = val;
            break;
        }

        case 'y': {
            int val = atoi(optarg);
            if (val != 0 && val != 1) {
                fprintf(stderr, "Error: --hostname-classify must be 0 or 1\n");
                parse_error(prog_name);
            }
            opts->hostname_classify = val;
            break;
        }

        case 'z': {
            int val = atoi(optarg);
            if (val != 0 && val != 1) {
                fprintf(stderr, "Error: --port-classify must be 0 or 1\n");
                parse_error(prog_name);
            }
            opts->port_classify = val;
            break;
        }

        case 'V':
            /* Delegate to version module — caller handles exit */
            opts->mode = 3; /* VERSION */
            return PARSE_EXIT_OK;

        case 'C':
            opts->no_color = 1;
            break;

        case 'h':
            opts->show_help = 1;
            if (subcmd == SUBCMD_ANALYZE) {
                fprintf(stdout, analyze_help, prog_name);
            } else if (subcmd == SUBCMD_CAPTURE) {
                fprintf(stdout, capture_help, prog_name);
            }
            return PARSE_EXIT_OK;

        default:
            parse_error(prog_name);
            break;
        }
    }

    /* Validate: input is required for both subcommands */
    if (!has_input) {
        fprintf(stderr, "Error: missing required option\n");
        if (subcmd == SUBCMD_ANALYZE) {
            fprintf(stderr, "Use --help for usage information\n");
        }
        parse_error(prog_name);
    }

    return PARSE_EXIT_OK;
}

void parse_help(const char *prog_name) {
    fprintf(stdout, general_help, prog_name, prog_name);
}

void parse_error(const char *prog_name) {
    fprintf(stderr, "Use \"%s --help\" for usage information\n", prog_name);
    exit(PARSE_EXIT_ERROR);
}
