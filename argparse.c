/**
 * argparse.c — Argument parsing implementation
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "argparse.h"

static void usage(const char *prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-b <value>     : Set buffer for pcap handler (MB)\n");
    fprintf(stderr, "\t-a             : Show protocol statistic for each protocol path.\n");
    fprintf(stderr, "\t-x <0|1>       : Enable/disable IP address classification\n");
    fprintf(stderr, "\t-y <0|1>       : Enable/disable hostname classification\n");
    fprintf(stderr, "\t-z <0|1>       : Enable/disable port classification\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

int mmt_parse_args(int argc, char **argv, mmt_config_t *cfg) {
    int opt;

    /* Defaults */
    cfg->source_type = -1;
    cfg->source[0] = '\0';
    cfg->buffer_size = 0;
    cfg->proto_path_detail = 1;
    cfg->ip_address_classify = 1;
    cfg->hostname_classify = 1;
    cfg->port_classify = 1;

    while ((opt = getopt(argc, argv, "t:i:b:x:y:z:ha")) != EOF) {
        switch (opt) {
            case 't':
                strncpy(cfg->source, optarg, MAX_FILENAME_SIZE);
                cfg->source[MAX_FILENAME_SIZE] = '\0';
                cfg->source_type = TRACE_FILE;
                break;
            case 'i':
                strncpy(cfg->source, optarg, MAX_FILENAME_SIZE);
                cfg->source[MAX_FILENAME_SIZE] = '\0';
                cfg->source_type = LIVE_INTERFACE;
                break;
            case 'b':
                cfg->buffer_size = atoi(optarg);
                break;
            case 'a':
                cfg->proto_path_detail = 1;
                break;
            case 'x':
                cfg->ip_address_classify = atoi(optarg);
                break;
            case 'y':
                cfg->hostname_classify = atoi(optarg);
                break;
            case 'z':
                cfg->port_classify = atoi(optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
                break;
        }
    }

    if (cfg->source_type == TRACE_FILE && cfg->source[0] == '\0') {
        fprintf(stderr, "Missing trace file name\n");
        usage(argv[0]);
    }
    if (cfg->source_type == LIVE_INTERFACE && cfg->source[0] == '\0') {
        fprintf(stderr, "Missing network interface name\n");
        usage(argv[0]);
    }
    if (cfg->source_type == -1) {
        fprintf(stderr, "No source specified (-t file or -i interface)\n");
        usage(argv[0]);
    }

    return 0;
}
