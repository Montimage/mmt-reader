/**
 * argparse.h — Argument parsing for mmtReader
 *
 * Parses command-line options and returns a validated config struct.
 */
#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <stdint.h>

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2

/* Parsed configuration from command-line arguments */
typedef struct {
    int source_type;        /* TRACE_FILE or LIVE_INTERFACE */
    char source[MAX_FILENAME_SIZE + 1];
    int buffer_size;        /* pcap buffer in MB (0 = default) */
    int proto_path_detail;  /* -a: show protocol path */
    int ip_address_classify;
    int hostname_classify;
    int port_classify;
} mmt_config_t;

/**
 * Parse command-line arguments into a config struct.
 * @param argc  argument count
 * @param argv  argument vector
 * @param cfg   output config (filled on success)
 * @return 0 on success, 1 on error (prints usage and exits)
 */
int mmt_parse_args(int argc, char **argv, mmt_config_t *cfg);

#endif /* ARGPARSE_H */
