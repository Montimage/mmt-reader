/**
 * mmtReader.c — MMT-READER CLI entry point
 *
 * Thin main: banner → parse → engine init → dispatch → cleanup
 *
 * Core DPI logic (handler init, packet processing, statistics)
 * is encapsulated in core/engine.h.
 * Argument parsing and subcommand dispatch are in cli/parse.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include "core/engine.h"
#include "utils/version.h"
#include "utils/colors.h"
#include "cli/parse.h"
#include "capture.h"

static volatile sig_atomic_t got_signal = 0;

/* ------------------------------------------------------------------ */
/* Signal handler                                                      */
/* ------------------------------------------------------------------ */

static void signal_handler(int type) {
    /* Use async-signal-safe write() — printf is not signal-safe */
    ssize_t ret;
    const char msg[] = "\nINFO: reception of signal ";
    ret = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)ret;
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "%d\n", type);
    if (len > 0 && (size_t)len < sizeof(buf)) {
        ret = write(STDERR_FILENO, buf, (size_t)len);
        (void)ret;
    }
    got_signal = 1;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    cli_options_t opts;

    /* Initialize color support (respects NO_COLOR env var) */
    colors_init();
    /* Parse options (may exit on --version or --help) */
    int rc = parse_options(argc, argv, &opts);
    if (rc != PARSE_EXIT_OK) {
        return EXIT_FAILURE;
    }

    /* Override color support if --no-color was passed */
    if (opts.no_color) {
        colors_set_enabled(0);
    }
    /* If --version was requested, print banner + version and exit */
    if (opts.mode == 3) {
        version_banner(argv[0]);
        version_print();
        return EXIT_SUCCESS;
    }

    /* If --help was shown, skip the rest */
    if (opts.show_help) {
        return EXIT_SUCCESS;
    }

    /* Banner (after --version/--help check)
     * Redirect to stderr for JSON output to keep stdout clean */
    if (opts.output_format == OUTPUT_FORMAT_JSON) {
        version_banner_fd(argv[0], stderr);
    } else {
        version_banner(argv[0]);
    }

    /* Verbose: print startup diagnostics to stderr */
    if (opts.verbose) {
        fprintf(stderr, "DEBUG: verbose mode enabled\n");
        fprintf(stderr, "DEBUG: json output=%d, quiet=%d, no_color=%d\n",
                opts.json, opts.quiet, opts.no_color);
    }

    /* Create engine */
    char mmt_errbuf[1024];
    engine_t *eng = engine_create(DLT_EN10MB, 0, mmt_errbuf);
    if (!eng) {
        fprintf(stderr, "[error] Failed to create MMT engine\n");
        return EXIT_FAILURE;
    }

    /* Configure classification */
    engine_set_ip_classify(eng, opts.ip_classify);
    engine_set_hostname_classify(eng, opts.hostname_classify);
    engine_set_port_classify(eng, opts.port_classify);

    /* Enable per-protocol-path detail if requested */
    engine_set_proto_path_detail(eng, opts.proto_path);

    /* Set output format and session display options */
    engine_set_output_format(eng, (output_format_t)opts.output_format);
    engine_set_show_sessions(eng, opts.show_sessions);

    /* Set up signal handling */
    signal(SIGINT, signal_handler);

    /* Dispatch based on mode */
    if (opts.mode == 1) {
        /* OFFLINE mode: read from pcap file */
        struct pcap_pkthdr p_pkthdr;
        const u_char *data;
        struct pkthdr header;

        pcap_t *pcap = pcap_open_offline(opts.input, mmt_errbuf);
        if (!pcap) {
            fprintf(stderr, "[error] pcap_open failed: %s\n", mmt_errbuf);
            engine_destroy(eng);
            return EXIT_FAILURE;
        }

        {
            int pkt_count = 0;
            while ((data = pcap_next(pcap, &p_pkthdr)) != NULL && !got_signal) {
                pkt_count++;
                if (opts.verbose) {
                    fprintf(stderr, "DEBUG: processing packet #%d (%d bytes)\n",
                            pkt_count, (int)p_pkthdr.caplen);
                }
                header.ts = p_pkthdr.ts;
                header.caplen = p_pkthdr.caplen;
                header.len = p_pkthdr.len;
                if (!engine_process_packet(eng, &header, data)) {
                    fprintf(stderr, "Packet data extraction failure.\n");
                }
            }
            if (opts.verbose) {
                fprintf(stderr, "DEBUG: processed %d packets\n", pkt_count);
            }
        }
        pcap_close(pcap);

    } else if (opts.mode == 2) {
        /* ONLINE mode: live capture from interface */
        pcap_t *pcap;

        if (!opts.quiet) {
            if (opts.buffer_mb == 50) {
                fprintf(stderr, "INFO: Use default buffer size: 50 (MB)\n");
            } else {
                fprintf(stderr, "INFO: Use buffer size: %d (MB)\n", opts.buffer_mb);
            }
        }

        if (opts.verbose) {
            fprintf(stderr, "DEBUG: capturing on interface '%s'\n", opts.input);
            fprintf(stderr, "DEBUG: buffer size %d MB\n", opts.buffer_mb);
        }

        pcap = capture_init(opts.input, (uint16_t)opts.buffer_mb, 65535);
        if (!pcap) {
            fprintf(stderr, "[error] Creating pcap handle failed\n");
            engine_destroy(eng);
            return EXIT_FAILURE;
        }

        (void)pcap_loop(pcap, -1, engine_live_callback, (u_char *)eng);
        pcap_close(pcap);

        /* Print final statistics before exit */
        if (!opts.quiet) {
            fprintf(stderr, "\nINFO: Capture stopped by user signal\n");
            engine_print_stats(eng);
        }

    } else {
        /* Should not reach here — parse_options validates input */
        parse_error(argv[0]);
    }

    /* Verbose: print summary diagnostics */
    if (opts.verbose) {
        fprintf(stderr, "DEBUG: processing complete\n");
    }

    /* Cleanup */
    engine_destroy(eng);

    return EXIT_SUCCESS;
}
