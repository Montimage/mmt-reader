/**
 * mmtReader.c — Main entry point
 *
 * Thin main: parse → dispatch → cleanup.
 * All logic is delegated to separate modules:
 *   argparse.c  — argument parsing
 *   dispatch.c  — command dispatch (analyze/capture)
 *   capture.c   — PCAP capture operations
 *   mmt_handler.c — MMT handler setup and packet processing
 *   display.c   — output and statistics
 */
#include <stdio.h>
#include <stdlib.h>
#include "argparse.h"
#include "dispatch.h"
#include "mmt_handler.h"

int main(int argc, char **argv) {
    mmt_config_t cfg;

    /* Print banner */
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("|\t\t MONTIMAGE\n");
    printf("|\t MMT-SDK version: %s\n", mmt_version());
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");

    /* Parse arguments */
    if (mmt_parse_args(argc, argv, &cfg) != 0) {
        return EXIT_FAILURE;
    }

    /* Dispatch to command handler */
    int rc = dispatch(&cfg);

    /* Clean up */
    mmt_cleanup();

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
