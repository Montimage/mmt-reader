/**
 * version.c — Version string handling and --version output
 *
 * Extracted from mmtReader.c to provide a clean separation for
 * version display. Supports both the full banner (on startup)
 * and a concise --version flag output.
 */
#include <stdio.h>
#include <stdlib.h>
#include "version.h"
#include "mmt_core.h"

/* ------------------------------------------------------------------ */
/* Internal: banner format                                             */
/* ------------------------------------------------------------------ */

#define BANNER_LINE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n"

static void banner_print(const char *prog_name, FILE *fp) {
    fprintf(fp, BANNER_LINE);
    fprintf(fp, "|\t\t MONTIMAGE\n");
    fprintf(fp, "|\t MMT-SDK version: %s\n", mmt_version());
    fprintf(fp, "|\t %s: built %s %s\n", prog_name, __DATE__, __TIME__);
    fprintf(fp, "|\t http://montimage.com\n");
    fprintf(fp, BANNER_LINE);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void version_banner(const char *prog_name) {
    banner_print(prog_name, stdout);
}

void version_banner_fd(const char *prog_name, FILE *fp) {
    banner_print(prog_name, fp);
}

void version_print(void) {
    printf("mmtReader version %s\n", mmt_version());
    printf("built %s %s\n", __DATE__, __TIME__);
    printf("MMT-DPI version: %s\n", mmt_version());
    exit(0);
}

const char *version(void) {
    return mmt_version();
}
