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
/* Product version                                                     */
/* ------------------------------------------------------------------ */

/* mmtReader's own release version, injected by the Makefile via
 * -DMMTREADER_VERSION='"x.y.z"'. The fallback keeps ad-hoc compiles
 * (hand-run unit tests, IDE indexers) building without the define. */
#ifndef MMTREADER_VERSION
#define MMTREADER_VERSION "0.0.0-dev"
#endif

/* ------------------------------------------------------------------ */
/* Internal: banner format                                             */
/* ------------------------------------------------------------------ */

#define BANNER_LINE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n"

static void banner_print(const char *prog_name, FILE *fp) {
    fprintf(fp, BANNER_LINE);
    fprintf(fp, "|\t\t MONTIMAGE\n");
    fprintf(fp, "|\t mmtReader version: %s\n", MMTREADER_VERSION);
    fprintf(fp, "|\t MMT-DPI SDK version: %s\n", mmt_version());
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
    printf("mmtReader version: %s\n", MMTREADER_VERSION);
    printf("MMT-DPI SDK version: %s\n", mmt_version());
    printf("built %s %s\n", __DATE__, __TIME__);
    exit(0);
}

const char *product_version(void) {
    return MMTREADER_VERSION;
}

const char *version(void) {
    return mmt_version();
}
