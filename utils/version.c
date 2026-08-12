/**
 * version.c — Version string handling and --version output
 *
 * Extracted from mmtReader.c to provide a clean separation for
 * version display. Supports both the full banner (on startup)
 * and a concise --version flag output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "version.h"
#include "core/engine.h"

/* ------------------------------------------------------------------ */
/* Internal: banner format                                             */
/* ------------------------------------------------------------------ */

#define BANNER_LINE "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n"

static void banner_print(const char *prog_name) {
    printf(BANNER_LINE);
    printf("|\t\t MONTIMAGE\n");
    printf("|\t MMT-SDK version: %s\n", mmt_version());
    printf("|\t %s: built %s %s\n", prog_name, __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf(BANNER_LINE);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void version_banner(const char *prog_name) {
    banner_print(prog_name);
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
