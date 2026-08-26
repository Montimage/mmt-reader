/**
 * colors.c — ANSI color support for MMT-READER output
 *
 * Provides color helper functions with automatic disabling when
 * the NO_COLOR environment variable is set or --no-color is passed.
 *
 * Color conventions:
 *   - Bold: section headers, important labels
 *   - Cyan: informational text
 *   - Bold green: emphasized input statistics
 *
 * Callers pass an ANSI code (COLOR_* macros) to colors_fprintf()
 * or colors_fprintf_fmt(); there are no per-color convenience
 * wrappers (#65).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "colors.h"

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

static int color_enabled = 1;  /* Default: colors enabled */

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void colors_init(void) {
    /*
     * Respect the NO_COLOR environment variable.
     * Per https://no-color.org/, if NO_COLOR is set (regardless of value),
     * color output should be disabled.
     */
    const char *no_color = getenv("NO_COLOR");
    if (no_color != NULL && no_color[0] != '\0') {
        color_enabled = 0;
    }
}

void colors_set_enabled(int enabled) {
    color_enabled = enabled;
}

void colors_fprintf(FILE *fp, const char *color, const char *str) {
    if (fp == NULL) return;

    if (!color_enabled || color == NULL) {
        fprintf(fp, "%s", str);
    } else {
        fprintf(fp, "%s%s%s", color, str, COLOR_RESET);
    }
}

void colors_fprintf_fmt(FILE *fp, const char *color, const char *fmt, ...) {
    if (fp == NULL || fmt == NULL) return;

    va_list args;
    va_start(args, fmt);

    if (!color_enabled || color == NULL) {
        vfprintf(fp, fmt, args);
    } else {
        fprintf(fp, "%s", color);
        vfprintf(fp, fmt, args);
        fprintf(fp, "%s", COLOR_RESET);
    }

    va_end(args);
}
