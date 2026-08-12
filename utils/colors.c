/**
 * colors.c — ANSI color support for MMT-READER output
 *
 * Provides color helper functions with automatic disabling when
 * the NO_COLOR environment variable is set or --no-color is passed.
 *
 * Color conventions:
 *   - Green: success, protocol names
 *   - Yellow: headers, important labels
 *   - Red: errors, warnings
 *   - Cyan: informational text
 *   - Bold: section headers
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "colors.h"

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

static int color_enabled = 1;  /* Default: colors enabled */

/* ------------------------------------------------------------------ */
/* Internal buffer for colorized strings                               */
/* ------------------------------------------------------------------ */

/*
 * Thread-local buffer for colorized string results.
 * In a multi-threaded app, each thread would need its own buffer.
 * For this single-threaded CLI tool, one static buffer is sufficient.
 */
static char color_buf[1024];

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

int colors_enabled(void) {
    return color_enabled;
}

const char *colors_wrap(const char *color, const char *str) {
    if (!color_enabled || color == NULL || str == NULL) {
        return (char *)str;
    }

    int color_len = (int)strlen(color);
    int str_len   = (int)strlen(str);
    int reset_len = (int)strlen(COLOR_RESET);

    if (color_len + str_len + reset_len >= (int)sizeof(color_buf)) {
        /* Buffer overflow — return plain string */
        return (char *)str;
    }

    memcpy(color_buf, color, (size_t)color_len);
    memcpy(color_buf + color_len, str, (size_t)str_len);
    memcpy(color_buf + color_len + str_len, COLOR_RESET, (size_t)reset_len);
    color_buf[color_len + str_len + reset_len] = '\0';

    return color_buf;
}

const char *colors_green(const char *str) {
    return colors_wrap(COLOR_GREEN, str);
}

const char *colors_red(const char *str) {
    return colors_wrap(COLOR_RED, str);
}

const char *colors_yellow(const char *str) {
    return colors_wrap(COLOR_YELLOW, str);
}

const char *colors_bold_green(const char *str) {
    if (!color_enabled || str == NULL) {
        return (char *)str;
    }

    int bold_len = (int)strlen(COLOR_BOLD);
    int str_len  = (int)strlen(str);
    int reset_len = (int)strlen(COLOR_RESET);

    if (bold_len + str_len + reset_len >= (int)sizeof(color_buf)) {
        return (char *)str;
    }

    memcpy(color_buf, COLOR_BOLD, (size_t)bold_len);
    memcpy(color_buf + bold_len, str, (size_t)str_len);
    memcpy(color_buf + bold_len + str_len, COLOR_RESET, (size_t)reset_len);
    color_buf[bold_len + str_len + reset_len] = '\0';

    return color_buf;
}

const char *colors_bold_yellow(const char *str) {
    if (!color_enabled || str == NULL) {
        return (char *)str;
    }

    int bold_len = (int)strlen(COLOR_BOLD);
    int str_len  = (int)strlen(str);
    int reset_len = (int)strlen(COLOR_RESET);

    if (bold_len + str_len + reset_len >= (int)sizeof(color_buf)) {
        return (char *)str;
    }

    memcpy(color_buf, COLOR_BOLD, (size_t)bold_len);
    memcpy(color_buf + bold_len, str, (size_t)str_len);
    memcpy(color_buf + bold_len + str_len, COLOR_RESET, (size_t)reset_len);
    color_buf[bold_len + str_len + reset_len] = '\0';

    return color_buf;
}

const char *colors_cyan(const char *str) {
    return colors_wrap(COLOR_CYAN, str);
}

const char *colors_reset(void) {
    if (!color_enabled) {
        return "";
    }
    return COLOR_RESET;
}

void colors_fprintf(FILE *fp, const char *color, const char *str) {
    if (fp == NULL) return;

    if (!color_enabled || color == NULL) {
        fprintf(fp, "%s", str);
    } else {
        fprintf(fp, "%s%s%s", color, str, COLOR_RESET);
    }
}

void colors_print(const char *color, const char *str) {
    colors_fprintf(stdout, color, str);
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
