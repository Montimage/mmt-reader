/**
 * colors.h — ANSI color support for MMT-READER output
 *
 * Provides color helper functions and constants for formatted terminal
 * output. Colors are automatically disabled when the NO_COLOR environment
 * variable is set, or when --no-color is passed on the command line.
 *
 * Usage:
 *   #include "colors.h"
 *   colors_init();          Call once at startup
 *   colors_set_enabled(0);  Optional override (--no-color)
 *   colors_fprintf(stdout, COLOR_BOLD_GREEN, "OK");
 */
#ifndef COLORS_H
#define COLORS_H

#include <stdio.h>

/* ------------------------------------------------------------------ */
/* ANSI color codes used by the output layer                           */
/* ------------------------------------------------------------------ */

#define COLOR_RESET      "\033[0m"
#define COLOR_BOLD       "\033[1m"
#define COLOR_BOLD_GREEN "\033[1;32m"
#define COLOR_CYAN       "\033[36m"

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * Initialize color support.
 *
 * Checks the NO_COLOR environment variable and sets the global
 * color_enabled flag accordingly. Must be called before any
 * color output functions are used.
 */
void colors_init(void);

/**
 * Override the color_enabled flag.
 *
 * Call this after colors_init() to disable colors based on
 * the --no-color command-line flag.
 *
 * @param enabled  1 to enable colors, 0 to disable.
 */
void colors_set_enabled(int enabled);

/**
 * Print a colored string to a file descriptor.
 *
 * @param fp     File descriptor (e.g., stdout)
 * @param color  ANSI color code
 * @param str    String to print
 */
void colors_fprintf(FILE *fp, const char *color, const char *str);

/**
 * Print a colored formatted string to a file descriptor.
 *
 * @param fp     File descriptor (e.g., stdout)
 * @param color  ANSI color code
 * @param fmt    Format string (printf-style)
 * @param ...    Format arguments
 */
void colors_fprintf_fmt(FILE *fp, const char *color, const char *fmt, ...);

#endif /* COLORS_H */
