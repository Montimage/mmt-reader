/**
 * colors.h — ANSI color support for MMT-READER output
 *
 * Provides color helper functions and constants for formatted terminal
 * output. Colors are automatically disabled when the NO_COLOR environment
 * variable is set, or when --no-color is passed on the command line.
 *
 * Usage:
 *   #include "colors.h"
 *   colors_init();          /* Call once at startup *\/
 *   printf(colors_green("OK"));
 *   printf(colors_reset());
 */
#ifndef COLORS_H
#define COLORS_H

#include <stdio.h>

/* ------------------------------------------------------------------ */
/* ANSI color codes                                                    */
/* ------------------------------------------------------------------ */

#define COLOR_RESET      "\033[0m"
#define COLOR_BOLD       "\033[1m"
#define COLOR_BOLD_GREEN   "\033[1;32m"
#define COLOR_DIM        "\033[2m"

#define COLOR_BLACK      "\033[30m"
#define COLOR_RED        "\033[31m"
#define COLOR_GREEN      "\033[32m"
#define COLOR_YELLOW     "\033[33m"
#define COLOR_BLUE       "\033[34m"
#define COLOR_MAGENTA    "\033[35m"
#define COLOR_CYAN       "\033[36m"
#define COLOR_WHITE      "\033[37m"

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
 * Check if colors are currently enabled.
 * @return 1 if colors are enabled, 0 if disabled.
 */
int colors_enabled(void);

/**
 * Wrap a string with a color code (if colors are enabled).
 *
 * @param color  ANSI color code (e.g., COLOR_GREEN)
 * @param str    String to colorize
 * @return       Colorized string (or original if colors disabled)
 */
const char *colors_wrap(const char *color, const char *str);

/**
 * Convenience: wrap string in green.
 */
const char *colors_green(const char *str);

/**
 * Convenience: wrap string in red.
 */
const char *colors_red(const char *str);

/**
 * Convenience: wrap string in yellow.
 */
const char *colors_yellow(const char *str);

/**
 * Convenience: wrap string in bold green.
 */
const char *colors_bold_green(const char *str);

/**
 * Convenience: wrap string in bold yellow.
 */
const char *colors_bold_yellow(const char *str);

/**
 * Convenience: wrap string in cyan.
 */
const char *colors_cyan(const char *str);

/**
 * Reset color to default.
 */
const char *colors_reset(void);

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

/**
 * Print a colored string to stdout.
 *
 * @param color  ANSI color code
 * @param str    String to print
 */
void colors_print(const char *color, const char *str);

#endif /* COLORS_H */
