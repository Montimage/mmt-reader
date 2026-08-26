/**
 * config.h — Config file support for MMT-READER
 *
 * Parses an INI-style configuration file (e.g., ~/.mmtreader.conf)
 * and provides defaults that can be overridden by CLI flags.
 *
 * Config file format (INI-style):
 *   [analyze]
 *   json = 1
 *   quiet = 0
 *   verbose = 0
 *   no_color = 0
 *   buffer = 50
 *   proto_path = 0
 *   sessions = 0
 *
 *   [capture]
 *   json = 0
 *   quiet = 1
 *   verbose = 0
 *   buffer = 100
 *
 * Sections are command-specific; options not in a section apply globally.
 * CLI flags always override config file values.
 */
#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>

#define CONFIG_MAX_PATH 512
#define CONFIG_MAX_LINE 256

/* Config file sections */
typedef enum {
    CONFIG_SECTION_GLOBAL = 0,
    CONFIG_SECTION_ANALYZE,
    CONFIG_SECTION_CAPTURE,
    CONFIG_SECTION_COUNT
} config_section_t;

/**
 * Parsed configuration values from a config file.
 *
 * All fields default to 0 (false) or 0 (numeric) when not specified
 * in the config file. The caller merges these with CLI defaults,
 * then applies CLI flags on top (CLI always wins).
 */
typedef struct {
    /* Global defaults */
    int     json;           /**< --json / JSON output         */
    int     quiet;          /**< --quiet / quiet mode         */
    int     verbose;        /**< --verbose / verbose mode     */
    int     no_color;       /**< --no-color / disable colors  */
    int     ip_classify;    /**< --ip-classify (default: 1)   */
    int     hostname_classify; /**< --hostname-classify (1)  */
    int     port_classify;    /**< --port-classify (1)      */

    /* Per-section overrides */
    int     buffer[CONFIG_SECTION_COUNT]; /**< buffer size per section */
    int     proto_path[CONFIG_SECTION_COUNT]; /**< proto-path flag */
    int     sessions[CONFIG_SECTION_COUNT];   /**< sessions flag */
    int     output_format[CONFIG_SECTION_COUNT]; /**< 0=text, 1=json */

    /* Source tracking */
    char    path[CONFIG_MAX_PATH]; /**< path to loaded config file */
    int     loaded;          /**< 1 if file was successfully loaded */
} config_t;

/**
 * Initialize all config_t fields to their default values.
 * @param cfg  Pointer to uninitialized config_t
 */
void config_init(config_t *cfg);

/**
 * Load and parse an INI-style config file.
 *
 * The config file uses sections like [analyze], [capture], and a
 * global section (options before any section header). CLI flags
 * always override config file values.
 *
 * If the file does not exist or cannot be read, cfg->loaded remains 0
 * and no error is printed (config loading is optional).
 *
 * @param cfg      Pointer to config_t to fill
 * @param path     Path to config file (NULL uses default ~/.mmtreader.conf)
 * @return 0 on success (file loaded), 1 if file not found/skipped (cfg->loaded = 0)
 */
int config_load(config_t *cfg, const char *path);

/**
 * Print the loaded config values to stdout (for debugging).
 * @param cfg  Pointer to loaded config_t
 */
void config_dump(const config_t *cfg);

#endif /* CONFIG_H */
