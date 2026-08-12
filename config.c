/**
 * config.c — Config file support for MMT-READER
 *
 * Parses an INI-style configuration file and provides defaults
 * that can be overridden by CLI flags.
 *
 * Config file format:
 *   ; comment lines start with ; or #
 *   [section]  — section header
 *   key = value  — key-value pair (values: 0/1 for bool, integer for numeric)
 *
 * Sections: [global], [analyze], [capture]
 * Options before any section header apply to all sections.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include "config.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static int parse_bool(const char *val) {
    val = trim((char *)val);
    if (strcmp(val, "1") == 0 || strcmp(val, "true") == 0 ||
        strcmp(val, "yes") == 0 || strcmp(val, "on") == 0) {
        return 1;
    }
    if (strcmp(val, "0") == 0 || strcmp(val, "false") == 0 ||
        strcmp(val, "no") == 0 || strcmp(val, "off") == 0) {
        return 0;
    }
    /* Try integer conversion */
    int ival = atoi(val);
    return (ival != 0) ? 1 : 0;
}

static int parse_int(const char *val) {
    val = trim((char *)val);
    return atoi(val);
}

/* Map section name string to enum */
static config_section_t section_from_name(const char *name) {
    if (strcmp(name, "global") == 0) return CONFIG_SECTION_GLOBAL;
    if (strcmp(name, "analyze") == 0) return CONFIG_SECTION_ANALYZE;
    if (strcmp(name, "capture") == 0) return CONFIG_SECTION_CAPTURE;
    return CONFIG_SECTION_GLOBAL; /* default to global */
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void config_init(config_t *cfg) {
    memset(cfg, 0, sizeof(config_t));
    cfg->ip_classify = 1;
    cfg->hostname_classify = 1;
    cfg->port_classify = 1;
    cfg->loaded = 0;
    cfg->path[0] = '\0';
}

int config_load(config_t *cfg, const char *path) {
    char resolved_path[CONFIG_MAX_PATH];
    FILE *fp;

    /* Determine path: use provided path or default ~/.mmtreader.conf */
    if (path != NULL && path[0] != '\0') {
        strncpy(resolved_path, path, CONFIG_MAX_PATH - 1);
        resolved_path[CONFIG_MAX_PATH - 1] = '\0';
    } else {
        const char *home = getenv("HOME");
        if (home == NULL) {
            /* No HOME — skip config loading (optional feature) */
            cfg->loaded = 0;
            return 1;
        }
        int len = snprintf(resolved_path, CONFIG_MAX_PATH, "%s/.mmtreader.conf", home);
        if (len < 0 || len >= CONFIG_MAX_PATH) {
            cfg->loaded = 0;
            return 1;
        }
    }

    /* Check if file exists */
    struct stat st;
    if (stat(resolved_path, &st) != 0) {
        cfg->loaded = 0;
        cfg->path[0] = '\0';
        return 1; /* Not found — not an error */
    }

    /* Open and parse the file */
    fp = fopen(resolved_path, "r");
    if (fp == NULL) {
        cfg->loaded = 0;
        cfg->path[0] = '\0';
        return 1;
    }

    strncpy(cfg->path, resolved_path, CONFIG_MAX_PATH - 1);
    cfg->path[CONFIG_MAX_PATH - 1] = '\0';

    config_section_t current_section = CONFIG_SECTION_GLOBAL;
    char line[CONFIG_MAX_LINE];

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (trimmed[0] == '\0' || trimmed[0] == ';' || trimmed[0] == '#') {
            continue;
        }

        /* Section header */
        if (trimmed[0] == '[') {
            char *close = strchr(trimmed, ']');
            if (close) {
                *close = '\0';
                current_section = section_from_name(trimmed + 1);
            }
            continue;
        }

        /* Key = Value pair */
        char *eq = strchr(trimmed, '=');
        if (eq == NULL) continue;

        *eq = '\0';
        char *key = trim(trimmed);
        char *val = trim(eq + 1);

        /* Apply to appropriate section(s) */
        if (current_section == CONFIG_SECTION_GLOBAL) {
            /* Global options apply to all sections */
            if (strcmp(key, "json") == 0) {
                cfg->json = parse_bool(val);
            } else if (strcmp(key, "quiet") == 0) {
                cfg->quiet = parse_bool(val);
            } else if (strcmp(key, "verbose") == 0) {
                cfg->verbose = parse_bool(val);
            } else if (strcmp(key, "no_color") == 0 || strcmp(key, "no-color") == 0) {
                cfg->no_color = parse_bool(val);
            } else if (strcmp(key, "ip_classify") == 0 || strcmp(key, "ip-classify") == 0) {
                cfg->ip_classify = parse_int(val);
            } else if (strcmp(key, "hostname_classify") == 0 || strcmp(key, "hostname-classify") == 0) {
                cfg->hostname_classify = parse_int(val);
            } else if (strcmp(key, "port_classify") == 0 || strcmp(key, "port-classify") == 0) {
                cfg->port_classify = parse_int(val);
            } else if (strcmp(key, "buffer") == 0) {
                int buf_val = parse_int(val);
                if (buf_val > 0) {
                    for (int i = 0; i < CONFIG_SECTION_COUNT; i++) {
                        cfg->buffer[i] = buf_val;
                    }
                }
            } else if (strcmp(key, "proto_path") == 0 || strcmp(key, "proto-path") == 0) {
                int pp = parse_bool(val);
                for (int i = 0; i < CONFIG_SECTION_COUNT; i++) {
                    cfg->proto_path[i] = pp;
                }
            } else if (strcmp(key, "sessions") == 0) {
                int sess = parse_bool(val);
                for (int i = 0; i < CONFIG_SECTION_COUNT; i++) {
                    cfg->sessions[i] = sess;
                }
            } else if (strcmp(key, "output_format") == 0 || strcmp(key, "output-format") == 0) {
                int fmt = parse_int(val);
                for (int i = 0; i < CONFIG_SECTION_COUNT; i++) {
                    cfg->output_format[i] = fmt;
                }
            }
        } else {
            /* Section-specific options */
            int idx = current_section;
            if (strcmp(key, "json") == 0) {
                cfg->json = parse_bool(val); /* json is global but section can override */
            } else if (strcmp(key, "quiet") == 0) {
                cfg->quiet = parse_bool(val);
            } else if (strcmp(key, "verbose") == 0) {
                cfg->verbose = parse_bool(val);
            } else if (strcmp(key, "no_color") == 0 || strcmp(key, "no-color") == 0) {
                cfg->no_color = parse_bool(val);
            } else if (strcmp(key, "buffer") == 0) {
                int buf_val = parse_int(val);
                if (buf_val > 0 && idx < CONFIG_SECTION_COUNT) {
                    cfg->buffer[idx] = buf_val;
                }
            } else if (strcmp(key, "proto_path") == 0 || strcmp(key, "proto-path") == 0) {
                int pp = parse_bool(val);
                if (idx < CONFIG_SECTION_COUNT) {
                    cfg->proto_path[idx] = pp;
                }
            } else if (strcmp(key, "sessions") == 0) {
                int sess = parse_bool(val);
                if (idx < CONFIG_SECTION_COUNT) {
                    cfg->sessions[idx] = sess;
                }
            } else if (strcmp(key, "output_format") == 0 || strcmp(key, "output-format") == 0) {
                int fmt = parse_int(val);
                if (idx < CONFIG_SECTION_COUNT) {
                    cfg->output_format[idx] = fmt;
                }
            }
            /* Unknown keys are silently ignored */
        }
    }

    fclose(fp);
    cfg->loaded = 1;
    return 0;
}

void config_dump(const config_t *cfg) {
    printf("Config file: %s\n", cfg->loaded ? cfg->path : "(not loaded)");
    printf("  json=%d quiet=%d verbose=%d no_color=%d\n",
           cfg->json, cfg->quiet, cfg->verbose, cfg->no_color);
    printf("  ip_classify=%d hostname_classify=%d port_classify=%d\n",
           cfg->ip_classify, cfg->hostname_classify, cfg->port_classify);
    printf("  buffer[analyze]=%d buffer[capture]=%d\n",
           cfg->buffer[CONFIG_SECTION_ANALYZE], cfg->buffer[CONFIG_SECTION_CAPTURE]);
    printf("  proto_path[analyze]=%d proto_path[capture]=%d\n",
           cfg->proto_path[CONFIG_SECTION_ANALYZE], cfg->proto_path[CONFIG_SECTION_CAPTURE]);
    printf("  sessions[analyze]=%d sessions[capture]=%d\n",
           cfg->sessions[CONFIG_SECTION_ANALYZE], cfg->sessions[CONFIG_SECTION_CAPTURE]);
}
