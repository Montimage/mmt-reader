/**
 * test_parse.c — Unit tests for cli/parse.c
 *
 * Tests parse_init defaults, option parsing, and error handling.
 * Compile: gcc -g -o test_parse test_parse.c cli/parse.c -I./cli -I./utils
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "cli/parse.h"

#include "test_util.h"

/* ---- parse_init tests ---- */

static void test_parse_init_defaults(void) {
    cli_options_t opts;
    parse_init(&opts);

    ASSERT_PTR_EQ(NULL, opts.input, "input should be NULL");
    ASSERT_EQ(MODE_NONE, opts.mode, "mode should be MODE_NONE");
    ASSERT_EQ(50, opts.buffer_mb, "buffer_mb should be 50");
    ASSERT_EQ(0, opts.proto_path, "proto_path should be 0");
    ASSERT_EQ(1, opts.ip_classify, "ip_classify should be 1");
    ASSERT_EQ(1, opts.hostname_classify, "hostname_classify should be 1");
    ASSERT_EQ(1, opts.port_classify, "port_classify should be 1");
    ASSERT_EQ(0, opts.show_help, "show_help should be 0");
    ASSERT_EQ(0, opts.no_color, "no_color should be 0");
    ASSERT_EQ(0, opts.quiet, "quiet should be 0");
    ASSERT_EQ(0, opts.verbose, "verbose should be 0");
    ASSERT_EQ(OUTPUT_FORMAT_TEXT, opts.output_format, "output_format should be text");
}

/* ---- parse_options tests ---- */

static void test_parse_no_subcommand(void) {
    char *argv[] = { "mmtReader" };
    int argc = 1;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "no subcommand returns OK");
    ASSERT_EQ(1, opts.show_help, "no subcommand sets show_help");
}

static void test_help_flag(void) {
    char *argv[] = { "mmtReader", "--help" };
    int argc = 2;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "--help returns OK");
    ASSERT_EQ(1, opts.show_help, "--help sets show_help");
}

static void test_parse_version_flag(void) {
    char *argv[] = { "mmtReader", "--version" };
    int argc = 2;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "--version returns OK");
    ASSERT_EQ(MODE_VERSION, opts.mode, "--version sets mode=MODE_VERSION");
}

static void test_parse_analyze_with_trace(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap" };
    int argc = 4;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "analyze -t returns OK");
    ASSERT_EQ(MODE_TRACE_FILE, opts.mode, "analyze -t sets mode=MODE_TRACE_FILE");
    ASSERT_STR_EQ("test.pcap", opts.input, "analyze -t sets input");
}

static void test_parse_capture_with_interface(void) {
    char *argv[] = { "mmtReader", "capture", "-i", "eth0" };
    int argc = 4;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "capture -i returns OK");
    ASSERT_EQ(MODE_LIVE_INTERFACE, opts.mode, "capture -i sets mode=MODE_LIVE_INTERFACE");
    ASSERT_STR_EQ("eth0", opts.input, "capture -i sets input");
}

static void test_parse_capture_positional_interface(void) {
    char *argv[] = { "mmtReader", "capture", "eth0" };
    int argc = 3;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "capture eth0 (positional) returns OK");
    ASSERT_EQ(MODE_LIVE_INTERFACE, opts.mode, "capture eth0 sets mode=MODE_LIVE_INTERFACE");
    ASSERT_STR_EQ("eth0", opts.input, "capture eth0 sets input");
}

static void test_parse_quiet_flag(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap", "-q" };
    int argc = 5;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-q returns OK");
    ASSERT_EQ(1, opts.quiet, "-q sets quiet=1");
}

static void test_parse_verbose_flag(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap", "-v" };
    int argc = 5;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-v returns OK");
    ASSERT_EQ(1, opts.verbose, "-v sets verbose=1");
}

static void test_parse_json_flag(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap", "--json" };
    int argc = 5;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "--json returns OK");
    ASSERT_EQ(OUTPUT_FORMAT_JSON, opts.output_format, "--json sets output_format=json");
}

static void test_parse_no_color_flag(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap", "--no-color" };
    int argc = 5;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "--no-color returns OK");
    ASSERT_EQ(1, opts.no_color, "--no-color sets no_color=1");
}

static void test_parse_buffer_size(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap", "-b", "100" };
    int argc = 6;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-b 100 returns OK");
    ASSERT_EQ(100, opts.buffer_mb, "-b sets buffer_mb=100");
}

static void test_parse_proto_path(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap", "-a" };
    int argc = 5;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-a returns OK");
    ASSERT_EQ(1, opts.proto_path, "-a sets proto_path=1");
}

/* ---- Consolidated option-argument helpers (issue #67) ---- */

/*
 * -b/--buffer and -F/--flows now share one bounded-integer parser, and
 * -x/-y/-z share one 0-or-1 parser. The success paths below pin the
 * per-flag destinations so a mis-wired shared helper cannot pass
 * unnoticed. Rejection paths stay in tests/test_cli.sh: they exit
 * through the noreturn parse_error(), which would kill this binary.
 */

static void test_parse_buffer_size_bounds(void) {
    char *argv_min[] = { "mmtReader", "analyze", "-t", "test.pcap", "-b", "1" };
    char *argv_max[] = { "mmtReader", "analyze", "-t", "test.pcap", "-b", "10000" };
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(6, argv_min, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-b 1 returns OK");
    ASSERT_EQ(1, opts.buffer_mb, "-b 1 sets buffer_mb=1 (lower bound)");

    parse_init(&opts);
    rc = parse_options(6, argv_max, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-b 10000 returns OK");
    ASSERT_EQ(10000, opts.buffer_mb, "-b 10000 sets buffer_mb=10000 (upper bound)");
}

static void test_parse_flows_seconds(void) {
    /* -F is capture-only: analyze rejects it during final validation */
    char *argv[] = { "mmtReader", "capture", "-i", "eth0", "-F", "5" };
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(6, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "capture -F 5 returns OK");
    ASSERT_EQ(5, opts.flows_seconds, "-F 5 sets flows_seconds=5");
}

/*
 * --flows has no upper bound: parse_bounded_int_arg() is shared with -b but is
 * called with LONG_MAX here, which a strtol() result can never exceed. Pin that
 * so a future tightening of the shared helper cannot silently cap --flows.
 */
static void test_parse_flows_seconds_large(void) {
    char *argv[] = { "mmtReader", "capture", "-i", "eth0", "-F", "2000000000" };
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(6, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "capture -F 2000000000 returns OK (no upper bound)");
    ASSERT_EQ(2000000000, opts.flows_seconds, "-F 2000000000 sets flows_seconds unclamped");
}

static void test_parse_classify_flags_zero(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap",
                     "-x", "0", "-y", "0", "-z", "0" };
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(10, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-x/-y/-z 0 returns OK");
    ASSERT_EQ(0, opts.ip_classify, "-x 0 sets ip_classify=0");
    ASSERT_EQ(0, opts.hostname_classify, "-y 0 sets hostname_classify=0");
    ASSERT_EQ(0, opts.port_classify, "-z 0 sets port_classify=0");
}

static void test_parse_classify_flags_one(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap",
                     "-x", "1", "-y", "1", "-z", "1" };
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(10, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "-x/-y/-z 1 returns OK");
    ASSERT_EQ(1, opts.ip_classify, "-x 1 sets ip_classify=1");
    ASSERT_EQ(1, opts.hostname_classify, "-y 1 sets hostname_classify=1");
    ASSERT_EQ(1, opts.port_classify, "-z 1 sets port_classify=1");
}

/* ---- Config precedence vs environment variables (issue #55) ---- */

/** Create a throwaway HOME directory containing a .mmtreader.conf */
static int make_test_home(char *dir_buf, size_t buf_size, const char *conf) {
    snprintf(dir_buf, buf_size, "/tmp/mmt_parse_home_XXXXXX");
    if (mkdtemp(dir_buf) == NULL) {
        return 0;
    }
    char conf_path[512];
    snprintf(conf_path, sizeof(conf_path), "%s/.mmtreader.conf", dir_buf);
    FILE *fp = fopen(conf_path, "w");
    if (fp == NULL) {
        return 0;
    }
    fputs(conf, fp);
    fclose(fp);
    return 1;
}

static void remove_test_home(const char *dir) {
    char conf_path[512];
    snprintf(conf_path, sizeof(conf_path), "%s/.mmtreader.conf", dir);
    unlink(conf_path);
    rmdir(dir);
}

static void clear_mmt_env(void) {
    unsetenv("MMTREADER_JSON");
    unsetenv("MMTREADER_NO_COLOR");
    unsetenv("MMTREADER_QUIET");
}

static void restore_home(char *saved_home) {
    if (saved_home != NULL) {
        setenv("HOME", saved_home, 1);
    } else {
        unsetenv("HOME");
    }
}

static int parse_analyze_test_pcap(cli_options_t *opts) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap" };
    parse_init(opts);
    return parse_options(4, argv, opts);
}

/*
 * A config-file value must survive when the corresponding env var is
 * UNSET: the old env_get_int() returned 0 for unset variables and
 * silently clobbered the values loaded from ~/.mmtreader.conf.
 */
static void test_config_survives_unset_env(void) {
    char home[64];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    ASSERT_TRUE(make_test_home(home, sizeof(home),
                "json = 1\nquiet = 1\nverbose = 1\nno_color = 1\nbuffer = 777\n"),
                "test home with config created");
    clear_mmt_env();
    setenv("HOME", home, 1);

    cli_options_t opts;
    int rc = parse_analyze_test_pcap(&opts);

    ASSERT_EQ(PARSE_EXIT_OK, rc, "analyze parses with config-only settings");
    ASSERT_EQ(OUTPUT_FORMAT_JSON, opts.output_format,
              "config json=1 survives unset MMTREADER_JSON");
    ASSERT_EQ(1, opts.quiet, "config quiet=1 survives unset MMTREADER_QUIET");
    ASSERT_EQ(1, opts.no_color, "config no_color=1 survives unset MMTREADER_NO_COLOR");
    ASSERT_EQ(1, opts.verbose, "config verbose=1 survives (no env var exists)");
    ASSERT_EQ(777, opts.buffer_mb, "config buffer=777 survives");

    restore_home(saved_home);
    free(saved_home);
    remove_test_home(home);
}

/*
 * A SET env var overrides the config file (documented precedence:
 * config < environment < CLI flags).
 */
static void test_set_env_overrides_config(void) {
    char home[64];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    ASSERT_TRUE(make_test_home(home, sizeof(home),
                "json = 0\nquiet = 0\nno_color = 0\nbuffer = 50\n"),
                "test home with config created");
    clear_mmt_env();
    setenv("MMTREADER_QUIET", "1", 1);
    setenv("HOME", home, 1);

    cli_options_t opts;
    int rc = parse_analyze_test_pcap(&opts);

    ASSERT_EQ(PARSE_EXIT_OK, rc, "analyze parses with env + config settings");
    ASSERT_EQ(1, opts.quiet, "set MMTREADER_QUIET=1 overrides config quiet=0");
    ASSERT_EQ(OUTPUT_FORMAT_TEXT, opts.output_format,
              "config json=0 kept when MMTREADER_JSON is unset");
    ASSERT_EQ(50, opts.buffer_mb, "config buffer=50 kept (no env override)");

    restore_home(saved_home);
    free(saved_home);
    clear_mmt_env();
    remove_test_home(home);
}

/*
 * Conflicting case: an explicit MMTREADER_JSON=0 beats a config that
 * enables json — applying the env value (not dropping it) is what makes
 * the precedence deterministic.
 */
static void test_env_zero_overrides_config_conflict(void) {
    char home[64];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    ASSERT_TRUE(make_test_home(home, sizeof(home), "json = 1\n"),
                "test home with config created");
    clear_mmt_env();
    setenv("MMTREADER_JSON", "0", 1);
    setenv("HOME", home, 1);

    cli_options_t opts;
    int rc = parse_analyze_test_pcap(&opts);

    ASSERT_EQ(PARSE_EXIT_OK, rc, "analyze parses in conflicting case");
    ASSERT_EQ(OUTPUT_FORMAT_TEXT, opts.output_format,
              "explicit MMTREADER_JSON=0 overrides config json=1");

    restore_home(saved_home);
    free(saved_home);
    clear_mmt_env();
    remove_test_home(home);
}

/* An empty env value behaves like an unset one (config survives) */
static void test_empty_env_value_treated_as_unset(void) {
    char home[64];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    ASSERT_TRUE(make_test_home(home, sizeof(home), "quiet = 1\n"),
                "test home with config created");
    clear_mmt_env();
    setenv("MMTREADER_QUIET", "", 1);
    setenv("HOME", home, 1);

    cli_options_t opts;
    int rc = parse_analyze_test_pcap(&opts);

    ASSERT_EQ(PARSE_EXIT_OK, rc, "analyze parses with empty env value");
    ASSERT_EQ(1, opts.quiet, "empty MMTREADER_QUIET leaves config quiet=1 intact");

    restore_home(saved_home);
    free(saved_home);
    clear_mmt_env();
    remove_test_home(home);
}

/* ---- Main ---- */

int main(void) {
    printf("=== parse.c Unit Tests ===\n\n");

    test_parse_init_defaults();
    test_parse_no_subcommand();
    test_help_flag();
    test_parse_version_flag();
    test_parse_analyze_with_trace();
    test_parse_capture_with_interface();
    test_parse_capture_positional_interface();
    test_parse_quiet_flag();
    test_parse_verbose_flag();
    test_parse_json_flag();
    test_parse_no_color_flag();
    test_parse_buffer_size();
    test_parse_proto_path();
    test_parse_buffer_size_bounds();
    test_parse_flows_seconds();
    test_parse_flows_seconds_large();
    test_parse_classify_flags_zero();
    test_parse_classify_flags_one();
    test_config_survives_unset_env();
    test_set_env_overrides_config();
    test_env_zero_overrides_config_conflict();
    test_empty_env_value_treated_as_unset();

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
