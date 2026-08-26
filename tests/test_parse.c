/**
 * test_parse.c — Unit tests for cli/parse.c
 *
 * Tests parse_init defaults, option parsing, and error handling.
 * Compile: gcc -g -o test_parse test_parse.c cli/parse.c -I./cli -I./utils
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cli/parse.h"

#include "test_util.h"

/* ---- parse_init tests ---- */

static void test_parse_init_defaults(void) {
    cli_options_t opts;
    parse_init(&opts);

    ASSERT_EQ(NULL, opts.input, "input should be NULL");
    ASSERT_EQ(0, opts.mode, "mode should be 0");
    ASSERT_EQ(50, opts.buffer_mb, "buffer_mb should be 50");
    ASSERT_EQ(0, opts.proto_path, "proto_path should be 0");
    ASSERT_EQ(1, opts.ip_classify, "ip_classify should be 1");
    ASSERT_EQ(1, opts.hostname_classify, "hostname_classify should be 1");
    ASSERT_EQ(1, opts.port_classify, "port_classify should be 1");
    ASSERT_EQ(0, opts.show_help, "show_help should be 0");
    ASSERT_EQ(0, opts.no_color, "no_color should be 0");
    ASSERT_EQ(0, opts.quiet, "quiet should be 0");
    ASSERT_EQ(0, opts.verbose, "verbose should be 0");
    ASSERT_EQ(0, opts.json, "json should be 0");
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

static void test_parse_help_flag(void) {
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
    ASSERT_EQ(3, opts.mode, "--version sets mode=3");
}

static void test_parse_analyze_with_trace(void) {
    char *argv[] = { "mmtReader", "analyze", "-t", "test.pcap" };
    int argc = 4;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "analyze -t returns OK");
    ASSERT_EQ(1, opts.mode, "analyze -t sets mode=1");
    ASSERT_STR_EQ("test.pcap", opts.input, "analyze -t sets input");
}

static void test_parse_capture_with_interface(void) {
    char *argv[] = { "mmtReader", "capture", "-i", "eth0" };
    int argc = 4;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "capture -i returns OK");
    ASSERT_EQ(2, opts.mode, "capture -i sets mode=2");
    ASSERT_STR_EQ("eth0", opts.input, "capture -i sets input");
}

static void test_parse_capture_positional_interface(void) {
    char *argv[] = { "mmtReader", "capture", "eth0" };
    int argc = 3;
    cli_options_t opts;

    parse_init(&opts);
    int rc = parse_options(argc, argv, &opts);
    ASSERT_EQ(PARSE_EXIT_OK, rc, "capture eth0 (positional) returns OK");
    ASSERT_EQ(2, opts.mode, "capture eth0 sets mode=2");
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
    ASSERT_EQ(1, opts.json, "--json sets json=1");
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

/* ---- Main ---- */

int main(void) {
    printf("=== parse.c Unit Tests ===\n\n");

    test_parse_init_defaults();
    test_parse_no_subcommand();
    test_parse_help_flag();
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

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
