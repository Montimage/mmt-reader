/**
 * test_config.c — Unit tests for config.c
 *
 * Tests config_init, config_load (file parsing), and config_dump.
 * Compile: gcc -g -o test_config test_config.c config.c -I.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "config.h"

#include "test_util.h"

/* ---- config_init tests ---- */

static void test_config_init_defaults(void) {
    config_t cfg;
    config_init(&cfg);

    ASSERT_EQ(0, cfg.json, "json should be 0");
    ASSERT_EQ(0, cfg.quiet, "quiet should be 0");
    ASSERT_EQ(0, cfg.verbose, "verbose should be 0");
    ASSERT_EQ(0, cfg.no_color, "no_color should be 0");
    ASSERT_EQ(1, cfg.ip_classify, "ip_classify should be 1");
    ASSERT_EQ(1, cfg.hostname_classify, "hostname_classify should be 1");
    ASSERT_EQ(1, cfg.port_classify, "port_classify should be 1");
    ASSERT_EQ(0, cfg.loaded, "loaded should be 0");
    ASSERT_EQ(0, cfg.buffer[CONFIG_SECTION_GLOBAL], "buffer[global] should be 0");
    ASSERT_EQ(0, cfg.buffer[CONFIG_SECTION_ANALYZE], "buffer[analyze] should be 0");
    ASSERT_EQ(0, cfg.buffer[CONFIG_SECTION_CAPTURE], "buffer[capture] should be 0");
}

/* ---- config_load tests ---- */

/* Helper: create a temp file with given content */
static int write_temp_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(fp, "%s", content);
    fclose(fp);
    return 0;
}

static void test_config_load_nonexistent(void) {
    config_t cfg;
    config_init(&cfg);

    int rc = config_load(&cfg, "/nonexistent/path/mmtreader.conf");
    ASSERT_EQ(1, rc, "nonexistent file returns 1");
    ASSERT_FALSE(cfg.loaded, "loaded should be 0 for nonexistent file");
}

static void test_config_load_global_section(void) {
    config_t cfg;
    config_init(&cfg);

    char tmp[] = "/tmp/mmt-test-config-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) { printf("SKIP: could not create temp file\n"); return; }
    close(fd);

    write_temp_file(tmp,
        "; Global defaults\n"
        "json = 1\n"
        "quiet = 0\n"
        "verbose = 1\n"
        "no_color = 1\n"
        "buffer = 100\n"
    );

    int rc = config_load(&cfg, tmp);
    ASSERT_EQ(0, rc, "valid config returns 0");
    ASSERT_TRUE(cfg.loaded, "loaded should be 1");
    ASSERT_EQ(1, cfg.json, "json should be 1 from global");
    ASSERT_EQ(0, cfg.quiet, "quiet should be 0 from global");
    ASSERT_EQ(1, cfg.verbose, "verbose should be 1 from global");
    ASSERT_EQ(1, cfg.no_color, "no_color should be 1 from global");
    ASSERT_EQ(100, cfg.buffer[CONFIG_SECTION_GLOBAL], "buffer[global] should be 100");

    unlink(tmp);
}

static void test_config_load_analyze_section(void) {
    config_t cfg;
    config_init(&cfg);

    char tmp[] = "/tmp/mmt-test-config-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) { printf("SKIP: could not create temp file\n"); return; }
    close(fd);

    write_temp_file(tmp,
        "[analyze]\n"
        "json = 1\n"
        "proto_path = 1\n"
        "sessions = 1\n"
        "buffer = 200\n"
    );

    int rc = config_load(&cfg, tmp);
    ASSERT_EQ(0, rc, "valid config returns 0");
    ASSERT_TRUE(cfg.loaded, "loaded should be 1");
    ASSERT_EQ(1, cfg.json, "json should be 1 from [analyze]");
    ASSERT_EQ(1, cfg.proto_path[CONFIG_SECTION_ANALYZE], "proto_path[analyze] should be 1");
    ASSERT_EQ(1, cfg.sessions[CONFIG_SECTION_ANALYZE], "sessions[analyze] should be 1");
    ASSERT_EQ(200, cfg.buffer[CONFIG_SECTION_ANALYZE], "buffer[analyze] should be 200");

    unlink(tmp);
}

static void test_config_load_capture_section(void) {
    config_t cfg;
    config_init(&cfg);

    char tmp[] = "/tmp/mmt-test-config-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) { printf("SKIP: could not create temp file\n"); return; }
    close(fd);

    write_temp_file(tmp,
        "[capture]\n"
        "quiet = 1\n"
        "buffer = 500\n"
        "proto_path = 0\n"
    );

    int rc = config_load(&cfg, tmp);
    ASSERT_EQ(0, rc, "valid config returns 0");
    ASSERT_TRUE(cfg.loaded, "loaded should be 1");
    ASSERT_EQ(1, cfg.quiet, "quiet should be 1 from [capture]");
    ASSERT_EQ(500, cfg.buffer[CONFIG_SECTION_CAPTURE], "buffer[capture] should be 500");
    ASSERT_EQ(0, cfg.proto_path[CONFIG_SECTION_CAPTURE], "proto_path[capture] should be 0");

    unlink(tmp);
}

static void test_config_load_comments_and_blanks(void) {
    config_t cfg;
    config_init(&cfg);

    char tmp[] = "/tmp/mmt-test-config-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) { printf("SKIP: could not create temp file\n"); return; }
    close(fd);

    write_temp_file(tmp,
        "; This is a comment\n"
        "# This is also a comment\n"
        "\n"
        "json = 1\n"
        "   \n"
        "quiet = 0\n"
    );

    int rc = config_load(&cfg, tmp);
    ASSERT_EQ(0, rc, "valid config with comments returns 0");
    ASSERT_TRUE(cfg.loaded, "loaded should be 1");
    ASSERT_EQ(1, cfg.json, "json should be 1");
    ASSERT_EQ(0, cfg.quiet, "quiet should be 0");

    unlink(tmp);
}

static void test_config_load_bool_variations(void) {
    config_t cfg;
    config_init(&cfg);

    char tmp[] = "/tmp/mmt-test-config-XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) { printf("SKIP: could not create temp file\n"); return; }
    close(fd);

    write_temp_file(tmp,
        "json = true\n"
        "quiet = yes\n"
        "verbose = on\n"
    );

    int rc = config_load(&cfg, tmp);
    ASSERT_EQ(0, rc, "valid config returns 0");
    ASSERT_EQ(1, cfg.json, "json=true should be 1");
    ASSERT_EQ(1, cfg.quiet, "quiet=yes should be 1");
    ASSERT_EQ(1, cfg.verbose, "verbose=on should be 1");

    unlink(tmp);
}

static void test_config_dump(void) {
    config_t cfg;
    config_init(&cfg);
    cfg.loaded = 1;
    strncpy(cfg.path, "/test/path.conf", CONFIG_MAX_PATH);
    cfg.json = 1;
    cfg.quiet = 0;

    /* Just verify it doesn't crash */
    config_dump(&cfg);
    ASSERT_TRUE(1, "config_dump does not crash");
}

/* ---- Main ---- */

int main(void) {
    printf("=== config.c Unit Tests ===\n\n");

    test_config_init_defaults();
    test_config_load_nonexistent();
    test_config_load_global_section();
    test_config_load_analyze_section();
    test_config_load_capture_section();
    test_config_load_comments_and_blanks();
    test_config_load_bool_variations();
    test_config_dump();

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
