/**
 * test_engine_output.c — Unit tests for the engine's output discipline
 *
 * Two rules the capture path depends on (issue #39):
 *
 *   1. engine_destroy() writes nothing. It used to print the summary, so
 *      the only way to avoid a second copy was to leak the engine, and a
 *      failed run printed a block of zeroes on its way out.
 *   2. engine_print_stats() honours the configured output format. It used
 *      to hardcode TEXT, so `capture --json` wrote a text table to stdout
 *      ahead of the JSON document and the result did not parse.
 *
 * Together they mean a caller that asks for the summary once gets exactly
 * one, in the format it configured. Each scenario replays the capture
 * path's call sequence — process packets, print, destroy — and inspects
 * stdout. No interface and no privileges are needed.
 *
 * Every scenario runs in its own forked process: engine_destroy() calls
 * close_extraction(), and MMT-DPI cannot re-init extraction afterwards in
 * the same process. A fork also matches what is being tested — the output
 * a single run leaves on stdout.
 *
 * Compile: gcc -g -o test_engine_output tests/test_engine_output.c \
 *              core/engine.c cli/output.c utils/colors.c utils/version.c \
 *              -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
 *              -L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pcap.h>
#include "core/engine.h"

/* Failures recorded by the scenario currently running (child process) */
static int scenario_fail = 0;

#define ASSERT_EQ(expected, actual, msg) do { \
    if ((expected) != (actual)) { \
        printf("  FAIL: %s (expected=%d, actual=%d)\n", msg, (int)(expected), (int)(actual)); \
        scenario_fail++; \
    } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { printf("  FAIL: %s\n", msg); scenario_fail++; } \
} while(0)

/* ------------------------------------------------------------------ */
/* stdout capture                                                      */
/* ------------------------------------------------------------------ */

#define CAP_MAX 262144

static int  g_saved_fd = -1;
static char g_cap_path[64];

/** Redirect stdout to a temporary file */
static int capture_begin(void) {
    int fd;

    strcpy(g_cap_path, "/tmp/mmtreader_out_XXXXXX");
    fflush(stdout);
    g_saved_fd = dup(fileno(stdout));
    if (g_saved_fd < 0) return 0;

    fd = mkstemp(g_cap_path);
    if (fd < 0) {
        close(g_saved_fd);
        g_saved_fd = -1;
        return 0;
    }
    if (dup2(fd, fileno(stdout)) < 0) {
        close(fd);
        close(g_saved_fd);
        g_saved_fd = -1;
        return 0;
    }
    close(fd);
    return 1;
}

/**
 * Restore stdout and read back everything written while redirected.
 *
 * A capture that does not fit the buffer fails the scenario outright: a
 * clipped tail could drop a second summary and turn a duplicate into a
 * PASS, which is the one assertion this file exists to make. stdout is
 * already restored by then, so the message reaches the real stdout.
 *
 * @return number of bytes captured
 */
static size_t capture_end(char *buf, size_t bufsz) {
    FILE *f;
    size_t n = 0;

    fflush(stdout);
    if (g_saved_fd >= 0) {
        dup2(g_saved_fd, fileno(stdout));
        close(g_saved_fd);
        g_saved_fd = -1;
    }

    buf[0] = '\0';
    f = fopen(g_cap_path, "rb");
    if (f != NULL) {
        long size = -1;

        if (fseek(f, 0, SEEK_END) == 0) {
            size = ftell(f);
            rewind(f);
        }
        n = fread(buf, 1, bufsz - 1, f);
        buf[n] = '\0';
        fclose(f);

        if (size < 0) {
            printf("  FAIL: could not measure the captured stdout\n");
            scenario_fail++;
        } else if ((size_t)size > bufsz - 1) {
            printf("  FAIL: captured stdout truncated (%ld bytes written, buffer holds %lu)\n",
                   size, (unsigned long)(bufsz - 1));
            scenario_fail++;
        }
    }
    unlink(g_cap_path);
    return n;
}

/** Count non-overlapping occurrences of needle in haystack */
static int count_occurrences(const char *haystack, const char *needle) {
    int n = 0;
    size_t len = strlen(needle);
    const char *p = haystack;

    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Engine helpers                                                      */
/* ------------------------------------------------------------------ */

#define TRACE_FILE "smallFlows.pcap"
#define MAX_PACKETS 400

/**
 * Build an engine and feed it a bounded slice of the sample trace.
 *
 * The trace keeps the figures realistic, but the output rules under test
 * hold with or without it, so a missing file is not a failure.
 *
 * @return engine handle, or NULL if the MMT handler could not be created
 */
static engine_t *engine_with_packets(output_format_t format, int show_sessions) {
    char errbuf[1024];
    engine_t *eng;
    pcap_t *pcap;

    eng = engine_create(DLT_EN10MB, 0, errbuf);
    if (eng == NULL) return NULL;

    engine_set_output_format(eng, format);
    engine_set_show_sessions(eng, show_sessions);

    pcap = pcap_open_offline(TRACE_FILE, errbuf);
    if (pcap != NULL) {
        struct pcap_pkthdr p_pkthdr;
        const u_char *data;
        int n = 0;

        while (n < MAX_PACKETS &&
               (data = pcap_next(pcap, &p_pkthdr)) != NULL) {
            struct pkthdr header;
            header.ts     = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len    = p_pkthdr.len;
            engine_process_packet(eng, &header, data);
            n++;
        }
        pcap_close(pcap);
    }
    return eng;
}

/* ------------------------------------------------------------------ */
/* engine_destroy() performs no output                                 */
/* ------------------------------------------------------------------ */

/* Destroying an engine must not write a single byte to stdout */
static void test_destroy_is_silent(void) {
    static char out[CAP_MAX];
    engine_t *eng = engine_with_packets(OUTPUT_FORMAT_TEXT, 0);
    size_t n;

    if (eng == NULL) { printf("  FAIL: engine_create failed\n"); scenario_fail++; return; }
    if (!capture_begin()) {
        printf("  FAIL: could not redirect stdout\n");
        scenario_fail++;
        engine_destroy(eng);
        return;
    }
    engine_destroy(eng);
    n = capture_end(out, sizeof(out));

    ASSERT_EQ(0, (int)n, "engine_destroy() writes nothing to stdout");
}

/* The same holds when JSON is configured — no stray document on teardown */
static void test_destroy_is_silent_in_json_mode(void) {
    static char out[CAP_MAX];
    engine_t *eng = engine_with_packets(OUTPUT_FORMAT_JSON, 1);
    size_t n;

    if (eng == NULL) { printf("  FAIL: engine_create failed\n"); scenario_fail++; return; }
    if (!capture_begin()) {
        printf("  FAIL: could not redirect stdout\n");
        scenario_fail++;
        engine_destroy(eng);
        return;
    }
    engine_destroy(eng);
    n = capture_end(out, sizeof(out));

    ASSERT_EQ(0, (int)n, "engine_destroy() writes nothing in JSON mode");
}

/* ------------------------------------------------------------------ */
/* engine_print_stats() honours the configured format                  */
/* ------------------------------------------------------------------ */

/* With JSON configured, the summary is JSON — not the text table */
static void test_print_stats_honours_json_format(void) {
    static char out[CAP_MAX];
    engine_t *eng = engine_with_packets(OUTPUT_FORMAT_JSON, 0);

    if (eng == NULL) { printf("  FAIL: engine_create failed\n"); scenario_fail++; return; }
    if (!capture_begin()) {
        printf("  FAIL: could not redirect stdout\n");
        scenario_fail++;
        engine_destroy(eng);
        return;
    }
    engine_print_stats(eng);
    capture_end(out, sizeof(out));
    engine_destroy(eng);

    ASSERT_EQ('{', out[0], "JSON format makes engine_print_stats() emit a JSON document");
    ASSERT_TRUE(strstr(out, "\"input_stats\"") != NULL,
                "JSON summary carries the input_stats object");
    ASSERT_TRUE(strstr(out, "INPUT STATISTICS") == NULL,
                "JSON summary carries no text table");
}

/* With TEXT configured, the summary is the text table */
static void test_print_stats_honours_text_format(void) {
    static char out[CAP_MAX];
    engine_t *eng = engine_with_packets(OUTPUT_FORMAT_TEXT, 0);

    if (eng == NULL) { printf("  FAIL: engine_create failed\n"); scenario_fail++; return; }
    if (!capture_begin()) {
        printf("  FAIL: could not redirect stdout\n");
        scenario_fail++;
        engine_destroy(eng);
        return;
    }
    engine_print_stats(eng);
    capture_end(out, sizeof(out));
    engine_destroy(eng);

    ASSERT_TRUE(strstr(out, "INPUT STATISTICS") != NULL,
                "TEXT format makes engine_print_stats() emit the text table");
    ASSERT_TRUE(out[0] != '{', "TEXT summary is not a JSON document");
}

/* show_sessions is carried too — it used to be hardcoded to 0 */
static void test_print_stats_honours_show_sessions(void) {
    static char out[CAP_MAX];
    engine_t *eng = engine_with_packets(OUTPUT_FORMAT_TEXT, 1);

    if (eng == NULL) { printf("  FAIL: engine_create failed\n"); scenario_fail++; return; }
    if (!capture_begin()) {
        printf("  FAIL: could not redirect stdout\n");
        scenario_fail++;
        engine_destroy(eng);
        return;
    }
    engine_print_stats(eng);
    capture_end(out, sizeof(out));
    engine_destroy(eng);

    /* The per-IP-version breakdown appears only under show_sessions;
     * "Total Sessions" is printed either way, so it cannot discriminate */
    ASSERT_TRUE(strstr(out, "IPv4 Sessions") != NULL,
                "engine_print_stats() carries show_sessions through");
}

/* ------------------------------------------------------------------ */
/* The capture path prints exactly one summary                         */
/* ------------------------------------------------------------------ */

/*
 * Replay of mmtReader's capture sequence in TEXT mode: process, print
 * once, destroy. Exactly one summary must reach stdout — the bug printed
 * the tables and INPUT STATISTICS twice.
 */
static void test_capture_sequence_prints_one_text_summary(void) {
    static char out[CAP_MAX];
    engine_t *eng = engine_with_packets(OUTPUT_FORMAT_TEXT, 0);

    if (eng == NULL) { printf("  FAIL: engine_create failed\n"); scenario_fail++; return; }
    if (!capture_begin()) {
        printf("  FAIL: could not redirect stdout\n");
        scenario_fail++;
        engine_destroy(eng);
        return;
    }
    engine_print_stats(eng);
    engine_destroy(eng);
    capture_end(out, sizeof(out));

    ASSERT_EQ(1, count_occurrences(out, "INPUT STATISTICS"),
              "capture sequence prints INPUT STATISTICS exactly once");
    ASSERT_EQ(1, count_occurrences(out, "MMT-READER STATS"),
              "capture sequence prints the protocol tables exactly once");
}

/*
 * The same sequence in JSON mode must leave exactly one document on
 * stdout. The bug emitted a text table first, so the stream did not parse
 * unless -q happened to suppress it.
 */
static void test_capture_sequence_prints_one_json_document(void) {
    static char out[CAP_MAX];
    engine_t *eng = engine_with_packets(OUTPUT_FORMAT_JSON, 1);
    size_t n;

    if (eng == NULL) { printf("  FAIL: engine_create failed\n"); scenario_fail++; return; }
    if (!capture_begin()) {
        printf("  FAIL: could not redirect stdout\n");
        scenario_fail++;
        engine_destroy(eng);
        return;
    }
    engine_print_stats(eng);
    engine_destroy(eng);
    n = capture_end(out, sizeof(out));

    ASSERT_EQ(1, count_occurrences(out, "\"input_stats\""),
              "capture sequence emits exactly one JSON document");
    ASSERT_TRUE(strstr(out, "INPUT STATISTICS") == NULL,
                "no text table precedes the JSON document");
    ASSERT_EQ('{', out[0], "the document starts at the first byte of stdout");
    /* Trailing whitespace aside, the document is the whole stream */
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' ')) n--;
    ASSERT_TRUE(n > 0 && out[n - 1] == '}',
                "the document ends at the last byte of stdout");
}

/* ------------------------------------------------------------------ */
/* Scenario runner                                                     */
/* ------------------------------------------------------------------ */

static int scenarios_run = 0;
static int scenarios_pass = 0;
static int scenarios_fail = 0;

/**
 * Run one scenario in a child process.
 *
 * The child exits with its failure count; anything else (a crash, say)
 * is reported as a failure too.
 */
static void run_scenario(const char *name, void (*fn)(void)) {
    pid_t pid;
    int status = 0;

    scenarios_run++;
    printf("- %s\n", name);
    fflush(stdout);

    pid = fork();
    if (pid < 0) {
        printf("  FAIL: fork failed\n");
        scenarios_fail++;
        return;
    }
    if (pid == 0) {
        scenario_fail = 0;
        fn();
        fflush(stdout);
        _exit(scenario_fail > 100 ? 100 : scenario_fail);
    }

    if (waitpid(pid, &status, 0) < 0) {
        printf("  FAIL: waitpid failed\n");
        scenarios_fail++;
        return;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        scenarios_pass++;
    } else {
        if (WIFSIGNALED(status)) {
            printf("  FAIL: scenario killed by signal %d\n", WTERMSIG(status));
        }
        scenarios_fail++;
    }
}

/* ---- Main ---- */

int main(void) {
    printf("=== Engine output Unit Tests ===\n\n");

    run_scenario("engine_destroy() is silent", test_destroy_is_silent);
    run_scenario("engine_destroy() is silent in JSON mode", test_destroy_is_silent_in_json_mode);
    run_scenario("engine_print_stats() honours JSON format", test_print_stats_honours_json_format);
    run_scenario("engine_print_stats() honours TEXT format", test_print_stats_honours_text_format);
    run_scenario("engine_print_stats() honours show_sessions", test_print_stats_honours_show_sessions);
    run_scenario("capture sequence prints one text summary", test_capture_sequence_prints_one_text_summary);
    run_scenario("capture sequence prints one JSON document", test_capture_sequence_prints_one_json_document);

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", scenarios_run);
    printf("Pass: %d\n", scenarios_pass);
    printf("Fail: %d\n", scenarios_fail);

    return (scenarios_fail > 0) ? 1 : 0;
}
