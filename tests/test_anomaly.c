/**
 * test_anomaly.c — Unit tests for anomaly detection hooks
 *
 * Tests the anomaly detection API: create, detect (no-op default),
 * and destroy. Links against engine.c for the implementation.
 *
 * Compile: gcc -g -o test_anomaly tests/test_anomaly.c core/engine.c \
 *           -I. -I/opt/mmt/dpi/include -I./cli -L/opt/mmt/dpi/lib \
 *           -lmmt_core -ldl -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* Needed for struct pkthdr — must come before any forward declarations */
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include <pcap.h>

/*
 * We include engine.h to get the full anomaly API.
 * The engine.c compilation unit (linked below) provides the definitions.
 */
#include "core/engine.h"

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define ASSERT_EQ(expected, actual, msg) do { \
    tests_run++; \
    if ((expected) == (actual)) { tests_pass++; } \
    else { printf("FAIL: %s (expected=%d, actual=%d)\n", msg, expected, actual); tests_fail++; } \
} while(0)

#define ASSERT_PTR_EQ(expected, actual, msg) do { \
    tests_run++; \
    if ((expected) == (actual)) { tests_pass++; } \
    else { printf("FAIL: %s (expected=%p, actual=%p)\n", msg, (void*)(expected), (void*)(actual)); tests_fail++; } \
} while(0)

#define ASSERT_NOT_NULL(ptr, msg) do { \
    tests_run++; \
    if ((ptr) != NULL) { tests_pass++; } \
    else { printf("FAIL: %s (expected non-NULL)\n", msg); tests_fail++; } \
} while(0)

#define ASSERT_STR_EQ(expected, actual, msg) do { \
    tests_run++; \
    if (strcmp((expected), (actual)) == 0) { tests_pass++; } \
    else { printf("FAIL: %s (expected=\"%s\", actual=\"%s\")\n", msg, expected, actual); tests_fail++; } \
} while(0)

/* ---- anomaly_ctx_create tests ---- */

static void test_anomaly_ctx_create_returns_valid_pointer(void) {
    anomaly_ctx_t *ctx = anomaly_ctx_create();
    ASSERT_NOT_NULL(ctx, "create returns non-NULL");
    if (ctx) {
        anomaly_ctx_destroy(ctx);
    }
}

static void test_anomaly_ctx_create_multiple(void) {
    anomaly_ctx_t *ctx1 = anomaly_ctx_create();
    anomaly_ctx_t *ctx2 = anomaly_ctx_create();
    ASSERT_NOT_NULL(ctx1, "first create returns non-NULL");
    ASSERT_NOT_NULL(ctx2, "second create returns non-NULL");
    if (ctx1) anomaly_ctx_destroy(ctx1);
    if (ctx2) anomaly_ctx_destroy(ctx2);
}

/* ---- anomaly_detect tests ---- */

static void test_anomaly_detect_returns_none(void) {
    anomaly_ctx_t *ctx = anomaly_ctx_create();
    anomaly_result_t result;
    struct timeval tv;
    struct pkthdr hdr;

    memset(&result, 0, sizeof(result));
    gettimeofday(&tv, NULL);
    hdr.ts = tv;
    hdr.caplen = 64;
    hdr.len = 64;

    u_char dummy_data[64];
    memset(dummy_data, 0, sizeof(dummy_data));

    anomaly_detect(ctx, &hdr, dummy_data, &result);

    ASSERT_EQ(ANOMALY_NONE, result.type, "anomaly type is ANOMALY_NONE");
    ASSERT_EQ(0, result.severity, "severity is 0");
    ASSERT_STR_EQ("", result.description, "description is empty");

    anomaly_ctx_destroy(ctx);
}

static void test_anomaly_detect_null_ctx(void) {
    anomaly_result_t result;
    struct timeval tv;
    struct pkthdr hdr;

    memset(&result, 0, sizeof(result));
    gettimeofday(&tv, NULL);
    hdr.ts = tv;
    hdr.caplen = 64;
    hdr.len = 64;

    u_char dummy_data[64];
    memset(dummy_data, 0, sizeof(dummy_data));

    /* NULL context should not crash */
    anomaly_detect(NULL, &hdr, dummy_data, &result);

    ASSERT_EQ(ANOMALY_NONE, result.type, "NULL ctx returns ANOMALY_NONE");
    ASSERT_EQ(0, result.severity, "NULL ctx severity is 0");
}

static void test_anomaly_detect_null_result(void) {
    anomaly_ctx_t *ctx = anomaly_ctx_create();
    struct timeval tv;
    struct pkthdr hdr;

    gettimeofday(&tv, NULL);
    hdr.ts = tv;
    hdr.caplen = 64;
    hdr.len = 64;

    u_char dummy_data[64];
    memset(dummy_data, 0, sizeof(dummy_data));

    /* NULL result should not crash */
    anomaly_detect(ctx, &hdr, dummy_data, NULL);

    anomaly_ctx_destroy(ctx);
}

/* ---- anomaly_ctx_destroy tests ---- */

static void test_anomaly_ctx_destroy_null_is_safe(void) {
    anomaly_ctx_destroy(NULL);
    /* If we reach here, NULL destroy is safe */
    tests_pass++;
    tests_run++;
}

/* ---- Main ---- */

int main(void) {
    printf("=== Anomaly Detection Unit Tests ===\n\n");

    test_anomaly_ctx_create_returns_valid_pointer();
    test_anomaly_ctx_create_multiple();
    test_anomaly_detect_returns_none();
    test_anomaly_detect_null_ctx();
    test_anomaly_detect_null_result();
    test_anomaly_ctx_destroy_null_is_safe();

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", tests_run);
    printf("Pass: %d\n", tests_pass);
    printf("Fail: %d\n", tests_fail);

    return (tests_fail > 0) ? 1 : 0;
}
