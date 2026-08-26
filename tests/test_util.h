/**
 * test_util.h — Shared assertion macros for the mmtReader unit tests
 *
 * Every C test binary in this directory includes this header instead of
 * redefining its own ASSERT boilerplate (F-TEST-003, modernization task 3.4).
 *
 * Two suites share the macro names, selected before inclusion:
 *
 *   default            — counter-based suites: each assertion bumps the
 *                        tests_run/tests_pass/tests_fail tally that the
 *                        suite's main() prints as its summary.
 *
 *   TEST_SCENARIO_MODE — fork-based suites (engine_output, engine_stats):
 *                        each assertion records failures in scenario_fail,
 *                        which the forked child reports through its exit
 *                        status to run_scenario(). Failure text goes to
 *                        stdout by default; define TEST_FAIL_OUT before
 *                        inclusion to route it elsewhere (stderr when the
 *                        child's stdout is discarded).
 */
#ifndef MMT_TEST_UTIL_H
#define MMT_TEST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef TEST_SCENARIO_MODE

/* Failures recorded by the scenario currently running (child process) */
static int scenario_fail = 0;

/* Stream scenario failures are reported on */
#ifndef TEST_FAIL_OUT
#define TEST_FAIL_OUT stdout
#endif

#define ASSERT_EQ(expected, actual, msg) do { \
    if ((expected) != (actual)) { \
        fprintf(TEST_FAIL_OUT, "  FAIL: %s (expected=%d, actual=%d)\n", msg, (int)(expected), (int)(actual)); \
        scenario_fail++; \
    } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { fprintf(TEST_FAIL_OUT, "  FAIL: %s\n", msg); scenario_fail++; } \
} while(0)

/*
 * Always on stderr: engine_stats scenarios discard their stdout, so a
 * failure printed there would never be seen.
 */
#define ASSERT_U64_EQ(expected, actual, msg) do { \
    if ((uint64_t)(expected) != (uint64_t)(actual)) { \
        fprintf(stderr, "  FAIL: %s (expected=%lu, actual=%lu)\n", msg, \
                (unsigned long)(expected), (unsigned long)(actual)); \
        scenario_fail++; \
    } \
} while(0)

#else /* counter-based suites */

/* Per-binary tally printed by each suite's main() */
static int tests_run  = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define ASSERT_EQ(expected, actual, msg) do { \
    tests_run++; \
    if ((expected) == (actual)) { tests_pass++; } \
    else { printf("FAIL: %s (expected=%d, actual=%d)\n", msg, expected, actual); tests_fail++; } \
} while(0)

#define ASSERT_STR_EQ(expected, actual, msg) do { \
    tests_run++; \
    if (strcmp((expected), (actual)) == 0) { tests_pass++; } \
    else { printf("FAIL: %s (expected=\"%s\", actual=\"%s\")\n", msg, expected, actual); tests_fail++; } \
} while(0)

#define ASSERT_MEM_EQ(expected, actual, len, msg) do { \
    tests_run++; \
    if (memcmp((expected), (actual), (size_t)(len)) == 0) { tests_pass++; } \
    else { printf("FAIL: %s (%d bytes differ)\n", msg, len); tests_fail++; } \
} while(0)

#define ASSERT_TRUE(val, msg) do { \
    tests_run++; \
    if ((val)) { tests_pass++; } \
    else { printf("FAIL: %s (expected true, got false)\n", msg); tests_fail++; } \
} while(0)

#define ASSERT_FALSE(val, msg) do { \
    tests_run++; \
    if (!(val)) { tests_pass++; } \
    else { printf("FAIL: %s (expected false, got true)\n", msg); tests_fail++; } \
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

#endif /* TEST_SCENARIO_MODE */

#endif /* MMT_TEST_UTIL_H */
