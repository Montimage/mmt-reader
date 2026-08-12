/**
 * test_engine_stats.c — Unit tests for the aggregate INPUT STATISTICS
 *
 * `data_volume` and `nb_protocols` were declared but never written, so
 * every run reported "Data: 0 bytes", "Bandwidth: 0.00" and
 * "Protocols: 0" while the per-protocol table beside them showed real
 * figures (issue #38). They are now read from MMT-DPI, which already
 * maintains them, rather than recomputed here.
 *
 * These tests pin that down from the other side: they ask MMT-DPI for the
 * per-protocol totals the same way cli/output.c builds the `protocols[]`
 * table — sum `data_volume` over the touched instances of each protocol
 * id — and require the aggregate to agree. A field that regresses to
 * zero, or a hand-rolled counter that drifts from the DPI's accounting,
 * fails here.
 *
 * Both entry points are covered: engine_process_packet(), which the
 * offline `analyze` path calls directly, and engine_process_packet_cb(),
 * the processor the live `capture` path registers. Neither needs an
 * interface or privileges.
 *
 * Every scenario runs in its own forked process: engine_destroy() calls
 * close_extraction(), and MMT-DPI cannot re-init extraction afterwards in
 * the same process.
 *
 * Compile: gcc -g -o test_engine_stats tests/test_engine_stats.c \
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

/*
 * Scenarios assert on the engine_stats_t values, never on printed text,
 * so a child runs with stdout discarded: the statistics summary these
 * calls may print is not what is under test, and it would bury the
 * results. Failures go to stderr, which is left alone.
 */
#define ASSERT_U64_EQ(expected, actual, msg) do { \
    if ((uint64_t)(expected) != (uint64_t)(actual)) { \
        fprintf(stderr, "  FAIL: %s (expected=%lu, actual=%lu)\n", msg, \
                (unsigned long)(expected), (unsigned long)(actual)); \
        scenario_fail++; \
    } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "  FAIL: %s\n", msg); scenario_fail++; } \
} while(0)

/** Discard the child's stdout; the summary printed there is not the subject */
static void silence_stdout(void) {
    fflush(stdout);
    if (freopen("/dev/null", "w", stdout) == NULL) {
        fprintf(stderr, "  WARN: could not silence stdout\n");
    }
}

/* ------------------------------------------------------------------ */
/* Independent view of MMT-DPI's per-protocol accounting               */
/* ------------------------------------------------------------------ */

/**
 * Totals for one named protocol, plus the number of protocols the DPI
 * actually saw — the same two quantities cli/output.c reports as the
 * `protocols[]` array and its length.
 */
typedef struct {
    const char *want_name;   /**< protocol to total, by name        */
    uint64_t    volume;      /**< its summed data_volume            */
    uint64_t    packets;     /**< its summed packets_count          */
    int         found;       /**< 1 if that protocol was seen       */
    uint64_t    nb_touched;  /**< distinct protocols with packets   */
    mmt_handler_t *mmt;
} proto_probe_t;

/**
 * Accumulate one protocol id, mirroring protocols_stats_iterator() in
 * cli/output.c: skip PROTO_META (id 1, the path root), sum over the
 * instance list, count only touched instances.
 */
static void probe_protocol(uint32_t proto_id, void *args) {
    proto_probe_t *p = (proto_probe_t *)args;
    proto_statistics_t *stats;
    const char *name;
    uint64_t pkts = 0, vol = 0;

    if (proto_id == 1) return;   /* PROTO_META is not a protocol on the wire */

    stats = get_protocol_stats(p->mmt, proto_id);
    for (; stats != NULL; stats = stats->next) {
        if (!stats->touched) continue;
        pkts += stats->packets_count;
        vol  += stats->data_volume;
    }
    if (pkts > 0) p->nb_touched++;

    name = get_protocol_name_by_id(proto_id);
    if (name != NULL && p->want_name != NULL && strcmp(name, p->want_name) == 0) {
        p->found   = 1;
        p->packets = pkts;
        p->volume  = vol;
    }
}

/** Ask the DPI directly for the totals of one protocol */
static proto_probe_t probe_dpi(mmt_handler_t *mmt, const char *name) {
    proto_probe_t p;
    memset(&p, 0, sizeof(p));
    p.mmt = mmt;
    p.want_name = name;
    iterate_through_protocols(probe_protocol, &p);
    return p;
}

/* ------------------------------------------------------------------ */
/* Feeding the engine                                                  */
/* ------------------------------------------------------------------ */

#define TRACE_FILE  "smallFlows.pcap"
#define MAX_PACKETS 600

/** How a scenario hands packets to the engine */
typedef enum {
    FEED_DIRECT,     /**< engine_process_packet()    — analyze path */
    FEED_CALLBACK    /**< engine_process_packet_cb() — capture path */
} feed_mode_t;

/**
 * Replay a bounded slice of the sample trace into a fresh engine.
 * @return packets fed, or -1 if the trace could not be opened
 */
static int feed_engine(engine_t *eng, feed_mode_t mode) {
    char errbuf[1024];
    struct pcap_pkthdr p_pkthdr;
    const u_char *data;
    pcap_t *pcap;
    int n = 0;

    pcap = pcap_open_offline(TRACE_FILE, errbuf);
    if (pcap == NULL) return -1;

    while (n < MAX_PACKETS && (data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        struct pkthdr header;
        header.ts     = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len    = p_pkthdr.len;

        if (mode == FEED_CALLBACK) {
            engine_process_packet_cb(eng, &header, data);
        } else {
            engine_process_packet(eng, &header, data);
        }
        n++;
    }
    pcap_close(pcap);
    return n;
}

/* ------------------------------------------------------------------ */
/* The aggregate agrees with the per-protocol totals                   */
/* ------------------------------------------------------------------ */

/**
 * Core check, shared by both feed modes.
 *
 * The trace is Ethernet, so every packet traverses the `ethernet` layer
 * and its total is the whole-capture total — which is exactly the
 * cross-check issue #38 asks for: `input_stats.data_volume` must match
 * the `ethernet` entry of `protocols[]`.
 */
static void check_aggregate(feed_mode_t mode) {
    char errbuf[1024];
    engine_t *eng;
    engine_stats_t stats;
    proto_probe_t eth;
    int fed;

    eng = engine_create(DLT_EN10MB, 0, errbuf);
    if (eng == NULL) {
        fprintf(stderr, "  FAIL: engine_create failed: %s\n", errbuf);
        scenario_fail++;
        return;
    }

    fed = feed_engine(eng, mode);
    if (fed < 0) {
        fprintf(stderr, "  FAIL: could not open %s\n", TRACE_FILE);
        scenario_fail++;
        engine_destroy(eng);
        return;
    }

    engine_get_stats(eng, &stats);
    eth = probe_dpi(engine_get_mmt(eng), "ethernet");

    /* The regression this guards: silent zeroes */
    ASSERT_TRUE(stats.data_volume > 0, "data_volume is populated, not zero");
    ASSERT_TRUE(stats.nb_protocols > 0, "nb_protocols is populated, not zero");
    ASSERT_TRUE(stats.nb_packets > 0, "nb_packets is populated, not zero");

    /* The aggregate is the DPI's own accounting, not a private tally */
    ASSERT_TRUE(eth.found, "the DPI reports an 'ethernet' protocol entry");
    ASSERT_U64_EQ(eth.volume, stats.data_volume,
                  "data_volume matches the ethernet entry of protocols[]");
    ASSERT_U64_EQ(eth.packets, stats.nb_packets,
                  "nb_packets matches the ethernet entry of protocols[]");
    ASSERT_U64_EQ(eth.nb_touched, stats.nb_protocols,
                  "nb_protocols equals the number of protocols in protocols[]");

    /* Every packet offered was accounted for */
    ASSERT_U64_EQ((uint64_t)fed, stats.nb_packets,
                  "every packet fed is counted");

    engine_destroy(eng);
}

/* The offline `analyze` path feeds engine_process_packet() directly */
static void test_aggregate_on_analyze_path(void) {
    check_aggregate(FEED_DIRECT);
}

/* The live `capture` path feeds engine_process_packet_cb() */
static void test_aggregate_on_capture_path(void) {
    check_aggregate(FEED_CALLBACK);
}

/**
 * Bandwidth is data_volume over the capture window, so a zeroed
 * data_volume silently zeroed bandwidth too. The window itself must be
 * non-degenerate for the division to mean anything.
 */
static void test_capture_window_supports_bandwidth(void) {
    char errbuf[1024];
    engine_t *eng;
    engine_stats_t stats;
    double duration;
    int fed;

    eng = engine_create(DLT_EN10MB, 0, errbuf);
    if (eng == NULL) {
        fprintf(stderr, "  FAIL: engine_create failed: %s\n", errbuf);
        scenario_fail++;
        return;
    }

    fed = feed_engine(eng, FEED_DIRECT);
    if (fed < 0) {
        fprintf(stderr, "  FAIL: could not open %s\n", TRACE_FILE);
        scenario_fail++;
        engine_destroy(eng);
        return;
    }

    engine_get_stats(eng, &stats);

    duration = (double)(stats.end_time.tv_sec - stats.init_time.tv_sec) +
               (double)(stats.end_time.tv_usec - stats.init_time.tv_usec) / 1000000.0;

    ASSERT_TRUE(duration > 0.0, "the capture window is non-degenerate");
    ASSERT_TRUE(stats.data_volume > 0,
                "bandwidth has a non-zero numerator");
    /* What cli/output.c divides — a real rate, not 0.00 */
    ASSERT_TRUE(duration > 0.0 && (double)stats.data_volume / duration > 0.0,
                "bandwidth computes to a non-zero rate");

    engine_destroy(eng);
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
        silence_stdout();
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
    printf("=== Engine statistics Unit Tests ===\n\n");

    run_scenario("aggregate matches per-protocol totals (analyze path)",
                 test_aggregate_on_analyze_path);
    run_scenario("aggregate matches per-protocol totals (capture path)",
                 test_aggregate_on_capture_path);
    run_scenario("capture window supports a non-zero bandwidth",
                 test_capture_window_supports_bandwidth);

    printf("\n=== Results ===\n");
    printf("Run:  %d\n", scenarios_run);
    printf("Pass: %d\n", scenarios_pass);
    printf("Fail: %d\n", scenarios_fail);

    return (scenarios_fail > 0) ? 1 : 0;
}
