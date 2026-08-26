# MMT-Reader Makefile — lightweight build helper
# Primary installer is install.sh (self-contained, installs everything)

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
MANDIR      ?= $(PREFIX)/share/man
MAN1DIR     ?= $(MANDIR)/man1
COMPLETIONS ?= $(PREFIX)/share/bash-completion/completions

CC          ?= gcc
CFLAGS      ?= -g -O2
TEST_CFLAGS ?= -g
COV_FLAGS   ?= --coverage -DCOVERAGE_BUILD

MMT_DPI     ?= /opt/mmt/dpi
SDK_MIN_VERSION = 1.8.0

SRCS        = mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c flows.c config.c
TARGET      = mmtReader

.PHONY: all build install uninstall clean test coverage completions check-sdk smoke-install

all: build

build: check-sdk $(TARGET)

# Abort early when the installed MMT-DPI SDK is missing or older than
# SDK_MIN_VERSION (see AGENT_ENVIRONMENT.md for the recorded environment).
check-sdk:
	@if [ ! -f "$(MMT_DPI)/include/mmt_core.h" ]; then \
		echo "ERROR: MMT-DPI SDK not found at $(MMT_DPI) (missing include/mmt_core.h)"; \
		echo "       Install the SDK first — see README.md or run ./install.sh."; \
		exit 1; \
	fi; \
	sdk_version=`sed -n 's/^#define VERSION "\([0-9][0-9.]*\)"/\1/p' $(MMT_DPI)/include/mmt_core.h | head -1`; \
	if [ -z "$$sdk_version" ]; then \
		echo "ERROR: cannot read SDK version from $(MMT_DPI)/include/mmt_core.h"; \
		exit 1; \
	fi; \
	lowest=`printf '%s\n%s\n' "$(SDK_MIN_VERSION)" "$$sdk_version" | sort -V | head -1`; \
	if [ "$$lowest" != "$(SDK_MIN_VERSION)" ]; then \
		echo "ERROR: MMT-DPI SDK ≥ $(SDK_MIN_VERSION) required, found $$sdk_version in $(MMT_DPI)"; \
		exit 1; \
	fi; \
	echo "MMT-DPI SDK $$sdk_version OK"

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ \
		-I. \
		-I$(MMT_DPI)/include \
		-I./utils \
		-I./cli \
		-L$(MMT_DPI)/lib \
		-lmmt_core -ldl -lpcap

install: build
	@mkdir -p $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)/$(TARGET)
	@mkdir -p $(MAN1DIR)
	install -m 644 mmtReader.1 $(MAN1DIR)/mmtReader.1
	@mkdir -p $(COMPLETIONS)
	install -m 644 completions/mmtReader.bash $(COMPLETIONS)/mmtReader
	@echo "Installed to $(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(MAN1DIR)/mmtReader.1
	rm -f $(COMPLETIONS)/mmtReader
	@echo "Uninstalled."

clean:
	rm -f $(TARGET)

test: build
	@echo "=== Test 1: Text output ==="
	./$(TARGET) analyze -t smallFlows.pcap -a 2>&1 | tail -5
	@# analyze prints its summary explicitly, not from engine_destroy():
	@# guard both directions — losing the call, or printing it twice again
	test "$$(./$(TARGET) analyze -t smallFlows.pcap 2>/dev/null | grep -c 'INPUT STATISTICS')" = "1" \
		&& echo "Summary printed exactly once OK"
	./$(TARGET) analyze -t smallFlows.pcap --json 2>/dev/null | jq -e 'has("input_stats")' > /dev/null \
		&& echo "JSON summary present OK"
	@echo ""
	@echo "=== Test 2: JSON output ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --json 2>/dev/null | jq '.input_stats.packets' > /dev/null && echo "JSON valid OK"
	@echo ""
	@echo "=== Test 2b: input_stats agrees with protocols[] ==="
	@# Run without -a on purpose: protocols[] must be populated either way.
	@# The ethernet match is compared as a list so a duplicate entry cannot
	@# be masked, and bandwidth uses a relative tolerance so the check does
	@# not become trace-dependent.
	./$(TARGET) analyze -t smallFlows.pcap --json 2>/dev/null | jq -e '(.input_stats.data_volume > 0) and (.input_stats.protocols > 0) and ([.protocols[] | select(.name=="ethernet") | .data_volume] == [.input_stats.data_volume]) and (.input_stats.protocols == (.protocols | length)) and (.input_stats.protocols == ([.protocols[] | select(.packets > 0)] | length)) and ((((.input_stats.bandwidth_bytes_per_sec - (.input_stats.data_volume / .input_stats.duration_seconds)) / .input_stats.bandwidth_bytes_per_sec) | if . < 0 then -. else . end) < 0.001)' > /dev/null && echo "Aggregate input_stats OK"
	@echo ""
	@echo "=== Test 3: Sessions flag ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --sessions 2>&1 | grep "IPv4 Sessions" > /dev/null && echo "Sessions flag works OK"
	@echo ""
	@echo "=== Test 4: JSON with sessions ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --json --sessions 2>/dev/null | jq '.protocols[0].sessions' > /dev/null && echo "JSON sessions valid OK"
	@echo ""
	@echo "=== Test 5: Config unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_config tests/test_config.c config.c -I. && ./test_config && rm -f test_config
	@echo ""
	@echo "=== Test 5b: Anomaly detection unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_anomaly tests/test_anomaly.c core/engine.c cli/output.c \
		utils/colors.c utils/version.c \
		-I. -I/opt/mmt/dpi/include -I./utils -I./cli \
		-L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap && ./test_anomaly && rm -f test_anomaly
	@echo ""
	@echo "=== Test 6: Parse unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_parse tests/test_parse.c cli/parse.c config.c -I. -I./utils && ./test_parse && rm -f test_parse
	@echo ""
	@echo "=== Test 7: WiFi conversion unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_wifi tests/test_wifi.c capture.c \
		-I. -I/opt/mmt/dpi/include -I./utils -I./cli \
		-L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap && ./test_wifi && rm -f test_wifi
	@echo ""
	@echo "=== Test 8: Flow reporting unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_flows tests/test_flows.c flows.c \
		-I. -I/opt/mmt/dpi/include -I./utils -I./cli \
		-L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap && ./test_flows && rm -f test_flows
	@echo ""
	@echo "=== Test 9: Capture dispatch unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_capture_dispatch tests/test_capture_dispatch.c capture.c \
		-I. -I/opt/mmt/dpi/include -I./utils -I./cli \
		-L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap && ./test_capture_dispatch && rm -f test_capture_dispatch
	@echo ""
	@echo "=== Test 10: Engine output unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_engine_output tests/test_engine_output.c core/engine.c cli/output.c \
		utils/colors.c utils/version.c \
		-I. -I/opt/mmt/dpi/include -I./utils -I./cli \
		-L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap && ./test_engine_output && rm -f test_engine_output
	@echo ""
	@echo "=== Test 11: Engine statistics unit tests ==="
	$(CC) $(TEST_CFLAGS) -o test_engine_stats tests/test_engine_stats.c core/engine.c cli/output.c \
		utils/colors.c utils/version.c \
		-I. -I/opt/mmt/dpi/include -I./utils -I./cli \
		-L/opt/mmt/dpi/lib -lmmt_core -ldl -lpcap && ./test_engine_stats && rm -f test_engine_stats
	@echo ""
	@echo "=== Test 12: CLI integration tests ==="
	./tests/test_cli.sh ./$(TARGET)
	@echo ""
	@echo "=== Test 13: Completions exist ==="
	@test -f completions/mmtReader.bash && echo "Bash completion OK" || echo "Bash completion missing"
	@test -f completions/mmtReader.zsh && echo "Zsh completion OK" || echo "Zsh completion missing"
	@test -f completions/mmtReader.fish && echo "Fish completion OK" || echo "Fish completion missing"
	@echo ""
	@echo "=== Test 14: SDK version check unit tests ==="
	bash tests/test_sdk_check.sh
	@echo ""
	@echo "All tests passed!"

# Coverage (task 3.1, closes F-TEST-002): rerun the suite with the unit-test
# binaries instrumented via --coverage and summarize per-source line/branch
# coverage with plain gcov. The default build is untouched — instrumentation
# reaches the suite only through TEST_CFLAGS; `make` / `make test` are unchanged.
coverage:
	@command -v gcov >/dev/null 2>&1 || { echo "ERROR: gcov not found (comes with gcc)"; exit 1; }
	$(MAKE) clean
	$(MAKE) test TEST_CFLAGS="-g $(COV_FLAGS)"
	@echo ""
	@echo "=== Coverage summary (unit suites, per source file) ==="
	@find . -name '*.gcda' | LC_ALL=C sort | while read -r f; do \
		gcov -b "$$f" 2>/dev/null || true; \
	done > .coverage.raw
	@awk -f tests/coverage-summary.awk .coverage.raw
	@rm -f .coverage.raw
	@find . \( -name '*.gcda' -o -name '*.gcno' -o -name '*.gcov' \) -delete
	@rm -f test_config test_anomaly test_parse test_wifi test_flows \
		test_capture_dispatch test_engine_output test_engine_stats
	@echo "Coverage artifacts cleaned."

completions:
	@echo "Shell completions are generated during install."

# Adversarial-path installer smoke test (task 1.2, closes F-BUG-003).
# Sandbox-only: no root, no container, no system changes.
smoke-install:
	bash ci/install-smoke.sh
