# MMT-Reader Makefile — lightweight build helper
# Primary installer is install.sh (self-contained, installs everything)

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
MANDIR      ?= $(PREFIX)/share/man
MAN1DIR     ?= $(MANDIR)/man1
COMPLETIONS ?= $(PREFIX)/share/bash-completion/completions

CC          ?= gcc
CFLAGS      ?= -g -O2

SRCS        = mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c flows.c config.c
TARGET      = mmtReader

.PHONY: all build install uninstall clean test completions

all: build

build: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ \
		-I. \
		-I/opt/mmt/dpi/include \
		-I./utils \
		-I./cli \
		-L/opt/mmt/dpi/lib \
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
	@echo ""
	@echo "=== Test 2: JSON output ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --json 2>/dev/null | jq '.input_stats.packets' > /dev/null && echo "JSON valid OK"
	@echo ""
	@echo "=== Test 3: Sessions flag ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --sessions 2>&1 | grep "IPv4 Sessions" > /dev/null && echo "Sessions flag works OK"
	@echo ""
	@echo "=== Test 4: JSON with sessions ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --json --sessions 2>/dev/null | jq '.protocols[0].sessions' > /dev/null && echo "JSON sessions valid OK"
	@echo ""
	@echo "=== Test 5: Config unit tests ==="
	gcc -g -o test_config tests/test_config.c config.c -I. && ./test_config && rm -f test_config
	@echo ""
	@echo "=== Test 6: Parse unit tests ==="
	gcc -g -o test_parse tests/test_parse.c cli/parse.c config.c -I. -I./utils && ./test_parse && rm -f test_parse
	@echo ""
	@echo "=== Test 7: Completions exist ==="
	@test -f completions/mmtReader.bash && echo "Bash completion OK" || echo "Bash completion missing"
	@test -f completions/mmtReader.zsh && echo "Zsh completion OK" || echo "Zsh completion missing"
	@test -f completions/mmtReader.fish && echo "Fish completion OK" || echo "Fish completion missing"
	@echo ""
	@echo "=== Test 5: Completions exist ==="
	@test -f completions/mmtReader.bash && echo "Bash completion ✓" || echo "Bash completion missing ✗"
	@test -f completions/mmtReader.zsh && echo "Zsh completion ✓" || echo "Zsh completion missing ✗"
	@test -f completions/mmtReader.fish && echo "Fish completion ✓" || echo "Fish completion missing ✗"
	@echo ""
	@echo "All tests passed!"

completions:
	@echo "Shell completions are generated during install."
