# MMT-Reader Makefile — lightweight build helper
# Primary installer is install.sh (self-contained, installs everything)

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
MANDIR      ?= $(PREFIX)/share/man
MAN1DIR     ?= $(MANDIR)/man1

CC          ?= gcc
CFLAGS      ?= -g -O2

SRCS        = mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c
TARGET      = mmtReader

.PHONY: all build install uninstall clean test

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
	@echo "Installed to $(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(MAN1DIR)/mmtReader.1
	@echo "Uninstalled."

clean:
	rm -f $(TARGET)

test: build
	@echo "=== Test 1: Text output ==="
	./$(TARGET) analyze -t smallFlows.pcap -a 2>&1 | tail -5
	@echo ""
	@echo "=== Test 2: JSON output ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --json 2>/dev/null | jq '.input_stats.packets' > /dev/null && echo "JSON valid ✓"
	@echo ""
	@echo "=== Test 3: Sessions flag ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --sessions 2>&1 | grep "IPv4 Sessions" > /dev/null && echo "Sessions flag works ✓"
	@echo ""
	@echo "=== Test 4: JSON with sessions ==="
	./$(TARGET) analyze -t smallFlows.pcap -a --json --sessions 2>/dev/null | jq '.protocols[0].sessions' > /dev/null && echo "JSON sessions valid ✓"
	@echo ""
	@echo "All tests passed!"
