# MMT-Reader Makefile — lightweight build helper
# Primary installer is install.sh (self-contained, installs everything)

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
MANDIR      ?= $(PREFIX)/share/man
MAN1DIR     ?= $(MANDIR)/man1

CC          ?= gcc
CFLAGS      ?= -g -O2 -Wall

SRCS        = mmtReader.c argparse.c dispatch.c capture.c mmt_handler.c display.c
OBJS        = $(SRCS:.c=.o)
TARGET      = mmtReader

.PHONY: all build install uninstall clean test

all: build

build: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ \
		-I/opt/mmt/dpi/include \
		-L/opt/mmt/dpi/lib \
		-lmmt_core -ldl -lpcap

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< \
		-I/opt/mmt/dpi/include

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
	rm -f $(TARGET) $(OBJS)

test: build
	./$(TARGET) -t smallFlows.pcap -a | tail -15
