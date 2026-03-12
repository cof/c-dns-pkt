
# Makefile for c-dns-pkt
# make all
# make tests

# verbosity - aka Kbuild/HAProxy style
V = 0
Q = @
ifeq ($V,1)
Q=
endif

DEBUG ?= 0

ifeq ($(V),1)
cmd_CC  = $(CC)
cmd_LD  = $(CC)
else
cmd_CC   = $(Q)echo "  CC    $@";$(CC)
cmd_LD   = $(Q)echo "  LD    $@";$(CC)
endif

# build commmand
INSTALL = install
CC = gcc
LD = gcc
CTAGS = ctags

# compiler flags
CFLAGS += -D_GNU_SOURCE -Wall -Werror -O2 -Isrc -MMD -MP
ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g
endif
LDFLAGS =


# dirs
BUILD_DIR = build
SRC_DIR = src
BIN_DIR = bin
SCRIPTS_DIR = scripts

DNS_INSPECT = dns-inspect
DNS_GEN = dns-gen

.PHONY: all
all: $(BUILD_DIR) dns-inspect dns-gen

# object files
$(BUILD_DIR):
	@mkdir -p $@

# build our binaries

# dns-inspect
DNS_INSPECT_SRCS = src/util.c src/log.c src/pcap.c src/dns_proto.c src/dns_inspect.c
DNS_INSPECT_OBJS = $(DNS_INSPECT_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DNS_INSPECT_DEPS = $(DNS_INSPECT_OBJS:.o=.d)
-include $(DNS_INSPECT_DEPS)
$(DNS_INSPECT): $(DNS_INSPECT_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(LDFLAGS) $(DNS_INSPECT_OBJS) -o $@

# dns-gen
DNS_GEN_SRCS = src/util.c src/log.c src/pcap.c src/dns_proto.c  src/dns_gen.c
DNS_GEN_OBJS = $(DNS_GEN_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DNS_GEN_DEPS = $(DNS_GEN_OBJS:.o=.d)
-include $(DNS_GEN_DEPS)
$(DNS_GEN): $(DNS_GEN_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(LDFLAGS) $(DNS_GEN_OBJS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(cmd_CC) $(CFLAGS) -c $< -o $@

.PHONY: test
test:  $(DNS_INSPECT) $(DNS_GEN)
	@echo "Starting tests"
	$(Q)./test-integration.sh

SOURCES = $(wildcard src/*.c src/*.h)
.PHONY: tags
tags: $(SOURCES)
	@echo "Creating tags file"
	$(Q)$(CTAGS) $(SOURCES)


# =======
# install
# =======
.PHONY: install
install : all
	@mkdir -p $(BIN_DIR)
	$(INSTALL) -D -m 755 $(DNS_INSPECT) $(BIN_DIR)/$(DNS_INSPECT)
	$(INSTALL) -D -m 755 $(DNS_GEN) $(BIN_DIR)/$(DNS_GEN)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(DNS_INSPECT) $(DNS_GEN)
