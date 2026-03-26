# Makefile for c-dns-pkt
# make all
# make tests

# #######################
#     Config
# #######################

# dirs
BUILD_DIR = build
SRC_DIR = src
BIN_DIR = bin
SCRIPTS_DIR = scripts

DNS_INSPECT = dns-inspect
DNS_GEN = dns-gen

# build tools
# --------------
INSTALL = install
CC = gcc
LD = gcc
CTAGS = ctags

# verbosity - aka Kbuild/HAProxy style
# -----------------------------------
V = 0
Q = @
ifeq ($V,1)
Q=
endif

ifeq ($(V),1)
cmd_CC  = $(CC)
cmd_LD  = $(CC)
else
cmd_CC   = $(Q)echo "  CC    $@";$(CC)
cmd_LD   = $(Q)echo "  LD    $@";$(CC)
endif

# compiler flags
# --------------
GCC_DEPS      := -MMD -MP
CPP_FLAGS     := -D_GNU_SOURCE -Isrc
EXTRA_CFLAGS  := -Wextra -Wno-missing-field-initializers
COMMON_CFLAGS := -Wall $(CPP_FLAGS) $(GCC_DEPS) 
DEBUG_CFLAGS   := -ggdb3 -fno-omit-frame-pointer -DDEBUG=1

# release build
# -----------
CFLAGS  = -O2 $(COMMON_CFLAGS) $(EXTRA_CFLAGS)

MAKEFLAGS += --no-print-directory


# Default target - build cmds
# --------------------------
.PHONY: all
all: $(BUILD_DIR) dns-inspect dns-gen

# debug build
# -----------
debug: CFLAGS = -O0 $(COMMON_CFLAGS) $(DEBUG_CFLAGS)
debug: all

# asan build
# -----------
asan: CFLAGS = -O0 $(COMMON_CFLAGS) $(DEBUG_CFLAGS) -fsanitize=address 
asan: LDFLAGS = -fsanitize=address
asan: all

# valgrind build
# --------------
valgrind: CFLAGS = -O0 $(COMMON_CFLAGS) $(DEBUG_CFLAGS)
valgrind: LDFLAGS = 
valgrind: all

# object files
$(BUILD_DIR):
	@mkdir -p $@

# build our binaries

# dns-inspect
# -----------
DNS_INSPECT_SRCS = src/util.c src/log.c src/pcap.c src/dns_proto.c src/dns_inspect.c
DNS_INSPECT_OBJS = $(DNS_INSPECT_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DNS_INSPECT_DEPS = $(DNS_INSPECT_OBJS:.o=.d)
-include $(DNS_INSPECT_DEPS)
$(DNS_INSPECT): $(DNS_INSPECT_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(DNS_INSPECT_OBJS) -o $@

# dns-gen
# -------
DNS_GEN_SRCS = src/util.c src/log.c src/pcap.c src/dns_proto.c  src/dns_gen.c
DNS_GEN_OBJS = $(DNS_GEN_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DNS_GEN_DEPS = $(DNS_GEN_OBJS:.o=.d)
-include $(DNS_GEN_DEPS)
$(DNS_GEN): $(DNS_GEN_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(DNS_GEN_OBJS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(cmd_CC) $(CFLAGS) -c $< -o $@

# tags file
# ----------
.PHONY: tags
SOURCES = $(wildcard src/*.c src/*.h)
tags: $(SOURCES)
	@echo "Creating tags file"
	$(Q)$(CTAGS) $(SOURCES)

# test
# ----
.PHONY: test
test:  $(DNS_INSPECT) $(DNS_GEN)
	@echo "Starting tests"
	$(Q)./test-integration.sh

# install
# -------
.PHONY: install
install : all
	@mkdir -p $(BIN_DIR)
	$(INSTALL) -D -m 755 $(DNS_INSPECT) $(BIN_DIR)/$(DNS_INSPECT)
	$(INSTALL) -D -m 755 $(DNS_GEN) $(BIN_DIR)/$(DNS_GEN)

# clean
# ----
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(DNS_INSPECT) $(DNS_GEN)
