# Makefile for c-dns-pkt
# make all
# make tests

# #######################
#     Config
# #######################

# dirs
BUILD_DIR = build
SRC_DIR = src
INSTALL_DIR = /usr/local/bin
SCRIPTS_DIR = scripts

INSPECT := dns-inspect
GEN     := dns-gen

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
COMMON_CFLAGS := -Wall -Werror=implicit-function-declaration $(CPP_FLAGS) $(GCC_DEPS)
DEBUG_CFLAGS  := -ggdb3 -fno-omit-frame-pointer -DDEBUG=1

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
INSPECT_SRCS = src/util.c src/log.c src/pcap.c src/dns_proto.c src/dns_inspect.c
INSPECT_OBJS = $(INSPECT_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
INSPECT_DEPS = $(INSPECT_OBJS:.o=.d)
-include $(INSPECT_DEPS)
$(INSPECT): $(INSPECT_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(INSPECT_OBJS) -o $@

# dns-gen
# -------
GEN_SRCS = src/util.c src/log.c src/pcap.c src/rwbuf.c src/sock.c src/dns_proto.c  src/dns_gen.c
GEN_OBJS = $(GEN_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
GEN_DEPS = $(GEN_OBJS:.o=.d)
-include $(GEN_DEPS)
$(GEN): $(GEN_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(GEN_OBJS) -o $@

# compile rule
# ------------
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(cmd_CC) $(CFLAGS) -c $< -o $@

# add non-root capabilities
# -------------------------
SETCAP_CMD = sudo setcap 'cap_net_raw,cap_net_admin=eip'

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

# setcap
# -------
.PHONY: setcap
setcap : dns-inspect
	@echo "Setting capabilities on $<"
	$(Q) $(SETCAP_CMD) $<

# install
# -------
.PHONY: install
install:
	@mkdir -p $(INSTALL_DIR)
	$(INSTALL) -D -m 755 $(INSPECT) $(INSTALL_DIR)/$(INSPECT)
	$(INSTALL) -D -m 755 $(GEN) $(INSTALL_DIR)/$(GEN)
	$(SETCAP_CMD) $(INSTALL_DIR)/$(INSPECT) || true

# clean
# ----
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(DNS_INSPECT) $(DNS_GEN)
