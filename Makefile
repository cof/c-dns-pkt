# Makefile for c-dns-pkt
#
# targets
# -------
# all     : build cmds (dns-inpsect,dns-gen)
# test    : run tests
# install : install dns-inspect
# gen-bpf : generate BFP filter

# #######################
#     Config
# #######################

DNS_INSP := dns-inspect
DNS_GEN  := dns-gen

# dirs
BUILD_DIR := build
SRC_DIR   := src
INSTALL_DIR = /usr/local/bin

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
COMMON_CFLAGS := -Wall \
	-Werror=sign-compare \
	-Werror=discarded-qualifiers \
	-Werror=shadow=compatible-local \
	-Werror=implicit-function-declaration \
	$(CPP_FLAGS) $(GCC_DEPS)
DEBUG_CFLAGS  := -ggdb3 -fno-omit-frame-pointer -DDEBUG=1

# release build
# -----------
CFLAGS  = -O2 $(COMMON_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS = --static

MAKEFLAGS += --no-print-directory

# Default target - build cmds
# --------------------------
.PHONY: all
all: $(BUILD_DIR) $(DNS_INSP) $(DNS_GEN)

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

# dns-insp
# ---------
INSP_SRCS = src/util.c src/log.c src/pcap.c src/dns_proto.c src/dns_inspect.c
INSP_OBJS = $(INSP_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
INSP_DEPS = $(INSP_OBJS:.o=.d)
-include $(INSP_DEPS)
$(DNS_INSP): $(INSP_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(INSP_OBJS) -o $@

# dns-gen
# -------
GEN_SRCS = src/util.c src/log.c src/pcap.c src/dns_proto.c  src/dns_gen.c
GEN_OBJS = $(GEN_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
GEN_DEPS = $(GEN_OBJS:.o=.d)
-include $(GEN_DEPS)
$(DNS_GEN): $(GEN_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(CFLAGS) $(LDFLAGS) $(GEN_OBJS) -o $@

# compile rule
# ------------
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(cmd_CC) $(CFLAGS) -c $< -o $@

# add non-root capabilities
# -------------------------
SETCAP_CMD = sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf=eip'

# gen-bpf
# -------
.PHONY: gen-bpf
BPF_FILTER = $(BUILD_DIR)/bpf_filter.h
BPF_OBJFILE = $(BUILD_DIR)/filter.o
BPF_CFLAGS = -O2 -I/usr/include
gen-bpf:
	bpf-gcc $(BPF_CFLAGS) -c bpf/filter.c -o $(BPF_OBJFILE)
	bpf-objdump -d $(BPF_OBJFILE) | awk -f bpf/gen_insn.awk > $(BPF_FILTER)

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
test: $(DNS_INSP) $(DNS_GEN)
	@echo "Starting tests"
	$(Q)./test-integration.sh

# install
# -------
.PHONY: install
install:
	@mkdir -p $(INSTALL_DIR)
	$(INSTALL) -D -m 755 $(DNS_INSP) $(INSTALL_DIR)/$(DNS_INSP)
	$(INSTALL) -D -m 755 $(DNS_GEN) $(INSTALL_DIR)/$(DNS_GEN)
	$(SETCAP_CMD) $(INSTALL_DIR)/$(DNS_INSP) || true

# clean
# ----
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(DNS_INSP) $(DNS_GEN)
