
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
DNS_INSPECT_SRCS = src/util.c src/pcap.c src/dns_proto.c src/dns_inspect.c
DNS_INSPECT_OBJS = $(DNS_INSPECT_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DNS_INSPECT_DEPS = $(DNS_INSPECT_OBJS:.o=.d)
-include $(DNS_INSPECT_DEPS)
$(DNS_INSPECT): $(DNS_INSPECT_OBJS) | $(BUILD_DIR)
	$(cmd_LD) $(LDFLAGS) $(DNS_INSPECT_OBJS) -o $@

# dns-gen
DNS_GEN_SRCS = src/util.c src/dns_proto.c src/dns_gen.c
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


# VM stuff

# alpine linux
OS_VARIANT= alpinelinux3.21
OS_NAME=alpine
REL_VER= 3.21
PATCH_VER=.6
REL_NAME = $(OS_NAME)-$(REL_VER)$(PATCH_VER)
REL_FILE = nocloud_$(REL_NAME)-x86_64-bios-cloudinit-r0.qcow2
REL_DIR = v$(REL_VER)/releases/cloud
MIRROR = https://dl-cdn.alpinelinux.org
REL_URL = $(MIRROR_URL)/$(REL_DIR)/$(REL_FILE)

# our vm
VM_NAME = test-dns
VM_FILE = myalpine.qcow2
VMDIR = vmdir

ifeq ($(origin CACHE_DIR), undefined)
  CACHE_DIR := $(shell echo $${XDG_CACHE_HOME:-$$HOME/.cache}/my-vm-project)
endif

BASE_IMAGE = $(CACHE_DIR)/$(REL_FILE)
RUN_IMAGE = $(VMDIR)/$(VM_FILE)
VM_MAC := 52:54:00:12:34:56
VM_IP  := 192.168.122.243

.PHONY: show-vmconfig
show-vmconfig:
	@echo "MIRROR=$(MIRROR)"
	@echo "REL_URL=$(REL_URL)"
	@echo "REL_FILE=$(REL_FILE)"
	@echo "REL_VER=$(REL_VER)"
	@echo "CACHE_DIR=$(CACHE_DIR)"
	@echo "BASE_IMAGE=$(BASE_IMAGE)"
	@echo "RUN_IMAGE=$(RUN_IMAGE)"

.PHONY: list-vm
list-vm:
	virsh dominfo $(VM_NAME) || true
	virsh domifaddr $(VM_NAME) || true

$(CACHE_DIR):
	mkdir -p $@

$(VMDIR):
	mkdir -p $@

# download image 
$(BASE_IMAGE) : | $(CACHE_DIR)
	wget -nv --no-verbose --show-progress -O $@.tmp $(REL_URL)
	mv $@.tmp $@
	chmod 444 $@

# build image-  XXX  virt-customize requires root read /boot/vmlinux ???
#$(RUN_IMAGE) : $(BASE_IMAGE)
#	@echo "Setting up image file"
#	@cp $(IMAGE_PATH) $(TEST_IMAGE)
#	virt-customize -a $(TEST_IMAGE) \
#	--root-password password:test \
#	--install openssh \
#	--edit '/etc/ssh/sshd_config: s/\#PermitRootLogin.*/PermitRootLogin yes/' \
#	--run-command "rc-update add sshd"
#	@touch $(TEST_IMAGE)

$(RUN_IMAGE): | $(BASE_IMAGE) $(VMDIR)
	cp $(BASE_IMAGE) $@

.PHONY:list-cache
list-cache: $(CACHE_DIR)
	ls -lh $(CACHE_DIR)

# XXX alpline vms will use user-data.yaml to autoconfigure
USER_DATA = tests/user-data.yaml
.PHONY:install-vm
install-vm: $(RUN_IMAGE)
	virt-install \
	--name $(VM_NAME) \
	--virt-type kvm \
	--ram 512 \
	--vcpus 1 \
	--disk path=$(RUN_IMAGE),format=qcow2,bus=virtio \
	--network network=default,model=virtio \
	--cloud-init user-data=$(USER_DATA) \
	--os-variant $(OS_VARIANT) \
	--graphics vnc \
	--rng /dev/urandom \
	--noautoconsole \
	--import

wipe-vm:
	 virsh destroy $(VM_NAME)  || true
	 virsh undefine $(VM_NAME) || true

