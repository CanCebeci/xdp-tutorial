# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC ?= llc
CLANG ?= clang
CC ?= gcc

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ../common/
LIBBPF_DIR ?= ../libbpf/src/

COPY_LOADER ?=
LOADER_DIR ?= $(COMMON_DIR)/../basic-solutions

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I../headers/
LDFLAGS ?= -L$(LIBBPF_DIR)

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/
BPF_CFLAGS += -Iinclude -I.
#BPF_CFLAGS += -I/lib/modules/5.4.0-89-generic/build/include/
#BPF_CFLAGS += -I/home/cancebeci/linux_5_4/include/

# for bpf_xdp.c 
# BPF_CFLAGS += -DSKIP_DEBUG=1 -DENABLE_IPV4=1 -DENABLE_IPV6=1 -DENABLE_HOST_SERVICES_TCP=1 -DENABLE_HOST_SERVICES_UDP=1 -DENABLE_HOST_REDIRECT=1 -DENABLE_ROUTING=1 -DNO_REDIRECT=1 -DPOLICY_VERDICT_NOTIFY=1 -DALLOW_ICMP_FRAG_NEEDED=1 -DENABLE_IDENTITY_MARK=1 -DMONITOR_AGGREGATION=3 -DCT_REPORT_FLAGS=0x0002 -DENABLE_HOST_FIREWALL=1 -DHAVE_LPM_TRIE_MAP_TYPE=1 -DHAVE_LRU_HASH_MAP_TYPE=1 -DENABLE_MASQUERADE=1 -DENABLE_SRC_RANGE_CHECK=1 -DENABLE_NODEPORT=1 -DENABLE_NODEPORT_ACCELERATION=1 -DENABLE_SESSION_AFFINITY=1 -DENABLE_DSR_ICMP_ERRORS=1 -DENABLE_DSR=1 -DENABLE_DSR_HYBRID=1 -DENABLE_IPV4_FRAGMENTS=1 -DENABLE_PREFILTER=1 -DLB_SELECTION=1 -DLB_SELECTION_MAGLEV=1

# for bpf_host.c 
#BPF_CFLAGS += -DSKIP_DEBUG=1 -DENABLE_IPV4=1 -DENABLE_IPV6=1 -DENABLE_HOST_SERVICES_TCP=1 -DENABLE_HOST_SERVICES_UDP=1 -DENABLE_HOST_REDIRECT=1 -DENABLE_ROUTING=1 -DNO_REDIRECT=1 -DPOLICY_VERDICT_NOTIFY=1 -DALLOW_ICMP_FRAG_NEEDED=1 -DENABLE_IDENTITY_MARK=1 -DMONITOR_AGGREGATION=3 -DCT_REPORT_FLAGS=0x0002 -DENABLE_HOST_FIREWALL=1 -DHAVE_LPM_TRIE_MAP_TYPE=1 -DHAVE_LRU_HASH_MAP_TYPE=1 -DENABLE_MASQUERADE=1 -DENABLE_SRC_RANGE_CHECK=1 -DENABLE_NODEPORT=1 -DENABLE_NODEPORT_ACCELERATION=1 -DENABLE_SESSION_AFFINITY=1 -DENABLE_DSR_ICMP_ERRORS=1 -DENABLE_DSR=1 -DENABLE_DSR_HYBRID=1 -DENABLE_IPV4_FRAGMENTS=1 -DENCAP_IFINDEX=1 -DTUNNEL_MODE=1 -DENABLE_EGRESS_GATEWAY=1 

# for bpf_network.c
#BPF_CFLAGS += -DENABLE_IPV4=1 -DENABLE_IPV6=1 -DENABLE_IPSEC=1 -DIP_POOLS=1 -DHAVE_LPM_TRIE_MAP_TYPE -DHAVE_LRU_HASH_MAP_TYPE

# for bpf_sock.c
BPF_CFLAGS += -DSKIP_DEBUG=1 -DENABLE_IPV4=1 -DENABLE_IPV6=1 -DENABLE_HOST_SERVICES_TCP=1 -DENABLE_HOST_SERVICES_UDP=1 -DENABLE_HOST_REDIRECT=1 -DENABLE_ROUTING=1 -DNO_REDIRECT=1 -DPOLICY_VERDICT_NOTIFY=1 -DALLOW_ICMP_FRAG_NEEDED=1 -DENABLE_IDENTITY_MARK=1 -DMONITOR_AGGREGATION=3 -DCT_REPORT_FLAGS=0x0002 -DENABLE_HOST_FIREWALL=1 -DHAVE_LPM_TRIE_MAP_TYPE=1 -DHAVE_LRU_HASH_MAP_TYPE=1 -DENABLE_MASQUERADE=1 -DENABLE_SRC_RANGE_CHECK=1 -DENABLE_NODEPORT=1 -DENABLE_NODEPORT_ACCELERATION=1 -DENABLE_SESSION_AFFINITY=1 -DENABLE_DSR_ICMP_ERRORS=1 -DENABLE_DSR=1 -DENABLE_DSR_HYBRID=1 -DENABLE_IPV4_FRAGMENTS=1 -DENABLE_NAT46=1 -DENCAP_IFINDEX=1 -DTUNNEL_MODE=1 -DLB_SELECTION=1 -DLB_SELECTION_MAGLEV=1 

BPF_CFLAGS += -D__NR_CPUS__=128 -O2 -g -target bpf -emit-llvm -Wall -Werror -Wshadow -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end # -Wdeclaration-after-statement -std=gnu89 -nostdinc -Wextra (last one complains about unused params)
BPF_CFLAGS += -Wno-unused-function

LIBS = -l:libbpf.a -lelf $(USER_LIBS)

all: llvm-check $(USER_TARGETS) $(XDP_OBJ) $(COPY_LOADER) $(COPY_STATS)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(COPY_LOADER) $(COPY_STATS)
	rm -f *.ll
	rm -f *~

ifdef COPY_LOADER
$(COPY_LOADER): $(LOADER_DIR)/${COPY_LOADER:=.c} $(COMMON_H)
	make -C $(LOADER_DIR) $(COPY_LOADER)
	cp $(LOADER_DIR)/$(COPY_LOADER) $(COPY_LOADER)
endif

ifdef COPY_STATS
$(COPY_STATS): $(LOADER_DIR)/${COPY_STATS:=.c} $(COMMON_H)
	make -C $(LOADER_DIR) $(COPY_STATS)
	cp $(LOADER_DIR)/$(COPY_STATS) $(COPY_STATS)
# Needing xdp_stats imply depending on header files:
EXTRA_DEPS += $(COMMON_DIR)/xdp_stats_kern.h $(COMMON_DIR)/xdp_stats_kern_user.h
endif

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) \
	 $< $(LIBS)

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(OBJECT_LIBBPF)
	$(CLANG) -S \
	    -D __BPF_TRACING__ \
		-Wno-compare-distinct-pointer-types \
	    $(BPF_CFLAGS) \
		-c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

# 	    -target bpf \
		-Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm 