# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#
# Luca Kernel-Native Network Observatory
#
#   make                  build into ./build. Uses the system libbpf when
#                         pkg-config reports >= $(LIBBPF_MIN); otherwise a
#                         pinned libbpf release is cloned and linked statically.
#   make LIBBPF=vendored  always use the pinned libbpf
#   make check            report whether this host can run the observatory
#   make test             kernel-level smoke test in network namespaces (root;
#                         ATTACH=tc or ATTACH=tcx forces an attach mode)
#   make clean
#
# Requirements: clang >= 12 (BPF target; CO-RE type checks), a C compiler,
# make, pkg-config, libelf and zlib headers, Linux UAPI headers; git only for
# LIBBPF=vendored. Where the default clang is older (Debian 11), install a
# newer one and pass it, e.g. make CLANG=clang-13.

OUTPUT     ?= build
CLANG      ?= clang
CC         ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS     ?= -O2 -g -Wall -Wextra
LIBBPF     ?= auto
LIBBPF_MIN := 0.6.0
LIBBPF_TAG ?= v1.5.0
LIBBPF_REPO ?= https://github.com/libbpf/libbpf.git
# Recorded in every snapshot so that results name the code that produced them.
LUCA_COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)

CLANG_MIN  := 12
CLANG_MAJOR = $(shell $(CLANG) -dumpversion 2>/dev/null | cut -d. -f1)

ARCH_TRIPLET := $(shell $(CC) -dumpmachine 2>/dev/null)
# Debian-family systems keep asm/types.h in the multiarch include directory,
# which clang does not search for the BPF target.
BPF_SYS_INCLUDES := $(if $(wildcard /usr/include/$(ARCH_TRIPLET)/asm),-I/usr/include/$(ARCH_TRIPLET))

ifeq ($(LIBBPF),auto)
override LIBBPF := $(if $(shell $(PKG_CONFIG) --atleast-version=$(LIBBPF_MIN) libbpf 2>/dev/null && echo ok),system,vendored)
endif

ifeq ($(LIBBPF),system)
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS   := $(shell $(PKG_CONFIG) --libs libbpf)
LIBBPF_DEP    :=
else
LIBBPF_SRC    := $(abspath $(OUTPUT)/libbpf-src)
LIBBPF_OBJ    := $(abspath $(OUTPUT)/libbpf)
LIBBPF_A      := $(LIBBPF_OBJ)/libbpf.a
LIBBPF_CFLAGS := -I$(LIBBPF_OBJ) -I$(LIBBPF_SRC)/include/uapi
LIBBPF_LIBS   := $(LIBBPF_A) -lelf -lz
LIBBPF_DEP    := $(LIBBPF_A)
endif

BPF_CFLAGS := -g -O2 -target bpf -Wall -Ibpf $(BPF_SYS_INCLUDES) $(LIBBPF_CFLAGS)
BPF_HEADERS := bpf/luca_observatory.h bpf/luca_bpf_common.h

TARGETS := $(OUTPUT)/luca-observatory $(OUTPUT)/luca_observatory.bpf.o \
	   $(OUTPUT)/luca_drops.bpf.o

.PHONY: all check test clean
all: $(TARGETS)
	@echo "Built with $(LIBBPF) libbpf: $(TARGETS)"

$(OUTPUT):
	mkdir -p $@

ifneq ($(LIBBPF),system)
$(LIBBPF_A): | $(OUTPUT)
	rm -rf $(LIBBPF_SRC)
	git clone --depth 1 --branch $(LIBBPF_TAG) $(LIBBPF_REPO) $(LIBBPF_SRC)
	$(MAKE) -C $(LIBBPF_SRC)/src BUILD_STATIC_ONLY=1 OBJDIR=$(LIBBPF_OBJ)/obj \
		DESTDIR=$(LIBBPF_OBJ) INCLUDEDIR= LIBDIR= UAPIDIR= install
endif

$(OUTPUT)/%.bpf.o: bpf/%.bpf.c $(BPF_HEADERS) $(LIBBPF_DEP) | $(OUTPUT)
	@test "$(CLANG_MAJOR)" -ge $(CLANG_MIN) 2>/dev/null || { 		echo "$(CLANG) is version '$(CLANG_MAJOR)'; clang >= $(CLANG_MIN) is required (make CLANG=clang-NN)" >&2; 		exit 1; }
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/luca-observatory: src/luca_observatory.c bpf/luca_observatory.h $(LIBBPF_DEP) | $(OUTPUT)
	$(CC) $(CFLAGS) -DLUCA_COMMIT='"$(LUCA_COMMIT)"' -Ibpf $(LIBBPF_CFLAGS) $< $(LIBBPF_LIBS) -o $@

check:
	@sh scripts/check-host.sh $(OUTPUT)

test: all
	python3 tests/netns_smoke.py --build-dir $(OUTPUT) $(if $(ATTACH),--attach $(ATTACH))

clean:
	rm -rf $(OUTPUT)
