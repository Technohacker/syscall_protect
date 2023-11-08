# The folder this Makefile is in, aka the project root
ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

PYTHON := python
PIP := $(PYTHON) -m pip
CMAKE := cmake
VENV_PATH := $(ROOT_DIR)/.venv

KMOD_PATH := $(ROOT_DIR)/syscall_protect_kmod
KMOD := $(KMOD_PATH)/syscall_protect.ko

all: venv musl mbedtls kmod

include Makefile.deps

# Create a venv if it doesn't exist already.
# Make sure to source setup-env.sh before building the rest
$(VENV_PATH):
	$(PYTHON) -m venv $(VENV_PATH)

$(KMOD_PATH):
	cd syscall_protect_kmod && \
		$(MAKE) KDIR=$(KERNEL_PATH) rust-analyzer

$(KMOD): $(KERNEL_PATH) $(KMOD_PATH)
	cd syscall_protect_kmod && \
		$(MAKE) KDIR=$(KERNEL_PATH) LLVM=1

clean:
	rm -r $(TOOLCHAIN_PATH) || true
	cd $(MUSL_PATH) && $(MAKE) clean 
	rm -r $(MBEDTLS_PATH)/build || true

# Phony rules
venv: $(VENV_PATH)
musl: $(TOOLCHAIN_PATH)
mbedtls: $(MBEDTLS_BUILD)
kernel: $(KERNEL)
kmod: $(KMOD)

.PHONY: all venv musl mbedtls kernel kmod clean
