# The folder this Makefile is in, aka the project root
ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

PYTHON := python
PIP := $(PYTHON) -m pip
CMAKE := cmake
VENV_PATH := $(ROOT_DIR)/.venv

all: venv musl mbedtls

include Makefile.deps

# Create a venv if it doesn't exist already.
# Make sure to source setup-env.sh before building the rest
$(VENV_PATH):
	$(PYTHON) -m venv $(VENV_PATH)

clean:
	rm -r $(TOOLCHAIN_PATH) || true
	cd $(MUSL_PATH) && $(MAKE) clean 
	rm -r $(MBEDTLS_PATH)/build || true

# Phony rules
venv: $(VENV_PATH)
musl: $(TOOLCHAIN_PATH)
mbedtls: $(MBEDTLS_BUILD)

.PHONY: all venv musl mbedtls clean
