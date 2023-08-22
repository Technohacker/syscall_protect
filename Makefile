PYTHON := python
PIP := $(PYTHON) -m pip
CMAKE := cmake

# Create a venv if it doesn't exist already.
# Make sure to source setup-env.sh before building the rest
.venv:
	$(PYTHON) -m venv .venv

mbedtls:
# Install mbedtls build deps
	$(PIP) install -r mbedtls/scripts/basic.requirements.txt
# Prepare the build
# 1. Force all executables to be statically linked
# 2. Disable tests
	mkdir -p mbedtls/build
	$(CMAKE) \
		-DCMAKE_EXE_LINKER_FLAGS="-static" \
		-DCMAKE_FIND_LIBRARY_SUFFIXES=".a" \
		-DENABLE_TESTING=Off \
		-B mbedtls/build -S mbedtls
# Build it
	$(MAKE) -C mbedtls/build

clean:
	rm -r mbedtls/build

all: mbedtls

.PHONY: all mbedtls
