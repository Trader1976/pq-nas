# Adapted from mlkem-native/examples/basic
# (SPDX-License-Identifier: CC-BY-4.0)

.PHONY: build clean
.DEFAULT_GOAL := all

CC = emcc
CFLAGS = -O3 -Wall -Wextra -DEMSCRIPTEN
WASM_FLAGS = -s WASM=1 \
             -s EXPORTED_RUNTIME_METHODS='["getValue","setValue","HEAP8","HEAPU8","stackSave","stackAlloc","stackRestore"]' \
             -s ALLOW_MEMORY_GROWTH=0 \
             -s MODULARIZE=1 \
			 -s EXPORT_ES6=1 \
             -s EXPORT_NAME="'MLKEM768Module'" \
             -s ENVIRONMENT='web,webview,worker' \
             -s EXPORTED_FUNCTIONS='["_mlkem768_keypair_derand","_mlkem768_enc_derand","_mlkem768_dec"]' \
             --no-entry \
			 -s SINGLE_FILE \
			 -s EXIT_RUNTIME=0 \
			 -s INCOMING_MODULE_JS_API=[] \
			 --emit-tsd wasm-module.d.ts


# When called from the root Makefile, CROSS_PREFIX has already been added here
ifeq (,$(findstring $(CROSS_PREFIX),$(CC)))
CC  := $(CROSS_PREFIX)$(CC)
endif

# mlkem-native source and header files
#
# Use the authoritative vendored copy in server/third_party/mlkem-native.
# This avoids a nested submodule/gitlink under src/mlkem-native and keeps
# fresh clones reproducible without requiring recursive submodule setup.
MLKEM_NATIVE_DIR ?= ../../mlkem-native

# If you are not concerned about minimizing for a specific backend,
# you can just include _all_ source files into your build.
MLK_SOURCE=$(wildcard                    \
	$(MLKEM_NATIVE_DIR)/mlkem/src/*.c           \
	$(MLKEM_NATIVE_DIR)/mlkem/src/**/*.c        \
	$(MLKEM_NATIVE_DIR)/mlkem/src/**/**/*.c     \
	$(MLKEM_NATIVE_DIR)/mlkem/src/**/**/**/*.c)

# Wrapper source code
APP_SOURCE=$(wildcard *.c)

ALL_SOURCE=$(MLK_SOURCE) $(APP_SOURCE)

BUILD_DIR=build
BIN=wasm-module.js


CFLAGS := \
	-Wall \
	-Wextra \
	-Werror \
	-Wshadow \
	-Werror \
	-Wpointer-arith \
	-Wredundant-decls \
	-Wno-long-long \
	-Wno-unknown-pragmas \
	-Wno-unused-command-line-argument \
	-fomit-frame-pointer \
	-std=c99 \
	-pedantic \
	-MMD \
	-O3 \
	$(CFLAGS)

CFLAGS += -I$(MLKEM_NATIVE_DIR)
CFLAGS += -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem

BINARY_NAME_FULL_768=$(BUILD_DIR)/$(BIN)
BINARIES_FULL=$(BINARY_NAME_FULL_768)

$(BINARY_NAME_FULL_768): CFLAGS += -DMLK_CONFIG_PARAMETER_SET=768

$(BINARIES_FULL): $(ALL_SOURCE)
	echo "$@"
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(WASM_FLAGS) $^ -o $@

all: build

build: $(BINARIES_FULL)

clean:
	rm -rf $(BUILD_DIR)
