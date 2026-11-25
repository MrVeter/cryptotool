CXX ?= g++
BUILD_DIR := build
BIN_DIR := $(BUILD_DIR)/bin
OBJ_DIR := $(BUILD_DIR)/obj

WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wold-style-cast \
            -Wcast-qual -Wnon-virtual-dtor -Wnull-dereference -Werror
CXXFLAGS ?= -O2
CXXFLAGS += -std=c++17 $(WARNINGS) -MMD -MP
CPPFLAGS += -Iinclude -Isrc -Iplugins

ifeq ($(OS),Windows_NT)
    EXE_SUFFIX := .exe
    LIBRARY_PREFIX :=
    LIBRARY_SUFFIX := .dll
    OPENSSL_DIR ?= deps
    OPENSSL_CFLAGS := -I$(OPENSSL_DIR)/include
    OPENSSL_LIBS := -L$(OPENSSL_DIR)/lib -lcrypto
    HOST_LIBS := -lshell32
    PIC_FLAGS :=
    LDFLAGS += -static-libgcc -static-libstdc++
else
    EXE_SUFFIX :=
    LIBRARY_PREFIX := lib
    LIBRARY_SUFFIX := .so
    OPENSSL_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
    OPENSSL_LIBS := $(or $(shell pkg-config --libs libcrypto 2>/dev/null),-lcrypto)
    HOST_LIBS := -ldl
    PIC_FLAGS := -fPIC
endif

ALGORITHMS := elgamal table vernam
PLUGINS := $(foreach name,$(ALGORITHMS),$(BIN_DIR)/$(LIBRARY_PREFIX)$(name)$(LIBRARY_SUFFIX))
PROGRAM := $(BIN_DIR)/cryptotool$(EXE_SUFFIX)
TEST_PROGRAM := $(BIN_DIR)/cryptotool_tests$(EXE_SUFFIX)

HOST_SOURCES := src/platform.cpp src/plugin_loader.cpp
PROGRAM_SOURCES := src/main.cpp src/application.cpp src/command_line.cpp src/crypto_service.cpp \
                   src/byte_stream.cpp src/stream_io.cpp $(HOST_SOURCES)
TEST_SOURCES := tests/plugin_tests.cpp $(HOST_SOURCES)

object_files = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(1))
PROGRAM_OBJECTS := $(call object_files,$(PROGRAM_SOURCES))
TEST_OBJECTS := $(call object_files,$(TEST_SOURCES))

.PHONY: all plugins test clean
.SECONDARY:

all: $(PROGRAM) $(TEST_PROGRAM) $(PLUGINS)

plugins: $(PLUGINS)

$(PROGRAM): $(PROGRAM_OBJECTS) | $(PLUGINS)
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) $^ $(HOST_LIBS) -o $@
ifeq ($(OS),Windows_NT)
	cp $(OPENSSL_DIR)/bin/libcrypto-3-x64.dll $(BIN_DIR)/
endif

$(TEST_PROGRAM): $(TEST_OBJECTS) | $(PLUGINS)
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) $^ $(HOST_LIBS) -o $@

$(BIN_DIR)/$(LIBRARY_PREFIX)%$(LIBRARY_SUFFIX): $(OBJ_DIR)/plugins/%.o
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -shared $< $(OPENSSL_LIBS) -o $@

define PLUGIN_OBJECT_RULE
$(OBJ_DIR)/plugins/$(1).o: plugins/$(1)/$(1).cpp
	@mkdir -p $$(dir $$@)
	$$(CXX) $$(CPPFLAGS) $$(OPENSSL_CFLAGS) $$(CXXFLAGS) $$(PIC_FLAGS) -fvisibility=hidden -c $$< -o $$@
endef
$(foreach name,$(ALGORITHMS),$(eval $(call PLUGIN_OBJECT_RULE,$(name))))

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

test: $(TEST_PROGRAM) $(PLUGINS)
	$(TEST_PROGRAM)

clean:
	rm -rf $(BUILD_DIR)

-include $(shell find $(OBJ_DIR) -name '*.d' 2>/dev/null)
