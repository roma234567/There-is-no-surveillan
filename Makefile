CXX      ?= g++
CXXFLAGS ?= -std=c++20 -Wall -Wextra -O2

BUILD_DIR := build/host

.PHONY: all clean test preview

all: $(BUILD_DIR)/sentineld $(BUILD_DIR)/sentinelctl

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/sentineld: native/daemon/sentineld.cpp native/daemon/firewall_controller.hpp native/daemon/proxy_relay.hpp native/include/sentinel_protocol.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -pthread native/daemon/sentineld.cpp -o $@

$(BUILD_DIR)/sentinelctl: native/cli/sentinelctl.cpp native/include/sentinel_protocol.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) native/cli/sentinelctl.cpp -o $@

test: all
	python3 scripts/test_daemon.py

clean:
	rm -rf build
