# Keep outputs isolated from any consumer's build tree.
BUILD_VOLUME ?= /Volumes/SSD1
ifeq ($(origin CARGO_TARGET_DIR),undefined)
CARGO_TARGET_DIR := $(shell sh scripts/cargo-target-dir.sh magicrun "$(CURDIR)" "$(BUILD_VOLUME)")
endif
ifeq ($(strip $(CARGO_TARGET_DIR)),)
$(error CARGO_TARGET_DIR must not be empty)
endif
export CARGO_TARGET_DIR
.DEFAULT_GOAL := help

help:
	@echo "MagicRun: make check | build | test | test-lifecycle | inventory ARGS='...' | classification ARGS='...' | replay ARGS='...'"
	@echo "Cargo artifacts: $(CARGO_TARGET_DIR) (print-target-dir; override CARGO_TARGET_DIR or BUILD_VOLUME)"
	@echo "Architecture: check-architecture | test-architecture | architecture-snapshot (candidate only)"

print-target-dir:
	@printf '%s\n' "$(CARGO_TARGET_DIR)"

# Routing regressions only: a harmless recorder replaces Cargo.
test-build-paths:
	python3 scripts/tests/test_build_paths.py

check-architecture:
	python3 scripts/check_architecture.py

architecture-snapshot:
	@python3 scripts/check_architecture.py --snapshot

test-architecture:
	python3 scripts/tests/test_architecture.py

check: check-architecture
	python3 scripts/check_store_durability_adoption.py
	cargo check --workspace --all-targets

build:
	cargo build --workspace

test:
	cargo test --workspace

test-lifecycle:
	cargo test -p tool-runtime-core credential_lifecycle

inventory classification replay:
	cargo run -p tool-runtime-core --bin tool-runtime-$@ -- $(ARGS)

.PHONY: help print-target-dir test-build-paths check-architecture architecture-snapshot test-architecture check build test test-lifecycle inventory classification replay
