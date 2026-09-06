# Keep outputs isolated from any consumer's build tree.
export CARGO_TARGET_DIR ?= $(CURDIR)/target
.DEFAULT_GOAL := help

help:
	@echo "MagicRun: make check | test | test-lifecycle | inventory ARGS='...' | classification ARGS='...' | replay ARGS='...'"

check:
	python3 scripts/check_store_durability_adoption.py
	cargo check --workspace --all-targets

test:
	cargo test --workspace

test-lifecycle:
	cargo test -p tool-runtime-core credential_lifecycle

inventory classification replay:
	cargo run -p tool-runtime-core --bin tool-runtime-$@ -- $(ARGS)

.PHONY: help check test test-lifecycle inventory classification replay
