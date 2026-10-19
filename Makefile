.PHONY: check fmt fmt-check lint test grind results all

all: fmt-check lint test

check:
	cargo check --all-targets

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

# Smoke test the attack side without a network.
grind:
	cargo run --release -- grind --trials 1000000

# Regenerate the Phase 1 result file. Takes ~16 minutes at the default plan;
# pass PLAN to shorten it, e.g. `make results PLAN=--plan=100000:5`.
# Result files are generated, never hand-copied — see docs/results/README.md.
results: RESULTS_OUT ?= docs/results/$(shell date -u +%Y-%m-%d)-grind.json
results:
	cargo build --release
	python3 scripts/phase1_grind.py $(PLAN) --out $(RESULTS_OUT)
