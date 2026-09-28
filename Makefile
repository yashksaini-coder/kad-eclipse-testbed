.PHONY: check fmt fmt-check lint test grind all

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
