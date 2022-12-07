# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

.NOTPARALLEL:

export RUST_LOG ?= info,cargo_tarpaulin=off
TEST_FEATURES ?=virtual,pivy-tests,opensc-tests

.PHONY: build-cortex-m4
build-cortex-m4:
	cargo build --target thumbv7em-none-eabi

.PHONY: test
test:
	cargo test --features $(TEST_FEATURES)

.PHONY: check
check:
	cargo fmt --check
	cargo check --all-targets --all-features
	cargo clippy --all-targets --all-features -- -Dwarnings
	RUSTDOCFLAGS='-Dwarnings' cargo doc --all-features
	reuse lint
	
.PHONY: tarpaulin
tarpaulin:
	cargo tarpaulin --features $(TEST_FEATURES) -o Html -o Xml

.PHONY: example
example:
	cargo run --example virtual --features virtual 
	
.PHONY: ci
ci: check tarpaulin
	
