.NOTPARALLEL:

-include variables.mk

export RUST_LOG ?= info,cargo_tarpaulin=off
TEST_FEATURES ?=vpicc,pivy-tests,opensc-tests,rsa
export PIV_DANGEROUS_TEST_CARD_READER ?= Virtual PCD 00 00
export PIV_DANGEROUS_TEST_CARD_PIV_SERIAL ?= 04 B2 BB FB 54 40 4A E3 9B B8 6A E3 CA 82 9C 24

.PHONY: build-cortex-m4
build-cortex-m4:
	cargo build --target thumbv7em-none-eabi

.PHONY: test
test:
	cargo test --features $(TEST_FEATURES)

.PHONY: dangerous-test-real-card
dangerous-test-real-card:
	cargo test --features $(TEST_FEATURES),dangerous-test-real-card

.PHONY: check
check:
	RUSTLFAGS='-Dwarnings' cargo check --all-features --all-targets

.PHONY: lint
lint:
	cargo fmt --check
	cargo check --all-features --all-targets
	cargo clippy --all-targets --all-features -- -Dwarnings
	RUSTDOCFLAGS='-Dwarnings' cargo doc --all-features
	
.PHONY: tarpaulin
tarpaulin:
	cargo tarpaulin --features $(TEST_FEATURES) -o Html -o Xml

.PHONY: vpicc-example
vpicc-example:
	cargo run --example vpicc --features vpicc
	
.PHONY: ci
ci: lint tarpaulin
	
