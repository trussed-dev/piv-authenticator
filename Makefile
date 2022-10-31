.NOTPARALLEL:

export RUST_LOG ?= info,cargo_tarpaulin=off

.PHONY: build-cortex-m4
build-cortex-m4:
	cargo build --target thumbv7em-none-eabi

.PHONY: test
test:
	cargo test --features virtual

.PHONY: check
check:
	cargo fmt --check
	cargo check --all-targets --all-features
	cargo check --target thumbv7em-none-eabi
	cargo clippy --all-targets --all-features -- -Dwarnings
	RUSTDOCFLAGS='-Dwarnings' cargo doc --all-features
	
.PHONY: tarpaulin
tarpaulin:
	cargo tarpaulin --features virtual -o Html -o Xml

.PHONY: example
example:
	cargo run --example virtual --features virtual 
