# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FROM docker.io/rust:latest

RUN apt update && apt install --yes scdaemon libclang-dev llvm python3-pip vsmartcard-vpcd pkg-config nettle-dev libpcsclite-dev

RUN rustup component add clippy rustfmt && rustup target add thumbv7em-none-eabi
RUN cargo install cargo-tarpaulin --profile release && rm -rf "$CARGO_HOME"/registry
# initialize cargo cache
RUN cargo search

ENV CARGO_HOME=/app/.cache/cargo

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
