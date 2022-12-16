# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FROM docker.io/rust:latest

RUN apt update && apt install --yes  libpcsclite-dev \
  && wget https://github.com/arekinath/pivy/releases/download/v0.10.0/pivy-0.10.0-src.tar.gz \
  && tar xvf pivy-0.10.0-src.tar.gz \
  && cd pivy-0.10.0 \
  && make pivy-tool

FROM docker.io/rust:latest

RUN apt update && apt install --yes scdaemon libclang-dev llvm python3-pip vsmartcard-vpcd pkg-config nettle-dev libpcsclite-dev opensc

RUN python3 -m pip install reuse

RUN rustup component add clippy rustfmt && rustup target add thumbv7em-none-eabi
RUN cargo install cargo-tarpaulin --profile release && rm -rf "$CARGO_HOME"/registry
# initialize cargo cache
RUN cargo search

ENV CARGO_HOME=/app/.cache/cargo

COPY --from=0 pivy-0.10.0/pivy-tool /bin/pivy-tool

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
