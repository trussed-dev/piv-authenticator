FROM docker.io/rust:latest

RUN apt update && apt install --yes ragel libpcsclite-dev libbsd-dev \
  && wget https://github.com/arekinath/pivy/archive/refs/tags/v0.12.1.tar.gz \
  && tar xvf v0.12.1.tar.gz

RUN cd pivy-0.12.1 && sed -i '1s/^/\#include \<sys\/stat.h\>\n/' bunyan.c
RUN cd pivy-0.12.1 && make pivy-tool

FROM docker.io/rust:latest

RUN apt update && apt install --yes scdaemon libclang-dev llvm python3-pip vsmartcard-vpicc pkg-config nettle-dev libpcsclite-dev opensc libbsd-dev 

RUN rustup component add clippy rustfmt && rustup target add thumbv7em-none-eabi
RUN cargo install cargo-tarpaulin --profile release && rm -rf "$CARGO_HOME"/registry
# initialize cargo cache
RUN cargo search

ENV CARGO_HOME=/app/.cache/cargo

COPY --from=0 pivy-0.12.1/pivy-tool /bin/pivy-tool

WORKDIR /app

LABEL org.opencontainers.image.source https://github.com/trussed-dev/piv-authenticator

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
