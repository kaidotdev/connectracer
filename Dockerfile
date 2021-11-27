FROM rust:1.55

RUN apt-get update -y && apt-get install -y libbpf-dev libelf-dev

WORKDIR /
RUN cargo new --lib build

WORKDIR /build
COPY Cargo.toml Cargo.lock /build/
RUN cargo build --release

COPY vmlinux.h /build/vmlinux.h

COPY src /build/src
RUN cargo build --release

ENTRYPOINT ["/build/target/release/connectracer"]
