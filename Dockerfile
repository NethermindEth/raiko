FROM rust:1.88.0 AS chef
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
RUN cargo binstall -y cargo-chef wild-linker
RUN apt-get update && apt-get install -y clang
WORKDIR /opt/raiko
ENV DEBIAN_FRONTEND=noninteractive
ARG BUILD_FLAGS=""

FROM chef AS planner
COPY . .
COPY docker/cargo-config.toml .cargo/config.toml
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /opt/raiko/recipe.json recipe.json
RUN cargo chef cook --release ${BUILD_FLAGS} --features "docker_build" --recipe-path recipe.json
COPY . .
COPY docker/cargo-config.toml .cargo/config.toml
RUN cargo build --release ${BUILD_FLAGS} --features "docker_build"

FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt/raiko

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libssl-dev \
    jq \
    sudo && \
    apt-get clean all && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p \
    ./bin \
    /var/log/raiko

COPY --from=builder /opt/raiko/docker/entrypoint.sh ./bin/
COPY --from=builder /opt/raiko/host/config/chain_spec_list_default.json /etc/raiko/chain_spec_list_default.json
COPY --from=builder /opt/raiko/target/release/raiko-host ./bin/

WORKDIR /opt/raiko/bin
ENTRYPOINT [ "/opt/raiko/bin/entrypoint.sh" ]
