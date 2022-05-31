FROM rust:1.61.0 AS builder
WORKDIR /usr/src/
RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new iptables-exporter
WORKDIR /usr/src/iptables-exporter
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

ADD . ./
RUN touch src/*
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

FROM alpine:latest
COPY --from=builder /usr/src/iptables-exporter/target/x86_64-unknown-linux-musl/release/iptables-exporter /
RUN apk update && \
    apk add iptables ip6tables nftables && \
    ln -sfT xtables-nft-multi /sbin/iptables && \
    ln -sfT xtables-nft-multi /sbin/iptables-restore && \
    ln -sfT xtables-nft-multi /sbin/ip6tables && \
    ln -sfT xtables-nft-multi /sbin/ip6tables-restore

EXPOSE 9119
ENTRYPOINT ["/iptables-exporter"]
