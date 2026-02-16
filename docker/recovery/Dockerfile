# SAW Recovery Co-signer (Party 2)
# Runs saw-policy with the recovery key share.
# Used when party 0 (daemon) or party 1 (primary policy) is lost.
#
# Usage:
#   docker build -t saw-recovery .
#   docker run -p 8080:8080 \
#     -e SAW_PASSPHRASE="your-passphrase" \
#     -e KEY_SHARE_BASE64="<base64-encoded-party2-share>" \
#     -e POLICY_YAML="<base64-encoded-policy>" \
#     saw-recovery

FROM rust:1.85-bookworm AS builder

WORKDIR /build
COPY . .

RUN apt-get update && apt-get install -y m4 pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN cargo build --release -p saw-policy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/saw-policy /usr/local/bin/saw-policy

RUN mkdir -p /data
WORKDIR /data

EXPOSE 8080
CMD ["saw-policy"]
