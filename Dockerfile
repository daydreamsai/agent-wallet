# ── Stage 1: Build SAW binaries from source ──────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --workspace \
    && strip target/release/saw target/release/saw-daemon

# ── Stage 2: Runtime image ────────────────────────────────────────────────
FROM node:22-slim AS runtime

# SAW configuration (override at runtime)
ENV SAW_ROOT=/opt/saw \
    SAW_SOCKET=/run/saw/saw.sock \
    SAW_WALLET=main \
    SAW_CHAIN=evm \
    SAW_POLICY_TEMPLATE=conservative

# OpenClaw Gateway configuration
ENV OPENCLAW_GATEWAY_BIND=lan \
    OPENCLAW_GATEWAY_PORT=18789 \
    OPENCLAW_GATEWAY_TOKEN="" \
    HOME=/home/node \
    XDG_CONFIG_HOME=/home/node/.openclaw

# OpenClaw build args
ARG OPENCLAW_REF=v2026.2.9-dreamclaw.14
ARG OPENCLAW_RELEASE_REPO=https://github.com/RedBeardEth/clawdbot

# System deps: curl for tarball download, git for fallback source install
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Force HTTPS for GitHub (npm git tries SSH by default)
RUN git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"

# Install SAW binaries
COPY --from=builder /src/target/release/saw /usr/local/bin/saw
COPY --from=builder /src/target/release/saw-daemon /usr/local/bin/saw-daemon

# Install OpenClaw globally (try release tarball first, fallback to git)
RUN set -eux; \
    tarball_url="${OPENCLAW_RELEASE_REPO}/releases/download/${OPENCLAW_REF}/openclaw-${OPENCLAW_REF}.tgz"; \
    if curl -fsSL --head --connect-timeout 5 "$tarball_url" >/dev/null 2>&1; then \
        echo "==> Installing OpenClaw from release tarball"; \
        npm install -g "$tarball_url"; \
    else \
        echo "==> Installing OpenClaw from git source"; \
        npm install -g "git+${OPENCLAW_RELEASE_REPO}.git#${OPENCLAW_REF}"; \
    fi \
    && npm cache clean --force

# Create SAW system user and agent group
RUN groupadd --system saw-agent \
    && useradd --system --no-create-home --shell /usr/sbin/nologin --groups saw-agent saw

# Initialize SAW data directory and OpenClaw config directory
RUN saw install --root "$SAW_ROOT" \
    && mkdir -p /run/saw /home/node/.openclaw/workspace \
    && chown -R saw:saw "$SAW_ROOT" /run/saw

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 18789

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD test -S "$SAW_SOCKET" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["openclaw", "gateway", "--bind", "lan", "--port", "18789", "--allow-unconfigured"]
