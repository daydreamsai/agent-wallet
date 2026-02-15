#!/usr/bin/env bash
set -euo pipefail

# SAW + OpenClaw Docker setup script.
# Pulls a pre-built image, runs onboarding if needed, and starts the gateway.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/daydreamsai/agent-wallet/master/setup.sh | bash
#
# Overrides:
#   SAW_IMAGE=frontboat1/agent-wallet:dev  # custom image (default: daydreamsai/agent-wallet:latest)
#   SAW_DIR=./my-saw                       # working directory (default: ./saw)
#   SAW_PORT=18789                         # gateway port (default: 18789)

SAW_IMAGE="${SAW_IMAGE:-daydreamsai/agent-wallet:latest}"
SAW_DIR="${SAW_DIR:-./saw}"
SAW_PORT="${SAW_PORT:-18789}"

# ── Preflight ────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is not installed." >&2
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo "ERROR: docker compose is not available." >&2
    exit 1
fi

# ── Create working directory ─────────────────────────────────────────────
mkdir -p "$SAW_DIR"
cd "$SAW_DIR"

# ── Generate docker-compose.yml ──────────────────────────────────────────
# Always regenerate to pick up SAW_IMAGE/SAW_PORT changes.
echo "==> Writing docker-compose.yml (image: ${SAW_IMAGE})..."
cat > docker-compose.yml <<COMPOSE
services:
  saw:
    image: ${SAW_IMAGE}
    container_name: saw
    restart: unless-stopped
    environment:
      - SAW_ROOT=/opt/saw
      - SAW_SOCKET=/run/saw/saw.sock
      - HOME=/home/node
      - XDG_CONFIG_HOME=/home/node/.openclaw
      - NODE_ENV=production
      - TERM=xterm-256color
    volumes:
      - saw-data:/opt/saw
      - openclaw-data:/home/node/.openclaw
    ports:
      - "127.0.0.1:${SAW_PORT}:18789"

volumes:
  saw-data:
  openclaw-data:
COMPOSE

# ── Pull image ───────────────────────────────────────────────────────────
echo ""
echo "==> Pulling image: ${SAW_IMAGE}..."
docker compose pull

# ── Start container (SAW daemon comes up immediately) ────────────────────
echo ""
echo "==> Starting container..."
docker compose up -d

# Give SAW daemon time to start
sleep 3

# ── Onboarding (first run only) ─────────────────────────────────────────
OPENCLAW_CONFIG_PATH="/home/node/.openclaw/openclaw.json"
has_config=$(docker compose exec -T saw test -f "$OPENCLAW_CONFIG_PATH" 2>/dev/null && echo "yes" || echo "no")

if [[ "$has_config" == "no" ]]; then
    echo ""
    echo "============================================"
    echo "  OpenClaw: first-time onboarding"
    echo "============================================"
    echo ""
    echo "  Follow the prompts to complete setup."
    echo ""
    echo "  (Press Ctrl+C when you see 'Onboarding complete')"
    echo ""

    # Trap SIGINT so the script continues after the user presses Ctrl+C
    # to escape the hanging exec process.
    trap '' INT
    docker compose exec -it saw openclaw onboard --auth-choice x402 || true
    trap - INT

    # Restore terminal after interactive prompts
    stty sane 2>/dev/null || true

    # Verify onboarding actually created the config
    has_config=$(docker compose exec -T saw test -f "$OPENCLAW_CONFIG_PATH" 2>/dev/null && echo "yes" || echo "no")
    if [[ "$has_config" == "no" ]]; then
        echo ""
        echo "Onboarding did not complete. Retry with:"
        echo "  cd $SAW_DIR && docker compose exec -it saw openclaw onboard --auth-choice x402"
        echo "  docker compose restart"
        exit 1
    fi

    echo ""
    echo "==> Restarting with gateway..."
    docker compose restart
    sleep 3
fi

# ── Print summary ────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  SAW + OpenClaw is running"
echo "============================================"
echo ""

# Show wallet address
docker compose exec -T saw saw address --chain evm --wallet main --root /opt/saw 2>/dev/null || true

echo ""
echo "  Gateway:  http://127.0.0.1:${SAW_PORT}/"
echo "  Logs:     cd ${SAW_DIR} && docker compose logs -f"
echo "  Stop:     cd ${SAW_DIR} && docker compose down"
echo ""
echo "============================================"
