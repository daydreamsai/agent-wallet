#!/usr/bin/env bash
set -euo pipefail

# SAW + OpenClaw Docker setup script.
# Builds the image, runs onboarding if needed, and starts the gateway.

cd "$(dirname "$0")"

# ── Preflight ────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is not installed." >&2
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo "ERROR: docker compose is not available." >&2
    exit 1
fi

# ── Build ────────────────────────────────────────────────────────────────
echo "==> Building Docker image..."
docker compose build

# ── Start container (SAW daemon comes up immediately) ────────────────────
echo ""
echo "==> Starting container..."
docker compose up -d

# Give SAW daemon time to start
sleep 3

# ── Onboarding (first run only) ─────────────────────────────────────────
OPENCLAW_CONFIG_PATH="/home/node/.openclaw/openclaw.json"
has_config=$(docker compose exec -T saw test -f "$OPENCLAW_CONFIG_PATH" && echo "yes" || echo "no")

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
    has_config=$(docker compose exec -T saw test -f "$OPENCLAW_CONFIG_PATH" && echo "yes" || echo "no")
    if [[ "$has_config" == "no" ]]; then
        echo ""
        echo "Onboarding did not complete. Retry with:"
        echo "  docker compose exec -it saw openclaw onboard --auth-choice x402"
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
echo "  Gateway:  http://127.0.0.1:18789/"
echo "  Logs:     docker compose logs -f"
echo "  Stop:     docker compose down"
echo ""
echo "============================================"
