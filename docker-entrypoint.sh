#!/usr/bin/env bash
set -euo pipefail

SAW_ROOT="${SAW_ROOT:-/opt/saw}"
SAW_SOCKET="${SAW_SOCKET:-/run/saw/saw.sock}"
SAW_WALLET="${SAW_WALLET:-main}"
SAW_CHAIN="${SAW_CHAIN:-evm}"
SAW_POLICY_TEMPLATE="${SAW_POLICY_TEMPLATE:-conservative}"

# ── Validate inputs ──────────────────────────────────────────────────────
case "$SAW_CHAIN" in
    evm|sol) ;;
    *)
        echo "ERROR: SAW_CHAIN must be 'evm' or 'sol', got '${SAW_CHAIN}'" >&2
        exit 1
        ;;
esac

# ── Key generation (idempotent) ───────────────────────────────────────────
key_file="${SAW_ROOT}/keys/${SAW_CHAIN}/${SAW_WALLET}.key"
if [[ ! -f "$key_file" ]]; then
    echo "==> SAW: generating key (chain=${SAW_CHAIN}, wallet=${SAW_WALLET})"
    saw gen-key --chain "$SAW_CHAIN" --wallet "$SAW_WALLET" --root "$SAW_ROOT"
    echo ""
    echo "    IMPORTANT: Fund this wallet before using x402 payments."
    echo ""
fi

# ── Policy (idempotent) ───────────────────────────────────────────────────
policy_file="${SAW_ROOT}/policy.yaml"
if [[ "$SAW_POLICY_TEMPLATE" != "none" ]]; then
    if [[ ! -s "$policy_file" ]] || ! grep -q "^  [a-zA-Z0-9_-]\+:" "$policy_file" 2>/dev/null; then
        echo "==> SAW: writing conservative default policy"
        cat > "$policy_file" <<POLICY
wallets:
  ${SAW_WALLET}:
    chain: ${SAW_CHAIN}
    allowed_chains: [8453]
    max_tx_value_eth: 0.01
    allow_contract_calls: false
    allowlist_addresses: []
    rate_limit_per_minute: 10
POLICY
    fi
fi

# ── Fix SAW permissions ──────────────────────────────────────────────────
chown -R saw:saw "$SAW_ROOT"
find "$SAW_ROOT/keys" -type d -exec chmod 0700 {} \;
find "$SAW_ROOT/keys" -type f -exec chmod 0600 {} \;
[[ -f "$policy_file" ]] && chmod 0640 "$policy_file"
[[ -f "$SAW_ROOT/audit.log" ]] && chmod 0640 "$SAW_ROOT/audit.log"
chown -R saw:saw /run/saw

# ── Fix OpenClaw permissions ─────────────────────────────────────────────
OPENCLAW_DIR="${XDG_CONFIG_HOME:-$HOME/.openclaw}"
if [[ -d "$OPENCLAW_DIR" ]]; then
    chown -R node:node "$OPENCLAW_DIR"
fi

# ── Start SAW daemon in background ────────────────────────────────────────
echo "==> SAW: starting daemon (socket=${SAW_SOCKET})"
su -s /bin/sh saw -c \
    "saw-daemon --socket '$SAW_SOCKET' --root '$SAW_ROOT'" &
SAW_PID=$!

# ── Trap for clean shutdown ───────────────────────────────────────────────
cleanup() {
    echo "==> Shutting down SAW daemon..."
    kill "$SAW_PID" 2>/dev/null || true
    wait "$SAW_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Verify daemon didn't crash immediately
sleep 0.2
if ! kill -0 "$SAW_PID" 2>/dev/null; then
    echo "ERROR: SAW daemon exited immediately. Check logs above." >&2
    wait "$SAW_PID" 2>/dev/null || true
    exit 1
fi

# Wait for socket
waited=0
while [[ ! -S "$SAW_SOCKET" ]] && (( waited < 50 )); do
    sleep 0.1
    waited=$((waited + 1))
done

if [[ -S "$SAW_SOCKET" ]]; then
    chmod 0660 "$SAW_SOCKET"
    chgrp saw-agent "$SAW_SOCKET"
    echo "==> SAW: daemon running (pid=${SAW_PID})"
else
    echo "ERROR: SAW socket not found after 5s" >&2
    exit 1
fi

# ── OpenClaw first-run detection ─────────────────────────────────────────
OPENCLAW_CONFIG="${OPENCLAW_DIR}/openclaw.json"
export SAW_SOCKET
if [[ "${1:-}" == "openclaw" && ! -f "$OPENCLAW_CONFIG" ]]; then
    if [[ "${2:-}" == "onboard" ]]; then
        # User explicitly running onboard — let it through below
        :
    elif [[ -t 0 ]]; then
        echo "==> OpenClaw: first run detected, running onboard..."
        su -s /bin/bash node -c "SAW_SOCKET='$SAW_SOCKET' openclaw onboard --auth-choice x402"
    else
        echo ""
        echo "============================================"
        echo "  OpenClaw: first-run setup required"
        echo "============================================"
        echo ""
        echo "  Run onboarding (interactive, one-time):"
        echo ""
        echo "    docker compose exec -it saw openclaw onboard --auth-choice x402"
        echo ""
        echo "  Then restart the container:"
        echo ""
        echo "    docker compose restart"
        echo ""
        echo "============================================"
        echo ""
        echo "==> SAW daemon running. Waiting for onboarding..."
        wait "$SAW_PID"
        exit 0
    fi
fi

# ── Drop to node user and run the main command ───────────────────────────
# Privileged setup is done. Everything below runs as the unprivileged node
# user. The shell stays as PID 1 so the EXIT trap keeps the SAW daemon
# alive for the lifetime of the foreground command.
if [[ $# -gt 0 ]]; then
    su -s /bin/bash node -c "SAW_SOCKET='$SAW_SOCKET' $(printf '%q ' "$@")" &
    CMD_PID=$!
    wait "$CMD_PID"
    exit $?
else
    echo "==> SAW daemon ready. Waiting for connections on ${SAW_SOCKET}"
    wait "$SAW_PID"
fi
