#!/usr/bin/env bash
set -euo pipefail

SAW_ROOT="${SAW_ROOT:-/opt/saw}"
SAW_SOCKET="${SAW_SOCKET:-/run/saw/saw.sock}"
SAW_WALLET="${SAW_WALLET:-main}"
SAW_CHAIN="${SAW_CHAIN:-evm}"
SAW_POLICY_TEMPLATE="${SAW_POLICY_TEMPLATE:-conservative}"

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
        # Only write default policy if file is empty or has no wallet entries.
        # Will not overwrite user-customized policies on restart.
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

# ── Fix permissions ───────────────────────────────────────────────────────
chown -R saw:saw "$SAW_ROOT"
find "$SAW_ROOT/keys" -type d -exec chmod 0700 {} \;
find "$SAW_ROOT/keys" -type f -exec chmod 0600 {} \;
chmod 0640 "$policy_file" 2>/dev/null || true
chmod 0640 "$SAW_ROOT/audit.log" 2>/dev/null || true
chown -R saw:saw /run/saw

# ── Start SAW daemon in background ────────────────────────────────────────
echo "==> SAW: starting daemon (socket=${SAW_SOCKET})"
su -s /bin/sh saw -c \
    "saw-daemon --socket '$SAW_SOCKET' --root '$SAW_ROOT'" &
SAW_PID=$!

# ── Trap for clean shutdown ───────────────────────────────────────────────
# Registered immediately after spawning the daemon so that an early exit
# (e.g. socket wait timeout) still cleans up the background process.
cleanup() {
    echo "==> Shutting down SAW daemon..."
    kill "$SAW_PID" 2>/dev/null || true
    wait "$SAW_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

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

# ── Run the main command ──────────────────────────────────────────────────
if [[ $# -gt 0 ]]; then
    # Run without exec so the shell stays as PID 1 and the EXIT trap
    # keeps the SAW daemon alive for the lifetime of the foreground command.
    "$@"
else
    # Default: keep container alive (SAW daemon serves requests)
    echo "==> SAW daemon ready. Waiting for connections on ${SAW_SOCKET}"
    wait "$SAW_PID"
fi
