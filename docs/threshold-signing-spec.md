# SAW Threshold Signing

**Status:** Implemented (branch `slymebot/threshold-signing`)
**Date:** 2026-02-16

## Overview

2-of-3 threshold ECDSA for SAW using the CGGMP21 protocol. The full private key never exists on any single machine — not on disk, not in memory, not during keygen.

## Architecture

```
Agent Machine                 Policy Server (Railway/VPS)      Human (Docker/offline)
┌──────────────────┐         ┌──────────────────┐            ┌──────────────────┐
│  saw-daemon       │◄──WSS──►│  saw-policy       │            │  saw-policy       │
│  Party 0 share    │         │  Party 1 share    │            │  Party 2 share    │
│  Unix socket API  │         │  Policy engine    │            │  Recovery only    │
└──────────────────┘         └──────────────────┘            └──────────────────┘
        ▲
   Agent code
```

**Normal signing:** Party 0 + Party 1 (daemon + policy, automatic)
**Recovery:** Any 2 of 3 parties can sign if one is lost

## Components

| Component | Crate | Role |
|-----------|-------|------|
| saw-daemon | `saw-daemon` | Holds party 0 share, serves Unix socket to agent, coordinates MPC |
| saw-policy | `saw-policy` | Holds party 1 share, evaluates policy rules, co-signs or denies |
| saw-mpc | `saw-mpc` | Core MPC library wrapping cggmp21 (keygen, signing, presignatures) |
| saw-cli | `saw-cli` | CLI for keygen, key management, wallet listing |

## Signing Flow

```
Agent ──signTx()──► saw-daemon ──SignRequest──► saw-policy
                         │                         │
                         │    [Policy evaluates:    │
                         │     chain, recipient,    │
                         │     value, rate limits]  │
                         │                         │
                         │  ◄──PolicyDecision───    │
                         │     (approve/deny)       │
                         │                         │
                    [If approved: 2-party MPC sign]  │
                         │  ◄──MPC rounds──►        │
                         │                         │
Agent ◄──{raw_tx}────    │
```

**Fast path:** Pre-generated presignatures → single round partial signature exchange (~50ms)
**Slow path:** Full MPC signing when no presignatures available (~200ms)

## Presignature Pool

Daemon and policy maintain a synchronized pool of presignatures for instant signing:
- **Target:** 5 presignatures ready
- **Refill threshold:** 2 remaining → trigger background refill
- **Memory-only** — not persisted to disk (regenerated on restart)

## Key Generation

Two modes:

### Local keygen (current)
Generate all 3 shares in one process, then distribute:
```bash
SAW_PASSPHRASE="secret" saw keygen-local --wallet mywallet --root ~/.saw
```
Outputs 3 encrypted share files + metadata with the derived address.

### Distributed keygen (implemented, not yet tested at scale)
Relay-based ceremony where each party runs independently:
```bash
saw keygen-threshold --relay --listen 0.0.0.0:9444    # relay
saw keygen-threshold --party 0 --wallet main --connect ws://relay:9444
saw keygen-threshold --party 1 --wallet main --connect ws://relay:9444
saw keygen-threshold --party 2 --wallet main --connect ws://relay:9444
```

## Encryption at Rest

Key shares are encrypted with **Argon2id + ChaCha20-Poly1305**:
- KDF: Argon2id (memory-hard, resistant to GPU/ASIC attacks)
- AEAD: ChaCha20-Poly1305
- Format: `SAW1` magic bytes + salt + nonce + ciphertext + tag
- Passphrase via `SAW_PASSPHRASE` env var
- Backward-compatible: detects plaintext shares and loads them directly

## Policy Engine

```yaml
version: 1
wallets:
  base-test:
    chain: evm
    rules:
      - name: base-sepolia-allow
        action: approve
        conditions:
          allowed_chains: [84532]
      - name: catch-all
        action: deny
```

Rules evaluated top-to-bottom, first match wins. Actions: `approve`, `deny`, `escalate`.

## Configuration

### saw-daemon (`config.yaml`)
```yaml
wallets:
  base-test:
    mode: threshold
    policy_url: "wss://saw-policy-production.up.railway.app"
    key_share_path: "keys/threshold/base-test_party0.json"
```

### saw-policy (env vars for deployment)
| Variable | Description |
|----------|-------------|
| `KEY_SHARE_BASE64` | Base64-encoded encrypted key share |
| `POLICY_YAML` | Base64-encoded policy.yaml |
| `SAW_PASSPHRASE` | Passphrase to decrypt key share |
| `PORT` | Listen port (default: 9443) |

## Deployment

### Primary policy server (Railway)
```bash
railway up --service saw-policy
```

### Recovery container (Docker)
```bash
docker build -f docker/recovery/Dockerfile -t saw-recovery .
docker run -p 9443:9443 \
  -e SAW_PASSPHRASE="passphrase" \
  -e KEY_SHARE_BASE64="$(base64 -i party2.json.enc)" \
  saw-recovery
```

## Recovery Scenarios

| Lost | Recovery path |
|------|--------------|
| Party 0 (daemon) | Party 1 (Railway) + Party 2 (Docker) sign → transfer funds to new wallet |
| Party 1 (Railway) | Party 0 (daemon) + Party 2 (Docker) sign → transfer funds to new wallet |
| Party 2 (recovery) | No immediate impact — Party 0 + Party 1 still sign normally. Generate new shares. |
| Two parties | **Unrecoverable** — this is inherent to 2-of-3. Back up shares separately. |

## Transport

- **Daemon ↔ Policy:** WebSocket (plaintext WS over Railway's TLS termination)
- **Message format:** JSON-serialized `WireMessage` enum (SignRequest, PolicyDecision, MpcWireMessage, PresignRequest, etc.)
- **Reconnection:** Persistent WS with exponential backoff (1s → 30s)
- **Future:** mTLS with pinned certificates

## Limitations

- **EVM only** — Solana requires Ed25519 (FROST protocol, future work)
- **No key refresh** — cggmp21 doesn't support threshold refresh yet. Compromised share → re-keygen + fund transfer.
- **No WS authentication** — relies on TLS termination. Auth planned for production.
- **No mTLS yet** — using Railway's HTTPS proxy. Direct mTLS planned.

## Protocol: CGGMP21

Library: [dfns/cggmp21](https://github.com/dfns/cggmp21) v0.6.3 (Rust, audited by Kudelski)

Key properties:
- Non-interactive presigning (message-independent preprocessing)
- Identifiable abort (cheating party is identified)
- UC-secure (composable security proof)
- 4 rounds presign + 1 round online sign

**Critical implementation note:** Use `DataToSign::from_scalar()` with raw message hash bytes for EVM signing. Do NOT use `DataToSign::from_digest()` — it double-hashes, causing ecrecover to return the wrong address.
