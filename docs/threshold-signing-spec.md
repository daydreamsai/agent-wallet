# SAW Threshold Signing Protocol Spec

**Status:** Draft
**Date:** 2026-02-15
**Authors:** Slyme + Modus

## Overview

Upgrade SAW (Secure Agent Wallet) from single-key signing to 2-of-3 threshold ECDSA, enabling autonomous agent signing without any single machine holding the full private key.

## Goals

1. **No full key anywhere** — not on disk, not in memory, not during keygen
2. **Agent-speed signing** — sub-second for policy-approved transactions
3. **Backward-compatible API** — existing SAW client SDK works unchanged
4. **Minimal infrastructure** — one additional lightweight process on a separate machine
5. **Human override** — operator can always intervene or recover

## Non-Goals

- Supporting arbitrary t-of-n (we fix 2-of-3 for now)
- Decentralized policy network (future work)
- Solana threshold signing (ECDSA first, Ed25519 later via FROST)

---

## Architecture

```
Machine A (Agent)              Machine B (Policy)           Human Device
┌─────────────────┐           ┌─────────────────┐          ┌──────────────┐
│                 │  mTLS/WSS │                 │          │              │
│  saw-daemon     │◄─────────►│  saw-policy      │          │ saw-cosigner │
│                 │           │                 │          │              │
│  ┌───────────┐  │           │  ┌───────────┐  │          │ ┌──────────┐ │
│  │ Share 1   │  │           │  │ Share 2   │  │          │ │ Share 3  │ │
│  │ (enc@rest)│  │           │  │ (enc@rest)│  │          │ │ (keychain│ │
│  └───────────┘  │           │  └───────────┘  │          │ │  or file)│ │
│                 │           │                 │          │ └──────────┘ │
│  ┌───────────┐  │           │  ┌───────────┐  │          │              │
│  │ MPC Engine│  │           │  │ MPC Engine│  │          │ ┌──────────┐ │
│  └───────────┘  │           │  │ + Policy  │  │          │ │ MPC      │ │
│                 │           │  │   Engine  │  │          │ │ Engine   │ │
│  ┌───────────┐  │           │  └───────────┘  │          │ └──────────┘ │
│  │ Unix Sock │  │           │                 │          │              │
│  │ (agent    │  │           │  ┌───────────┐  │          └──────────────┘
│  │  facing)  │  │           │  │ Alert     │  │                 ▲
│  └───────────┘  │           │  │ (→ human) │  │                 │
│        ▲        │           │  └───────────┘  │          Connect on-demand
│        │        │           └─────────────────┘          for keygen, refresh,
│   Agent Code    │                                        or escalated signing
└─────────────────┘
```

### Components

| Component | Binary | Role | Always On? |
|-----------|--------|------|-----------|
| saw-daemon | `saw-daemon` | Holds Share 1, coordinates MPC, serves Unix socket to agent | Yes |
| saw-policy | `saw-policy` | Holds Share 2, evaluates policy, auto-cosigns or escalates | Yes |
| saw-cosigner | `saw-cosigner` | Holds Share 3, human approval interface | No — on demand |

---

## Protocol: CGGMP21

We use the CGGMP21 protocol (Canetti, Gennaro, Goldfeder, Makriyannis, Peled) for threshold ECDSA. Properties:

- **Non-interactive presigning** — message-independent preprocessing
- **Identifiable abort** — if a party cheats, we know who
- **Proactive refresh** — rotate shares without changing the public key
- **UC-secure** — composable security proof

### Why CGGMP over alternatives

| Protocol | Rounds (sign) | Identifiable Abort | Refresh | Status |
|----------|---------------|-------------------|---------|--------|
| GG18 | 8 | No | No | Deprecated |
| GG20 | 6 | Yes | No | Superseded |
| CGGMP21 | 4 (presign) + 1 (online) | Yes | Yes | Current best |
| FROST | 2 | Yes | Yes | Ed25519/Schnorr only |

---

## 1. Key Generation Ceremony

### Preconditions
- All three parties online and mutually authenticated
- Secure channel established (mTLS or Noise protocol)

### Flow

```
 saw-daemon          saw-policy          saw-cosigner
     │                    │                    │
     │◄──── mTLS connect ─┤                    │
     │◄──── mTLS connect ──────────────────────┤
     │                    │                    │
     ├─── CGGMP Keygen Round 1 (commitments) ──►
     │◄── CGGMP Keygen Round 1 ────────────────┤
     │                    │                    │
     ├─── CGGMP Keygen Round 2 (decommit) ────►
     │◄── CGGMP Keygen Round 2 ────────────────┤
     │                    │                    │
     ├─── CGGMP Keygen Round 3 (Paillier) ────►
     │◄── CGGMP Keygen Round 3 ────────────────┤
     │                    │                    │
     │   [Each party now holds:]               │
     │   - Their key share (xi)                │
     │   - Public key (Q = x1·G + x2·G + x3·G)│
     │   - Paillier keys for MPC               │
     │   - Other parties' verification data    │
     │                    │                    │
     ├─── Encrypt share, save to disk ─────────┤
     │                    │                    │
     │   [Output: wallet address derived from Q]│
```

### Keygen Output Per Party

```rust
struct KeyShare {
    // Party identity
    party_id: PartyId,           // 1, 2, or 3
    threshold: u8,               // 2
    
    // Secret material
    secret_share: Scalar,        // xi — NEVER leaves this process
    paillier_sk: PaillierSK,     // For MPC multiplication
    
    // Public material (same for all parties)
    public_key: Point,           // Q — the combined public key
    party_public_shares: Vec<Point>,  // Xi = xi·G for each party
    party_paillier_pks: Vec<PaillierPK>,
    
    // Metadata
    chain: Chain,
    wallet_name: String,
    created_at: u64,
    refresh_count: u32,
}
```

### Storage

Shares are encrypted at rest using a key derived from:
- **saw-daemon:** machine-specific secret (from `/etc/machine-id` + a random salt)
- **saw-policy:** similar, different machine
- **saw-cosigner:** user passphrase or device keychain

```
~/.saw/keys/evm/main.share    # Encrypted KeyShare (replaces main.key)
~/.saw/keys/evm/main.pub      # Public key + party metadata (plaintext)
```

### CLI

```bash
# Initiator (saw-daemon)
saw keygen \
  --wallet main \
  --chain evm \
  --threshold 2 \
  --parties 3 \
  --listen 0.0.0.0:9443

# Output:
# Keygen session started. Session ID: abc123
# 
# Connect other parties:
#   saw-policy --join wss://agent-host:9443/keygen/abc123 --token <token1>
#   saw-cosigner --join wss://agent-host:9443/keygen/abc123 --token <token2>
#
# Waiting for 2 more parties...

# Policy agent (on Machine B)
saw-policy --join wss://agent-host:9443/keygen/abc123 --token <token1>

# Human cosigner (on laptop)
saw-cosigner --join wss://agent-host:9443/keygen/abc123 --token <token2>

# Keygen completes:
# ✓ Wallet "main" created
# Address: 0x7a3b...9f2e
# Threshold: 2-of-3
# Share saved to ~/.saw/keys/evm/main.share
```

---

## 2. Signing Protocol

### 2a. Presigning (Message-Independent)

Presigning can happen ahead of time. The output is a "presignature" that can be combined with any message later in a single round.

```
 saw-daemon              saw-policy
     │                       │
     │── Presign Round 1 ───►│
     │◄── Presign Round 1 ───│
     │                       │
     │── Presign Round 2 ───►│
     │◄── Presign Round 2 ───│
     │                       │
     │── Presign Round 3 ───►│
     │◄── Presign Round 3 ───│
     │                       │
     │  [Both hold presignature shares]
     │  [Can be stockpiled for instant signing]
```

### 2b. Online Signing (With Message)

```
Agent                saw-daemon              saw-policy
  │                       │                       │
  │── signTx(tx) ────────►│                       │
  │   (Unix socket)       │                       │
  │                       │── SignRequest(tx) ────►│
  │                       │   {wallet, action,     │
  │                       │    tx_details, hash}   │
  │                       │                       │
  │                       │   [saw-policy checks:] │
  │                       │   - chain allowed?     │
  │                       │   - recipient allowed? │
  │                       │   - value under limit? │
  │                       │   - rate limit ok?     │
  │                       │   - daily spend ok?    │
  │                       │                       │
  │                       │◄── PolicyDecision ─────│
  │                       │    {approved | denied  │
  │                       │     | escalate}        │
  │                       │                       │
  │              [If approved:]                    │
  │                       │── Presig share ───────►│
  │                       │◄── Presig share ───────│
  │                       │                        │
  │                       │  [Combine presignature │
  │                       │   with message hash    │
  │                       │   → full ECDSA sig]    │
  │                       │                        │
  │◄── {raw_tx, tx_hash}──│                        │
  │                        │                        │
```

### 2c. Escalated Signing (Human Required)

When saw-policy escalates (value too high, unknown recipient, etc.):

```
saw-daemon              saw-policy              saw-cosigner
     │                       │                       │
     │── SignRequest ───────►│                       │
     │                       │                       │
     │◄── Escalate ──────────│                       │
     │    {reason: "value    │                       │
     │     exceeds policy"}  │                       │
     │                       │                       │
     │   [Notify human via Telegram/push]            │
     │                       │                       │
     │◄──────────────────────────── Approve ─────────│
     │                       │                       │
     │── MPC Round (Share 1) ────────────────────────►
     │◄── MPC Round (Share 3) ───────────────────────│
     │                       │                       │
     │  [Signature produced with Share 1 + Share 3]  │
     │  [Share 2 not needed — any 2 of 3 works]      │
```

### Timing Expectations

| Scenario | Latency | Bottleneck |
|----------|---------|-----------|
| Presigned + policy auto-approve | <50ms | Network RTT to policy |
| Live sign + policy auto-approve | ~200ms | 3 MPC rounds |
| Escalated to human | Seconds to minutes | Human reaction time |

### Presignature Pool

To minimize latency, saw-daemon and saw-policy maintain a pool of presignatures:

```yaml
# daemon config
presign_pool:
  target_size: 20          # Keep 20 presigs ready
  refill_threshold: 5      # Refill when pool drops below 5
  refill_batch: 10         # Generate 10 at a time
  max_age_hours: 24        # Expire after 24h (security hygiene)
```

When the agent calls `signTx()`, a presignature is consumed from the pool and combined with the message hash in a single round. Pool refills happen in the background.

---

## 3. Policy Engine

### Policy File

Lives on the saw-policy machine. Controls what gets auto-approved.

```yaml
# /opt/saw-policy/policy.yaml

version: 1

defaults:
  action: escalate    # If no rule matches, ask the human

wallets:
  main:
    chain: evm
    
    rules:
      # x402 micropayments — auto approve
      - name: x402-micro
        action: approve
        conditions:
          max_value_usd: 1.00
          allowed_chains: [8453]          # Base only
          allowed_contracts:
            - "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # USDC on Base
          max_daily_spend_usd: 50.00
          max_per_minute: 30
          
      # Known recipients — approve up to $10
      - name: trusted-recipients
        action: approve
        conditions:
          max_value_usd: 10.00
          allowed_chains: [1, 8453]
          allowlist_recipients:
            - "0xabc..."   # Known agent
            - "0xdef..."   # Known service
          max_daily_spend_usd: 100.00

      # Everything else — ask the human
      - name: catch-all
        action: escalate
        notify: telegram
        timeout_seconds: 300    # Deny if no response in 5 min

    # Emergency stops
    circuit_breakers:
      - name: daily-limit
        condition: daily_spend_usd > 200
        action: deny_all
        alert: telegram
        cooldown_hours: 24
        
      - name: rapid-drain
        condition: spend_last_5min_usd > 50
        action: deny_all
        alert: telegram
        cooldown_hours: 1
```

### Policy Evaluation Order

1. Check circuit breakers → if tripped, deny immediately
2. Evaluate rules top-to-bottom → first match wins
3. If no rule matches → use `defaults.action`

### Price Oracle

Policy rules reference USD values. saw-policy needs a price feed:

```yaml
price_oracle:
  provider: coingecko    # or chainlink, or static
  cache_seconds: 60
  fallback_action: escalate   # If oracle is down, ask human
```

---

## 4. Key Refresh

Periodic share rotation without changing the public key or address.

### Why Refresh

- Invalidates any previously leaked share
- Proactive security — attacker has a time window, not forever
- No on-chain transaction needed

### Flow

```
saw-daemon          saw-policy          saw-cosigner
     │                    │                    │
     │   [All 3 must be online for refresh]    │
     │                    │                    │
     ├── Refresh Round 1 (new commitments) ───►
     │◄── Refresh Round 1 ────────────────────┤
     │                    │                    │
     ├── Refresh Round 2 (new shares) ────────►
     │◄── Refresh Round 2 ────────────────────┤
     │                    │                    │
     │  [Each party now holds new xi']         │
     │  [Q unchanged — same address]           │
     │  [Old shares are useless]               │
     │                    │                    │
     ├── Save new share, delete old ───────────┤
```

### Refresh Schedule

```yaml
refresh:
  auto_interval_days: 7          # Weekly refresh
  require_human: true            # Human must participate
  notify_before_hours: 24        # "Refresh due tomorrow"
  max_age_days: 30               # Force refresh, deny signing if overdue
```

---

## 5. Transport Protocol

### Between saw-daemon and saw-policy

**Protocol:** WebSocket over mTLS

```
wss://policy-host:9443/v1/mpc
```

Both sides present client certificates. Connection is persistent — reconnects on failure.

**Authentication:**
- Mutual TLS with self-signed certs generated during keygen
- Each party's cert fingerprint is pinned in the other's config
- No CA dependency

```yaml
# saw-daemon config
policy_agent:
  endpoint: wss://policy-host:9443/v1/mpc
  tls_cert: /opt/saw/certs/daemon.pem
  tls_key: /opt/saw/certs/daemon.key
  peer_fingerprint: "sha256:abc123..."   # Pinned policy agent cert
  
  reconnect:
    initial_delay_ms: 100
    max_delay_ms: 30000
    backoff_factor: 2
```

### Message Format

```json
{
  "version": 1,
  "type": "sign_request | mpc_round | policy_decision | presign | refresh | heartbeat",
  "request_id": "uuid",
  "wallet": "main",
  "payload": { ... }
}
```

### Between saw-policy and Human

**Escalation channel:** Telegram (via bot API), with fallback to CLI cosigner WebSocket.

**Approval message includes:**
- Transaction details (to, value, chain, contract)
- Policy rule that triggered escalation
- Risk assessment
- Inline approve/deny buttons
- Expiry countdown

---

## 6. Recovery Scenarios

| Scenario | Recovery |
|----------|---------|
| Agent machine dies | New machine + keygen with Share 2 (policy) + Share 3 (human) to reconstruct. Or: restore Share 1 from backup + reconnect. |
| Policy machine dies | Agent can sign with human cosigner (Share 1 + Share 3). Deploy new policy machine + refresh. |
| Human loses device | Share 1 + Share 2 can sign. Generate new Share 3 via refresh ceremony. |
| Agent compromised | Human connects cosigner, initiates emergency refresh to invalidate Share 1. Transfer funds if needed using Share 2 + Share 3. |
| Policy compromised | Human + agent do emergency refresh. Redeploy policy on new machine. |
| Two shares compromised | Emergency: transfer all funds using the two compromised shares (attacker may race you). This is the same as any 2-of-3 multisig. |

---

## 7. Migration Path

### Phase 1: Keygen + Signing (MVP)

- [ ] Select and integrate CGGMP Rust library
- [ ] Implement keygen ceremony in saw-daemon
- [ ] Build saw-policy binary (policy engine + MPC + WebSocket server)
- [ ] Build saw-cosigner binary (CLI only)
- [ ] Presignature pool
- [ ] Share encryption at rest

### Phase 2: Production Hardening

- [ ] mTLS transport
- [ ] Telegram escalation integration
- [ ] Key refresh protocol
- [ ] Circuit breakers and anomaly detection
- [ ] Audit logging on both sides
- [ ] Systemd units for saw-policy

### Phase 3: Ecosystem

- [ ] Hosted policy agent (multi-tenant SaaS)
- [ ] TEE support (AWS Nitro Enclaves)
- [ ] FROST for Ed25519/Solana wallets
- [ ] SDK support for agent-to-agent cosigning
- [ ] Dashboard for monitoring signing activity

---

## 8. Library Selection

### Candidates

| Library | Language | Protocol | Maintained | Audited |
|---------|----------|----------|-----------|---------|
| [cggmp21](https://github.com/dfns/cggmp21) (Dfns) | Rust | CGGMP21 | Active | Partial |
| [multi-party-sig](https://github.com/taurushq-io/multi-party-sig) | Go | CGGMP | Active | No |
| [gotham-city](https://github.com/ZenGo-X/gotham-city) | Rust | Lindell17 | Maintained | Yes (2-of-2 only) |

**Recommendation: Dfns `cggmp21`**

- Rust (matches SAW codebase)
- Implements full CGGMP21 including refresh
- Active development
- Supports secp256k1 (Ethereum)
- Threshold t-of-n (we use 2-of-3)

### Integration Surface

```rust
// Keygen
let (key_share, public_key) = cggmp21::keygen(
    party_id,
    threshold: 2,
    parties: 3,
    &mut transport,  // sends/receives MPC messages
)?;

// Presign
let presignature = cggmp21::presign(
    &key_share,
    signers: [party1, party2],
    &mut transport,
)?;

// Sign
let signature = cggmp21::sign(
    &presignature,
    &message_hash,
)?;

// Refresh
let new_key_share = cggmp21::refresh(
    &key_share,
    &mut transport,
)?;
```

---

## 9. Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| Agent machine compromised | Share 1 alone can't sign. Refresh invalidates stolen share. |
| Policy machine compromised | Share 2 alone can't sign. Human + agent can still operate. |
| Network eavesdropping | mTLS. MPC messages don't leak shares even in plaintext. |
| Rogue policy agent (signs everything) | Circuit breakers. Human alerts. Audit logs on both sides. |
| Denial of service (policy goes offline) | Human cosigner as fallback signing path. |
| Replay attacks | Request IDs + nonces in MPC protocol. |
| Share theft + later use | Proactive refresh with TTL. Old shares become invalid. |
| Compromised price oracle | Policy falls back to escalation. Conservative static limits. |

---

## Open Questions

1. **~~Presignatures: disk or memory?~~** — **DECIDED: Memory-only.** Regeneration delay on restart is negligible. Presignatures are dangerous to persist — they're closer to ready-to-use signatures than key shares.

2. **~~Policy agent downtime handling?~~** — **DECIDED: Fail fast + agent decides.** Daemon returns `policy_unavailable` error after 5s timeout. Agent code explicitly chooses to retry, fallback to human cosigner (`fallback: "human"`), or skip. No silent queuing.

3. **~~2-of-2 mode?~~** — **DECIDED: Support with explicit warning.** Identical signing security to 2-of-3, but no recovery path if a share is lost. Requires explicit confirmation. Never the default.

4. **~~Key export for migration~~** — **DECIDED: No.** We will not provide key reconstruction tooling. The full private key should never exist, not even momentarily. Migration path is: create new wallet on new system, transfer funds on-chain, destroy old shares.

5. **Multi-wallet support** — one saw-policy instance managing shares for multiple wallets on the same agent? Probably yes, same as SAW today.
