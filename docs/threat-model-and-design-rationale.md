# Threat Model & Design Rationale

**Date:** 2026-02-15
**Authors:** Slyme + Modus

## Why Threshold Signing?

A natural question: if an attacker gets root on the machine running saw-daemon, they can initiate transactions through the normal signing API — so what does threshold MPC actually buy you?

### What root access gives an attacker

With root on the agent machine, an attacker **can**:
- Call saw-daemon's signing API directly
- Initiate any transaction through the normal flow
- Read environment variables, memory, disk

With threshold signing, an attacker **cannot**:
- Extract the full private key (only a key share exists on each machine)
- Use the key offline or on another system
- Sign without the policy co-signer approving

### The key insight

**Threshold MPC protects against key exfiltration. The policy co-signer protects against unauthorized signing.** These are complementary — you need both for full security.

Without MPC, even with a policy co-signer, an attacker who compromises the agent machine gets the full private key. They can:
- Exfiltrate it and use it later, even after you've patched the breach
- Use it from any machine, bypassing the policy signer entirely
- Drain funds at their leisure, long after the initial compromise

With MPC, a compromise of one machine is recoverable — rotate the shares via a new keygen ceremony and the stolen share becomes useless.

### Why not just use an on-chain multisig?

On-chain multisig (e.g., Safe) provides similar co-signing guarantees and is battle-tested. We considered this. The tradeoffs:

| | Threshold ECDSA | On-chain Multisig |
|---|---|---|
| On-chain appearance | Normal EOA | Contract wallet |
| Gas overhead | None | Higher (multi-sig tx) |
| Chain support | Any EVM chain | Needs deployed contracts |
| Complexity | High (MPC protocol) | Low (well-known pattern) |
| Key exfiltration protection | ✅ PK never exists | ❌ Each signer holds full key |
| Ecosystem compatibility | Universal (looks like EOA) | Some protocols don't support contract wallets |

For a framework serving other developers' agents — potentially holding unknown amounts of value — the stronger guarantee of "private key never exists in any single location" justifies the added complexity. An accidental git push, a log leak, or a memory dump can never expose a key that doesn't exist.

### Why we kept all three deployment modes

Not every agent needs the same security posture. A bot managing $10 in gas money has different needs than one managing a treasury.

1. **Single-key (default)** — Zero additional infrastructure. Works today. Appropriate for low-value wallets, development, and agents that don't handle significant funds.

2. **Self-hosted threshold** — Run your own policy signer on a separate machine. Full control, no third-party trust. Appropriate for teams who can manage infrastructure and want strong key protection.

3. **TEE/premium threshold** — Managed co-signing service running in a Trusted Execution Environment. Appropriate for agents handling real money where operators want professional-grade security without running their own infrastructure.

The framework defaults to single-key so there's zero friction to get started. Upgrading to threshold is a configuration change — the client SDK API is identical across all modes.

### Accepted risks

- **Root compromise + active policy signer**: An attacker with root on the agent machine can sign transactions as long as they pass policy rules and the policy signer is reachable. Mitigation: strict policy rules (allowlists, rate limits, circuit breakers).
- **Policy signer downtime**: Signing fails fast (5s timeout) and returns `policy_unavailable`. The agent decides whether to retry, queue, or skip. No silent failures.
- **2-of-2 mode (no recovery share)**: Supported but explicitly warned against. If either share is lost, the wallet is irrecoverable. Only appropriate when operators accept this tradeoff.
- **No key refresh in v1**: The cggmp21 crate doesn't support threshold key refresh. If a share is suspected compromised, the mitigation is a full re-keygen to a new wallet and on-chain fund transfer. This is a known limitation we accept for v1.
