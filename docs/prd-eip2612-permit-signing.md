# PRD: EIP-2612 Permit Signing

## Summary
Add a new SAW daemon action to sign ERC-2612 permit typed data (EIP-712) using an EVM wallet stored by the daemon. This enables services like the x402 router to obtain a permit signature without exposing private keys in application code.

## Problem
The current SAW daemon only supports `get_address`, `sign_evm_tx`, and `sign_sol_tx`. Clients that need ERC-2612 permits must sign EIP-712 typed data, which currently requires direct access to the private key. We need a daemon action that signs a permit with the existing wallet keys and policy enforcement.

## Goals
- Provide a single daemon action to sign ERC-2612 Permit typed data.
- Keep keys inside the daemon; the client never handles private keys.
- Enforce existing policy constraints where relevant.
- Return a standard 65-byte ECDSA signature (`0x`-hex with `v` as 27/28).

## Non-Goals
- Generic EIP-712 typed data signing.
- Key import/export or wallet management changes.
- New on-chain transaction flows.

## Requirements
### New daemon action
Action name: `sign_eip2612_permit`

Request payload:
- `chain_id` (number) — EVM chain id for the domain.
- `token` (string) — ERC-20 contract address (verifyingContract).
- `name` (string) — EIP-712 domain name (token name).
- `version` (string) — EIP-712 domain version.
- `spender` (string) — permit spender.
- `value` (string) — permit value, decimal or hex.
- `nonce` (string) — permit nonce, decimal or hex.
- `deadline` (string) — permit deadline, decimal or hex.
- `owner` (string, optional) — if provided, must match the wallet address.

Response:
- On success: `{ "signature": "0x..." }`
- On failure: standard `status: "denied"` with error message.

### Policy enforcement
- `chain` must be `evm`.
- If `allowed_chains` is set, `chain_id` must be included.
- If `allowlist_addresses` is set, both `token` and `spender` must be allowlisted.
- `rate_limit_per_minute` must be enforced.
- If `owner` is provided and does not match the wallet address, deny.

### Signing
- Use EIP-712 domain:
  - `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`
- Use Permit struct:
  - `Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)`
- Digest: `keccak256("\x19\x01" || domainSeparator || structHash)`
- Signature: secp256k1 recoverable signature; `v` = recovery id + 27.

## UX / Developer Experience
- The request/response mirrors existing socket usage patterns.
- Minimal extra fields beyond standard EIP-2612 input.

## Security Considerations
- Enforcing allowlists and chain checks prevents signing for unexpected spenders or tokens.
- Owner mismatch check prevents accidental mis-binding to another address.

## Testing
- Integration test: happy path returns a valid signature that recovers to the wallet address for the computed digest.
- Deny test: chain_id not in allowlist.
- Deny test: allowlist does not include spender or token.
- Deny test: owner mismatch.

## Rollout
- Add to README and daemon API examples.
- Clients should switch from local key signing to `sign_eip2612_permit` via socket.
