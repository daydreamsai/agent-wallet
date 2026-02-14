# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Secure Agent Wallet (SAW) — a local signing service for AI agents. Private keys never leave the daemon process. Policy rules gate every signing request. All access is via Unix domain sockets.

## Build & Test Commands

```bash
# Build all Rust crates
cargo build --workspace

# Run all tests (CI runs this)
cargo test --workspace

# Run a single test by name
cargo test --workspace -- test_name

# Run tests for a specific crate
cargo test -p saw          # CLI crate
cargo test -p saw-daemon   # daemon crate

# Build the Node.js client
cd packages/saw && npm install && npm run build

# Run Node.js client tests (requires vitest)
cd packages/saw && npm test

# Docker (gateway mode — SAW daemon + OpenClaw gateway)
cp .env.example .env                 # set OPENCLAW_GATEWAY_TOKEN
docker compose up -d                 # build + start
docker compose logs -f               # watch startup
```

## Architecture

**Rust workspace** with two crates:

- **`crates/saw-cli`** (`saw` binary) — Key generation (EVM via k256/secp256k1, Solana via ed25519-dalek), policy management (YAML with `serde_yaml`, `deny_unknown_fields`), directory layout setup. The `lib.rs` exposes core types (`Chain`, `Policy`, `WalletPolicy`, `GenKeyResult`) and functions (`gen_key`, `validate_policy`, `get_address`, `list_wallets`, `install_layout`). The `cli` module parses args manually (no clap).

- **`crates/saw-daemon`** (`saw-daemon` binary) — AF_UNIX server that accepts JSON requests, enforces policy checks (chain allowlist, address allowlist, value limits, contract call restriction, rate limiting), signs transactions, and writes to `audit.log`. The `Server` struct in `lib.rs` holds mutable rate-limit state. Public API: `serve_once`, `serve_n`, `serve_forever`, `serve_forever_with_shutdown`. Daemon tests use `serve_n` or `serve_once` with temp directories.

- **`packages/saw`** (`@daydreamsai/saw` npm package) — TypeScript client that talks to the daemon over the Unix socket. Built with tsup, tested with vitest.

**Data layout** (default `~/.saw/`):
- `keys/{evm,sol}/<wallet>.key` — raw binary private keys (0600)
- `policy.yaml` — per-wallet signing rules (strict schema, unknown fields rejected)
- `audit.log` — append-only request log
- `saw.sock` — Unix domain socket (0660)

**Key patterns:**
- Both crates duplicate `Chain`, `WalletPolicy`, `Policy` types (no shared crate). The daemon re-reads `policy.yaml` on every request.
- Wallet names are validated: alphanumeric, `_`, `-`, 1-64 chars.
- EVM signing uses `secp256k1` crate for recoverable ECDSA (not k256's signer). EIP-1559 (type 2) transactions only.
- Solana signing operates on raw message bytes — no transaction parsing or policy enforcement beyond rate limits.
- Tests create isolated temp directories and use the library API directly (not shelling out to binaries).
- No async runtime — the daemon uses blocking I/O with non-blocking listener accept loop and `set_read_timeout`.
