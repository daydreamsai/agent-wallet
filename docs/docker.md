# Docker Setup

Bundles SAW + [DreamClaw](https://github.com/RedBeardEth/clawdbot) — RedBeard's fork of OpenClaw with a custom `daydreams-x402-auth` plugin for x402 payment routing. Instead of API keys, the gateway pays for AI inference per-request via x402: SAW signs EIP-2612 permits on Base, and the x402 router (`https://ai.xgate.run`) forwards requests to the upstream AI provider (Anthropic, Moonshot, etc.).

## First-Time Setup

1. Run `./setup.sh`
2. Confirm the auto-filled onboarding values
3. Fund the wallet address printed during setup
4. Configure your channel (e.g. Telegram bot token)
5. Wait for "Onboarding complete", then press **Ctrl+C**
6. Enter the container as the `node` user and approve pairing:

```bash
docker compose exec -it saw su -s /bin/bash node
openclaw pairing approve <channel> <code>
```

Example: `openclaw pairing approve telegram ABC123`

## Lifecycle Commands

Stop (preserves wallet keys and config):
```bash
docker compose down
```

Start again:
```bash
docker compose up -d
```

Wipe everything and start fresh:
```bash
docker compose down -v
```

## Volume Layout

| Volume | Mount Path | Contents |
|--------|-----------|----------|
| `saw-data` | `/opt/saw` | Wallet keys, policy, audit log |
| `openclaw-data` | `/home/node/.openclaw` | OpenClaw state, auth profiles |

## Notes

- Run `openclaw` commands as `node`, not root.
- The host port is bound to `127.0.0.1:18789` (loopback only). Access from a remote host via SSH tunnel:

```bash
ssh -L 18789:127.0.0.1:18789 user@your-server
```

## Multi-Arch Build

Build for both amd64 and arm64:
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t saw:latest .
```
