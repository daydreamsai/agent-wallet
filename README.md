# Secure Agent Wallet (SAW)

Local signing service for AI agents. Private keys never leave the daemon process, policy rules gate every request, and all access is over a Unix domain socket.

## Get Started

### Docker (recommended)

Bundles SAW + [DreamClaw](https://github.com/RedBeardEth/clawdbot) (OpenClaw fork with x402 payment routing).

```bash
git clone https://github.com/daydreamsai/agent-wallet.git && cd agent-wallet
./setup.sh
```

Fund the wallet address printed during setup, then follow the onboarding prompts. See [docs/docker.md](docs/docker.md) for the full walkthrough.

### Install binary

```bash
curl -sSL https://raw.githubusercontent.com/daydreamsai/agent-wallet/master/install.sh | sh
```

### Build from source

```bash
cargo build --release
sudo cp target/release/saw target/release/saw-daemon /usr/local/bin/
```

## Quick Start

```bash
saw install                                    # create ~/.saw layout
saw gen-key --chain evm --wallet main          # generate a wallet
nano ~/.saw/policy.yaml                        # set signing constraints
saw policy validate                            # check policy syntax
saw-daemon                                     # start the daemon
```

The default policy stub has **no limits** — configure it before exposing the daemon. See [docs/policy.md](docs/policy.md) for the schema.

## CLI Reference

| Command | Description |
|---------|-------------|
| `saw install` | Create the `~/.saw` directory layout |
| `saw gen-key --chain <evm\|sol> --wallet <name>` | Generate a new keypair |
| `saw address --chain <evm\|sol> --wallet <name>` | Print wallet address |
| `saw list` | List all wallets |
| `saw policy validate` | Validate `policy.yaml` |
| `saw policy add-wallet --wallet <name> --chain <evm\|sol>` | Add a wallet stub to the policy |
| `saw-daemon` | Start the signing daemon |

All commands support `--root <path>` and `--help`.

## Node.js Client

```bash
npm install @daydreamsai/saw
```

```typescript
import { createSawClient } from "@daydreamsai/saw";
const saw = createSawClient();
const address = await saw.getAddress();
```

Full API: [packages/saw/README.md](packages/saw/README.md)

## Documentation

| Topic | Description |
|-------|-------------|
| [Docker + OpenClaw](docs/docker.md) | Container setup, DreamClaw x402 integration, lifecycle commands |
| [Policy](docs/policy.md) | YAML schema, field reference, Solana limitations |
| [Socket API](docs/api.md) | JSON request/response examples for all actions |
| [Security](docs/security.md) | File permissions, socket access, hardening options |
| [Production](docs/production.md) | Systemd, remote access, GCP deployment |
| [Contributing](docs/contributing.md) | Build, test, architecture, releases |

## License

MIT
