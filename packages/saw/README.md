# @daydreamsai/saw

Node.js client for Secure Agent Wallet (SAW). Simple Unix socket API to sign EVM/Solana payloads without exposing private keys.

**Prerequisite:** The SAW daemon (`saw-daemon`) must be installed and running. See the [main README](../../README.md) for setup instructions.

## Install
```bash
npm install @daydreamsai/saw
```

## Quickstart
```ts
import { createSawClient } from "@daydreamsai/saw";

const saw = createSawClient();

const address = await saw.getAddress();
console.log("wallet:", address);

const sig = await saw.signEip2612Permit({
  chain_id: 1,
  token: "0x1111111111111111111111111111111111111111",
  name: "USD Coin",
  version: "2",
  spender: "0x2222222222222222222222222222222222222222",
  value: "1000000",
  nonce: "0",
  deadline: "9999999999",
});

console.log(sig);
```

## Configuration
Defaults are zero-config. Override if needed:
- `SAW_SOCKET` (default `~/.saw/saw.sock`)
- `SAW_WALLET` (default `main`)

```ts
const saw = createSawClient({
  socketPath: "~/.saw/saw.sock",
  wallet: "main",
});
```

## API
- `getAddress()`
- `signEvmTx(payload)`
- `signSolTx(payload)`
- `signEip2612Permit(payload)`

## Policy Notes
If `allowlist_addresses` is set, **both** `token` and `spender` must be allowed for permit signing.

## Node Only
This client uses Unix domain sockets and is intended for Node.js environments.
