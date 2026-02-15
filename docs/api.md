# Socket API

All messages are JSON over a Unix domain socket. The daemon reads one request per connection and replies with one response.

Requests larger than 64 KiB are rejected.

## Get Address

**Request:**
```json
{
  "request_id": "1",
  "action": "get_address",
  "wallet": "main"
}
```

**Response:**
```json
{
  "request_id": "1",
  "status": "approved",
  "result": {
    "address": "0x..."
  }
}
```

## Sign EVM Transaction (EIP-1559)

Only type-2 (EIP-1559) transactions are supported.

**Request:**
```json
{
  "request_id": "2",
  "action": "sign_evm_tx",
  "wallet": "main",
  "payload": {
    "chain_id": 1,
    "nonce": 0,
    "to": "0x1111111111111111111111111111111111111111",
    "value": "0x0",
    "gas_limit": 21000,
    "max_fee_per_gas": "0x3b9aca00",
    "max_priority_fee_per_gas": "0x3b9aca00",
    "data": "0x"
  }
}
```

**Response:**
```json
{
  "request_id": "2",
  "status": "approved",
  "result": {
    "raw_tx": "0x...",
    "tx_hash": "0x..."
  }
}
```

## Sign EIP-2612 Permit (EIP-712 Typed Data)

**Request:**
```json
{
  "request_id": "3",
  "action": "sign_eip2612_permit",
  "wallet": "main",
  "payload": {
    "chain_id": 1,
    "token": "0x1111111111111111111111111111111111111111",
    "name": "USD Coin",
    "version": "2",
    "spender": "0x2222222222222222222222222222222222222222",
    "value": "1000000",
    "nonce": "0",
    "deadline": "9999999999",
    "owner": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

**Response:**
```json
{
  "request_id": "3",
  "status": "approved",
  "result": {
    "signature": "0x..."
  }
}
```

**Notes:**
- If `allowlist_addresses` is set in policy, both `token` and `spender` must be in the allowlist.
- If `owner` is provided, it must match the wallet's address.

## Sign Solana Transaction (Raw Bytes)

**Warning:** The daemon signs raw message bytes only. It cannot enforce policy checks like recipient allowlists, value limits, or chain IDs for Solana. See [policy.md](policy.md#solana-limitations) for mitigations.

**Request:**
```json
{
  "request_id": "4",
  "action": "sign_sol_tx",
  "wallet": "treasury",
  "payload": {
    "message_base64": "aGVsbG8tc29sYW5h"
  }
}
```

**Response:**
```json
{
  "request_id": "4",
  "status": "approved",
  "result": {
    "signature": "...",
    "signed_tx_base64": "..."
  }
}
```

`signed_tx_base64` is a minimal encoding: `1 || signature || message` (signature count + signature + message bytes).

## Error Response

When a request is denied by policy:
```json
{
  "request_id": "2",
  "status": "denied",
  "error": "chain_id 137 not in allowed_chains"
}
```
