# Policy Configuration

SAW uses a strict YAML schema for per-wallet signing rules. Unknown fields are rejected — typos in field names cause validation errors, not silent misconfiguration.

The policy file lives at `~/.saw/policy.yaml` (or `<root>/policy.yaml` if using a custom `--root`).

## Schema

```yaml
wallets:
  <wallet-name>:
    chain: evm | sol
    allowed_chains: [<chain-id>, ...]    # EVM only
    max_tx_value_eth: <float>            # EVM only
    allow_contract_calls: <bool>         # EVM only
    allowlist_addresses:                 # EVM only
      - "0x..."
    rate_limit_per_minute: <int>         # Both chains
```

## Example

```yaml
wallets:
  main:
    chain: evm
    allowed_chains: [1, 8453]
    max_tx_value_eth: 0.05
    allow_contract_calls: false
    allowlist_addresses:
      - "0xabc..."
    rate_limit_per_minute: 5
```

## Field Reference

| Field | Chain | Description |
|-------|-------|-------------|
| `chain` | Both | `evm` or `sol` |
| `allowed_chains` | EVM | Chain IDs the wallet can sign for |
| `max_tx_value_eth` | EVM | Maximum transaction value in ETH |
| `allow_contract_calls` | EVM | Whether non-empty `data` fields are allowed |
| `allowlist_addresses` | EVM | Permitted `to` addresses. For EIP-2612 permits, both `token` and `spender` must be in the allowlist |
| `rate_limit_per_minute` | Both | Maximum signing requests per minute (in-memory, resets on daemon restart) |

## CLI Helpers

Add a wallet stub to the policy file:
```bash
saw policy add-wallet --wallet <name> --chain <evm|sol>
```

Validate the policy file:
```bash
saw policy validate
```

## Solana Limitations

Solana signing currently operates on raw message bytes. The daemon **cannot** enforce recipient allowlists, value limits, or chain IDs for Solana wallets. Only `rate_limit_per_minute` is enforced.

**Recommended mitigations (until full transaction parsing is implemented):**
- Only send pre-validated messages from a trusted component
- Use a dedicated Solana wallet with low balances and restrictive operational controls

Tracking: [issue #2](https://github.com/daydreamsai/agent-wallet/issues/2)
