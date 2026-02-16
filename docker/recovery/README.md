# SAW Recovery Co-signer

This Docker container holds **Party 2** (the recovery key share) for the SAW threshold wallet.

## When to use

If either the daemon (party 0) or the primary policy server (party 1) is permanently lost,
you can use this recovery co-signer alongside the surviving party to sign transactions
and migrate funds to a new wallet.

## Quick start

```bash
# Build from repo root
docker build -f docker/recovery/Dockerfile -t saw-recovery .

# Run
docker run -d --name saw-recovery -p 8080:8080 \
  -e SAW_PASSPHRASE="your-passphrase" \
  -e KEY_SHARE_BASE64="<party2-share-base64>" \
  -e POLICY_YAML="$(base64 -w0 policy.yaml)" \
  saw-recovery
```

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SAW_PASSPHRASE` | Yes | Passphrase to decrypt the key share |
| `KEY_SHARE_BASE64` | Yes | Base64-encoded encrypted party 2 key share |
| `POLICY_YAML` | Yes | Base64-encoded policy.yaml |
| `PORT` | No | Listen port (default: 8080) |

## Recovery procedure

1. Start this container
2. Point the surviving party's config at this container's WS endpoint
3. Sign a transaction to transfer all funds to a new wallet
4. Generate new threshold key shares for the new wallet
5. Destroy this container and its key share

## Security

- Keep the `KEY_SHARE_BASE64` and `SAW_PASSPHRASE` separate — don't store them in the same place
- This container should only be run when recovery is needed, not 24/7
- After recovery, rotate to fresh key shares
