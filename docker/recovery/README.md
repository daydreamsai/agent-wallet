# SAW Recovery Co-signer (Party 2)

Runs `saw-policy` with the recovery key share. Use when party 0 (daemon) or party 1 (primary policy) is lost and you need to sign with the surviving party.

## Quick start

```bash
# Build from repo root
docker build -f docker/recovery/Dockerfile -t saw-recovery .

# Run (macOS)
docker run -p 9443:9443 \
  -e SAW_PASSPHRASE="your-passphrase" \
  -e KEY_SHARE_BASE64="$(base64 -i ~/saw-recovery/party2.json.enc)" \
  saw-recovery

# Run (Linux)
docker run -p 9443:9443 \
  -e SAW_PASSPHRASE="your-passphrase" \
  -e KEY_SHARE_BASE64="$(base64 -w0 ~/saw-recovery/party2.json.enc)" \
  saw-recovery
```

## Recovery procedure

1. Start this container
2. Point the surviving party's config at `wss://your-machine:9443`
3. Sign a transaction to transfer funds to a new wallet
4. Generate new key shares for the new wallet
5. Destroy this container

## Security

- Store `party2.json.enc` and `SAW_PASSPHRASE` in separate locations
- Only run this container during recovery — not 24/7
- After recovery, rotate to fresh key shares
