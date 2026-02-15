# Production Deployment

## Systemd

The included systemd unit runs the daemon as a dedicated user with `/opt/saw` as the root directory and `/run/saw/saw.sock` as the socket path.

### Setup

Create the required user and group:
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin saw
sudo groupadd --system saw-agent
sudo usermod -aG saw-agent saw
```

Install layout and set ownership:
```bash
sudo saw install --root /opt/saw
sudo chown -R saw:saw /opt/saw
sudo chgrp -R saw-agent /opt/saw/keys
```

Install and enable the service:
```bash
sudo cp systemd/saw.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now saw
```

Verify:
```bash
sudo systemctl status saw
```

### Connecting Clients

The daemon listens on `/run/saw/saw.sock`. Add your agent's service user to the `saw-agent` group:
```bash
sudo usermod -aG saw-agent <agent-user>
```

Point clients at the production socket:
```bash
export SAW_SOCKET=/run/saw/saw.sock
```

## Remote Access

The Docker setup binds the host port to `127.0.0.1:18789` (loopback only). Access from a remote machine via SSH tunnel:

```bash
ssh -L 18789:127.0.0.1:18789 user@your-server
```

Then open `http://127.0.0.1:18789/` in your browser.

### Tailscale / VPN

If you run the gateway on a persistent host (VPS or home server), you can reach it via Tailscale or any VPN instead of SSH tunneling:

- Keep `gateway.bind: "loopback"` and use **Tailscale Serve** for the Control UI
- Or keep loopback + SSH tunnel from any machine that needs access

### Remote CLI

With the tunnel active, CLI commands reach the remote gateway at `ws://127.0.0.1:18789`. You can persist a remote target in your OpenClaw config:

```json5
{
  gateway: {
    mode: "remote",
    remote: {
      url: "ws://127.0.0.1:18789",
      token: "your-token",
    },
  },
}
```

## GCP Deployment

For a full guide on running SAW + OpenClaw on a GCP Compute Engine VM (~$5-12/mo), see the [OpenClaw GCP deployment guide](https://docs.openclaw.ai/install/gcp).

Quick summary:
1. Create GCP project + enable Compute Engine API
2. Create VM (e2-small, Debian 12, 20GB)
3. SSH in, install Docker
4. Clone and configure the repository
5. `docker compose build && docker compose up -d`
6. Access via SSH tunnel: `gcloud compute ssh <vm> --zone=<zone> -- -L 18789:127.0.0.1:18789`

## Runtime Notes

- Rate limits are in-memory per daemon process and reset on restart.
- Requests larger than 64 KiB are rejected.
- Daemon exits cleanly on `SIGINT` or `SIGTERM`.
