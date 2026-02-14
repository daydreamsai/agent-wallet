# Security & Permissions

SAW's security model relies on Unix file permissions and socket access control. The daemon performs no additional authentication or authorization beyond what the OS enforces.

## File Permissions

| Path | Mode | Purpose |
|------|------|---------|
| `keys/` and `keys/<chain>/` | `0700` | Only the daemon user can traverse |
| `keys/<chain>/<wallet>.key` | `0600` | Only the daemon user can read |
| `saw.sock` | `0660` | Owner + group can connect |
| `audit.log` | `0640` | Owner can write, group can read |

## Socket Access

The socket is set to `0660` so multiple authorized processes can connect. Access control is entirely through Unix owner/group/mode on the socket file.

**Operator guidance:** Restrict the socket's group to a dedicated minimal-permission group. Create a dedicated group, `chgrp` the socket and key directories, and avoid adding users to broad groups.

## Hardening Options

- **Filesystem ACLs:** Use `setfacl` for fine-grained access control beyond basic owner/group/other.
- **Startup enforcement:** Enforce `chown`/`chgrp` on daemon startup to prevent permission drift.
- **MAC controls:** Apply SELinux or AppArmor policies to limit which processes can access the socket and key paths.

## Example: Single-Service Access

```bash
# Create a dedicated group
sudo groupadd --system saw-agent

# Create the daemon user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin saw
sudo usermod -aG saw-agent saw

# Set ownership
sudo chown -R saw:saw /opt/saw
sudo chgrp -R saw-agent /opt/saw/keys

# Add only the agent's service user
sudo usermod -aG saw-agent <agent-user>
```

After setup:
- Only `saw` can read keys and write to the socket
- Only members of `saw-agent` can connect to the socket
- Monitor `audit.log` for access visibility

## Audit Logging

Each request appends a single line to `audit.log` with:
- Timestamp
- Wallet name
- Action
- Status (approved/denied)
- Transaction hash (when applicable)

The audit log is append-only. The daemon does not rotate or truncate it. Use external log rotation (e.g. `logrotate`) in production.
