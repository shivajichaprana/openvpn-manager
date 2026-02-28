# CLI Usage

All flags run non-interactively and exit. Omit flags to launch the interactive menu.

## Flags

| Flag | Description |
|------|-------------|
| `--add-client NAME` | Create a new client |
| `--revoke-client NAME` | Revoke a client |
| `--list-clients` | List active clients |
| `--status` | Show server status |
| `--revoke-expired` | Revoke all expired clients |
| `--install-timer` | Install daily auto-renewal systemd timer |
| `--days N` | Certificate validity in days (default: 365, max: 3650) |
| `--output-dir PATH` | Directory for `.ovpn` output (default: `$HOME`) |
| `--expiry-warn-days N` | Warn N days before expiry (default: 7, env: `OVPN_WARN_DAYS`) |
| `--json` | JSON output for `--list-clients` and `--status` |
| `--dry-run` | Preview `--revoke-expired` without making changes |
| `--notify CMD` | Run `CMD <client>` after each revocation |
| `--version` | Print version |
| `--help` | Show help |

## Examples

```bash
# Add a client valid for 90 days, save .ovpn to /tmp
bash openvpn-manager.sh --add-client alice --days 90 --output-dir /tmp

# Revoke a client
bash openvpn-manager.sh --revoke-client alice

# List clients as JSON (pipe-friendly)
bash openvpn-manager.sh --list-clients --json

# Server status as JSON
bash openvpn-manager.sh --status --json

# Preview what --revoke-expired would do
bash openvpn-manager.sh --revoke-expired --dry-run

# Install the daily auto-revoke timer
bash openvpn-manager.sh --install-timer

# Warn 14 days before expiry (or set OVPN_WARN_DAYS=14 in environment)
bash openvpn-manager.sh --expiry-warn-days 14 --status
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OVPN_WARN_DAYS` | `7` | Days before expiry to start warning |
| `OVPN_NOTIFY_CMD` | `` | Command to run after each auto-revocation (receives client name as arg) |
