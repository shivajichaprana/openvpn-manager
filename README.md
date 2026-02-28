# openvpn-manager

[![ShellCheck](https://github.com/shivajichaprana/openvpn-manager/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/shivajichaprana/openvpn-manager/actions/workflows/shellcheck.yml)
[![Latest Release](https://img.shields.io/github/v/release/shivajichaprana/openvpn-manager)](https://github.com/shivajichaprana/openvpn-manager/releases/latest)

A hardened OpenVPN server installer and management script for Linux.

## Features

- Automated OpenVPN installation with security hardening
- ECC keys (prime256v1), AES-256-GCM, TLS 1.2+, tls-crypt
- Client management: add, revoke, renew, bulk operations
- Certificate expiry tracking and warnings
- Backup & restore
- Live log viewer
- QR code generation for mobile import
- Multi-distro support

## Supported Distributions

| Distribution | Version |
|---|---|
| Ubuntu | 20.04+ |
| Debian | 11+ |
| Rocky Linux / AlmaLinux | 8+ |
| Fedora | latest |
| Alpine | latest |
| openSUSE | latest |
| Amazon Linux | 2 / 2023 |

## Quick Install

```bash
wget -O openvpn-manager.sh https://raw.githubusercontent.com/shivajichaprana/openvpn-manager/main/openvpn-manager.sh
bash openvpn-manager.sh
```

## Usage

```bash
sudo bash openvpn-manager.sh
```

Run as root. On first run it installs OpenVPN. On subsequent runs it opens the management menu.

---

## Management Menu — All Options

### 1. Add a New Client
**Why:** Create a VPN profile for a new user or device.  
**How:** Enter a name and validity period (days). Optionally set a passphrase to protect the private key. Outputs a `.ovpn` file and a QR code for mobile import.

### 2. Add Multiple Clients (Bulk)
**Why:** Onboard many users at once without repeating option 1.  
**How:** Enter one client name per line, press Enter on an empty line to finish. All clients share the same validity period entered at the start.

### 3. Revoke a Client
**Why:** Immediately block a user from connecting — lost device, employee offboarding, compromised key.  
**How:** Select the client from the numbered list and confirm. The certificate is revoked, the CRL is updated, and the `.ovpn` file is deleted.

### 4. Revoke Multiple Clients (Bulk)
**Why:** Offboard several users at once.  
**How:** Enter space-separated numbers from the client list (e.g. `1 3 5`). All selected clients are revoked and the CRL is updated once at the end.

### 5. Revoke All Expired Clients
**Why:** Clean up clients whose certificates have passed their validity date so they can no longer connect.  
**How:** No input needed — the script finds all expired entries in `clients.db`, revokes them, and reloads the service. Use `--revoke-expired --dry-run` via CLI to preview first.

### 6. Show Server Status
**Why:** Quick health check — see if OpenVPN is running, what port/protocol/cipher it uses, and who is connected.  
**How:** No input needed. Displays systemd service status, server config summary, connected clients, and registered clients with expiry dates. Warns about expiring certificates.

### 7. Remove OpenVPN
**Why:** Completely uninstall OpenVPN and all its configuration from the server.  
**How:** Confirm with `y`. Removes the service, firewall rules, PKI, all `.ovpn` files, and the OpenVPN package. **This is irreversible — take a backup first (option 11).**

### 8. Renew Client Certificate
**Why:** Extend access for a client whose certificate is expiring without changing their name or revoking them.  
**How:** Select the client, enter new validity days. The old certificate is revoked, a new one is issued, and a fresh `.ovpn` is generated.

### 9. Show Client Connection History
**Why:** Audit who connected, from which IP, and when.  
**How:** No input needed. Parses `/var/log/openvpn.log` for connect/disconnect events and displays the last 50 entries in a table.

### 10. Restart / Reload OpenVPN
**Why:** Apply config changes or recover from a hung state.  
**How:** Choose `1` to reload (applies changes, keeps existing connections) or `2` to restart (drops all connections). Reload automatically falls back to restart if the service doesn't support it.

### 11. Backup & Restore
**Why:** Protect your PKI, client configs, and server config against data loss. Essential before upgrades or migrations.  
**How:**
- **Backup:** Creates a timestamped `.tar.gz` of `/etc/openvpn/server/` in `/root/`.
- **Restore from list:** Shows all backups in `/root/`, select by number.
- **Restore from path:** Enter the full path to any backup file.

After restore, the service is restarted automatically and all client certificates remain valid.

### 12. Show Client QR Code
**Why:** Import a client profile on a mobile device without transferring files.  
**How:** Select the client — the `.ovpn` file is rendered as a QR code in the terminal. Scan with the OpenVPN Connect app.

### 13. Change Client Expiry
**Why:** Extend or shorten a client's access window without revoking and re-issuing the certificate.  
**How:** Select the client, enter new validity in days from today. Only the `clients.db` record is updated — the certificate itself is not reissued.

### 14. Disconnect a Client
**Why:** Immediately drop an active connection without revoking the certificate (temporary block).  
**How:** Select from the list of currently connected clients. Uses the OpenVPN management socket to send a `kill` command.

### 15. View Live Logs
**Why:** Real-time debugging of connection issues or monitoring activity.  
**How:** Choose the log source:
- `1` — OpenVPN log (`/var/log/openvpn.log`)
- `2` — systemd journal (`journalctl -f`)
- `3` — Manager log (`/var/log/openvpn-manager.log`)

Press `Ctrl+C` to stop.

### 16. Update EasyRSA
**Why:** Get the latest EasyRSA version for security fixes or new features without reinstalling OpenVPN.  
**How:** No input needed. Downloads the latest release from GitHub, verifies it, and replaces the binary in place. Existing PKI is untouched.

### 17. Install / Refresh Auto-Renewal Timer
**Why:** Automatically revoke expired certificates daily without manual intervention.  
**How:** No input needed. Installs a systemd `.service` + `.timer` that runs `--revoke-expired` every day. Safe to run again to refresh the timer after moving the script.

### 18. Export Client .ovpn via SCP
**Why:** Securely transfer a client profile to a remote server or another machine.  
**How:** Select the client, then enter an SCP destination in `user@host:/path` format. The `.ovpn` file is copied using your existing SSH credentials.

### 19. Rename a Client
**Why:** Fix a typo or update a client name without revoking and re-issuing the certificate.  
**How:** Select the client, enter the new name. Updates `clients.db` and renames the `.ovpn` file. The certificate CN is not changed.

### 20. Bandwidth Usage per Client
**Why:** See how much data each connected client has transferred in the current session.  
**How:** No input needed. Reads the live OpenVPN status log and displays bytes in/out per connected client.

### 21. Rotate tls-crypt Key
**Why:** Invalidate all existing client configs at once — useful after a suspected key compromise or as a periodic security measure.  
**How:** Confirm with `y`. A new `tc.key` is generated and the service is reloaded. **All existing `.ovpn` files become invalid** — regenerate them with option 1 or 8.

### 22. Test Connectivity
**Why:** Quickly verify the VPN is reachable and the tunnel interface is up.  
**How:** No input needed. Checks if the configured port is open on localhost and pings the `tun0` interface IP.

### 23. Change Server Port / Protocol
**Why:** Move OpenVPN to a different port (e.g. 443/TCP to bypass firewalls) or switch between UDP and TCP.  
**How:** Enter the new port number and select UDP or TCP. The server config and firewall rules are updated and the service is restarted. **Existing clients need new `.ovpn` files** after this change.

### 24. List Revoked Clients
**Why:** Audit which clients have been revoked and can no longer connect.  
**How:** No input needed. Reads the PKI index and lists all revoked certificate CNs.

---

## Requirements

- Root privileges
- TUN device available (`/dev/net/tun`)
- Kernel 3.x+
- `$PATH` must include sbin

## Logs

- Manager log: `/var/log/openvpn-manager.log`
- OpenVPN log: `/var/log/openvpn.log`

## CLI Reference

See [docs/usage.md](docs/usage.md) for all non-interactive flags and examples.
