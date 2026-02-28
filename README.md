# openvpn-manager

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

## Usage

```bash
bash openvpn-manager.sh
```

Run as root. On first run it installs OpenVPN. On subsequent runs it opens the management menu.

## Management Menu Options

| Option | Description |
|---|---|
| 1 | Add a new client |
| 2 | Add multiple clients (bulk) |
| 3 | Revoke a client |
| 4 | Revoke multiple clients (bulk) |
| 5 | Revoke all expired clients |
| 6 | Show server status |
| 7 | Remove OpenVPN |
| 8 | Renew client certificate |
| 9 | Show client connection history |
| 10 | Restart / Reload OpenVPN |
| 11 | Backup & Restore |
| 12 | Show client QR code |
| 13 | Change client expiry |
| 14 | Disconnect a client |
| 15 | View live logs |
| 16 | Update EasyRSA |
| 18 | Export client .ovpn via SCP |
| 19 | Rename a client |
| 20 | Bandwidth usage per client |
| 21 | Rotate tls-crypt key |
| 22 | Test connectivity |
| 23 | Change server port/protocol |
| 24 | List revoked clients |

## Requirements

- Root privileges
- TUN device available (`/dev/net/tun`)
- Kernel 3.x+
- `$PATH` must include sbin

## Logs

- Manager log: `/var/log/openvpn-manager.log`
- OpenVPN log: `/var/log/openvpn.log`
