# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.0] - 2025-01-01

### Added
- Automated OpenVPN installation with security hardening (ECC keys, AES-256-GCM, TLS 1.2+, tls-crypt)
- Client management: add, revoke, renew, bulk operations
- Certificate expiry tracking and warnings
- Backup & restore
- Live log viewer
- QR code generation for mobile import
- Multi-distro support (Ubuntu, Debian, Rocky, AlmaLinux, Fedora, Alpine, openSUSE, Amazon Linux)
- `--version` / `--help` flags
- GitHub Actions ShellCheck CI
- Non-interactive CLI args (`--add-client`, `--revoke-client`, `--list-clients`, `--status`, `--days`)
- Auto-renewal systemd timer (`--install-timer`, `--revoke-expired`, menu option 17)
