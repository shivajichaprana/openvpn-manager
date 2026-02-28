# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.4.0] - 2026-02-28

### Fixed
- AL2023: `curl-minimal` conflicts with `curl` — removed `curl`, added `--allowerasing` to `dnf install`
- EasyRSA `build-server-full` and `build-client-full` missing `--batch` flag causing interactive prompt
- `check_db_integrity` exits 1 under `set -e` when DB is clean — replaced `&&` with `if-then`
- `local` keyword used outside function in CLI dispatch block — replaced with plain variable assignments
- DNS value in `show_status` had trailing `"` from `push "dhcp-option DNS ..."` line — stripped with `gsub`
- `easyrsa revoke` ran from wrong directory (PKI not found) — added `cd "$EASYRSA_DIR"` in `do_revoke` and menu option 8
- Menu 10 reload called `systemctl reload` directly (fails on AL2023) — now uses `reload_service()` with restart fallback
- Menu 11 restore: `pipefail` caused `tar | grep` validation to fail on valid archives — neutralised tar exit code
- Menu 11 restore: `err` called on validation/extract failure exits script mid-menu — replaced with `warn + pause + continue`
## [1.2.0] - 2025-07-01

### Added
- `umask 077` on tmp `.ovpn` file (secure from creation, not just after chmod)
- `check_db_integrity()` — warns on corrupt/truncated `clients.db` lines
- `--dry-run` flag for `--revoke-expired` — preview without making changes
- `.github/ISSUE_TEMPLATE/` bug report and feature request templates
- `.github/PULL_REQUEST_TEMPLATE.md` with ShellCheck/test checklist
- `docs/usage.md` — full CLI flag reference with examples
- Quick-install one-liner in README

## [1.1.0] - 2025-07-01

### Added
- Atomic `.ovpn` write (tmp → mv) — no corrupt files on interrupted writes
- `flock` on `clients.db` — safe against concurrent runs
- `--output-dir PATH` — specify `.ovpn` destination directory
- `--json` output for `--list-clients` and `--status`
- `--expiry-warn-days N` / `OVPN_WARN_DAYS` env var
- `SECURITY.md` — private vulnerability disclosure policy
- Latest release badge in README

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
