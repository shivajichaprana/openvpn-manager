# Contributing

## Requirements

- Run `shellcheck openvpn-manager.sh` before submitting — zero warnings required
- Test on at least one supported distro
- Keep changes minimal and focused

## Workflow

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Make your changes
3. Run `bash -n openvpn-manager.sh` and `shellcheck openvpn-manager.sh`
4. Update `CHANGELOG.md` under `[Unreleased]`
5. Open a pull request against `main`

## Guidelines

- Match the existing code style (no external dependencies, pure bash)
- One logical change per PR
- Commit messages: `type: short description` (e.g. `feat:`, `fix:`, `docs:`)
