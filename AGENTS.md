# AGENTS.md

Instructions for AI coding agents working on this repository.

## Project

`pkgwatch` is a Rust CLI that reviews Arch Linux AUR package scripts before install. It scans `PKGBUILD`, `.install`, `.SRCINFO`, and helper scripts, checks AUR metadata and known-malware lists, and can wrap `paru` so scanning happens before build/install.

## Safety Rules

- Never execute untrusted AUR package code while testing this project.
- Do not run `makepkg`, `pkgbuild` sourcing, package `build()` functions, install hooks, or helper scripts from fixtures or AUR snapshots.
- Tests should inspect package files as text only.
- Remote AUR snapshot handling must read archive entries safely and reject absolute paths or `..` traversal.
- AI review providers must receive package files as untrusted text only. Do not pipe package content into a shell or interpreter.
- AI output is advisory unless explicitly handled by fail-closed policy.

## Dependency Rules

- Do not add new Rust crates without a clear reason and user approval.
- Prefer standard library or existing dependencies when practical.
- Do not run dependency install commands unless the user explicitly asks.
- `Cargo.lock` should be kept for this binary crate.

## Development Commands

Use:

```sh
cargo fmt
cargo test
```

Useful smoke tests:

```sh
cargo run -- --no-network file fixtures/clean/PKGBUILD
cargo run -- --no-network --json file fixtures/malicious-npm/PKGBUILD
```

For config smoke tests, isolate user state:

```sh
XDG_CONFIG_HOME=/tmp/pkgwatch-config XDG_CACHE_HOME=/tmp/pkgwatch-cache cargo run -- init
```

## Wrapper Testing

- Be careful with `pkgwatch paru -- ...`: after scanning, it can delegate to the real `paru`.
- Prefer non-installing checks first, such as `pkgwatch update-check`.
- For real pending updates, inspect the report before approving continuation.
- Critical findings require the explicit word `INSTALL`; do not bypass this in tests.

## Code Style

- Keep the CLI conservative and explicit.
- Keep detection rules explainable and evidence-based.
- Avoid broad refactors while adding detection rules.
- Preserve JSON output fields unless intentionally versioning the report schema.
- Add unit tests for parser, policy, and detection-rule changes.

