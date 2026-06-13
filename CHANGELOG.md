# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning once published.

## [Unreleased]

### Added

- Initial Rust CLI with `scan`, `file`, `batch`, `update-check`, `update-list`, `init`, and `paru` wrapper commands.
- Static PKGBUILD, `.install`, `.SRCINFO`, and helper shell script scanning.
- AUR RPC metadata checks and AUR dependency closure scanning.
- Cached known-malware package list with built-in fallback entries.
- Optional advisory AI review through `codex`, `claude`, `gemini`, or a custom command.
- JSON and human-readable report output.
- Wrapper config under `~/.config/pkgwatch/config.toml`.

### Security

- Scans read package files as text only and do not execute package scripts.
- Snapshot archive paths are validated against absolute paths and `..` traversal.
- Critical risk continuation requires typing `INSTALL`.

