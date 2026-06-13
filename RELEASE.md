# Release Checklist

## Before Tagging

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

Smoke test:

```sh
pkgwatch update-check
pkgwatch --ai --ai-threshold always update-check
```

Review:

- `README.md` install instructions.
- `CHANGELOG.md` release notes.
- `Cargo.toml` version.

## Tag

```sh
git tag v0.1.0
git push origin v0.1.0
```

Pushing the tag runs the release workflow and uploads:

- `pkgwatch-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
- `pkgwatch-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256`

## GitHub Release Notes

Use:

```text
Initial MVP release.

- Static AUR PKGBUILD, .install, .SRCINFO, and helper script scanning.
- paru wrapper and update-check flow.
- AUR metadata and dependency closure checks.
- Optional advisory AI review through codex, claude, gemini, or custom command.
- JSON and human-readable reports.
- Linux x86_64 binary artifact and SHA256 checksum.
```

## After Release

- Verify `cargo install --git https://github.com/bkbalci/pkgwatch --tag v0.1.0` works.
- Verify the release asset checksum and binary run.
- Consider adding an AUR package for `pkgwatch`.
- Watch issues for wrapper false positives and AI provider command compatibility.
