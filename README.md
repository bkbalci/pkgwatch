# pkgwatch

`pkgwatch` is a Rust CLI for reviewing AUR `PKGBUILD` and `.install` content before install. It reports suspicious build/install patterns, checks a cached known-malware package list, reads AUR RPC metadata when network access is allowed, and can wrap `paru`.

`pkgwatch` is a guardrail, not a verifier. It never executes package scripts during scans, but users should still review PKGBUILDs and prefer clean build environments for high-risk packages.

## Commands

```sh
pkgwatch scan <package>
pkgwatch file <path>
pkgwatch -f <path>
pkgwatch batch
pkgwatch update-check
pkgwatch update-list
pkgwatch init
pkgwatch paru -- <paru args...>
```

Global flags:

```sh
--json        Emit stable JSON output
--strict      Exit non-zero on high or critical findings
--no-network  Use local cache and built-in fallbacks only
--yes         Auto-accept non-critical prompts
--ai          Enable advisory AI review for this command
--ai-provider auto|codex|claude|gemini
--ai-threshold always|info|low|medium|high|critical
--ai-custom-command /path/to/reviewer
```

## Paru Wrapper Setup

Run:

```sh
pkgwatch init
```

This creates `~/.config/pkgwatch/config.toml` and prints a shell function:

```sh
paru() {
  pkgwatch paru -- "$@"
}
```

Add that function to your shell rc file if you want normal `paru -S ...` usage to pass through `pkgwatch` first.

Example config:

```toml
[policy]
strict = false
ask_on = "high"
block_on = "critical"
yes = false

[network]
auto_update_list = true
use_aur_metadata = true
max_aur_packages = 25

[ai]
enabled = false
provider = "auto"
threshold = "medium"
timeout_seconds = 45
fail_closed = false
max_file_bytes = 65536
max_total_bytes = 245760

[wrapper]
enabled = true
real_paru_path = "/usr/bin/paru"
```

AI review is opt-in. When enabled, `pkgwatch` looks for `codex`, `claude`, or `gemini` in `PATH`, or runs `custom_command` when `provider = "custom"`. It sends only package script text for advisory review. AI output does not execute package code and is not treated as a blocking signal by itself unless `fail_closed = true` and the AI review cannot complete.

Remote AUR scans download the package snapshot and inspect `PKGBUILD`, `.install`, `.SRCINFO`, and helper shell scripts before build. `pkgwatch paru -- ...` also expands AUR dependency closure up to `max_aur_packages`.

Exit codes:

- `0`: clean or accepted warnings
- `1`: scan completed with warnings in strict mode
- `2`: critical finding blocked or user declined
- `3`: usage/config error

## Verification

When a Rust toolchain is available:

```sh
cargo fmt --check
cargo test
cargo run -- file fixtures/clean/PKGBUILD
cargo run -- --json file fixtures/malicious-npm/PKGBUILD
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep scanner changes evidence-based, add tests for new rules, and do not add package execution to tests or scan paths.

## Security

Please report security issues privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
