# pkgwatch

`pkgwatch` is a Rust CLI for reviewing AUR `PKGBUILD` and `.install` content before install. It reports suspicious build/install patterns, checks a cached known-malware package list, reads AUR RPC metadata when network access is allowed, and can wrap `paru`.

`pkgwatch` is a guardrail, not a verifier. It never executes package scripts during scans, but users should still review PKGBUILDs and prefer clean build environments for high-risk packages.

## Why

The June 2026 AUR malicious package incident was a reminder that build scripts run before `pacman` ever sees a package. A pacman hook is too late for this class of problem: the risky code can execute during `makepkg` as the user.

`pkgwatch` sits earlier in the flow. It downloads and reads package scripts as text, flags suspicious patterns, and can wrap `paru` so review happens before the build starts.

## Install

Install from crates.io:

```sh
cargo install pkgwatch
```

Install the latest tagged release from source:

```sh
cargo install --git https://github.com/bkbalci/pkgwatch --tag v0.1.1
```

Install the current development version from `main`:

```sh
cargo install --git https://github.com/bkbalci/pkgwatch
```

Or download the Linux x86_64 binary from the GitHub release:

```sh
curl -L -o pkgwatch.tar.gz https://github.com/bkbalci/pkgwatch/releases/download/v0.1.1/pkgwatch-v0.1.1-x86_64-unknown-linux-gnu.tar.gz
curl -L -o pkgwatch.tar.gz.sha256 https://github.com/bkbalci/pkgwatch/releases/download/v0.1.1/pkgwatch-v0.1.1-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c pkgwatch.tar.gz.sha256
tar -xzf pkgwatch.tar.gz
mkdir -p ~/.local/bin
cp pkgwatch-v0.1.1-x86_64-unknown-linux-gnu/pkgwatch ~/.local/bin/pkgwatch
```

Or build from a local checkout:

```sh
cargo build --release
mkdir -p ~/.local/bin
cp target/release/pkgwatch ~/.local/bin/pkgwatch
```

Make sure the install location is in `PATH`:

```sh
command -v pkgwatch
```

## Quick Start

Create the config and print the shell wrapper:

```sh
pkgwatch init
```

Add the printed function to your shell rc file.

For bash or zsh:

```sh
paru() {
  pkgwatch paru -- "$@"
}
```

For fish:

```fish
function paru
    pkgwatch paru -- $argv
end
```

Reload your shell and verify that `paru` is wrapped:

```sh
source ~/.zshrc
type paru
```

Run a non-installing AUR update scan:

```sh
pkgwatch update-check
```

Then use `paru` normally:

```sh
paru -Syu
paru -S package-name
```

Without the shell wrapper, normal `paru` commands do not automatically run `pkgwatch`.

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

Enable AI for one command:

```sh
pkgwatch --ai --ai-threshold always update-check
```

Enable AI by default in `~/.config/pkgwatch/config.toml`:

```toml
[ai]
enabled = true
provider = "auto"
threshold = "medium"
```

Remote AUR scans download the package snapshot and inspect `PKGBUILD`, `.install`, `.SRCINFO`, and helper shell scripts before build. `pkgwatch paru -- ...` also expands AUR dependency closure up to `max_aur_packages`.

`pkgwatch paru -- ...` skips AUR scanning for repo-only operations such as `paru --repo ...`.

For high or critical findings, human output writes a report draft under `/tmp/pkgwatch-report-<package>.txt`. It is never sent automatically.

Exit codes:

- `0`: clean or accepted warnings
- `1`: scan completed with warnings in strict mode
- `2`: critical finding blocked or user declined
- `3`: usage/config error

## Uninstall

Remove the shell wrapper function from your shell rc file, then remove the binary:

```sh
rm -f ~/.local/bin/pkgwatch
```

If installed with Cargo:

```sh
cargo uninstall pkgwatch
```

Optional config/cache cleanup:

```sh
rm -rf ~/.config/pkgwatch ~/.cache/pkgwatch
```

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
