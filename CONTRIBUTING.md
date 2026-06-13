# Contributing

Thanks for helping improve `pkgwatch`.

## Development

Use the standard Rust workflow:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

`cargo clippy` may require the clippy component to be installed.

## Scanner Changes

- Keep detection rules explainable and tied to concrete evidence.
- Add unit tests for every new detection rule or parser behavior.
- Avoid broad rewrites when adding a focused rule.
- Prefer lower severity when a pattern is common but ambiguous.
- Avoid hiding false positives by special-casing one package unless the rule itself is wrong.

## Safety

- Do not execute fixture or AUR package scripts in tests.
- Do not source PKGBUILDs.
- Do not run `makepkg` as part of automated tests.
- Treat all package files as untrusted text.
- AI provider output must remain advisory unless fail-closed policy explicitly applies.

## Pull Requests

Include:

- What changed and why.
- How it was tested.
- Any expected false positives or false negatives.
- Whether JSON report output changed.

