# Security Policy

## Supported Versions

`pkgwatch` is pre-1.0. Security fixes are expected to land on `main` until release branches exist.

## Reporting a Vulnerability

Please do not open a public issue for a vulnerability that could help attackers bypass scanning or trick users into executing malicious package code.

Report privately to the repository owner once the project is published. Include:

- Affected version or commit.
- Reproduction steps.
- Whether untrusted package code is executed.
- Example PKGBUILD or minimized fixture, if safe to share.

## Scope

Security-sensitive areas include:

- Any path that executes package-controlled content.
- Snapshot archive extraction and path validation.
- AI prompt construction and verdict parsing.
- Wrapper behavior that may incorrectly skip scanning.
- False negatives for known malicious AUR patterns.

