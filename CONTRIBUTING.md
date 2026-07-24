# Feedback And Local Development

Thanks for helping improve KeptNear through issue reports and security
feedback.

This project is a pre-alpha local-first password manager. Treat every change as
security-sensitive unless it is clearly documentation-only.

## Current Contribution Policy

- Reproducible bug reports and focused feature requests are welcome through
  GitHub Issues.
- Security vulnerabilities must be reported privately according to
  `SECURITY.md`, not through public issues.
- External pull requests are not currently accepted. Please do not invest in a
  code contribution with an expectation that it will be reviewed or merged.
- Issue responses, fixes, and roadmap commitments are best effort; this is a
  personal-interest project without a support service level.

## Before You Start

- Read `README.md`, `docs/architecture.md`, `docs/security-model.md`, and
  `docs/release-readiness.md`.
- Do not submit real password vaults, real password-manager exports, real
  credentials, signing certificates, notary credentials, or local Keychain
  material.
- Use synthetic fixtures only.

## Development Checks

Run the main local check when modifying a local checkout:

```sh
scripts/check.sh
```

Useful focused checks:

```sh
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
swift test --package-path apps/macos
```

## Security-Sensitive Changes

Changes touching cryptography, vault format, unlock behavior, import/export,
sync conflict handling, diagnostics, logging, clipboard behavior, Keychain,
packaging, signing, or release gates need extra review.

Do not weaken a security boundary only to improve convenience without updating
the security model and release readiness notes.
