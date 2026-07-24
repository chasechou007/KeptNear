# Open-Source Readiness

Review date: 2026-07-24

## Current Position

The repository is being prepared as a personal-interest, primarily self-used
password manager that may be published as a public source preview. External
security review is not a prerequisite for source publication, but the project
must remain clearly described as experimental, unaudited, and unsuitable for
production secrets. Source publication is not approval of a public binary or a
production-ready password-manager release.

The first public publication is source-only. It does not include `.app`,
`.dmg`, or other installable release artifacts, and no GitHub Release is
required for the initial repository opening.

## Ready Before Public Source Publication

- The root GPLv3 license text is present and Rust package metadata declares
  `GPL-3.0-only`.
- Maintainer identity is recorded as
  `Chase Chou <chasechou007@gmail.com>`.
- Issue and private security reporting guidance exists.
- The contribution policy accepts Issues on a best-effort basis and states
  that external pull requests are not currently accepted.
- CI configuration exists for local checks and maintainer pull requests.
- Generated artifacts, local development context, vault files, environment
  files, plaintext password-manager exports, and signing material are ignored.
- README clearly states pre-alpha status and links release/security evidence.
- Rust package metadata records the GitHub source URL and disables accidental
  crates.io publication.

## Local Pre-Publication Audit

The 2026-07-24 local audit completed without using an external security-review
service:

- `scripts/check.sh` passed 87 Rust tests and 171 Swift tests.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed.
- RustSec `cargo-audit` scanned 46 resolved crate dependencies against 1,169
  advisories and reported no known vulnerabilities.
- `script/verify_dependency_licenses.sh` found only the project GPLv3 license
  and reviewed permissive dependency license expressions.
- `script/verify_public_source_tree.sh` found no private development context,
  real vaults, plaintext export artifacts, private keys, access tokens, or
  developer-machine paths in the candidate source tree.
- The Swift package has no third-party package dependencies.

This is a bounded local review, not an external security audit or a claim that
the application is safe for production secrets.

## Still Not Ready For Public Alpha Distribution

- External security review has not started.
- Public alpha release readiness is not approved.
- Signed and notarized distribution has not been verified with real release
  credentials.
- The vault format remains experimental until an explicit freeze decision.
- Public release notes, tester onboarding, and feedback intake still need a
  final pass.

## Files That Must Not Be Published

- `dist/`
- `target/`
- `.build/`
- `apps/macos/.build/`
- `.codex/`
- `.echopath/`
- `AGENTS.md`
- `CONTEXT.md`
- `openspec/`, which is managed as a separate local Git repository
- real `.pswvault` directories
- real password-manager export files
- signing certificates, notary credentials, private keys, and local `.env`
  files

## Publication Checklist

- Run `scripts/check.sh`.
- Run `script/verify_public_source_tree.sh` immediately before staging.
- Run `script/verify_dependency_licenses.sh` after dependency changes.
- Review `git status --short` and confirm only intentional source files are
  staged.
- Inspect ignored files with `git status --ignored --short` before the first
  public push.
- Confirm the GitHub repository is Private for the source-preview review.
- Confirm the package metadata points to
  `https://github.com/chasechou007/KeptNear`.
- Configure the public repository to use the checked-in Issue templates and
  keep the no-external-PR policy visible in the README.
