# Open-Source Readiness

Review date: 2026-07-31

## Current Position

The repository is being prepared as a personal-interest, primarily self-used
password manager that may be published as a public source preview. External
security review is not a prerequisite for source publication, but the project
must remain clearly described as experimental, unaudited, and unsuitable for
production secrets. Source publication and binary publication use separate
readiness profiles.

The source preview does not require Apple signing or external security review.
An unsigned Apple Silicon DMG may also be published as a separate, explicitly
unsigned and unaudited experimental artifact after its local build, integrity,
privacy, license, disclosure, and installation checks pass. Signed and
notarized distribution remains a stricter optional profile.

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

The 2026-07-31 local publication audit completed without using Codex Security
or another external security-review service:

- `scripts/check.sh` passed 509 Rust tests, 232 Swift tests, the FFI build, and
  the Swift build.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passed.
- Strict OpenSpec validation passed 33 of 33 active items.
- `script/verify_dependency_licenses.sh` reviewed 125 resolved registry
  packages, required every workspace crate to inherit `GPL-3.0-only`, rejected
  non-registry dependency sources, checked the MPL secondary-license
  compatibility condition, and verified the bundled SQLCipher notice.
- The exact-expression allowlist contains only license choices reviewed for
  GPLv3 distribution. The current `MPL-2.0` dependency is
  `webpki-roots 0.26.7`, whose source does not opt out with an
  `Incompatible With Secondary Licenses` notice. The SQLCipher refresh also
  introduced `foldhash 0.2.0` under the GPL-compatible SPDX `Zlib` license.
- `script/verify_public_source_tree.sh` checked 229 candidate files and found
  no private development context, real vaults, plaintext export artifacts,
  signing material, or build products.
- `script/verify_repository_secrets.sh` checks the same candidate tree plus
  every reachable historical Git blob for known private-key and provider-token
  formats, credential-bearing filenames, private AI-development paths, and the
  current developer home path.
- The Swift package has no third-party package or binary-target dependencies.

The compatibility policy follows the
[GNU GPL-compatible license list](https://www.gnu.org/licenses/license-list.html),
the [Mozilla MPL 2.0 compatibility conditions](https://www.mozilla.org/en-US/MPL/2.0/FAQ/),
and the [Unicode License v3 description](https://unicode.org/faq/unicode_license.html).
It is a conservative automated project check, not legal advice. New license
expressions, non-registry sources, Swift dependencies, binary targets, or an
MPL secondary-license opt-out fail closed for human review.

This is a bounded local review, not an external security audit or a claim that
the application is safe for production secrets.

## Remaining Distribution Work

- External security review has not started.
- The current source and unsigned-DMG readiness profiles must be rerun against
  the exact revision selected for publication.
- Signed and notarized distribution has not been verified with real release
  credentials and must not be claimed.
- Vault v2 is frozen as the released pre-alpha source-preview schema, but the
  application remains experimental and unaudited.
- Public release notes, tester onboarding, and feedback intake still need a
  final pass.

Missing external review evidence requires the `unaudited` label but does not
block source publication or an explicitly unsigned experimental DMG.

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
- Run `script/verify_repository_secrets.sh` against the final reachable Git
  history before the first public push.
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
- If publishing an unsigned DMG, run the unsigned artifact verifier, publish
  its checksum and manifest, and keep unsigned installation instructions and
  the unaudited pre-alpha warning adjacent to the download.
- Do not reuse the signed-distribution readiness label for an unsigned
  artifact.
