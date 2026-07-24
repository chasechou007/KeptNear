# Security Review Plan

This plan prepares KeptNear for an external security review. It is not
evidence that an external review has already happened.
Completed review evidence, findings, accepted risks, validation, and release
decision status are tracked separately in `docs/security-review-evidence.md`.

## Review Goals

- Validate the local-first vault threat model and non-claims.
- Review cryptographic usage, key envelope handling, and record authentication.
- Review local file sync behavior under malicious, stale, duplicated, and
  conflicting encrypted records.
- Review macOS secret-handling behavior, including clipboard clearing,
  auto-lock, Keychain convenience unlock, diagnostics, import cleanup, and
  plaintext export confirmation.
- Review alpha packaging and release artifacts for claims, integrity evidence,
  and unsafe distribution assumptions.

## In Scope

- Rust vault core:
  - `crates/psw-core/src/crypto.rs`
  - `crates/psw-core/src/export.rs`
  - `crates/psw-core/src/record.rs`
  - `crates/psw-core/src/storage.rs`
  - `crates/psw-core/src/api.rs`
  - `crates/psw-core/src/import.rs`
  - `crates/psw-core/src/totp.rs`
- FFI boundary:
  - `crates/psw-ffi/src/lib.rs`
- macOS client security behavior:
  - `apps/macos/Sources/PSWMac/RustCoreBridge.swift`
  - `apps/macos/Sources/PSWMac/VaultStore.swift`
  - `apps/macos/Sources/PSWMac/ClipboardManager.swift`
  - `apps/macos/Sources/PSWMac/ConvenienceUnlockStore.swift`
  - `apps/macos/Sources/PSWMac/ImportSourceHandler.swift`
  - `apps/macos/Sources/PSWMac/Diagnostics.swift`
- Packaging and release scripts:
  - `script/build_and_run.sh`
  - `script/package_macos_alpha.sh`
  - `scripts/check.sh`
- Security-sensitive docs:
  - `docs/security-model.md`
  - `docs/vault-format.md`
  - `docs/sync.md`
  - `docs/import-formats.md`
  - `docs/diagnostics.md`
  - `docs/macos-alpha-packaging.md`
  - `docs/release-readiness.md`

## Out of Scope

- Cloud provider confidentiality or integrity guarantees.
- Protection against fully compromised devices, keyboard capture, or privileged
  process memory inspection.
- Public vulnerability disclosure program design.
- Production code signing, notarization, auto-update, and Mac App Store review.
- Mobile clients and cross-device account services.
- Formal cryptographic proof of the construction.

## Prepared Materials

- Architecture overview: `docs/architecture.md`
- Security model and explicit non-claims: `docs/security-model.md`
- Vault format: `docs/vault-format.md`
- Local file sync model: `docs/sync.md`
- Import/export behavior and plaintext file warnings: `docs/import-formats.md`
- Diagnostics inclusion/exclusion rules: `docs/diagnostics.md`
- Alpha packaging notes: `docs/macos-alpha-packaging.md`
- Release readiness gates: `docs/release-readiness.md`
- Security review evidence register: `docs/security-review-evidence.md`
- Sanitized fixtures: `fixtures/`
- Generated reviewer handoff package:
  `dist/security-review/psw-security-review-materials-<version>.tar.gz`
  with adjacent manifest and SHA-256 checksum. This package is handoff
  material only and is not evidence that review has completed.

## Reviewer Setup Commands

Run the full local verification suite:

```sh
scripts/check.sh
```

Run Rust tests only:

```sh
cargo test --workspace
```

Run macOS Swift tests only:

```sh
swift test --package-path apps/macos
```

Build and launch the macOS app bundle for local verification:

```sh
script/build_and_run.sh --verify
```

Create an unsigned alpha package with checksum and manifest:

```sh
script/package_macos_alpha.sh
```

Create the reviewer handoff package with checksum and manifest:

```sh
script/package_security_review_materials.sh
(
  cd dist/security-review
  shasum -a 256 -c psw-security-review-materials-0.1.0-alpha.tar.gz.sha256
)
```

## Review Questions

- Can a wrong master password, tampered key envelope, tampered item record, or
  future format version be accepted unexpectedly?
- Are Argon2id parameters, nonce generation, AEAD usage, and associated data
  coherent for the current threat model?
- Can local unlock material or master passwords leak into files, diagnostics,
  clipboard state, logs, import/export output, or support artifacts?
- Does local convenience unlock create an acceptable alpha risk, and are the
  limitations documented clearly enough?
- Can untrusted sync providers cause silent data loss, unsafe conflict
  resolution, or acceptance of unauthenticated records?
- Do plaintext import warnings, import cleanup actions, and export confirmation
  reduce accidental plaintext retention risk enough for alpha testing?
- Do packaging artifacts avoid overclaiming production readiness while still
  giving testers integrity evidence?

## Expected Reviewer Outputs

- Finding list with severity, affected path, exploit preconditions, impact, and
  recommended remediation.
- Explicit note for any reviewed area where no finding was identified.
- Assessment of whether the current alpha security model and non-claims are
  coherent.
- Follow-up checklist for issues that must block public alpha.
- Optional recommendations for future stable vault format and convenience unlock
  redesign.

## Severity Taxonomy

- Critical: practical compromise of vault secrets without the master password or
  local unlock material, or reliable tampering that bypasses authentication.
- High: realistic secret exposure, persistent unsafe unlock behavior, or sync
  behavior that can silently destroy or replace data.
- Medium: security boundary weakness requiring meaningful preconditions, unsafe
  default that can be corrected before public alpha, or incomplete user warning
  around plaintext secrets.
- Low: hardening opportunity, documentation gap, confusing status, or issue
  with limited security impact.
- Informational: design note or future improvement that does not change alpha
  readiness by itself.

## Follow-Up Handling

- Critical and High findings block public alpha until fixed or explicitly
  accepted with a documented rationale.
- Medium findings need a planned fix, mitigation, or release-readiness note.
- Low and Informational findings may be tracked as post-alpha hardening if they
  do not contradict the security model.
- Every accepted risk must name the affected behavior, reason for acceptance,
  user-facing implication, and revisit trigger.

## Readiness Evidence

Before considering the review complete, the repository should contain:

- Reviewer report or issue list linked from `docs/security-review-evidence.md`.
- Links to fixes or documented accepted risks in
  `docs/security-review-evidence.md`.
- Passing `scripts/check.sh` after review-driven fixes.
- Updated `docs/security-model.md` and `docs/release-readiness.md` if review
  changes any claim, gate, non-claim, or workflow.
- A release decision that separates "external review completed" from
  "production use recommended."
- Passing strict `script/verify_security_review_evidence.sh` after the evidence
  register is updated. Before evidence exists, use
  `script/verify_security_review_evidence.sh --allow-missing` only as a
  non-approving status report.
- The reviewed package archive, manifest, and SHA-256 checksum should be linked
  from the evidence register once review evidence is attached, but the package
  by itself does not complete the review or approve public alpha.
