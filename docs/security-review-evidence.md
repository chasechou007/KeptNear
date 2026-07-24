# Security Review Evidence Register

This register tracks external security review evidence, review-driven fixes,
maintainer-accepted risks, validation, and release decision status for
KeptNear.

Current status: **Experimental pre-release risk accepted**. No external
security review evidence has been attached. The maintainer accepts `AR-001`
only for signed and notarized `v0.1.x` pre-alpha macOS Apple Silicon DMGs. This
does not recommend production use or bypass any distribution gate.

## Review Summary

- Review status: Not started
- Reviewer or firm: None selected yet
- Review window: Not scheduled
- Reviewed commit or release artifact: None selected yet
- Final report: None attached yet
- Finding tracker: None attached yet
- Release decision: Experimental pre-release risk accepted

## Reviewer Reports

| Date | Reviewer | Scope | Artifact | Notes |
| --- | --- | --- | --- | --- |
| None | None selected yet | None reviewed yet | None attached yet | No external report attached yet. |

## Findings

Each finding should link to a reviewer report section, issue, pull request, or
accepted-risk entry.

| ID | Severity | Status | Affected Area | Evidence | Resolution |
| --- | --- | --- | --- | --- | --- |
| None recorded yet | None | Not Applicable | None reviewed yet | None attached yet | No external findings recorded yet. |

Status values:

- Open
- Fixed
- Accepted Risk
- Duplicate
- Not Applicable

## Accepted Risks

Accepted risks are release decisions. Each accepted risk must be explicit enough
for a reviewer or maintainer to re-evaluate later.

| ID | Severity | Affected Behavior | Rationale | User-Facing Implication | Mitigation | Owner | Revisit Trigger |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AR-001 | High | Publishing an externally unaudited password-manager binary | KeptNear is a personal-interest, local-first project and the initial binary is explicitly limited to an experimental pre-alpha for informed testers. External review is deferred, not treated as completed. | Unknown security defects could expose vault secrets or damage vault data. Testers must not store production credentials. | Require a clean source commit, Apple Silicon-only build checks, Developer ID signing, hardened runtime, Apple notarization, DMG and app verification, published checksum and manifest, experimental warnings, manual updates, and no automatic telemetry or hosted vault service. | Chase Chou | Revisit before recommending production use, removing the experimental warning, broadening platform or audience scope, declaring 1.0, or after a material cryptographic or vault-format change. |

Required accepted-risk fields:

- severity
- affected behavior
- reason for acceptance
- user-facing implication
- mitigation or compensating control
- owner
- revisit trigger

## Review-Driven Fixes

| Finding ID | Change | Validation | Status |
| --- | --- | --- | --- |
| None recorded yet | None | None | No review-driven fixes recorded yet. |

## Validation Evidence

Record validation after review-driven fixes or accepted-risk decisions. Local
pre-review baseline validation may be recorded here, but it does not complete
external review and must be repeated if reviewer findings drive changes.

| Date | Command Or Check | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-29 | `scripts/check.sh` | Passed | Pre-review local baseline; passed with Rust checks, FFI build, Swift workflow tests, and Swift build. Repeat after review-driven fixes. |
| 2026-06-29 | `script/package_macos_alpha.sh` | Passed | Generated unsigned local alpha archive; signing and notarization are not covered by this evidence. |
| 2026-06-29 | `script/verify_macos_alpha_artifact.sh` | Passed | Verified unsigned alpha archive checksum, manifest, bundle contents, manual update channel, and `.pswvault` metadata. |
| 2026-06-29 | `script/package_security_review_materials.sh` | Passed | Generated security review handoff archive with manifest and SHA-256 checksum; this is not evidence that external review is complete. |
| 2026-07-24 | `scripts/check.sh` | Passed | Passed public-source checks, 87 Rust tests, 171 Swift tests, dependency-license verification, FFI build, and macOS build after the `AR-001` policy and release-mode changes. |
| 2026-07-24 | `script/package_macos_alpha.sh` | Passed | Generated an unsigned local macOS 13+ Apple Silicon DMG in `local-test` mode; Developer ID signing and notarization remain separate release gates. |
| 2026-07-24 | `script/verify_macos_alpha_artifact.sh` | Passed | Verified DMG integrity, checksum, mounted app structure, Applications link, manifest, arm64-only app and FFI binaries, and non-distributable local-test status. |
| 2026-07-24 | `script/verify_public_source_tree.sh` | Passed | Verified that local AI context, vaults, plaintext exports, credentials, DMGs, and other build products are not publishable source candidates. |

## Release Decision

External review has not approved public alpha. The separate maintainer
accepted-risk path below approves only the security-policy component of an
experimental pre-release. Overall release readiness still requires every
non-review gate, including signed and notarized install verification.

- External review completed: No
- Critical findings fixed or explicitly accepted: No
- High findings fixed or explicitly accepted: No
- Medium findings fixed, mitigated, or tracked: No
- Validation after review-driven changes passed: No
- Security model or readiness claims updated after review: No
- Public alpha decision: Not approved
- Experimental pre-release risk accepted: Yes
- Accepted risk ID: AR-001
- Risk acceptance owner: Chase Chou
- Risk acceptance date: 2026-07-24
- Accepted release scope: v0.1.x pre-alpha macOS 13+ Apple Silicon DMG
- Public alpha security decision: Approved for experimental pre-release
- External review required before production use: Yes
- Production-use recommendation: Not recommended

## Maintenance Rules

- Do not mark review complete without a reviewer report or tracked finding list.
- Do not mark public alpha approved if Critical or High findings are open.
- Do not accept a risk without the required accepted-risk fields.
- Do not use `AR-001` to bypass signing, notarization, signed-install
  verification, user-facing warnings, or the accepted release scope.
- Keep production-use recommendation separate from public alpha readiness.
- Run `script/verify_security_review_evidence.sh` before an experimental
  pre-release. Strict mode passes only when either external review evidence is
  complete or the maintainer accepted-risk path is complete. `--allow-missing`
  remains a report mode.
- Replace explicit missing-state rows with external review evidence,
  finding-disposition records, or documented accepted risks before approving a
  broader release.
