# Security Review Evidence Register

This register tracks external security review evidence, review-driven fixes,
accepted risks, validation, and release decision status for KeptNear.

Current status: **Not complete**. No external security review evidence has been
attached yet, and this document does not approve public alpha or production use.

## Review Summary

- Review status: Not started
- Reviewer or firm: None selected yet
- Review window: Not scheduled
- Reviewed commit or release artifact: None selected yet
- Final report: None attached yet
- Finding tracker: None attached yet
- Release decision: Not approved

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
| None recorded yet | None | None accepted yet | No external findings accepted yet | None | None | None assigned yet | Add accepted-risk entry before approval if any finding is accepted. |

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

## Release Decision

Public alpha is not approved by this register until all required review evidence
is attached and the release decision below is updated.

- External review completed: No
- Critical findings fixed or explicitly accepted: No
- High findings fixed or explicitly accepted: No
- Medium findings fixed, mitigated, or tracked: No
- Validation after review-driven changes passed: No
- Security model or readiness claims updated after review: No
- Public alpha decision: Not approved
- Production-use recommendation: Not recommended

## Maintenance Rules

- Do not mark review complete without a reviewer report or tracked finding list.
- Do not mark public alpha approved if Critical or High findings are open.
- Do not accept a risk without the required accepted-risk fields.
- Keep production-use recommendation separate from public alpha readiness.
- Run `script/verify_security_review_evidence.sh` before changing the public
  alpha decision to approved. `--allow-missing` is a report mode only and does
  not approve strict security review readiness.
- Replace explicit missing-state rows with external review evidence,
  finding-disposition records, or documented accepted risks before strict
  approval.
