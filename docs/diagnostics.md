# Support Diagnostics

The macOS app can copy a local diagnostics report from Settings > Diagnostics.
The report is intended for alpha feedback when unlock, sync, import, packaging,
or Rust core loading behavior is unclear.

Diagnostics are copied only when the user presses the copy button. The app does
not upload diagnostics, telemetry, logs, vault records, or crash reports.
The broader logging, telemetry, diagnostics, and crash report boundary is
documented in `docs/logging-policy.md`.

## Included

- App name, version, and build string when available.
- Rust core availability and status.
- Whether a vault is selected and whether it is unlocked.
- Selected vault basename, such as `Personal.pswvault`.
- Visible item count.
- Whether plaintext import/export cleanup is pending, without file names or
  paths.
- Whether local Keychain convenience unlock material is available for the
  selected vault, without including the material.
- Clipboard clear timeout and auto-lock duration.
- Selected interface language.
- Last sync refresh counts, when available.
- Rejected sync record counts, without rejected `.enc` file names or paths.
- Whether local sync refresh is currently deferred by unsaved edits.

## Excluded

The diagnostics report must not include:

- master passwords
- master password strength scores or hints
- local unlock material
- local Keychain convenience unlock material
- item titles
- usernames
- passwords
- URLs
- notes
- tags
- TOTP secrets or codes
- revealed saved-secret view-state values
- plaintext import source names or paths
- plaintext export destination names or paths
- rejected sync record file names or paths
- full local vault paths
- encrypted vault record contents

The selected vault basename can still reveal a user-chosen vault name. Testers
should review copied diagnostics before sharing them outside a trusted alpha
feedback channel.
