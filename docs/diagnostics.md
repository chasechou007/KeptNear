# Support Diagnostics

The macOS app can copy a local diagnostics report from Settings > Diagnostics.
The report is intended for alpha feedback when unlock, sync, import, packaging,
or Rust core loading behavior is unclear.

Diagnostics are copied only when the user presses the copy button. The app does
not upload diagnostics, telemetry, logs, vault records, or crash reports.
The broader logging, telemetry, diagnostics, and crash report boundary is
documented in `docs/logging-policy.md`.

## Vault Doctor

The public local diagnostic command is:

```sh
keptnear vault doctor [--json] <vault-path>
```

The legacy `psw doctor [--json] <vault-path>` entrypoint remains available and
is still the `psw-cli` package default. Both entrypoints use the same read-only
inspection and report schema. They check required local structure, supported
format metadata, aggregate encrypted-record counts, and local unlock-envelope
presence. They do not request a master password, unlock or decrypt records,
load a Consumer Keychain identity, contact the Broker, or contact a sync
provider.

The report omits the supplied full path and item-record content. It can include
the unencrypted Vault display name from `vault.json`, so a user should still
review the report before sharing it. `--json` changes only the report format.
A usable Vault exits successfully; incomplete or unsupported Vaults return a
nonzero status with the same bounded report.

The support report is separate from encrypted device-local machine-access
audit. It does not contain audit history, Consumer identities, Access Rules,
Use Grants, approval state, or operation outcomes.

## Included

- App name, version, and build string when available.
- Rust core availability and a closed `connected` or `unavailable` status.
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
- Logical labels for missing or invalid required vault paths, without their
  local path values.
- A bounded likely sync-provider classification, without provider account data.
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
- request bodies and API response bodies
- request URLs, headers, and query values
- command arguments
- command environment values and standard input
- full executable paths
- standard output and standard error
- Consumer identities, labels, Access Rules, Use Grants, and audit events
- free-form Core status, errors, parser diagnostics, or provider responses

The selected vault basename can still reveal a user-chosen vault name. Testers
should review copied diagnostics before sharing them outside a trusted alpha
feedback channel.

The report snapshot is an explicit support-field projection. It does not
forward free-form Rust Core status or error text, even if a component has
observed operation payload data internally.

Copying places the report on the system clipboard. KeptNear does not
automatically upload it or clear it as a secret, and other software with
clipboard access may observe it. Users should inspect the complete report
before sharing it.

## Troubleshooting

| Symptom | Bounded next step |
| --- | --- |
| A vault cannot be opened or reports missing structure | Run `keptnear vault doctor [--json] <vault-path>`. It inspects structure without unlocking or repairing the vault. Preserve the original encrypted directory before making manual filesystem changes. |
| MCP or CLI cannot connect, or no machine tools are available | The DMG bundles the Broker and adapters but does not activate a Broker service. Follow the source-level setup guides; installing the App alone is not an end-user machine-access setup. |
| Sync appears stale or reports rejected records | Use Refresh Sync, reveal the vault directory, and review the aggregate sync panel. Quarantine only through the explicit App action. Provider upload, download, version history, and account state remain outside KeptNear. |
| macOS blocks an unsigned alpha on first launch | Verify the adjacent checksum and trusted source, then use the explicit Finder Open or System Settings Open Anyway flow documented in `docs/macos-alpha-packaging.md`. Do not disable Gatekeeper globally. |
| Support needs more context | Copy diagnostics only on request, inspect the complete clipboard report, and remove anything you do not intend to share. KeptNear never uploads it automatically, and support diagnostics are not the encrypted machine-access audit. |
