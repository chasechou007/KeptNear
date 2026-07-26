<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/keptnear-lockup-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/brand/keptnear-lockup.svg">
    <img src="assets/brand/keptnear-lockup.svg" alt="KeptNear" width="460">
  </picture>
</p>

<p align="center"><strong>Local-first password manager</strong></p>

KeptNear is an open-source password manager built around a local,
user-controlled encrypted vault. The current client is native to macOS, backed
by a reusable Rust core, and stores an encrypted directory vault that can be
synchronized by untrusted file providers such as iCloud Drive, Dropbox,
Syncthing, or WebDAV.

## Project Status

This project is a source-only pre-alpha preview. It is experimental and has not
received an external security audit. Do not use it to store production
credentials. No installable binary or GitHub Release is provided yet. The first
binary target is macOS 13 or newer on Apple Silicon (`arm64`), distributed as a
DMG. The maintainer has explicitly accepted the risk of an externally unaudited
experimental pre-release under `AR-001`; this does not recommend production
use. See
`docs/release-readiness.md` and `docs/security-review-evidence.md` for the
current release and review state.

## Current Scope

- Rust core for vault format, cryptographic boundaries, item model, sync metadata, import/export, TOTP, and search.
- Native macOS 13+ client, with Apple Silicon (`arm64`) as the first binary
  release target.
- Vaults stored as encrypted directories rather than a single monolithic database file.
- Cloud providers treated only as encrypted-file transport.

## Repository Layout

```text
apps/
  macos/              SwiftUI macOS client shell
crates/
  psw-cli/            Rust command-line vault inspection tools
  psw-core/           Rust vault core API and implementation
docs/                 Architecture, build, and security notes
fixtures/             Sanitized vault and import fixtures
scripts/              Local build and verification helpers
```

## Development

This repository is maintained by `Chase Chou <chasechou007@gmail.com>`.

Run the Rust checks:

```sh
cargo test --workspace
```

Inspect a local vault directory without unlocking it:

```sh
cargo run -p psw-cli -- doctor path/to/Vault.pswvault
cargo run -p psw-cli -- doctor --json path/to/Vault.pswvault
```

Verify the vault doctor support CLI against generated local vault cases:

```sh
script/verify_vault_doctor_readiness.sh
```

Build the macOS shell:

```sh
scripts/build-macos.sh
```

Build and launch the macOS app bundle:

```sh
script/build_and_run.sh
```

Run all available local checks:

```sh
scripts/check.sh
```

Verify that the candidate public source tree excludes local development
context, real vaults, plaintext exports, credentials, and build products:

```sh
script/verify_public_source_tree.sh
```

Review all resolved Rust dependency license expressions:

```sh
script/verify_dependency_licenses.sh
```

Report current public-alpha release blockers without approving readiness:

```sh
script/verify_public_alpha_release_ready.sh --allow-missing
```

Report current external-review or maintainer accepted-risk decision state:

```sh
script/verify_security_review_evidence.sh --allow-missing
```

Package external security review handoff materials with a manifest and SHA-256
checksum:

```sh
script/package_security_review_materials.sh
```

Create an unsigned local Apple Silicon DMG:

```sh
script/package_macos_alpha.sh
```

Verify a signed and notarized DMG before public-alpha install checks:

```sh
script/verify_macos_signed_install.sh dist/releases/KeptNear-0.1.0-alpha-macos-arm64.dmg
```

Preflight the local Developer ID and notarization environment before attempting
a signed alpha package:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
NOTARIZE=1 \
NOTARY_KEYCHAIN_PROFILE="psw-notary" \
  script/verify_macos_distribution_environment.sh
```

On machines without release credentials, use report mode to see the missing
prerequisites without approving distribution readiness:

```sh
script/verify_macos_distribution_environment.sh --allow-missing
```

## Alpha Workflows

- Start from the in-app first-run panel to create a new local vault, open an
  existing `.pswvault`, or reopen a recent vault. When macOS supplies a
  `.pswvault` path to the running app, the client routes it through the same
  locked open-vault workflow.
- Create or open a local `.pswvault` directory, including inside an iCloud
  Drive, Dropbox, Syncthing, or WebDAV-synced folder. New vault master
  passwords must be non-empty and confirmed, with local advisory strength
  guidance shown during vault creation and password rotation.
- Create, view, and edit login items, secure notes, credit cards, and software
  licenses from the macOS client. Login items can keep multiple associated URLs
  as newline-separated values; Open URL uses the first saved value that can be
  safely opened as HTTP or HTTPS.
- Duplicate an existing login item, secure note, credit card, or software
  license as a new active item while preserving supported fields and saved
  secrets.
- Add raw Base32 or `otpauth://` TOTP secrets for login items, then edit,
  clear, and copy generated TOTP codes from the macOS client. TOTP copy is
  unavailable until the selected login has a saved TOTP secret. The selected
  login username, password, TOTP, secure-note body, card number, card
  verification code, and license-key copy actions are also available from the
  macOS Item menu with `Command+Option` shortcuts.
- Search unlocked items by title, tags, item type, login metadata and notes,
  secure note body text, credit-card non-secret fields, and software-license
  non-secret fields, then combine search with archived-item inclusion and a
  favorite-only filter, conflict-only filter, explicit item-type filter, or
  explicit tag filter. Item-type and tag filters are derived from currently
  loaded non-secret item summaries. When filters change, the selected detail
  follows the visible results unless doing so would discard unsaved editor
  changes. Secret values such as passwords, TOTP seeds, card numbers,
  verification codes, and license keys are not searchable. If filters hide
  every row, the detail area shows a
  no-matching-items state with a clear-filters action instead of implying the
  vault is empty.
- Empty usernames, card numbers, verification codes, and license keys do not
  overwrite the clipboard when copied.
- Saved passwords, TOTP seeds, card numbers, verification codes, and license
  keys are hidden in the editor until explicitly revealed, and revealed values
  are cleared from view state when the item context or vault state changes.
- Use item-list context menus for common daily actions such as copying login
  fields, copying structured-item secrets, opening login URLs, toggling
  favorites, duplicating items, resolving conflicts, restoring archives,
  archiving, and deleting. Row actions target the requested item through the
  same guarded selection and confirmation paths and do not render secret values
  in the menu.
- Run a local password health check from the unlocked Security panel to find
  obvious weak and reused login passwords. The check runs inside the unlocked
  Rust core and returns only item IDs, titles, issue kinds, and counts; it does
  not contact breach services or return passwords, hashes, usernames, URLs, or
  notes. Each issue can show the affected item through the normal guarded item
  selection path, clearing hiding list filters and enabling archived visibility
  without rendering secrets in the issue row. Results are cleared after vault
  content changes and must be refreshed before new counts are shown.
- Use the login editor's password generator to fill a new password that includes
  each enabled character class. Length, character classes, and ambiguous
  character avoidance persist as local app preferences, but generated password
  values are not kept as generator history. Generate is unavailable until at
  least one character class is selected.
- Import Bitwarden plaintext JSON exports or generic login CSV exports from the
  unlocked app through `Import`, preview counts, then confirm import. Imported
  login items, secure notes, and credit cards can be opened and edited in the
  macOS client. After import, reveal the plaintext source file in Finder or
  move it to Trash from the import sheet.
- Export supported login items, secure notes, credit cards, and software
  licenses to plaintext Bitwarden JSON through `Export` after an explicit
  warning and confirmation. After export, reveal the plaintext export in Finder
  or move it to Trash from the result sheet. Software licenses are exported as
  secure notes because Bitwarden JSON has no native software-license record.
- Put the vault directory in any local sync folder and use `Refresh Sync` or the
  unlocked app's local file-change detection to reload encrypted item changes.
  Sync refresh preserves active list filters, asks before discarding unsaved
  editor drafts, and automatic file refresh waits until active editor drafts
  are clean while showing a persistent paused sync status.
- Use `psw doctor` from the Rust CLI to inspect local `.pswvault` structure,
  supported format metadata, encrypted record counts, and local unlock envelope
  presence without entering a master password or contacting a sync provider.
  The local alpha readiness gate also verifies this command against generated
  supported, incomplete, and future-format vault cases.
- Resolve a selected sync-conflicted item from the editor command area by
  filtering the item list to conflicts from the sync issue panel or sidebar,
  loading candidate summaries, and choosing which version to keep. A quick
  resolver remains available for simple alpha workflows.
- Reopen the most recently used vault from `Open Recent`; unlocking still
  requires the master password or the explicit Keychain convenience unlock
  option. If the remembered vault directory has been moved or deleted, Open
  Recent clears that stale shortcut locally without calling the core. Opening
  or creating another vault clears the previous unlocked vault session and
  active secret state. `Close Vault` leaves the current vault, clears active
  state, and returns to the first-run view without deleting the vault directory
  or forgetting the recent vault shortcut.
- Use the locked-vault `Forgot master password?` recovery flow when no master
  password is available. KeptNear cannot recover or reset that password. The
  flow can reveal or close the vault without deleting it, or move a validated
  local `.pswvault` directory to macOS Trash after a second confirmation,
  clear its local recent-vault and Keychain references, and start the existing
  create-vault flow. Trash affects only that local copy; synchronized,
  backed-up, and other-device copies require separate handling.
- Switch the interface between English, Simplified Chinese, and Japanese, and
  configure the clipboard clear timeout and auto-lock duration from the macOS
  Settings window. Security timing preferences persist across app launches,
  and the vault also locks on system sleep, screen sleep, or session lock.
- Copied secrets clear after the configured timeout and are also cleared when
  the vault locks if they are still the app-managed clipboard value.
- Change the master password for an unlocked vault from Settings. The existing
  vault contents stay encrypted with the same vault key, `keys.enc` is rewrapped,
  the new master password must be non-empty and confirmed, and local Keychain
  convenience unlock is disabled until the user opts in again.
- Copy a non-secret diagnostics report from the macOS Settings window when
  filing alpha feedback about unlock, sync, import, or core loading behavior.
- Use editor guardrails for daily work: empty-title saves are blocked for login
  items, secure notes, credit cards, and software licenses; unsaved edits in
  those editors are confirmed before discard-prone item selection, opening,
  creating, or closing vaults, committing imports, manual sync refresh, sync
  recovery actions, and destructive archive/delete requests; archive/delete also
  ask for destructive-action confirmation and reject unconfirmed dirty editor
  state at the store layer. Archived items can be found with archived search
  enabled and restored to the active list.

## Documentation

- [Architecture](docs/architecture.md)
- [Product requirements](docs/product-requirements.md)
- [Security model](docs/security-model.md)
- [Experimental vault format](docs/vault-format.md)
- [Local file sync](docs/sync.md)
- [Import and export formats](docs/import-formats.md)
- [Support diagnostics](docs/diagnostics.md)
- [Logging and crash report policy](docs/logging-policy.md)
- [Alpha update policy](docs/update-policy.md)
- [Security review plan](docs/security-review-plan.md)
- [Security review evidence](docs/security-review-evidence.md)
- [macOS alpha packaging](docs/macos-alpha-packaging.md)
- [Release readiness](docs/release-readiness.md)
- [Open-source readiness](docs/open-source-readiness.md)

## Issues And Security

Reproducible bug reports and focused feature requests are welcome through
GitHub Issues on a best-effort basis. External pull requests are not currently
accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for the current project policy.

Security issues should be reported privately by email to
`Chase Chou <chasechou007@gmail.com>`. See [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 Chase Chou.

Licensed under the GNU General Public License, Version 3 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
