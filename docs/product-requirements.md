# Product Requirements Document

Review date: 2026-07-24

## Product Summary

KeptNear is a local-first password manager for users who want a native
desktop vault with encrypted file sync instead of a hosted password-management
account. The first shippable product targets macOS 13 or newer on Apple Silicon
(`arm64`), backed by a reusable Rust core, and stores vault data in an encrypted
`.pswvault` directory that can be copied by untrusted sync providers such as
iCloud Drive, Dropbox, Syncthing, or WebDAV.

The product is not trying to become a hosted 1Password 8 style cloud service.
It is trying to be a more polished local-first open-source vault than
KeePassXC for users who prefer a 1Password 7 style local file workflow.

## Target Users

- The primary first-version user is the maintainer, who is building the project
  as a personal-interest local password manager for daily macOS use.
- Local-first individuals who do not want their password database hosted by a
  vendor-operated cloud service.
- macOS users who want native vault management, strong daily ergonomics, and
  file-provider sync they can inspect.
- Technical alpha testers who can tolerate manual updates and explicit trust
  boundary disclosures while core security and release processes mature.

Non-target users for the first product phase:

- Teams that need shared vaults, server-side access control, or organization
  administration.
- Users who need browser autofill, passkeys, mobile clients, or family sharing
  before adopting the product.
- Users who require vendor-managed recovery, cloud accounts, or web access.

## Product Principles

- Local first: vault data stays in user-selected local files.
- Untrusted sync: sync providers only transport encrypted files.
- Reduced remote exposure is not a general security guarantee: local malware,
  stolen vault files, malicious synced input, weak master passwords, clipboard
  exposure, and software supply-chain compromise remain in scope.
- Native daily use: macOS interactions should feel direct, keyboard-friendly,
  and safer than editing a generic database file.
- No silent trust expansion: diagnostics, updates, sync placement, and
  convenience unlock must disclose their boundaries.
- Security before distribution: public alpha must not be approved without
  signed install verification and either external review evidence or an
  explicit, scoped maintainer accepted-risk record.

## Implemented Review

### Daily Usable Core

Implemented:

- Native macOS vault flows for create, open, unlock, lock, close, switch, and
  recent vault reopening.
- Encrypted `.pswvault` directory storage with a Rust core handling vault
  format, key derivation, record encryption, item records, tombstones, import,
  export, TOTP, search, and sync metadata.
- Login items, secure notes, credit cards, and software licenses with
  type-specific create, view, edit, favorite, archive, restore, delete, and
  duplicate workflows.
- Login multi-URL support, safe Open URL handling, TOTP secret editing and code
  copy, and local password generation.
- Fast local search over non-secret fields, tags, and item types, plus
  archived inclusion, favorite-only, conflict-only, tag, and item-type filters.
- No-matching-items recovery state with clear filters.
- Item row context menus and native Item menu shortcuts for login, secure-note,
  credit-card, and software-license copy workflows.
- Hidden saved secrets with explicit reveal controls and transient reveal state.
- Empty secret-copy protection so empty usernames, card numbers, verification
  codes, and license keys do not overwrite the clipboard.
- Plaintext Bitwarden JSON and generic login CSV import, plus plaintext
  Bitwarden JSON export with explicit warnings and cleanup actions.
- Encrypted backup and restore workflows that copy portable encrypted vault
  structure without creating plaintext exports.
- English and Simplified Chinese UI language setting, clipboard timeout
  setting, and auto-lock duration setting.

Key evidence:

- `README.md`
- `apps/macos/Sources/PSWMac/`
- `apps/macos/Tests/PSWMacTests/PSWMacWorkflowTests.swift`
- `crates/psw-core/src/`
- `crates/psw-core/tests/`

### File Sync Usability

Implemented:

- Vaults are local encrypted directories that can live inside external sync
  folders.
- Manual `Refresh Sync` and local file-change polling for required vault
  structure, item records, and tombstone records.
- Local sync status counts for loaded records, tombstones, conflicts, and
  rejected records.
- Sync placement hints for common local provider folders without calling
  provider APIs.
- Sync readiness checks for portable vault structure and local unlock envelope
  presence.
- `Copy to Sync` workflow that copies a selected encrypted vault to a sync
  destination, clears active decrypted state, and selects the copied vault
  locked.
- Rejected encrypted record handling that counts malformed or unauthenticatable
  records without blocking trusted records.
- Rejected record quarantine into a vault-local quarantine batch directory.
- Sync conflict candidates, structured comparison fields, selected-candidate
  resolution, and safe non-secret field merge.
- Stale edit revision guard for saves, favorite, archive, and delete actions.
- Sync refresh preserves active list filters and protects dirty editor drafts.
- `psw doctor` CLI for non-secret local vault structure inspection.

Key evidence:

- `docs/sync.md`
- `crates/psw-core/src/api.rs`
- `apps/macos/Sources/PSWMac/VaultStore.swift`
- `apps/macos/Tests/PSWMacTests/PSWMacWorkflowTests.swift`

### Security and Trust

Implemented:

- Argon2id master-password key derivation and authenticated vault key wrapping.
- Encrypted item records and tombstones owned by the Rust core.
- Master password rotation that rewraps `keys.enc` without rewriting item
  records.
- Local Keychain convenience unlock using local unlock material plus
  `local_unlock.enc`, without storing the master password or raw vault key.
- Cleanup for known legacy alpha Keychain entries.
- Clipboard timeout clearing, lock-time clipboard clearing, and preservation of
  unrelated later clipboard contents.
- Auto-lock on idle timeout, system sleep, screen sleep, session lock, app
  termination, and last-window close.
- Dirty-editor guardrails before discard-prone navigation, imports, refreshes,
  recovery, archive, delete, and vault switching.
- Conflicted items are read-only for ordinary mutations until resolved.
- Local password health check for weak and reused login passwords without
  returning password values, hashes, usernames, URLs, notes, or secrets.
- Non-secret support diagnostics from Settings and sync issue surfaces.
- Logging, diagnostics, telemetry, and crash report policy stating current alpha
  builds do not automatically upload logs, diagnostics, telemetry, vault
  records, or crash reports.
- Security review plan, evidence register, and handoff package tooling.

Key evidence:

- `docs/security-model.md`
- `docs/security-review-plan.md`
- `docs/security-review-evidence.md`
- `docs/logging-policy.md`
- `crates/psw-core/src/crypto.rs`
- `crates/psw-core/src/record.rs`
- `crates/psw-core/tests/property_hardening.rs`

### Product Completion and Distribution

Implemented:

- First-run and empty-vault guidance in the macOS client.
- Manual alpha update policy.
- Unsigned local Apple Silicon DMG generation with checksum and manifest.
- Optional Developer ID signing and notarization support in packaging scripts
  when credentials are provided.
- Distribution environment preflight.
- Signed install verification script for signed and notarized DMGs.
- `.pswvault` package-style document registration metadata and verification.
- Local Launch Services smoke verification for `.pswvault` registration, with
  managed-workspace blockers reported rather than hidden.

Key evidence:

- `docs/update-policy.md`
- `docs/macos-alpha-packaging.md`
- `docs/release-readiness.md`
- `script/package_macos_alpha.sh`
- `script/verify_macos_signed_install.sh`

## Current Gaps

### Must Finish Before Public Alpha

- External security review has not started. The current evidence register says
  review status is not started and public alpha is not approved.
- Developer ID signing, notarization, stapling, Gatekeeper assessment, and
  signed install verification still need release-operator execution with real
  Apple credentials.
- Strict public alpha release readiness must pass without `--allow-missing`.
- Vault format remains experimental until an explicit public alpha freeze
  decision.
- Signed app install and Finder double-click behavior need verification outside
  the managed workspace where Launch Services registration can be blocked.
- Public alpha release notes, tester onboarding, known limits, and feedback
  intake need a polished handoff.

### Should Finish for a More Credible Alpha

- Guided migration from 1Password 7, 1Password export formats, KeePass, and
  additional CSV variants.
- More user-facing sync recovery guidance for common provider behaviors such as
  duplicated records, delayed downloads, and reappearing rejected files.
- Accessibility, keyboard navigation, and VoiceOver review for the macOS UI.
- Visual polish pass for dense daily workflows, especially conflict resolution,
  sync readiness, diagnostics, and first-run flows.
- More structured manual QA scripts using realistic vaults and sync folders.
- Clear backup and recovery guidance for users who lose local Keychain
  convenience unlock material but still know their master password.

### Post-Alpha Product Work

- iOS client and browser extension work are deferred until the macOS first
  release is closed. Neither has a current implementation milestone.
- A future iOS client may open the same `.pswvault` format through local file
  providers after the cross-platform format boundary is deliberately reviewed.
- A future browser extension may add autofill after its native-app integration
  and secret-exposure boundaries are deliberately reviewed.
- Passkey support.
- Attachment UX beyond portable encrypted structure handling.
- Optional automatic updater after update-feed signing and network trust
  boundaries are reviewed.
- Community contribution guide, issue templates, roadmap, and release process.

### Deliberate Non-Goals for the Current Product

- Hosted cloud sync service.
- Server-side vault sharing, teams, family plans, billing, or admin controls.
- Provider-specific upload or download status.
- Vendor-managed account recovery.
- Secret-value conflict merge inside the conflict picker.
- Automatic telemetry, crash reports, diagnostics upload, or analytics.

## Roadmap

### Phase 1: Daily Usable Core

Status: mostly implemented for macOS alpha.

Exit criteria:

- A user can create or open a local vault, unlock it, manage the four supported
  item types, search and filter, copy secrets safely, import and export, back
  up and restore encrypted vaults, and recover from common dirty-editor states.
- `scripts/check.sh` passes.
- Manual macOS smoke test covers create, unlock, CRUD, copy, search, import,
  export, backup, restore, lock, and settings.

### Phase 2: File Sync Truly Usable

Status: strong local-file sync base implemented, but still alpha-limited.

Exit criteria:

- Local sync refresh, file-change detection, rejected records, quarantine,
  conflict candidates, selected-candidate resolution, safe merge, stale edit
  guard, diagnostics, and doctor CLI all pass automated validation.
- Manual two-device or two-folder sync simulation proves expected conflict,
  delete, restore, rejected-record, and stale-edit behavior.
- User docs explain provider trust boundaries and common recovery actions
  without implying provider upload/download visibility.

### Phase 3: Security and Trust

Status: local controls implemented; `AR-001` accepts the limited unaudited
experimental pre-release risk, while signed distribution gates remain
incomplete.

Exit criteria:

- External security review completed or explicit accepted-risk records exist.
- Strict security review evidence verification passes.
- Strict public alpha readiness passes.
- Signed and notarized DMG passes clean install verification.
- Security model, logging policy, diagnostics, update policy, and release notes
  are aligned with reviewed behavior.

### Phase 4: Product Completion

Status: local alpha packaging and product workflows exist, but final polish and
distribution handoff remain.

Exit criteria:

- First-run, empty states, conflict resolution, sync status, settings, import,
  export, backup, restore, and diagnostics are manually reviewed for clarity.
- Accessibility and keyboard navigation review completed.
- Public alpha onboarding, known limits, feedback path, manual update path, and
  troubleshooting docs are ready.
- Release artifact, checksum, manifest, and signed install evidence are
  published together.

### Phase 5: Ecosystem

Status: intentionally deferred.

Exit criteria:

- iOS plan and file-provider constraints documented.
- Browser extension/autofill plan documented.
- Passkey and attachment strategy documented.
- Community contribution and release governance process documented.

## Functional Requirements for the Next Product Baseline

### Vault and Item Management

- The product must support local `.pswvault` create, open, unlock, lock, close,
  and recent reopen on macOS.
- The product must support login, secure note, credit card, and software
  license item workflows.
- The product must protect unsaved editor drafts before replacing selection or
  vault context.
- The product must keep saved secrets hidden until explicit copy or reveal.

### Sync and Conflict Handling

- The product must never require a provider account or provider API.
- The product must refresh from local encrypted files and surface local counts.
- The product must fail closed on missing required vault structure.
- The product must reject bad encrypted records without blocking valid records.
- The product must expose conflict candidates without rendering secret values.
- The product must let users keep one conflict candidate or merge only safe
  non-secret fields.

### Security and Privacy

- The product must keep crypto and encrypted record parsing in the Rust core.
- The product must clear transient secret state on lock, sleep, session lock,
  app termination, and vault switching.
- The product must keep diagnostics non-secret and user-initiated.
- The product must not automatically upload telemetry, diagnostics, crash
  reports, vault records, or logs in the alpha.
- The product must not approve public alpha until external review or an
  explicit maintainer accepted-risk path passes and all signed distribution
  gates are satisfied.

### Import, Export, Backup, and Recovery

- Plaintext import and export must warn users and offer cleanup actions.
- Encrypted backup and restore must not decrypt records or copy local-only
  convenience unlock material.
- Doctor and diagnostics must support support workflows without master password
  entry or secret disclosure.

## Success Metrics

- Daily task completion: alpha tester can perform a full password-manager day
  loop without terminal commands after installing the app.
- Sync resilience: alpha tester can recover from stale edits, conflicts,
  rejected records, missing structure, and dirty-editor refresh deferral using
  visible UI guidance.
- Trust clarity: tester can explain what sync providers, diagnostics,
  convenience unlock, and manual updates do and do not guarantee.
- Release discipline: no public alpha artifact is approved without strict
  readiness, signed install verification, and review evidence.

## Publication Policy

- The first product closure is macOS-only. iOS and browser-extension work have
  no current implementation milestone.
- The initial public repository is a personal-interest, unaudited source
  preview and does not claim suitability for production secrets.
- The initial publication contains source and local build instructions, not
  installable application artifacts or GitHub Releases.
- GitHub Issues are accepted on a best-effort basis. External pull requests are
  not currently accepted, and security reports use the private channel.
- The project is licensed under GNU GPL Version 3 only (`GPL-3.0-only`).
- AI development records and local Agent governance are maintained outside the
  public product-source repository.

## Related Records

- `README.md`
- `docs/security-model.md`
- `docs/sync.md`
- `docs/release-readiness.md`
- `docs/security-review-evidence.md`
- `docs/update-policy.md`
