# Release Readiness Notes

## Release Profiles

KeptNear has three explicit, non-interchangeable readiness profiles:

```sh
# Source only; no DMG, Apple signing, or external review prerequisite.
script/verify_source_preview_ready.sh

# Clean-source Apple Silicon DMG; explicitly unsigned and unaudited.
script/verify_unsigned_alpha_release_ready.sh

# Optional Developer ID signed, notarized, and stapled distribution.
script/verify_public_alpha_release_ready.sh
```

Each command supports `--allow-missing` report mode. Report mode lists blockers
and never approves publication. Strict source and unsigned profiles always
report `Audit status: unaudited` while external review is absent. That status
does not block those two bounded profiles, but every profile keeps the
production-use recommendation at `Not recommended`.

The source profile verifies a clean revision, broad Rust/Swift checks,
public-tree exclusions and repository secret patterns, dependency licenses,
strict OpenSpec state, and the source review policy without building an
artifact. The unsigned profile adds AR-002, local macOS and vault-format gates,
Launch Services verification, clean-source packaging in
`unsigned-experimental` mode, checksum and protocol-manifest verification, and
explicit unsigned installation warnings. The signed profile alone performs
Developer ID, hardened-runtime, notarization, stapling, Gatekeeper, and signed
install checks.

## Dependency Review

Current security-sensitive Rust dependencies:

- `argon2`: master password key derivation with Argon2id.
- `chacha20poly1305`: XChaCha20-Poly1305 authenticated encryption.
- `rand_core`: operating system randomness.
- `hmac` and `sha1`: TOTP generation per RFC 6238 SHA-1 compatibility.
- `serde` and `serde_json`: vault metadata, record encoding, and import parsing.
- `zeroize`: pinned for Rust 1.75 compatibility; `SecretBytes` also clears its allocation on drop.
- `hkdf` and `sha2`: domain-separated SQLCipher database-key derivation.
- `rusqlite` and bundled SQLCipher Community Edition: authenticated encrypted
  device-state pages, WAL, transactions, and schema migration support.
- `core-foundation` and `security-framework-sys`: Rust 1.75-compatible,
  macOS-only bindings for the Broker's device-bound Data Protection Keychain
  item.

Current compatibility pins:

- `base64ct = 1.6.0`
- `core-foundation = 0.9.4`
- `rusqlite = 0.31.0`, embedding SQLCipher 4.5.3
- `security-framework-sys = 2.9.1`
- `rustls = 0.23.43`, selecting `rustls-webpki = 0.103.13`
- `zeroize = 1.8.1`

These pins avoid transitive crates that require Rust 2024 edition and newer compilers than the current workspace Rust 1.75 toolchain.
The SQLCipher pin is older than the current upstream line and is not approved
for distribution of the new device-state feature. Before enabling that feature
in any DMG, raise the Rust toolchain, refresh `rusqlite` and bundled SQLCipher,
repeat wrong-key/tamper/format/permission tests, rerun the dependency audit, and
verify schema compatibility. Source distributions and future binaries must
retain `THIRD_PARTY_NOTICES.md`.

The 2026-07-31 local review upgraded the TLS chain after the prior
`rustls-webpki` selection matched four RustSec advisories. The resulting
lockfile reports no known vulnerability against the available local
`cargo-audit` snapshot. The attempted online advisory refresh did not complete,
and the snapshot did not expose its last-update timestamp, so this is not
represented as a live online audit. See `docs/local-security-review.md`.

## macOS Target

The first binary release target is macOS 13 or newer on Apple Silicon
(`arm64`). Intel Macs, Windows, iOS, and browser extensions are outside this
first distribution scope. The reusable Rust core remains structured so later
platform work does not require changing the portable vault format.

Before recommending the macOS app for production use or publishing a signed
distribution, confirm:

- signing identity and hardened runtime requirements
- Keychain access group behavior
- Broker device-root-key continuity across reinstall and signed, ad-hoc, and
  unsigned upgrade paths, with no file fallback
- current SQLCipher dependency, encrypted database/WAL/SHM behavior, and
  schema-version compatibility after raising the Rust toolchain
- local convenience unlock review, including the Keychain local-key plus
  `local_unlock.enc` envelope boundary and cleanup behavior for old alpha
  Keychain entries that stored master passwords
- Launch Services and Finder double-click association behavior after installing
  a signed/notarized `.pswvault`-aware app bundle
- day-use item coverage for login items, secure notes, credit cards, and
  software licenses

## Distribution Notes

The current macOS packaging workflow can create an unsigned local Apple Silicon
DMG with a checksum and manifest:

```sh
script/package_macos_alpha.sh
```

The project uses three separate publication profiles:

- **Source preview:** publish source only. This does not require Apple signing,
  notarization, or an external security review.
- **Unsigned experimental DMG:** publish an Apple Silicon DMG only after local
  build, integrity, privacy, license, disclosure, and clean-install checks pass.
  The download and installation instructions must state `unsigned`,
  `unaudited`, `experimental`, and `do not use production secrets`.
- **Signed distribution:** optionally publish a Developer ID signed and
  notarized DMG after the stricter signed-distribution checks pass.

The packaging command defaults to `local-test`, which cannot claim distribution
readiness. The unsigned readiness command selects
`RELEASE_MODE=unsigned-experimental`; that mode forbids a signing identity and
notarization, requires a clean worktree and the AR-002 policy gate, and records
`unsigned`, `unaudited`, and non-production status in the artifact manifest.

The existing strict public-alpha scripts implement the signed-distribution
profile and require:

- passing strict public alpha release readiness with
  `script/verify_public_alpha_release_ready.sh`
- generated and checksum-verified security review handoff materials from
  `script/package_security_review_materials.sh`
- passing strict macOS distribution environment preflight with
  `script/verify_macos_distribution_environment.sh` on the release operator's
  Mac
- running the packaging workflow with a real Developer ID signing identity
- successful notarization and stapling with Apple notarytool credentials
- setting `RELEASE_MODE=experimental-pre-release`; the default `local-test`
  mode cannot claim distribution readiness
- signed macOS install verification with `script/verify_macos_signed_install.sh`
  against the signed/notarized DMG
- completed external security review evidence or explicit accepted-risk records

The unsigned experimental profile uses
`script/verify_unsigned_alpha_release_ready.sh` and its own release-mode label.
It must not reuse a signed-distribution readiness result or imply that
Gatekeeper, Developer ID, notarization, or external audit checks passed.

## Security Review

An external security review plan exists at
`docs/security-review-plan.md`. This is a readiness artifact for preparing an
independent review; it is not evidence that external review has been completed.
Review evidence, findings, accepted risks, validation, and release decision
status are tracked in `docs/security-review-evidence.md`.

No external security review evidence has been attached. External review remains
valuable before recommending production use, but it is not a prerequisite for
the source-preview or explicitly unsigned experimental-DMG profiles.

The accepted-risk register distinguishes the signed and unsigned profiles:

- `AR-001` covers an externally unaudited, signed and notarized experimental
  pre-release.
- `AR-002` covers an externally unaudited and unsigned experimental DMG with
  stronger disclosure and installation requirements.

Neither decision recommends production use. Artifact readiness remains
separate from accepting the policy risk.

Use the evidence gate to check the current status:

```sh
script/verify_security_review_evidence.sh --allow-missing
```

Prepare reviewer handoff materials before external review:

```sh
script/package_security_review_materials.sh
```

The generated archive, manifest, and SHA-256 checksum live under
`dist/security-review/`. They are preparation artifacts only; they do not
replace reviewer findings, accepted-risk records, validation, or release
approval.

Before using the existing signed-distribution approval path, strict mode must
pass:

```sh
script/verify_security_review_evidence.sh
```

The strict evidence gate passes through either of these paths:

- completed external review evidence, finding disposition, and post-review
  validation
- an explicit maintainer accepted-risk record with complete scope,
  user-facing implications, mitigations, owner, revisit triggers, and
  validation

For the signed profile, the accepted-risk path does not bypass Developer ID
signing, notarization, signed-install verification, or experimental user
warnings. The unsigned profile intentionally omits those Apple trust-chain
claims and instead requires explicit unsigned installation guidance, checksum
and manifest publication, local artifact verification, and adjacent
experimental warnings.

## First-Version Closure Limitations

The macOS first-version closure keeps these limitations explicit:

- The project is locally reviewed but externally unaudited. No source or DMG is
  recommended for production credentials.
- The current local-test DMG is unsigned and not notarized. macOS may warn or
  block normal launch, Apple does not attest its publisher identity, and
  unsigned/ad-hoc Keychain continuity across replacement or reinstall is not a
  release guarantee.
- A dirty-worktree `local-test` DMG is test evidence only. Public source
  preview and unsigned experimental packaging each require a clean committed
  revision and their own strict profile.
- Broker, MCP adapter, and CLI executables are packaged but are not installed
  or activated as an end-user service. The complete first-run pairing,
  approval, restart, upgrade, and uninstall lifecycle is not shipped.
- The bundled SQLCipher 4.5.3 compatibility pin must be upgraded and
  revalidated before machine-access state is enabled in a distributed DMG.
- KeptNear does not operate iCloud Drive, Dropbox, Syncthing, WebDAV, or any
  other sync provider. Provider upload, deletion, ordering, and availability
  behavior has not been validated by the two-device filesystem matrix.
- `keptnear-json` is currently the complete plaintext export format but is not
  an import format. Plaintext export and import files remain outside vault
  protection.
- Rust secret byte containers and selected serialization buffers are cleared,
  but Swift strings, Foundation data, parser-owned strings, OS clipboard
  history, child processes, and crash-memory snapshots cannot be promised to
  zeroize deterministically.
- An authorized Consumer can misuse the exact field and capability the user
  granted. KeptNear enforces its Broker scope; it does not edit agent policy
  files, interpret prompts, or police behavior outside that scope. A direct
  child or descendant may retain a delivered secret after the Broker operation
  ends.
- Duplicate portable vault identity is detected when a path is presented to
  one Broker process, not by a filesystem-wide scan. The user may need to close
  an unintended copied vault and reopen the authoritative path.
- Updates are manual. There is no automatic security-update channel, signed
  update feed, or rollback service in the first version.
- The exact final DMG still requires human launch and workflow acceptance.
  Automated build and artifact verification do not replace that check.

## Pre-Alpha Gates

Do not recommend production use until these gates are complete:

- public alpha release readiness verification passes with
  `script/verify_public_alpha_release_ready.sh`, including security review
  handoff package generation and checksum verification; report mode with
  `--allow-missing` runs the local handoff package step, lists blockers, and
  does not approve readiness
- local alpha readiness verification passes with
  `script/verify_local_alpha_readiness.sh`; report mode with `--allow-missing`
  can list managed-workspace blockers such as Launch Services registration
  access, but it does not approve local alpha readiness. This is automated
  local evidence only and does not replace signed/notarized clean-install
  testing or the selected external-review or accepted-risk decision path
- local vault-format readiness verification passes with
  `script/verify_vault_format_readiness.sh`, proving the frozen v1 migration
  source and released pre-alpha v2 schema remain aligned with their sanitized
  fixtures
- vault doctor readiness verification passes with
  `script/verify_vault_doctor_readiness.sh`, proving both the public
  `keptnear vault doctor` namespace and legacy `psw doctor` entrypoint can
  inspect generated supported vaults, reject incomplete and unsupported future
  vaults, emit equivalent JSON, omit full paths, and avoid known plaintext item
  output without checking provider sync state
- vault format documented and reviewed
- golden vectors checked in and stable
- parser hardening tests pass
- sync conflict fixtures pass
- malformed, unreadable, or authentication-failing synced records are counted as
  rejected without blocking trusted records from loading
- sync refresh revalidates required vault structure and fails closed when
  metadata, key material, or record directories are missing or have the wrong
  file/directory type
- macOS automatic file-change detection watches required vault structure as well
  as encrypted item and tombstone records
- macOS sidebar shows a local-only sync-location hint for common provider
  folders without contacting provider APIs or exposing full local paths
- macOS sidebar shows local sync readiness for required portable vault
  structure, likely provider placement, and local unlock envelope presence
  without contacting provider APIs or exposing full local paths
- macOS can copy the selected encrypted vault to a sync destination, keep the
  original vault in place, switch to the copied vault locked, and report
  non-secret copied-record counts
- sync issue UI can refresh again, reveal the vault directory, and copy
  non-secret diagnostics when conflicts or rejected records are present
- selected sync conflicts can show candidate summaries, resolve by choosing the
  version to keep, and refresh the visible conflict count from the macOS client
- sync refresh preserves active search, archived-item inclusion,
  favorite-only, conflict-only, tag, and item-type filters while updating sync
  counts and refresh time
- conflict candidate summaries show changed-field labels, including secret
  field labels without exposing secret values
- conflict candidate cards show structured comparison fields and keep
  password, TOTP, card number, verification code, secure-note body, and license
  key values redacted
- Keychain convenience unlock stores only opaque local unlock keys, requires the
  matching `local_unlock.enc` envelope, and never stores the master password or
  raw vault key
- old alpha Keychain entries that may have stored master passwords can be
  cleaned up for the selected vault without deleting current local unlock
  material
- conflicted items remain read-only for ordinary save, favorite, archive,
  delete, tag replacement, and secret-copy actions until explicit conflict
  resolution
- existing-item save, favorite, archive, and delete actions send expected item
  revisions and reject stale revisions without writing a new item record or
  tombstone
- macOS client uses the Rust core for all vault operations
- login items, secure notes, credit cards, and software licenses can be created,
  selected, edited, and reloaded through type-specific macOS editors
- login items can preserve, edit, search, and open multiple associated URLs
  from the macOS client without reducing them to the first saved URL
- selected login items, secure notes, credit cards, and software licenses can be
  duplicated as new active items while preserving supported fields and saved
  secrets
- login TOTP secrets can be manually added from raw Base32 or `otpauth://`
  input, edited, cleared, and used for code copy from the macOS client only
  when the selected login has a saved TOTP secret
- login password generation requires at least one selected character class,
  localizes invalid generator-option feedback, and does not retain generator
  history outside the active editor draft
- vault creation and master-password rotation show local, advisory strength
  guidance without recording scores in diagnostics or blocking non-empty weak
  passwords
- unsigned Apple Silicon macOS alpha DMG can be generated with checksum and
  manifest
- macOS alpha packaging supports optional Developer ID signing, hardened
  runtime, notarization, stapling, and manifest status metadata when local
  Apple credentials are provided
- macOS distribution environment preflight can verify required local signing
  and notarization tools, a configured Developer ID Application identity, and
  notarization credential shape without printing secret credential values; an
  allow-missing report mode exists for development machines without release
  credentials and does not approve distribution readiness
- macOS alpha DMGs can be verified with a repository command that checks the
  checksum, mounted image structure, Applications link, arm64-only app and FFI
  binaries, manifest integrity metadata, signing status, manual update channel,
  `.pswvault` document metadata, and distribution boundary
- signed and notarized macOS alpha DMGs can be verified from a clean temporary
  install directory with `script/verify_macos_signed_install.sh`, including
  signed manifest status, notarization acceptance, staple validation,
  `codesign`, Gatekeeper assessment, and Launch Services `.pswvault`
  registration; unsigned DMGs are rejected by this verifier
- public alpha update policy is manual, documented, and recorded in the package
  manifest; automatic updates are deferred until after alpha review
- first-run and empty-vault guidance is visible in the macOS client
- macOS system file-open events for `.pswvault` paths route through the same
  locked open-vault workflow as the in-app Open action, reject unsupported paths
  locally before calling the core, and preserve unsaved-editor guardrails
- generated macOS app bundles advertise `.pswvault` as a package-style vault
  document type through shared Info.plist generation, and alpha artifact
  verification fails if that metadata is missing or inconsistent
- local Launch Services smoke verification can register a generated app bundle
  and confirm the `.pswvault` package UTI, extension tag, document role, owner
  rank, package flag, and binding are visible in the Launch Services database;
  sandboxed or permission-blocked registration fails with an actionable
  diagnostic rather than claiming readiness, while local alpha report mode can
  surface that blocker without converting it into a passing strict gate
- macOS Settings shows a localized trust-boundary summary covering local vault
  files, untrusted encrypted file-sync transports, user-copied diagnostics, and
  experimental alpha vault-format status without rendering paths, provider
  account state, diagnostics payload contents, item data, or secrets
- macOS password health can refresh local weak/reused counts, list only
  non-secret issue metadata, and navigate from an issue row to the affected item
  through dirty-editor guardrails while clearing hiding filters and enabling
  archived visibility
- macOS item-list context menus expose daily selected-item workflows while
  reusing guarded selection, conflict, archive, and destructive confirmation
  behavior and without rendering secret values in row menus
- macOS Item menu shortcuts expose login, secure-note, credit-card, and
  software-license copy workflows through the same guarded clipboard paths as
  visible editor actions
- macOS filtered search/list states show a no-matching-items recovery state with
  a clear-filters action instead of confusing filtered-empty results with a
  newly empty vault
- macOS item lists can be filtered by a selected tag derived from non-secret
  item summaries, composing with search text, archived inclusion, favorites,
  and conflicts while preserving dirty-editor selection guardrails
- macOS item lists can be filtered by selected item type derived from
  non-secret item summaries, composing with search text, archived inclusion,
  favorites, conflicts, and tags while preserving dirty-editor selection
  guardrails
- macOS security-state readiness verification passes with
  `script/verify_macos_security_state.sh`, while signed install behavior,
  notarization, and the selected external-review or accepted-risk path remain
  separate public-alpha decisions
- clipboard behavior verified on macOS, including clearing copied secrets after
  timeout, clearing the current managed secret on vault lock, and preserving
  later user clipboard contents
- auto-lock behavior verified on macOS, including idle timeout, system sleep,
  screen sleep, and session lock clearing decrypted active state and transient
  view-layer secret state, including Settings master password rotation fields
- vault switching verified on macOS, including opening or creating another
  vault clearing the previous unlocked session and active secret state
- close-vault workflow verified on macOS, including clearing selected vault
  context and active secret state without deleting files or forgetting the
  recent vault shortcut
- clipboard and auto-lock preference persistence verified across app launches
- import flow supports login items, secure notes, and credit cards, warns about
  plaintext export files, and reports preview/commit counts
- export flow supports login items, secure notes, credit cards, and software
  licenses, requires a clean editor state and explicit plaintext confirmation,
  and reports exported/skipped counts and warnings
- encrypted backup flow copies the portable encrypted vault structure without
  decrypting records, excludes local-only unlock material, rejects unsafe
  destinations, and reports non-secret copied-record counts
- encrypted backup restore flow copies a selected encrypted backup to a new
  vault destination, excludes local-only unlock material, clears previous active
  state, and leaves the restored vault locked until normal unlock
- copy actions verified on macOS, including empty usernames, card numbers,
  verification codes, and license keys leaving the clipboard unchanged
- convenience unlock stores local unlock material instead of the master password
  and discards failed stale material before requiring master-password fallback
- new vault creation and master password rotation reject empty master passwords
  in macOS validation and at the Rust core boundary
- master password rotation verifies the current password, rewraps only
  `keys.enc`, preserves existing items, and clears local convenience unlock
  material
- editor guardrails block empty-title saves for login items, secure notes,
  credit cards, and software licenses and confirm discard-prone navigation for
  unsaved edits in those editors, including item selection,
  open/create/close-vault workflows, destructive archive/delete requests,
  import commit, manual sync refresh, and sync recovery actions
- item selection rejects unconfirmed dirty editor state at the store layer
  before replacing the active editor detail
- vault switch and close workflows reject unconfirmed dirty editor state at the
  store layer before replacing selected vault context or clearing the active
  session
- sync refresh and sync recovery protect unsaved editor drafts, including
  store-level rejection of unconfirmed manual refresh and rejected-record
  quarantine, manual refresh discard confirmation, and deferred automatic
  file-change refresh while drafts are dirty
- destructive archive/delete actions require confirmation after any required
  unsaved-edit discard confirmation and reject unconfirmed dirty editor state at
  the store layer before writing archive/delete mutations
- archived items can be searched and restored to the active list from the macOS
  client, while active or conflicted selections are rejected locally before any
  core restore call
- plaintext import source cleanup actions are available after import
- plaintext export destination cleanup actions are available after export
- local sync issue UI shows available rejected `.enc` file names without full
  paths, while copied diagnostics continue to omit rejected record file names
- non-secret support diagnostics can be copied from Settings and exclude item
  content, secrets, plaintext import/export file names and paths, and full local
  vault paths while allowing boolean plaintext cleanup state
- logging, telemetry, diagnostics, and crash report policy exists and states
  that current alpha builds do not automatically upload logs, diagnostics,
  telemetry, vault records, or crash reports
- external security review plan exists
- security review evidence register exists and clearly states whether external
  review evidence, accepted risks, validation, and public-alpha approval are
  complete
- security review handoff materials can be packaged under
  `dist/security-review/` with a manifest and SHA-256 checksum, while remaining
  clearly separate from completed external review evidence
- security decision evidence verification reports both the external-review and
  maintainer accepted-risk paths; strict mode passes when common validation is
  complete and either path is complete

External review must not be treated as complete until review evidence is
attached. Its absence does not block source publication or the dedicated
unsigned experimental-DMG profile, but both remain unaudited and unsuitable for
production secrets. `AR-001` and `AR-002` accept bounded release-policy risk;
they do not prove artifact readiness.
