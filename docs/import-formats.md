# Import and Export Formats

The default human export format is `keptnear-json`, a documented structured
plaintext representation of the typed credential model. `bitwarden-json`
remains a lossy compatibility export. Imports support both `bitwarden-json` and
a conservative `generic-login-csv` format for login-only migration from
desktop password managers and browsers.

## Import

Supported imported records:

- Login items with name, username, password, URI list, notes, favorite flag, and
  TOTP secret.
- Secure notes with name, notes, and favorite flag.
- Credit cards with name, cardholder name, number, expiration month and year,
  verification code, notes, and favorite flag.

Bitwarden folder membership is imported as a local tag for supported records.
If an item references a missing folder or a folder with a blank name, the item
is still imported and no folder tag is added. Folder hierarchy and Bitwarden
collections are not represented in the local vault.

Login TOTP values may be raw Base32 secrets or `otpauth://` URIs with a
`secret` query parameter. The import path stores only the normalized uppercase
Base32 secret. Issuer, account label, algorithm, digit count, and period
parameters from `otpauth://` URIs are not persisted in the current item schema.

Unsupported records are skipped and reported in the import preview. Encrypted Bitwarden exports are rejected because the MVP import path expects the user to provide a plaintext export that can be parsed locally and immediately re-encrypted into the vault.

Import source files may contain plaintext secrets. The app must warn users before import and should remind them to delete or secure the source export after import completes.

### Typed Fields And Local Identities

Supported records are converted directly into KeptNear's typed credential
model. Passwords, TOTP seeds, secure-note bodies, card numbers, and card
verification codes become independently identified Secret Fields with
provider-neutral kinds. External provider record IDs are not reused as
KeptNear authorization identities.

Preview reads and classifies the source locally but does not write imported
records or identities into the vault. Commit allocates a fresh local
Credential ID and fresh Secret Field IDs and persists them only inside the
authenticated encrypted record. If the user intentionally keeps the same
likely duplicate in a later import, it receives independent identities and
does not inherit Access Rules or grants from the earlier item.

Likely-duplicate matching uses normalized non-secret title, template category,
and, for logins, the first username and URL. It does not inspect secret values,
tags, provider IDs, or authorization IDs. Existing API tokens, keys,
certificates, and custom typed credentials remain valid inputs to duplicate
detection even when they cannot be represented by the frozen v1 item model.

### Generic Login CSV Import

The `generic-login-csv` importer requires a header row and imports valid rows
as login items only. Supported header aliases are matched case-insensitively
after trimming punctuation and whitespace:

- Title: `title`, `name`, `item`, `account`.
- Username: `username`, `user`, `login`, `login username`, `email`.
- Password: `password`, `pass`.
- URL: `url`, `uri`, `website`, `websites`, `login url`, `login uri`.
- Notes: `notes`, `note`, `comments`, `comment`.
- Tags: `tags`, `tag`.
- Group/folder tag: `group`, `folder`.
- Favorite: `favorite`, `favourite`, `starred`.
- TOTP: `totp`, `otp`, `otpauth`, `one time password`.

Rows without a non-empty title or name are skipped and counted in the preview.
If no supported title or name header exists, the importer rejects the preview
instead of guessing column positions. `tags` values are split on comma,
semicolon, or pipe; `group` and `folder` values are imported as single local
tags. Invalid TOTP values do not block row import, but the TOTP secret is
omitted and a warning is shown.

## macOS Import Flow

Unlock a vault, choose `Import`, select a Bitwarden JSON export or generic
login CSV file, review the preview counts, choose whether to keep likely
duplicates, then confirm import. The macOS client routes `.csv` files to
`generic-login-csv` and `.json` files to `bitwarden-json`; it does not parse or
retain export contents. Preview and commit run through the Rust core. Imported
login items, secure notes, and credit cards are persisted as typed credentials
and are immediately available through their type-specific macOS editors.

## Export

The macOS human export flow writes `keptnear-json` by default. The Rust core
also retains `bitwarden-json` as a lossy compatibility format.

### KeptNear Structured JSON

`keptnear-json` version 1 is a documented plaintext snapshot of every
non-deleted, non-conflicted typed credential that could be authenticated. Its
top-level object contains:

- `format`: fixed to `keptnear-plaintext-export`.
- `version`: fixed to `1`.
- `warning`: an explicit plaintext-equivalent and Base64 warning.
- `sourceVaultId`: the source Vault ID when the source format has one.
- `items`: ordered typed credential snapshots.
- `omissions`: aggregate structured omission reasons and counts.

Each item contains optional `sourceCredentialId`, `status` (`active` or
`archived`), title, optional open `templateId`, ordered fields, tags, and
favorite state. Text fields preserve role, optional label, and text. Secret
fields preserve role, optional label, provider-neutral kind, optional
`sourceSecretFieldId`, `encoding: "base64"`, and `valueBase64`. Base64 allows
arbitrary secret bytes to round-trip through JSON; it is reversible encoding
and provides no confidentiality.

The `source*Id` values preserve provenance and field relationships inside the
snapshot. They do not carry Consumers, Access Rules, Use Grants, Usage
Profiles, approvals, audit history, machine-access settings, runtime state,
convenience-unlock material, or any other authorization. A future plaintext
import must treat the file as untrusted and allocate fresh local identities,
matching the current Bitwarden and CSV import rule.

KeptNear does not currently import `keptnear-json`. It is the complete
plaintext export and preservation format, not a round-trip migration promise
in this version. The implemented Bitwarden JSON and generic login CSV importers
always allocate fresh local Credential and Secret Field IDs and never transfer
authorization.

The fixed top-level schema has no device-state object and never reads
`~/.keptnear`, the device root or Consumer signing identities from Keychain, or
`local_unlock.enc`. Importing this snapshot elsewhere must not pair a Consumer,
recreate authorization, transfer audit history, or enable convenience unlock.

Deleted credentials are intentionally absent. Credentials with unresolved
authenticated conflicts are omitted with `conflicted-credential`; rejected
encrypted record files are reported as `rejected-record`. The export result
returns the same structured reasons plus exported and skipped counts and
human-readable warnings. The checked-in synthetic example is
[`fixtures/exports/keptnear-plaintext-v1.json`](../fixtures/exports/keptnear-plaintext-v1.json).

### Bitwarden Compatibility JSON

The `bitwarden-json` compatibility exporter supports:

- Login items with name, username, password, URL list, notes, favorite flag, and
  TOTP secret.
- Secure notes with name, body, and favorite flag.
- Credit cards with name, cardholder name, number, expiration month and year,
  verification code, notes, favorite flag, and first tag folder.
- Software licenses with name, product, licensed-to value, license key, notes,
  favorite flag, and first tag folder. These are exported as secure notes
  because Bitwarden JSON has no native software-license item type.

Exported login TOTP values are the stored normalized Base32 secrets. The alpha
exporter does not reconstruct `otpauth://` URIs or emit custom TOTP parameters.

The alpha exporter includes latest non-deleted login, secure note, credit-card,
and software-license items, including archived supported items.

Tags are represented as Bitwarden folders where possible. Bitwarden folders can
represent one folder per item, so only the first tag is attached to an exported
item and additional tags are reported with a warning. This is the inverse of the
import behavior, where a supported item's Bitwarden folder is restored as one
local tag.

The compatibility exporter converts a typed credential only when the complete
template and every field can be represented by the frozen legacy shape. It
skips the whole credential instead of partially dropping a secret. The
structured result reports `unsupported-template`, `unsupported-field`, and
`additional-tags` as applicable and recommends `keptnear-json` for the complete
typed structure.

Export destination files contain plaintext secrets. The app requires explicit
confirmation, a clean editor state, and the current master password. Core
reopens the current key envelope and verifies that the unwrapped Vault Key
matches the active unlocked session before it reads the export snapshot or
writes the destination. A missing or incorrect password leaves the destination
unwritten. The result flow reminds users to delete or secure the file after
migration.

Complete plaintext export is not part of the Broker capability model and is
unavailable to MCP, CLI, Consumers, Access Rules, and Use Grants. Calling the
internal FFI export command with only an unlocked session ID is also rejected;
it must carry the current master password supplied by the interactive App.

## macOS Export Flow

Unlock a vault, save or discard any active editor draft, choose `Export`, select
a destination JSON file, read the plaintext warning, enter the current master
password, and confirm. Then review the exported/skipped counts, structured
omissions, and warnings. The current macOS flow selects `keptnear-json` so open
typed templates and arbitrary secret bytes are preserved. The view clears its
transient password binding immediately after the request; the Swift and JSON
bridge do not claim deterministic zeroization of runtime string copies.
After a successful export, the result sheet keeps the destination file visible
and offers actions to reveal the exported JSON in Finder or move it to Trash.
The SwiftUI client does not assemble the export contents; export serialization
and file writing run through the Rust core.
