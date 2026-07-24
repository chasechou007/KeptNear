# Import and Export Formats

The first alpha export format is `bitwarden-json`, covering a small unencrypted
subset of Bitwarden JSON exports. Imports support both `bitwarden-json` and a
conservative `generic-login-csv` format for login-only migration from desktop
password managers and browsers.

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
login items, secure notes, and credit cards are immediately available through
their type-specific macOS editors.

## Export

Supported exported records:

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

Export destination files contain plaintext secrets. The app must require
explicit confirmation and a clean editor state before writing the file and must
remind users to delete or secure the file after migration.

## macOS Export Flow

Unlock a vault, save or discard any active editor draft, choose `Export`, select
a destination JSON file, confirm the plaintext export warning, then review the
exported/skipped counts and warnings.
After a successful export, the result sheet keeps the destination file visible
and offers actions to reveal the exported JSON in Finder or move it to Trash.
The SwiftUI client does not assemble the export contents; export serialization
and file writing run through the Rust core.
