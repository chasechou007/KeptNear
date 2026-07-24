# Encrypted Vault Backups

The encrypted backup workflow copies an unlocked vault to another local
directory without decrypting item records or creating a plaintext export.

Backups include the portable vault structure:

- `vault.json`
- `keys.enc`
- `items/`
- `attachments/`
- `tombstones/`

Backups intentionally exclude `local_unlock.enc`. Convenience unlock material is
local to the current Mac and Keychain state; a backup should require the master
password when opened on another device or after restore.

The backup destination must be outside the source vault and must be missing or
empty. The app rejects the source vault itself, destinations inside the source
vault, existing files, and non-empty directories.

After a successful backup, the macOS app shows a result confirmation with
aggregate copied counts for item records, attachments, and tombstones. The
confirmation shows only the backup destination name and can reveal that
destination in Finder; it does not display item contents, secrets, or full
record data.

## Restore

The macOS app can restore a backup by selecting a source `.pswvault` backup
directory and a new destination. Restore copies the same portable encrypted
vault structure without decrypting records and excludes `local_unlock.enc`, even
if the selected source contains one.

Restore destinations follow the same safety rules as backup destinations: the
destination must be outside the source vault and must be missing or empty. The
app rejects the source vault itself, destinations inside the source vault,
existing files, and non-empty directories.

After restore completes, the app selects the restored vault in a locked state.
Unlock it with the original master password before item metadata or secrets are
shown. Restore is encrypted file recovery, not password recovery. The restore
result confirmation shows aggregate copied counts and the restored vault
destination name, with a Reveal in Finder action for locating the restored
`.pswvault` directory.
