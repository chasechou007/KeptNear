# Encrypted Vault Backups

The encrypted backup workflow copies an unlocked vault to another local
directory without decrypting item records or creating a plaintext export.

Backups include the portable vault structure:

- `vault.json`
- `keys.enc`
- `recovery.enc` when offline recovery has been initialized
- `items/`
- `attachments/`
- `tombstones/`

This list is an exact allowlist. Backup does not traverse or copy any other
vault-root entry.

Backups intentionally exclude `local_unlock.enc` and all device-local
`~/.keptnear` content, including the SQLCipher database, Consumers, Access
Rules, Use Grants, Usage Profiles, approvals, audit events, machine-access
settings, runtime IPC, and reserved logs. The device root key, Consumer signing
identities, and local convenience-unlock key remain in the non-synchronizing
Keychain and are not backup inputs.

Convenience unlock material is local to the current Mac and Keychain state; a
backup requires the master password when opened on another device or after
restore. A valid portable `recovery.enc` remains useful only with its
separately stored recovery key; the plaintext recovery key is never included
in the backup.

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
vault structure, including `recovery.enc` when present, without decrypting
records and excludes `local_unlock.enc`, even if the selected source contains
one.

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

Restore does not pair a Consumer, recreate Access Rules, Use Grants, Usage
Profiles, approvals or audit history, restore machine-access settings, or
enable convenience unlock. Existing device-local state is neither read into
the backup nor modified by backup or restore.

When a restored vault contains a supported `recovery.enc`, the locked-vault
`Forgot master password?` flow can use that envelope plus a separately held,
valid recovery kit to establish a new master password without rewriting item
records. Successful recovery unlocks the vault and removes current and known
legacy Keychain convenience-unlock entries. If macOS rejects part of that
Keychain cleanup, the app reports partial success instead of claiming that all
local unlock material was removed.

Without the original master password or valid recovery authority, KeptNear
cannot decrypt the restored vault. The user can keep or reveal the encrypted
directory, close it, or explicitly move that local copy to Trash and create a
new vault. Deleting one local copy does not remove synchronized, backed-up, or
other-device copies.
