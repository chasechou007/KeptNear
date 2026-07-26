# Security Model

## Trust Boundary

The master password and vault key are secrets. Plaintext item fields, TOTP
secrets, passwords, secure notes, imported export contents, and generated
plaintext export files are secrets. These values must only be available while a
vault session is explicitly unlocked or after an explicit user export action.

The Rust core owns:

- master password key derivation
- vault key wrapping and unwrapping
- record encryption and authentication
- record parsing
- item merge metadata
- import conversion before encrypted persistence
- plaintext export serialization after explicit user request

The macOS client owns:

- user interaction
- local file selection
- locked and unlocked presentation
- clipboard actions
- local convenience unlock requests
- system sleep, screen sleep, and session lock handling
- explicit plaintext export confirmation and destination selection

The macOS client must call into the Rust core for vault operations instead of parsing encrypted records itself.

## Vault Switching and Closing

When the user opens or creates another vault while a vault is unlocked, the
macOS client treats that as leaving the previous vault. The client clears the
previous vault's active session state, locks the previous Rust core session
best-effort, clears managed clipboard secrets from the previous vault, stops
sync polling, and clears previous search, import, export, and sync status before
the new vault becomes active.

When the user closes the selected vault, the client performs the same active
state cleanup and clears the selected vault context. Closing a vault does not
delete the vault directory or clear the recent vault shortcut.

## Forgotten Master Password Recovery

KeptNear cannot recover, reset, or bypass a forgotten master password. The
master password is not escrowed by a KeptNear account or remote service. If
local Keychain convenience unlock is available, the user can try that normal
unlock path before replacing the vault.

From the locked-vault recovery view, revealing the selected vault in Finder or
closing it is non-destructive. Moving a forgotten vault to Trash is available
only after a separate destructive confirmation and only for the selected,
locked, existing, non-symbolic-link local `.pswvault` directory. The client uses
macOS Trash semantics and does not permanently delete the directory.

After a successful Trash move, the client clears the selected-vault context,
forgets a matching recent-vault shortcut, and attempts to remove current and
known legacy Keychain convenience-unlock material for that vault. A Keychain
cleanup failure is reported as partial cleanup rather than complete success.
Moving one local vault copy to Trash does not delete copies in sync providers,
on other devices, in backups, or already retained in Trash.

## Clipboard Handling

The macOS client routes secret copy actions through a managed clipboard helper.
Copied secrets are cleared after the configured timeout if the clipboard still
contains the copied value. When the vault locks manually, through inactivity, or
because macOS reports system sleep, screen sleep, or session lock, the client
also clears the current managed clipboard secret immediately if the clipboard
still contains that managed value.

Clipboard cleanup must not clear unrelated clipboard contents copied after the
managed secret. Cleanup is best-effort and cannot prevent another local process
from reading the pasteboard while the secret is present.

## Explicit Secret Reveal

Saved password-like fields are hidden by default in the unlocked editor. The
macOS client provides explicit reveal and hide controls for saved login
passwords, login TOTP seeds, credit-card numbers, credit-card verification
codes, and software-license keys. Revealing a value is separate from copying it:
copy still uses the managed clipboard timeout, while reveal keeps the plaintext
only in transient SwiftUI view state.

Revealed values are not written to preferences, diagnostics, vault records, sync
metadata, or release artifacts. The client clears revealed values when the
selected item changes, a new editor context starts, selected details are
reloaded by save, sync, import, or conflict resolution, or when the vault locks,
switches, or closes.

## Local Password Health Audit

Password health checks are local-only unlocked-vault operations. The Rust core
inspects decrypted saved login passwords inside the existing unlocked session
boundary, reports obvious weak-password issues with a deterministic local
heuristic, and detects reused login passwords by exact in-memory equality. The
audit does not contact breach databases, sync providers, telemetry endpoints,
or third-party scoring services.

Audit results are non-secret metadata for finding affected items: checked login
password count, weak count, reused count, affected item IDs, affected item
titles, issue kind, and reuse group size. Results must not include password
values, password hashes, password-derived prefixes, usernames, URLs, notes, TOTP
secrets, card numbers, license keys, master passwords, vault keys, or local
unlock material.

The macOS client clears password health results when the vault locks, switches,
closes, or when unlocked vault content changes through saves, imports, sync
refresh, conflict resolution, or item lifecycle actions. Copied diagnostics
remain aggregate-only and do not include password health issue rows or affected
item titles.

## Locking and View State

When the vault locks manually, through inactivity, because macOS reports system
sleep, screen sleep, or session lock, during normal app termination, or after
the last app window closes, the macOS client clears both the active Rust session
state and transient SwiftUI state that may contain secrets. This includes editor
drafts, create/unlock password fields, Settings master password rotation fields,
plaintext import/export modal state, pending editor or destructive actions,
conflict merge selections, and revealed saved-secret values. The same lock
cleanup clears any currently app-managed copied secret without clearing
unrelated clipboard content copied later. Last-window-close locking keeps the
app running and preserves the selected vault context so reopening the UI returns
to the locked-vault workflow. Unlocking is required before item details, copy
actions, reveal actions, or password rotation are available again.

## Master Password Rotation

The master password wraps the random vault key stored in `keys.enc`; it does not
directly encrypt item records. Changing the master password requires the current
master password, decrypts the existing vault key, and rewrites `keys.enc` with a
fresh Argon2id salt, nonce, and XChaCha20-Poly1305 key envelope under the new
master password. Creating a new vault or rotating to a new master password
requires non-empty password material and matching confirmation in the macOS
client; the Rust core rejects empty password material at key-envelope write
boundaries. Existing vault unlocks continue to verify against their stored key
envelope so older vaults remain accessible.

The macOS client also shows local, advisory master-password strength guidance
while a user creates a vault or enters a new master password in Settings. This
guidance is not a formal entropy proof and is advisory rather than a hard
blocking policy. The entered password, strength category, and hint are
transient UI state and are not written to diagnostics, preferences, vault
records, or sync metadata.

Item records, tombstones, and sync metadata are not rewritten during this
operation. Other devices will require the new master password after the updated
`keys.enc` syncs to them. The macOS client removes local Keychain convenience
unlock material after a successful change, so users must explicitly opt in again
if they still want local convenience unlock on that Mac.

## Local Convenience Unlock

The alpha macOS client can optionally save unlock material in the user's local
macOS Keychain using a `ThisDeviceOnly` generic password item. This material is a
random 32-byte local unlock key exported by the Rust core after a successful
master-password unlock. The local key is used only to decrypt the vault-local
`local_unlock.enc` envelope, which wraps the vault key with XChaCha20-Poly1305
and separate associated data from the master-password `keys.enc` envelope.

The client must not store the user's master password or the raw vault key for
this feature. Convenience unlock requires both the Keychain item and the
matching `local_unlock.enc` envelope; if either is missing or tampered with, the
core refuses convenience unlock and requires the master password.

If saved local unlock material is loaded from Keychain but rejected by the Rust
core, the macOS client deletes that local Keychain material and marks
convenience unlock unavailable for the selected vault. Re-enabling convenience
unlock requires a successful master-password unlock and explicit opt-in.

Users must opt in when creating or unlocking a vault, can disable the item from
the client, and must still know the master password to move the vault to another
device. This is a local usability feature, not account recovery and not portable
trust. Sync providers may see that `local_unlock.enc` exists, but it contains
only authenticated ciphertext and is not useful without the local Keychain item.

Older alpha Keychain entries that may have stored broader convenience-unlock
material are not read as local unlock material. The macOS Settings security tab
provides a selected-vault cleanup action that deletes known legacy alpha
Keychain services without deleting current local unlock material.

If the local Keychain item and vault files are both compromised, the vault can be
unlocked on that device.

## Untrusted Components

External sync providers are untrusted transports. The vault format must not rely on provider confidentiality or integrity. Providers can copy, delay, reorder, delete, or duplicate encrypted files; the core must verify records before use and surface unsafe conflicts.

Import source files may be plaintext. The application should warn users before
import and must not retain plaintext import contents after the import flow
completes.

Export destination files are intentionally plaintext. The application must warn
users before export, must not export while the vault is locked, and must not
claim exported files remain protected by the vault after they are written.

The current alpha does not automatically upload diagnostics, telemetry, logs,
vault records, or crash reports. User-copied diagnostics are the only support
payload and must follow `docs/logging-policy.md`.

The macOS Settings security tab surfaces these current trust boundaries as a
static local summary: local vault files, untrusted encrypted file-sync
transports, manual diagnostics, and experimental alpha vault-format status. The
summary is disclosure text only and must not render item content, full vault
paths, provider account state, diagnostics payload contents, or secret material.

## Explicit Non-Claims

This project cannot protect secrets from a fully compromised device, malicious keyboard input capture, or a process with sufficient privileges to inspect another process's memory. The goal is encrypted local storage, robust sync handling, and careful system integration.
