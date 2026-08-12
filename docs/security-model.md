# Security Model

This document describes the implemented pre-alpha boundary unless a section is
explicitly marked as planned. The approved first-version Broker, MCP, CLI, and
complete offline-recovery direction is specified in
`docs/product-requirements.md` and `docs/architecture.md`. Offline-recovery
cryptographic, kit rendering, explicit save or print, confirmation, and
two-phase rotation workflows exist. The locked-vault recovery UI can set a new
master password from a valid user-held kit and then revoke current and known
legacy Keychain convenience-unlock material.

## Trust Boundary

The master password and vault key are secrets. Plaintext item fields, TOTP
secrets, passwords, secure notes, imported export contents, and generated
plaintext export files are secrets. These values must only be available while a
vault session is explicitly unlocked or after an explicit user export action.

The Rust core owns:

- master password key derivation
- vault key wrapping and unwrapping
- strict recovery-key and recovery-envelope parsing
- recovery wrapping, two-phase rotation, and master-password envelope replacement
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
- explicit recovery-kit PDF destination selection and system printing
- recovery-kit confirmation without automatic clipboard use
- locked-vault recovery presentation and post-recovery Keychain cleanup
- system sleep, screen sleep, and session lock handling
- explicit plaintext export confirmation and destination selection

The macOS client must call into the Rust core for vault operations instead of parsing encrypted records itself.

The version-one master-password envelope accepts only the documented Argon2id
version 19 parameters: 65,536 KiB memory, three iterations, one lane, a
16-byte salt, a 24-byte XChaCha20-Poly1305 nonce, and a 48-byte wrapped-key
ciphertext. These values use canonical lowercase hexadecimal encoding.
Untrusted `keys.enc` content cannot increase KDF memory, CPU, or parallelism.

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

The master password is not escrowed by a KeptNear account or remote service.
If local Keychain convenience unlock is available, the normal unlock action
remains visible outside the recovery view so the user can try it first.

When the selected locked vault has a supported `recovery.enc`, the macOS App
offers recovery-code entry plus a new master password and confirmation before
showing replacement options. Successful recovery returns a normal unlocked
session, removes current and known legacy Keychain convenience-unlock material,
and requires the user to opt in again if convenience unlock is still desired.
If Keychain deletion fails after the master-password envelope has already been
replaced, the App reports explicit partial success and continues to show the
remaining convenience-unlock availability instead of claiming revocation.

The Rust core now supports an optional portable `recovery.enc` that
independently wraps the same random vault key, strict `knr` Bech32m recovery-key
parsing, first-time no-overwrite initialization, and locked-vault recovery that
atomically replaces only `keys.enc` under a non-empty new master password.
Wrong, malformed, tampered, missing, oversized, or cross-vault material leaves
the existing master-password envelope unchanged. Item records and tombstones
are not re-encrypted.

An unlocked vault can now create a recovery kit through the FFI and macOS App.
The kit contains the canonical and grouped recovery code, QR payload, vault ID,
recovery-key ID, generation time, and an authority warning. It contains no
vault path or item metadata. The user must explicitly choose a PDF destination
or the macOS print flow before the in-App source is hidden and the complete
saved code can be confirmed. KeptNear never automatically copies recovery
material to the clipboard or stores a plaintext copy in `.pswvault` or
`~/.keptnear`.

Unlocked-vault rotation creates a non-serializable candidate without modifying
the current envelope. Confirmed commit revalidates the candidate against the
session vault key, locks the stable metadata file, rejects a candidate if the
current recovery-key generation changed, and atomically replaces only
`recovery.enc`. Recovery workflow handles are bound to their unlocked session;
cancel, lock, or interruption drops pending authority. Failed or cancelled
rotation preserves the old envelope, while a successful commit makes the prior
key fail.

Confirmation is deliberately not stored as a durable custody assertion.
After restart, the App can report that `recovery.enc` exists but warns that it
cannot verify the user still holds the corresponding kit. If first-time setup
is deferred before saving, the installed envelope remains but its in-memory
authority is discarded; the user must rotate the recovery key to obtain a new
kit.

Malformed, wrong, or cross-vault recovery material leaves the selected vault
locked and preserves its existing Keychain material. If no supported recovery
envelope is present, or the user no longer holds its authority, the same view
states that KeptNear cannot recover the vault and retains replacement as a
secondary fallback.

Revealing the selected vault in Finder or closing it is non-destructive. Moving
a forgotten vault to Trash is available only after a separate destructive
confirmation and only for the selected, locked, existing, non-symbolic-link
local `.pswvault` directory. The client uses macOS Trash semantics and does not
permanently delete the directory.

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

Current-format sync refresh can write a two-parent merge revision only after
authenticated ancestry proves one unique known base and component-level changes
are independent. Secret Fields are indivisible by stable field ID, and all text
fields are one component because they do not have stable IDs. Concurrent edits
to the same Secret Field, concurrent text changes, field-shape changes,
delete-edit or lifecycle differences, rejected records, missing or ambiguous
ancestry, and more than two logical heads fail closed to preserved conflict
candidates. Filesystem timestamps and last-writer-wins order are never trusted.
Refresh does not rewrite, move, or delete either unsafe authenticated head; a
delete-edit conflict continues to retain records in both the item and tombstone
directories. Manual resolution appends a descendant and preserves the source
history.

Current-format conflict comparison is an unlocked human-control-plane
projection over authenticated logical heads. It supports open typed Credentials
and deletion revisions without converting them through the legacy item enum.
Text values may be shown after unlock. Secret Fields expose only role, optional
label, immutable field ID, authenticated kind, value presence, and a Boolean
complete-field change result; no secret bytes cross the Core summary, FFI, or
Swift conflict model. Whole-version resolution validates that the selected
Revision ID is still a current head, revokes local authorization for fields not
retained by the chosen active version, and appends a descendant naming all
heads. Selecting a deleted head revokes all candidate field authorization and
keeps the deleted lifecycle. Explicit non-secret field merge remains available
only for losslessly mapped built-in candidates.

Random revision IDs do not prevent convergence: independently authored
multi-parent merge revisions are equivalent logical heads only when complete
credential content, lifecycle, and exact parent IDs match. Ordinary
single-parent concurrent edits remain distinct. Device ID is deliberately
excluded from merge equivalence because it records authorship, while any
content or parent difference remains visible as conflict.

Import source files may be plaintext. The application should warn users before
import and must not retain plaintext import contents after the import flow
completes.

Portable vault control files are limited to 64 KiB, encrypted record files to
16 MiB, and plaintext import files to 64 MiB before parsing. Core vault,
migration, refresh, quarantine, and import readers require regular files and
reject symbolic links; Unix readers use `O_NOFOLLOW` to close the
check-to-open link substitution path. Vault roots and required portable entries
must likewise be regular directories or files of the expected kind.

Import preview does not write imported records or stable identities. A
current-format commit converts supported records directly into typed fields and
allocates fresh local Credential and Secret Field IDs; provider IDs and an
earlier duplicate's authorization state are not reused. Duplicate matching is
limited to normalized non-secret semantics and reads custom typed credentials
without converting them to the frozen v1 model.

Export destination files are intentionally plaintext. The application warns
users before export, refuses export while the vault is locked, and requires the
current master password in the interactive confirmation. Core reopens the key
envelope and verifies the resulting Vault Key against the active session before
snapshot construction or destination writing. Missing or incorrect
reauthentication creates no destination file, and a direct FFI caller cannot
export using only a session ID. The application does not claim exported files
remain protected by the vault after they are written. The App clears its
transient password binding immediately after the request and does not persist
or log it, but Swift and JSON bridge string copies do not provide deterministic
memory zeroization.
On Unix, Core rejects a symbolic-link or non-regular destination, opens the
selected path with `O_NOFOLLOW`, changes the file to owner-only mode `0600`
before writing secret bytes, syncs it, and clears the serialized Rust plaintext
buffer on drop. These controls do not turn the export back into encrypted vault
data.
The default KeptNear JSON format encodes arbitrary Secret Field bytes as
Base64, which is reversible and must be treated exactly like plaintext.
Exported source Vault, Credential, and Secret Field IDs are provenance only and
do not transfer Consumers, Access Rules, Use Grants, Usage Profiles, approvals,
audit history, machine-access settings, or authorization.
Authenticated conflicts and rejected encrypted records are omitted with
structured reasons rather than guessed or silently ignored. A lossy
compatibility serializer skips an entire credential if any template or field
cannot be represented, preventing partial secret-bearing exports.

Encrypted backup copies only `vault.json`, `keys.enc`, optional
`recovery.enc`, `items/`, `attachments/`, and `tombstones/`. It excludes
`local_unlock.enc`, all `~/.keptnear` state, the Keychain device root, Consumer
signing identities, and local convenience-unlock keys. Plaintext export uses a
closed credential-only schema with the same device-trust exclusion. Backup,
restore, and export do not mutate device-local trust, and restore or import
cannot pair Consumers, recreate machine authorization, transfer audit history,
or enable convenience unlock.

The current alpha does not automatically upload diagnostics, telemetry, logs,
vault records, or crash reports. User-copied diagnostics are the only support
payload and must follow `docs/logging-policy.md`.

The implemented encrypted machine-access audit is not a support log. It remains
in device-local SQLCipher state, is not included in the copied diagnostics
report, and is not written into or synchronized with `.pswvault`.

`~/.keptnear/logs` is an owner-only reserved Broker directory. The current App
and Broker have no persistent general-purpose log writer. The current alpha
also uses manual updates, bundles Usage Profile templates offline, and has no
background updater or template downloader.

The macOS Settings security tab surfaces these current trust boundaries as a
static local summary: local vault files, untrusted encrypted file-sync
transports, manual diagnostics, and experimental alpha vault-format status. The
summary is disclosure text only and must not render item content, full vault
paths, provider account state, diagnostics payload contents, or secret material.

## Network And Operation Boundary

KeptNear performs local file I/O against a selected `.pswvault`. An external
file provider may transport the encrypted directory, but KeptNear does not
operate that sync service or send it plaintext. Opening a selected website is
an explicit handoff to the default browser, whose request is outside the
KeptNear process.

The owner-only Broker Unix socket is local IPC, not an Internet, LAN, or
ordinary localhost TCP endpoint. The current alpha does not contact an update,
telemetry, crash, support, or template server.

Only `http.request` and `process.run` can enter the implemented outbound
attribution boundary. The Broker records admission before it returns an opaque
authorization. Both internal executors exist and are reachable through the
credential-capability protocol, MCP tools, and source-level CLI; the App
invocation path does not yet exist. "Explicit" means an
authenticated Consumer requested a named capability and the configured rule
and grant admitted it; a persistent user-approved policy need not prompt for
every operation.

An approved HTTP service or child process receives the placed credential. The
child and any surviving descendant can retain or transmit
compatibility-delivered material. Local revocation prevents future delivery but
cannot recall either copy.

## Explicit Non-Claims

This project cannot protect secrets from a fully compromised device, malicious
keyboard input capture, clipboard or screen capture, or a process with
sufficient privileges to inspect another process's memory. It cannot control a
malicious authorized Consumer, child process, external service, sync provider,
or user-shared diagnostics after data crosses the corresponding boundary.

An audit event proves a local authorization decision, not Consumer intent,
remote endpoint integrity, execution safety, or upstream credential revocation.
The goal is encrypted local storage, robust sync handling, and careful system
integration; local-first is not a complete security guarantee.

## Machine Credential Boundary

The first-version design adds a trusted local Broker between the vault and
machine Consumers. Consumer pairing grants identity only; field-scoped Access
Rules and bounded Use Grants remain separate. Persistent authorization never
bypasses vault unlock, and vault lock invalidates active grants.

The local MCP adapter delegates pairing, connection authentication, and six
credential-capability tools to the Broker. It advertises those tools only after
authentication; pending pairing and Broker-unavailable initialization expose
no tools. The MCP tools and public CLI contract use the same Broker capabilities
and do not return raw secret fields through tool results, standard output,
diagnostics, logs, or audit. There is no `secret.get` or complete plaintext
export capability. Because the Broker capability enum is closed to
`credential.search`, `access.request`, `grant.status`, `grant.revoke`,
`http.request`, and `process.run`, Consumers, Access Rules, and Use Grants
cannot express such an export.

The `keptnear` CLI validates canonical typed identities, rejects duplicate and
unknown options, keeps HTTP body bytes out of process arguments, requires an
explicit direct-child separator, and redacts private input classes from Debug
and parse failures. The closed parser rejects get, reveal, copy, print, dump,
plaintext-backup, and Vault-export aliases plus raw-output options attached to
valid commands before identity or Broker access. It uses the shared
first-party client to negotiate, pair, authenticate, and dispatch over the
owner-only Broker socket. Status does not access the Consumer Keychain. Other
commands use an independent device-only CLI signing seed and never parse a
Vault, decrypt records, receive the Broker device root, or accept a
caller-selected Consumer identity. Success and failure output uses a
versioned JSON envelope; HTTP bodies and child streams are base64-framed rather
than emitted as unframed terminal bytes. `keptnear run` accepts no credential
value or placeholder: the Broker resolves and places the approved field from
the typed target and Usage Profile. Known command interpreters and environment
launchers are rejected; metacharacters in another child's argument list remain
literal and are not expanded by KeptNear. Its help states the compatibility
trust boundary, and each completed result includes only fixed booleans for
child retention, future-delivery-only revocation, and upstream rotation.
Base64 remains reversible encoding, and transformed child output may still be
sensitive. Raw UTF-8 argument copies and temporary parsed options are zeroized
after parsing, and the CLI-owned HTTP URL is zeroized on drop.

The public CLI guide separates human terminal use, Agent subprocess use, and
native MCP host use while preserving the same Broker boundary. Its command
examples contain synthetic stable IDs and non-secret context only. They direct
the caller to `access request`, `http request`, or `run`, never to retrieve a
selected field into output, shell state, Agent context, or persistent
configuration. Agents cannot approve their own pairing or access request, and
documentation is not an Agent-policy enforcement mechanism. The enforceable
scope remains the paired Consumer, exact Access Rule, Use Grant, Usage Profile,
global pause, and named Broker capability. `script/verify_cli_usage_docs.sh`
checks this contract as part of the repository suite.

The public `keptnear vault doctor [--json] <vault-path>` action is separate
from the seven Broker-connected machine command families. It accepts no
pairing profile, loads no Consumer Keychain identity, and contacts no Broker or
sync provider. It reuses the legacy `psw doctor` read-only inspection, does not
unlock or decrypt item records, and omits the supplied full path. Its bounded
report contains only required structure, public Vault format metadata,
aggregate encrypted-record counts, and local unlock-envelope presence.

The MCP stdio parser rejects duplicate JSON object keys at every depth before
dispatch and bounds each newline-delimited message to one MiB. Both frozen
protocol revisions expose the same closed tool schemas; standard `_meta`
objects are ignored as protocol metadata rather than merged into credential
arguments. A cancellation notification produces no response and its optional
reason is discarded. The current synchronous adapter cannot preempt a request
after it enters the Broker, so bounded approval-wait, process-run, and internal
HTTP timeouts remain the resource-exhaustion boundary. Broker-internal
cooperative process cancellation is not represented as MCP cancellation.

Local host setup is a provider-neutral command-plus-arguments contract.
Codex-, Claude Code-, and generic-host examples select different non-secret
pairing profiles but use the same adapter and Broker authorization model. No
credential is placed in host configuration, environment variables, or adapter
arguments. Removing a host entry does not revoke its Consumer or delete its
device-local Keychain signing key; revocation remains an explicit Apps & Tools
control, and automatic cleanup of every profile key is not implemented yet.

Brokered HTTP use keeps placement internal. Explicit child-process
compatibility delivery is weaker because the child can retain the secret;
revocation then prevents only future delivery, and complete invalidation
requires upstream credential rotation.

The absence of a first-party raw-output operation is not a claim that an
authorized remote service or child process cannot transform a credential and
return or transmit a derivative. Exact redaction is not general data-loss
prevention. Authorization and compatibility disclosures remain the boundary
for those external recipients.

Broker capability request JSON contains no caller-selected `consumer_id`.
After exact version negotiation, the dispatcher requires the connection's
Ed25519-authenticated Consumer and injects that identity into every
authorization target. Requests for an unnegotiated capability fail as
`unsupported-capability`; negotiated capability requests on an
unauthenticated connection fail as `authentication-failed`. Request and
response types use redacted `Debug` implementations and zeroize owned private
operation material where the protocol boundary controls the allocation.
Base64 fields carry binary request or process data through JSON; base64 is an
encoding, not an additional encryption layer.

The implemented Broker transport accepts current-device local IPC only. It
provides no public, LAN, or ordinary localhost TCP control interface. The alpha
DMG bundles the Broker executable but does not yet install or activate it as a
long-running service. Consumer identity, rules, grants, Usage Profiles,
approvals, and encrypted audit remain device-local under `~/.keptnear` and do
not sync in `.pswvault`.

The implemented `psw-broker` foundation resolves the current user's home from
the operating-system account database rather than an inherited `HOME`
environment variable. It idempotently creates `.keptnear`, `config`, `state`,
`runtime`, and `logs` with mode `0700`. Startup fails before opening device
state if the home is group/world writable, a managed path is a symlink or
non-directory, ownership differs from the effective user, or an existing
managed directory has broader permissions. Its errors identify only the
logical entry and sanitized I/O category, not the full path.

The device-key slice generates one random 256-bit root as an opaque,
non-cloneable, zeroizing Rust value. Its manager exposes separate
initialize-new and load-existing paths, rejects duplicate creation, rejects
non-32-byte stored data, and verifies a newly created item by reading it back.
There is deliberately no load-or-create path. Missing material therefore
fails closed instead of creating a replacement key over existing encrypted
state.

On macOS the adapter performs an atomic generic-password `SecItemAdd` into the
Data Protection Keychain with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
`kSecUseDataProtectionKeychain` enabled, and
`kSecAttrSynchronizable` disabled. The stable item identity contains no local
path, and root-key bytes are never formatted into errors or debug output.
There is no plaintext file fallback under `~/.keptnear` or elsewhere.

The MCP adapter owns one 32-byte Ed25519 seed per selected pairing profile,
used only for that profile's Consumer identity. On macOS it stores each seed
under the stable `app.keptnear.mcp.consumer-key.v1` generic-password service
and a profile-specific account in the Data Protection Keychain with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, synchronization disabled,
and no file fallback. The no-argument default retains the original
`default-v1` account; named profiles use `profile-v1:<canonical-id>`. Seeds are
zeroizing in adapter memory and are never stored in Broker SQLCipher state; the
Broker stores only their public keys.

The CLI uses the same shared identity implementation but a distinct stable
`app.keptnear.cli.consumer-key.v1` service. It preserves `default-v1` for its
default account and `profile-v1:<canonical-id>` for named accounts. A
same-named MCP and CLI profile therefore has a separate signing key and
Consumer permission set. Neither profile label enters Broker protocol or
authorization state.

The separate human-controller authority is frozen as source contract
`keptnear.controller-authority.v1`. It uses one 32-byte Ed25519 seed under the
stable `app.keptnear.human-controller-key.v1` / `primary-v1` Data Protection
Keychain identity. An activation-qualified build must place that item in the
exact `<signing-prefix>.app.keptnear.human-controller` access group declared
only by the signed App and packaged Broker, name the group in every Keychain
query, disable synchronization, and use
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Bootstrap and ordinary
authentication have separate fixed-order, length-prefixed domains, 30-second
single-use challenges, and bounded failure windows. Disable, update, and
reinstall preserve complete authority; v1 supports rotation only through a
confirmed device-access clear followed by a later explicit enable. A
`removal-pending-v1` item in the same restricted access group is created before
either authority side is removed and deleted last, so an interrupted clear
cannot be mistaken for resumable bootstrap. The runtime Keychain adapter,
Broker controller record, challenge manager, and strict wire boundary are
implemented in source, but the App human-control client and service activation
are not, so this contract does not activate machine access. See
`docs/controller-authority-contract.md`.

Pairing protocol messages carry a fresh client nonce, Broker nonce, comparison
code, and strict Ed25519 proof. Repeating pairing start with the same public key
resumes the exact pending request rather than creating another identity. After
pairing, a separate 30-second challenge binds the negotiated protocol,
connection session, immutable Consumer ID, public key, and fresh Broker nonce.
The challenge is consumed on completion, revoked or changed Consumers fail
closed, failures are bounded per Consumer and globally, and only stable
identity plus allow or deny state enters audit. Successful connection
authentication grants no credential scope.

The next implemented slice derives a 32-byte SQLCipher key with HKDF-SHA-256
and the domain `KeptNear device state SQLCipher v1`. It encodes that value for
SQLCipher raw-key semantics and supplies it directly through
`sqlite3_key_v2`; the temporary derived and encoded buffers are zeroized.
`device-v1.db` uses an encrypted header, SQLCipher page HMACs, WAL mode,
full synchronous writes, secure delete, foreign keys, memory sanitization,
disabled SQLCipher diagnostic logging, and schema version 2. Version 2 adds
only the controller authority contract, algorithm, derived public identity,
public key, and creation timestamp; it never stores the controller seed.

Initialization pre-creates the database with mode `0600`, refuses existing
database or sidecar entries, keys the empty connection before its first schema
read, and creates the complete schema in one exclusive transaction. Opening
existing state refuses symlinks, wrong types, wrong owners, non-`0600` modes,
truncated files, plaintext SQLite headers, failed key authentication, failed
page integrity, missing schema tables, and unsupported schema versions.
Database, WAL, and shared-memory errors identify only logical entries and
sanitized categories, never SQL or full paths.

The typed schema can persist Consumers and public pairing keys, bounded
path-free OS evidence, field-scoped rules, session-bound grants, declarative
profiles, secret-free approvals, pause settings, and stable-identity audit
events. It has no arbitrary payload or columns for vault keys, master
passwords, recovery keys, Consumer private keys, raw credential fields,
request or response bodies, URLs, commands, standard streams, or full paths.
SQLCipher page authentication protects these records at rest.

Audit insertion, retention-setting changes, and startup pruning enforce the
same bounded policy. Retention defaults to 90 days, accepts 1 through 3650
days, and has an independent ceiling of 10,000 newest events. Insert/update,
age pruning, count pruning, and commit share one immediate SQLCipher
transaction. Broker startup advances a persisted monotonic retention watermark
before exposing the runtime, so an idle database or backward wall-clock change
cannot extend earlier retention. Authorization behavior remains a separate
boundary from retention.

Only the trusted local runtime exposes audit view, clear, and export
operations. Views use at most 500 newest-first records with an immutable
timestamp-and-event-ID cursor. Filters accept only typed enums and stable IDs;
they have no free-text predicate. Clearing requires an explicit-confirmation
marker and removes only the selected encrypted rows in one transaction.
Versioned troubleshooting JSON is assembled from a fixed projection of the
allowed audit columns and never includes Consumer labels, credential titles,
paths, or operation payloads. These operations do not modify `.pswvault`.

Privacy regression coverage places unique markers in a real encrypted
credential title, URL, and secret, and in Consumer metadata representing
request bodies, command arguments, standard output, standard error, and API
response bodies. Audit page/debug/export output is scanned for every marker.
The observed-identity model rejects full executable paths before persistence,
and the output is also checked against the real full Vault path. Separately,
the macOS diagnostics snapshot exposes a fixed support-field set and maps Core
availability to a closed `connected` or `unavailable` value instead of
forwarding arbitrary Core status text. These checks cover current audit and
App diagnostics; adapter-wide output scans remain a later gate.

Explicit outbound credential use has a fail-closed audit gate. Only
`http.request` and `process.run` can produce an opaque operation
authorization. A pending event is committed before the authorization is
returned; finalization consumes it and writes one allowed or failed outcome
with the exact Consumer, field, capability version, and Use Grant. Paused and
denied attempts are also attributable, while metadata and management
capabilities are rejected before Grant consumption.

The operation authorization has no destination or payload fields and the
attribution module itself has no network client. It cannot represent URLs,
request or response bodies, arguments, executable or Vault paths, standard
streams, telemetry endpoints, template URLs, or background network tasks. Both
internal executors consume this same opaque authorization.

The HTTP executor requires an exact Consumer-owned, capability-matching Usage
Profile and an exact current vault session, Credential ID, Secret Field ID, and
field kind. It accepts bounded HTTPS requests only, rejects URL credentials,
fragments, caller-controlled framing headers, and placement-header overrides,
and follows no redirects or environment proxy configuration. Transport logging
is disabled at compile time. The response omits headers and reason text, bounds
the body, and replaces exact secret echoes. This does not protect a secret after
the approved remote service receives it, nor can exact matching detect a
transformed or encoded response derivative.

The internal `process.run` executor resolves the same exact Consumer-owned
Profile and active Secret Field before direct OS process spawn. It accepts only
bounded absolute dot-segment-free executable and working-directory paths, rejects
common shell launchers and `/usr/bin/env`, clears inherited environment state,
adds only explicit non-secret context, connects no terminal or PTY, and pipes
both outputs. The Profile selects a child-only environment variable,
secret-only stdin, or an anonymous pipe remapped to descriptor 3. The Broker
creates no plaintext file and rejects exact secret duplication in process
inputs.

Output reads and secret writes are non-blocking and bounded. Exact secret
occurrences are replaced across read chunks before at most 1 MiB per stream is
returned. Timeout and cancellation close the writer, kill the direct child,
and wait for it to be reaped; controlled secret and capture buffers are
zeroized. A CLI connection owns a non-consuming peer-closure probe.
Native terminal interruption closes that connection and activates the same
cancellation path without consuming queued protocol bytes. The CLI propagates
valid numeric direct-child statuses after writing one structured result;
signal or invalid status states map to fixed failure. This does not constrain
an authorized child, kill independent descendants, detect encoded or
split-stream derivatives, or recall a delivered value.
Complete invalidation after delivery requires upstream rotation.

The macOS human control plane repeats this boundary at process Usage Profile
setup, one-time and persistent process authorization, saved process profiles,
field revocation, and Consumer unpairing. English, Simplified Chinese, and
Japanese text states that children and descendants may retain or transmit the
credential, local revocation stops future delivery only, and the credential
must be rotated with its provider to invalidate delivered copies. The CLI now
preserves the same meaning in local help and in the fixed
`compatibilityDelivery` result object without rendering the selected field.

The reviewed Rust 1.93 dependency set uses `rusqlite 0.39.0` and
`libsqlite3-sys 0.37.0`, embedding SQLCipher 4.10.0. The source-bound release
receipt covers the complete first-party Rust tree and the exact encrypted-state
regression set, including wrong keys, ciphertext tampering, missing state, and
unsafe permissions. The SQLCipher BSD notice is retained in
`THIRD_PARTY_NOTICES.md`.

The transport-independent Broker process core now reads and writes bounded
four-byte big-endian frames, performs strict duplicate-key-free JSON parsing,
negotiates protocol and capability versions through `hello`, and dispatches
only typed messages. A declared frame over 16 MiB is rejected before payload
allocation. Invalid UTF-8, duplicate keys, unknown messages or capabilities,
ambiguous version advertisements, non-canonical request IDs, and
post-negotiation version changes fail closed.

Protocol errors contain only a stable code, retryability, an optional required
action, and an optional approval ID. The dispatcher never serializes request
payloads, parser text, exceptions, stack traces, SQL errors, secrets, titles,
URLs, bodies, arguments, streams, or paths. The process loop remains
transport-independent and serves only a byte stream supplied by the local
transport.

The implemented macOS transport binds only
`~/.keptnear/runtime/broker-v1.sock`. It requires the runtime directory to be
owned by the current effective user with exact mode `0700`, creates the socket
with exact mode `0600`, and rejects symbolic links, unexpected types, owners,
or permissions. It refuses an active existing listener. A stale socket is
removed only after validation, a failed connection probe, and an unchanged
device-and-inode check; shutdown likewise preserves replacement entries.
Accepted and connected peers are checked with `getpeereid` and a different
effective user is rejected before dispatch. Errors retain only logical entry,
operation, and OS error category, never the socket path.

The process-owned vault-session manager accepts only current-format vaults with
a stable `vault_id`. Canonical paths and unlocked core objects remain private;
snapshots expose only the vault ID, lock state, and a fresh random session ID
created after each successful unlock. Reusing one identity at another path or
replacing a tracked path with a different identity fails closed. Unlock accepts
only a master password or device-local convenience material and delegates
validation to `psw-core`; an Access Rule is never unlock material.

The macOS FFI does not treat an existing `vault_id` snapshot as proof that the
currently selected path is the tracked Vault. After human unlock it asks the
Broker to canonicalize and reopen that path with the authenticated ID as an
expected value. Duplicate-copy and changed-identity failures lock any older
machine session and make its grants unusable. They do not undo the separate
human unlock. The App receives one Boolean conflict flag and disables its Apps
& Tools inventory; Consumer protocol errors remain the generic
`operation-failed` projection. No path is placed in the flag, protocol error,
diagnostics, or audit.

A dedicated worker measures inactivity with monotonic time and locks expired
sessions without depending on incoming requests. Only accepted human or
credential operations may refresh activity. Manual lock, close, timeout, and
shutdown drop the unlocked core object and identify the ended session. Lock,
close, and shutdown supersede concurrent unlock attempts; shutdown waits until
their unpublished results have been discarded. All ended-session events enter
a bounded queue and remain pending until their SQLCipher grant-deletion
transaction commits. A failed transaction leaves the checkpoint available for
retry, events arriving during a commit are not acknowledged with the older
checkpoint, and overflow deletes all Use Grants.

Grant deletion matches both the stable vault and random unlock-session
identity. Consumer removal transactionally cascades persistent rules, sourced
and Allow Once grants, profiles, and approvals. Deleting a secret field removes
that exact field's rules, grants, and approvals without erasing non-secret
audit history or unrelated fields. Device-data reset preparation shuts down
sessions before deleting every grant; the later destructive reset workflow
must not proceed if preparation fails. Failure to start the worker prevents
process construction rather than silently disabling auto-lock.

User revocation is a separate typed boundary. Revoking one Consumer-field pair
deletes all capabilities for only that pair and preserves other Consumers,
fields, and Usage Profiles. Consumer-wide revocation deletes the pairing
identity and all dependent authorization. Global revocation deletes all
Consumers and machine authorization. Durable deletion uses one immediate
SQLCipher transaction; process-local approval contexts and pairing handshakes
are reconciled afterward, and approval waiters are awakened.

All scopes are idempotent and retain non-secret audit history, device settings,
the device root, portable Vaults, and human unlock sessions. A transaction
racing with grant consumption leaves no future authorization, although an
operation that crossed authorization first may complete. For compatibility
delivery, revocation cannot erase a secret already observed by a child
process; upstream rotation is required for full invalidation.

The global Apps & Tools gate is loaded from authenticated encrypted device
state and is checked before any new machine capability reaches authorization or
grant consumption. Pause and resume serialize the SQLCipher write and
process-local state change under one mutex. A failed write leaves the prior
state active; unreadable persisted state fails startup rather than defaulting
to resumed. Paused requests receive only the stable `broker-paused` code.

Pause is intentionally not revocation and not vault lock. Existing rules,
grants, approvals, and unlocked human sessions remain intact, one-use grants
are not consumed by denied requests, and resume does not recreate
authorization. A machine operation that passed the gate before pause began may
complete; every operation beginning after the persisted transition is denied.
Human control-plane actions, including resume, do not pass through the machine
gate.

`BrokerRuntime` now assembles these foundations behind one fail-closed startup
boundary. It prepares current-user paths, loads the existing Keychain root,
authenticates SQLCipher, restores the pause gate, removes all Use Grants left
by the previous process, and only then creates a fresh process core. A listener
is not part of this constructor and cannot be exposed through a returned
runtime when any earlier step fails.

Every restart has a new random process identity and an empty vault-session set.
Persistent Consumers, Access Rules, Usage Profiles, approvals, audit, and
pause state survive. Since no process-owned `vault_session_id` survives,
startup transactionally deletes every prior Use Grant. Graceful shutdown ends
sessions and performs the same all-grant invalidation; after an abrupt exit,
the next startup performs the cleanup before serving work.

Cross-module tests use a real temporary current-format vault and encrypted
SQLCipher state to verify restart and shutdown behavior. Corrupt ciphertext,
missing or wrong device keys, insecure database permissions, and a missing
database all block runtime creation without replacement initialization and
without path or secret text in errors. The credential-store test double avoids
destructive access to the user's live Keychain.

The runtime now also owns an in-memory Consumer pairing manager. A proposal
must contain a structurally valid Ed25519 public key, a nonzero 32-byte client
nonce, and the already selected Broker protocol version. The Broker adds a
random 128-bit request ID and 32-byte nonce, bounds each request to five
minutes of monotonic time, limits the process to 64 pending requests, and
rejects a second pending or already-persisted cryptographic identity.

Local approval and key possession are independent gates. Approval validates
the user-selected label and allocates the immutable random `consumer_id`, but
does not write a Consumer or grant any metadata or credential access. The
Consumer signs a domain-separated, fixed-order, length-prefixed binary
transcript containing protocol version, request ID, Consumer ID, public key,
and both nonces. Strict Ed25519 verification is required before the Consumer
is inserted. An invalid proof consumes the request, a valid proof cannot be
replayed, and a transient encrypted-state write failure leaves the approved
request retryable without granting access. Public keys are atomically unique
in repository writes, so shared pairing material maps to one Consumer.

Pending pairing requests, nonces, transcripts, proof bytes, and user labels
are not durable pairing records and are redacted from debug output. Restart
and graceful shutdown cancel pending requests, while completed Consumers
remain encrypted in device state. The Broker stores only the public key; the
Consumer private key remains outside this crate. Protocol pairing, local
approval presentation, the MCP Consumer's device-only Keychain storage,
connection authentication, and Consumer-scoped capability dispatch are
implemented. MCP profile selection now maps the unchanged no-argument default
to the legacy `default-v1` Keychain account and each bounded canonical named
profile to a distinct account under the same service. Each account holds an
independent signing seed, so the resulting public keys and Broker Consumers
cannot inherit authorization from one another. Profile IDs are non-secret
local configuration, never enter Broker request bodies, and never replace
cryptographic Consumer identity. Installed-service packaging remains a later
task.

The public runtime pairing API has no authorization parameters and the raw
pairing manager plus Consumer insertion are not exported across the crate
boundary. Completing a pairing has one explicit authorization effect:
unchanged. It does not create, copy, remove, or update an Access Rule or Use
Grant and does not enable a credential capability in the dispatcher. Pairing
and unlock approval subjects return no credential access target; only the
separate access-approval variant can identify one.

User labels and OS evidence are deliberately excluded from authorization
matching. Regression coverage seeds a Consumer with a metadata-search rule and
grant, then pairs another key using the same label and observed process
evidence. The new Consumer receives no rule or grant, while the original
authorization remains unchanged. Reuse of the same pairing key still maps to
the same Consumer and therefore the same existing permission set; that is
cryptographic identity reuse, not authorization created by pairing.

Access Rule creation is a separate human control-plane operation that requires
an explicit approval object and an existing paired Consumer. It persists one
exact Consumer, vault, credential, Secret Field, capability name, and
capability version target together with confirmation policy and lifetime. The
Secret Field kind is derived from authenticated Vault content and checked for
capability compatibility at trusted approval and operation boundaries; it is
not a Consumer-selected or separately persisted authorization identity. The
rule accepts no command, repository, host, URL, task, prompt, or Agent-policy
scope. An identical active rule is idempotent, while a different active policy
or lifetime for the same target fails closed instead of silently replacing
authorization.

The rule manager rejects non-field-scoped capabilities, unknown capability
versions, and capability/Secret Field combinations outside the shared
compatibility matrix. The Secret Field kind supplied to evaluation is a
trusted Broker input that must be derived from authenticated vault content;
Consumers cannot select a more permissive kind. Persistent rules survive until
explicit revocation. Bounded rules are inactive before creation and at the
exact expiry instant. An expired rule may be removed and recreated only from a
fresh explicit approval, and a failed replacement leaves no active rule.

Every machine-side rule evaluation passes the global Apps & Tools pause gate
before inspecting the Consumer or rule. A successful exact match returns only
the stored policy and lifetime. It discloses no credential metadata or secret,
does not unlock a vault, and never creates or consumes a Use Grant. Rule
configuration can remain available to the local human while machine access is
paused, preserving the distinction between the human control plane and
Consumer operations.

Use Grant mutation is now reachable only through `BrokerRuntime`; raw
insertion, removal, and consumption are crate-internal. `Allow Once` creates a
source-less one-operation grant without creating a rule. An `every-use` rule
requires a fresh local confirmation and also produces a one-operation grant.
A `once-per-unlock-session` confirmation and an
`automatic-while-unlocked` rule produce rule-sourced unlock-session grants;
only the automatic policy can issue without a new human confirmation.

Each grant is bound to the exact Consumer, vault, credential, Secret Field,
capability name and version, and random current `vault_session_id`. A
rule-sourced grant is also bound by foreign key to its exact rule, and its
absolute expiry is capped at the rule expiry. Grant activity uses an inclusive
creation and exclusive expiry boundary. A grant from an old unlock session
cannot authorize a new session even if its encrypted row has not yet been
removed by the retryable lock-event coordinator.

One-operation use performs an exact checked delete and authorizes only when
that delete removes the row. Two concurrent SQLCipher connections therefore
cannot consume the same grant successfully. A wrong Consumer, field,
capability version, or session returns denial without consuming the grant or
revealing which dimension differed. An exact expired grant is removed and
returns the stable expired result. Unlock-session grants remain reusable only
within their exact active session and time boundary.

The protocol's `grant.status` and `grant.revoke` handlers scope lookup and
deletion to the authenticated connection Consumer. A grant owned by another
Consumer, an unknown identity, and an already removed grant all produce the
same unavailable or `revoked: false` projection. Only an owned active grant
returns its fixed non-secret scope metadata, and observing an owned expired
grant removes it before reporting `expired`.

Automatic issuance and grant use check the global pause gate before session,
rule, or grant state. A paused request neither issues an automatic grant nor
consumes an existing one. Explicit local Allow Once and rule-confirmation
actions may persist a grant while paused, but it remains unusable until resume.
The runtime validates the process-owned session before and after issuance or
use, closing lock and session-rotation races by failing closed. These
operations expose no secret or credential metadata by themselves.

Before any requested vault-session lookup, automatic issuance performs a
non-mutating exact-rule preflight and grant use performs a non-mutating exact
Consumer, target, Grant, and Grant-session preflight. Unauthorized real,
random, and other-Vault identities consequently return the same access denial
instead of revealing whether a Vault is open. The later checked authorization
remains authoritative and atomically consumes one-operation Grants.

The internal authorized-search operation is the first credential capability
built on this boundary. It checks the global pause gate before authorization,
requires an exact `credential.search` version 1 target, authorizes the Use
Grant against the current random vault session, and only then asks `psw-core`
for the one Credential named by the target. The session lock remains held
around the exact lookup, so lock or rotation cannot race the metadata
projection. One-operation grants are consumed before the lookup; session
grants remain reusable only for their exact session.

There is no Consumer-facing full-vault catalog. A successful result contains
at most one stable Credential identity and title plus the exact authorized
Secret Field identity, role, optional label, and authenticated kind. It omits
templates, tags, favorite state, usernames, URLs, notes, all unrelated field
descriptors, all values, and vault paths. Query matching is limited to the
title and authorized field role or label. Omitted metadata therefore cannot
match and cannot be used to enumerate unrelated Credentials or fields.

The query is valid UTF-8 bounded to 256 bytes, rejects control characters, has
redacted `Debug`, and zeroizes its normalized memory on drop. Returned title,
role, and label buffers likewise have redacted `Debug` and are zeroized on
drop. Missing, archived, deleted, or conflicting Credentials; deleted or
changed fields; field-kind mismatch; wrong target; stale session; and pause
all fail closed. The field kind is checked against authenticated vault
content, never a Consumer assertion. No secret is returned. Authenticated
Broker protocol, MCP requests, and the source-level CLI expose this operation;
the macOS machine-operation UI does not.

Authorization regression coverage exhaustively checks every known
capability/Secret Field-kind combination and future versions, immutable
Consumer identity despite copied labels and OS evidence, pairing-proof and
one-operation Grant replay, stale Grants across unlock and process identities,
and indistinguishable metadata denial for real unrelated, random, and
other-Vault targets.

Requests for a previously unauthorized Credential use a separate human-only
matching path. The submitted description is non-empty, valid UTF-8 bounded to
256 bytes, rejects control and bidirectional-control characters, zeroizes its
display and normalized buffers, and has redacted `Debug`. Machine admission
checks the global pause gate before confirming that the Consumer still exists;
the admitted value has no candidate accessor or serialization contract.

Only the trusted local control plane can build the candidate review. It must
name an exact current unlock session. Core matching may inspect authenticated
non-secret text such as usernames, URLs, notes, tags, templates, titles, roles,
and labels, but Secret Field values never participate. Matching text values
are not copied into the result. Each human candidate contains only display
metadata, stable identities, and Secret Field descriptors compatible with the
requested capability. The list is capped at 50 and marks truncation. Candidate
and review `Debug` projections redact private text, and their owned text
buffers are zeroized on drop.

Approval consumes the review and selects exact Credential and Secret Field
identities. The runtime rechecks the paired Consumer, exact unlock session,
current Credential state, every displayed candidate attribute, field kind,
and capability compatibility. Removed, archived, deleted, conflicted, changed,
or session-rotated state fails closed. The approved result reveals only one
exact authorization target and minimal selected-field metadata and creates no
Access Rule or Use Grant. A pause that occurs after admission does not prevent
the local human from reviewing or denying the request.

Asynchronous approval state is split by sensitivity. SQLCipher stores a random
request ID, a typed secret-free subject, status, bounded timestamps, and a
coalescing digest derived with a separate device-root-key domain. It does not
store a new-Credential description, candidate list, selected secret value,
request body, or vault path. Consumer poll, wait, and resume receipts exclude
the subject and require the exact owning Consumer; a mismatched Consumer gets
the same unavailable result as an unknown ID.

New-Credential descriptions and admitted request state remain in zeroizing
process memory. Exact Access and Unlock requests can resume after restart,
while pairing and new-Credential requests are cancelled because their
process-local context cannot be reconstructed safely. A hard pending cap,
bounded lifetime and wait duration, serialized coalescing, and a conditional
SQL terminal transition constrain denial-of-service and resolution races.
Unrelated notifications do not terminate a targeted wait. Broker protocol and
MCP `access.request` expose bounded submission, status, resume, and wait
operations under the same negotiated capability. The dispatcher derives the
Consumer from the authenticated connection, and MCP accepts no Consumer
identity in lifecycle arguments. Foreign, absent, and random approval IDs
produce the same unavailable error. Waits are bounded to five minutes and
return whether the request remained pending at timeout. The macOS human queue
alone owns subject review and terminal decisions.

MCP regression coverage scans every success and error projection for seeded
private query, request-description, URL, header, body, executable-argument,
environment, cancellation-reason, duplicate-value, and unknown-input markers.
This proves that the adapter does not reflect those request-side values. It
does not replace the later cross-adapter real-secret marker gate: HTTP response
bodies and child output are permitted operation results, and exact-secret
redaction remains the Broker executor's responsibility.

Reinstall recovery now has an explicit load-existing-only boundary. It reads
the stable device root from Keychain and authenticates the existing SQLCipher
database; it never creates a replacement key or database. A missing key,
missing database, corrupt ciphertext, or unsafe path therefore fails without
modifying preserved state.

Explicit local-device-state clearing requires a caller-held confirmation value.
For authenticated state it first shuts down vault sessions and transactionally
removes all grants. It then closes SQLCipher, validates the database, WAL, and
shared-memory entries without following symlinks, removes sidecars before the
database, verifies absence, and synchronizes the private state directory. The
device root Keychain item is deleted by its stable service and account only
after file removal succeeds, and a read-back verifies absence.

Filesystem validation or deletion failure leaves the device root in Keychain.
If Keychain deletion fails after the database is gone, the Broker reports that
partial state explicitly and supports an idempotent retry. A separate confirmed
path can remove corrupt or missing-key state without claiming transactional
grant counts. Both paths preserve the `~/.keptnear` directory layout and never
traverse or delete portable `.pswvault` data. The confirmation UI and verified
cleanup of every MCP pairing-profile signing-key account are not implemented
yet.

OS peer identity is supporting local evidence, not Consumer authentication.
After `getpeereid` accepts the current effective user, the macOS transport may
read the peer audit token. It discards all optional evidence unless the audit
token reports the same effective user, retains its process identifier only for
the live connection, and uses `proc_name` rather than `proc_pidpath` so a full
executable path is never obtained. The Broker does not accept a client-reported
process name, signing identifier, team, or digest.

Security.framework validation runs with network access disabled and may yield a
bundle identifier, team identifier, and code-directory digest. Each value is
bounded and sanitized before presentation. No verified signature, a verified
ad-hoc or linker signature without a team identifier, and a verified
developer-signed identity are all valid evidence states. Apple signing is not a
pairing prerequisite.

An executable basename can be selected by another process running as the same
user, signing can change across upgrades, and a short 64-bit display
fingerprint is not collision-resistant enough to act as an identity root.
Consequently these values are recognition hints only. Pairing still requires
local approval and strict proof of the proposed Ed25519 private key; the
verified public key and immutable `consumer_id` remain the durable identity.
The display projection excludes the full public key, full code-signature
digest, process path, user label, and transient process identifier.

The Broker executable and serial service loop are implemented and bundled, but
the App-controlled installation/activation lifecycle, protocol exposure of
trusted vault-session controls, and accepted end-to-end App machine-operation
path are not complete yet.
CLI access submission waits once through the Broker's five-minute bound by
default or returns immediately with `--no-wait`. Both modes return one
secret-free approval receipt; timeout remains pending, and a post-submission
wait failure retains only the stable approval identity needed for retry.
Source-level Broker protocol and MCP adapters now expose
separate pairing profiles, pairing, connection authentication, resumable
access approval lifecycle, Consumer-scoped grant management, authorized
metadata search, HTTP execution, and child-process execution. They are not yet
packaged as a shipped machine-use installation. The documented MCP host
configuration is therefore a developer contract, not a claim that this
installation exists.
Unsigned or ad-hoc-signed hosts may also be denied Data Protection Keychain
access; packaging must prove Keychain continuity before enabling device state
and must fail without a file fallback.
