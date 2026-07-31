# KeptNear Vault Format v2

This document defines the released pre-alpha `.pswvault` schema written by the
current KeptNear core. Vault format version `2` is paired only with encrypted
record format version `2`.

This is a source-preview compatibility contract, not a production-security or
long-term-stability claim. A future incompatible schema must use a new version,
provide a verified forward migration, and retain sanitized compatibility
fixtures.

## Version Negotiation

Current readers accept these exact vault/record pairs:

| Vault | Record | Role |
| --- | --- | --- |
| `1` | `1` | Frozen legacy migration source |
| `2` | `2` | Current released pre-alpha format |

Readers must reject mixed pairs, unlisted older pairs, unknown format names,
and versions newer than they implement. v1 metadata must not contain a
`vault_id`; v2 metadata must contain one.

New vaults use v2/v2. Existing v1/v1 vaults can be migrated explicitly after a
portable encrypted backup has been verified.

## Directory Shape

```text
Example.pswvault/
  vault.json
  keys.enc
  recovery.enc      # optional, portable offline-recovery envelope
  items/
    credential_<32-lowercase-hex>_revision_<32-lowercase-hex>.enc
  attachments/
  tombstones/
    tombstone_credential_<32-lowercase-hex>_revision_<32-lowercase-hex>.enc
  local_unlock.enc  # optional, device-local, excluded from portable backup
```

`attachments/` is reserved and copied as opaque portable content. The current
schema does not define an encrypted attachment-record protocol.

Portable backup uses an exact root allowlist: `vault.json`, `keys.enc`,
optional `recovery.enc`, `items/`, `attachments/`, and `tombstones/`.
`local_unlock.enc` is deliberately excluded. Device-local `~/.keptnear` state
and Keychain material are outside the `.pswvault` format and are never part of
backup, restore, or plaintext export.

## Public Metadata

`vault.json` is UTF-8 JSON with no unknown fields:

```json
{
  "format_name": "psw-local-vault",
  "vault_format_version": 2,
  "record_format_version": 2,
  "display_name": "Personal",
  "vault_id": "vault_0123456789abcdef0123456789abcdef"
}
```

`display_name` may be `null`. `vault_id` is a random 128-bit value encoded as
the literal `vault_` followed by 32 lowercase hexadecimal characters. It is an
identity, not a secret. File-system paths and display names are never identity
inputs.

All stable IDs use random 128-bit values with distinct prefixes:

- `vault_`
- `credential_`
- `secret_field_`
- `revision_`
- `device_`
- `recovery_key_`

Cross-kind IDs, uppercase hex, wrong lengths, and additional characters are
invalid.

## Master-Password Envelope

`keys.enc` wraps one random 32-byte vault key. It is JSON containing:

- `format`: `psw-local-vault-key-envelope`
- `version`: `1`
- `kdf.algorithm`: `argon2id`
- `kdf.version`: `19` (`0x13`)
- `kdf.memory_kib`: `65536`
- `kdf.iterations`: `3`
- `kdf.parallelism`: `1`
- `kdf.salt_hex`: 16 random bytes as lowercase hex
- `aead`: `xchacha20poly1305`
- `nonce_hex`: 24 random bytes as lowercase hex
- `ciphertext_hex`: encrypted 32-byte vault key plus the 16-byte AEAD tag

Argon2id derives a 32-byte wrapping key. XChaCha20-Poly1305 authenticates the
literal associated-data bytes:

```text
psw-local-vault:key-envelope:v1
```

Changing the master password rewraps the vault key and does not rewrite
credential records.

`local_unlock.enc`, when present, uses envelope format
`psw-local-unlock-envelope`, version `1`, XChaCha20-Poly1305, a random 24-byte
nonce, and associated data `psw-local-vault:local-unlock-envelope:v1`. Its
independent 32-byte local key belongs in the platform Keychain. The file is
device convenience state and is excluded from portable backup and migration
backup.

## Offline-Recovery Envelope

`recovery.enc` is optional so existing v2 vaults without configured recovery
remain readable. When present, it independently wraps the same random 32-byte
vault key and is portable with the vault:

```json
{
  "format": "keptnear-recovery-envelope",
  "version": 1,
  "vault_id": "vault_0123456789abcdef0123456789abcdef",
  "recovery_key_id": "recovery_key_0123456789abcdef0123456789abcdef",
  "role": "vault-key-recovery",
  "kdf": "hkdf-sha256",
  "aead": "xchacha20poly1305",
  "nonce_hex": "<48 lowercase hexadecimal characters>",
  "ciphertext_hex": "<96 lowercase hexadecimal characters>"
}
```

The plaintext recovery authority is 32 random bytes. It is never written in
the vault and is encoded externally as Bech32m with HRP `knr` and a payload
containing format byte `0x01` followed by the 32 authority bytes. Canonical
encoding is one 63-character lowercase string. Input may remove ASCII
whitespace and normalize one consistent case; mixed case, Bech32 instead of
Bech32m, wrong HRP, wrong checksum, unknown format byte, wrong length, and
non-canonical padding fail before unwrap.

HKDF-SHA-256 uses the canonical UTF-8 `vault_id` string as salt and exact info
bytes `KeptNear recovery wrap key v1`. Its 32-byte output wraps the vault key
with XChaCha20-Poly1305.

Recovery-envelope associated data begins with the exact UTF-8 bytes
`KeptNear recovery envelope AAD v1`. It then appends each component as
`u32be(length) || bytes`, in this order:

1. format
2. four-byte big-endian version
3. canonical UTF-8 `vault_id`
4. canonical UTF-8 `recovery_key_id`
5. role
6. KDF
7. AEAD
8. raw 24-byte nonce

JSON parsing rejects unknown fields, unsupported constants or versions,
non-canonical IDs or hex, incorrect fixed lengths, and files larger than 4096
bytes. Recovery also requires the expected `vault_id`; transplanting an
envelope between vaults fails authentication.

Initial core setup installs `recovery.enc` without replacing an existing
authority and returns pending recovery material for explicit external custody.
The recovery kit renders the canonical lowercase code, uppercase grouped code,
QR payload, vault ID, recovery-key ID, and generation time. It includes no
vault path or item metadata. The plaintext buffers are held only for the
active workflow and are zeroized when dropped.
Successful core recovery authenticates that envelope, unwraps the existing
vault key, and atomically replaces only `keys.enc` under a non-empty new master
password. Item records, tombstones, and `recovery.enc` are not rewritten.

Core recovery-key rotation is two phase. Begin returns a non-serializable,
in-memory candidate and does not modify `recovery.enc`. After the caller has
explicitly confirmed external custody, commit validates that the candidate
wraps the unlocked session's vault key, serializes local commits with an
exclusive advisory lock on `vault.json`, and requires the current
`recovery_key_id` to match the generation observed at begin time. It then
atomically replaces only `recovery.enc`. Cancellation, write failure, or a
stale candidate leaves the previous envelope authoritative. A successful
commit makes the previous recovery key fail authentication while leaving
`keys.enc`, item records, tombstones, and attachments unchanged.

The current macOS source preview exposes unlocked recovery setup, explicit PDF
save or system print, complete-code confirmation, and two-phase rotation. The
FFI binds each pending workflow to its unlocked session and drops pending
material on cancel or lock. The App never automatically uses the clipboard and
does not persist a plaintext kit in device state. For a locked vault with a
supported envelope, the App accepts a user-held recovery code and confirmed new
master password, then opens the returned normal unlocked session.

Envelope presence does not prove continued custody of a recovery kit, so the
App does not persist or display such a claim after restart. After successful
recovery, the macOS client removes current and known legacy Keychain
convenience-unlock entries. Because Keychain cleanup follows the already
committed `keys.enc` replacement, an operating-system cleanup failure is
reported as partial success and is never presented as completed revocation.

## Credential Record Header

Each v2 item or tombstone file is UTF-8 JSON with exactly these public fields:

```json
{
  "format": "psw-local-vault-item-record",
  "version": 2,
  "vault_id": "vault_...",
  "credential_id": "credential_...",
  "revision_id": "revision_...",
  "nonce_hex": "<48 lowercase hex characters>",
  "ciphertext_hex": "<lowercase hex ciphertext and tag>"
}
```

The nonce is 24 random bytes. Ciphertext must contain at least the 16-byte
XChaCha20-Poly1305 tag. The header's three IDs must agree with the encrypted
plaintext and the vault ID must agree with `vault.json`.

The associated-data byte sequence is:

```text
u32be(len(domain)) || domain
|| u32be(len(format)) || format
|| u32be(record_version)
|| raw_vault_id_16
|| raw_credential_id_16
|| raw_revision_id_16
```

where:

- `domain` is the UTF-8 bytes `KeptNear credential revision record v2`
- `format` is the UTF-8 bytes `psw-local-vault-item-record`
- ID bytes are the 16 decoded bytes after each textual prefix

## Encrypted Revision

Authenticated plaintext is JSON with no unknown fields:

```json
{
  "revision_id": "revision_...",
  "parent_revision_ids": ["revision_..."],
  "content_digest": "sha256_<64-lowercase-hex>",
  "device_id": "device_...",
  "lifecycle": "active",
  "credential": {
    "vault_id": "vault_...",
    "credential_id": "credential_...",
    "draft": {
      "title": "Example",
      "template_id": "login",
      "fields": [],
      "tags": [],
      "favorite": false
    }
  }
}
```

`lifecycle` is `active`, `archived`, or `deleted`. Active and archived
revisions belong under `items/`; deleted revisions belong under `tombstones/`.
Directory placement and canonical file name are validated after decryption.

An initial revision has no parents. A descendant has one or more sorted,
unique parent IDs and cannot name itself. Normal edits use one parent. Conflict
resolution uses every resolved head as a parent. Revision IDs are random, so
readers derive current heads from the authenticated parent graph and must not
use lexical ID order, file modification time, or last-writer-wins.

Readers reject duplicate revision IDs, cycles, and known parent links crossing
credential IDs. Missing parents can occur while file synchronization is
incomplete; they are not fabricated or treated as ordering evidence.

On explicit refresh, readers may create a new encrypted two-parent revision
only for exactly two logical heads with a unique known authenticated common
base and provably independent changes. Title, template ID, tags, and favorite
are separate merge components. A Secret Field is one indivisible component
identified by its immutable field ID. All text fields are one component because
they lack immutable field identities. Field shape changes, same-Secret-Field
changes, concurrent text-component changes, lifecycle differences, deleted
heads, missing or ambiguous ancestry, rejected records, and three-or-more-head
sets are retained for manual resolution.

Revision and device IDs remain random. If two devices independently author
multi-parent merge revisions with equal complete credential content, lifecycle,
and exact parent sets, readers select the lower revision ID only as a canonical
representative of that equivalent logical head. Ordinary single-parent
concurrent edits remain distinct. A descendant whose known ancestry contains
an equivalent merge revision also subsumes the alternate equivalent head.
Lexical order does not choose between different content or parent sets.

## Credential Fields

`draft.fields` is ordered. Each field has:

- an open semantic `role` string
- an optional presentational `label`
- a tagged `value`

A text value is:

```json
{"type":"text","text":"alice"}
```

A secret value is:

```json
{
  "type": "secret",
  "secret_field_id": "secret_field_...",
  "kind": "password",
  "secret": [115, 101, 99, 114, 101, 116]
}
```

Secret bytes serialize as a JSON byte array. Supported secret kinds are
`password`, `api-token`, `api-key`, `totp-seed`, `private-key`, `certificate`,
and `generic-secret`. Unknown tagged value types, unknown secret kinds, and
duplicate secret-field IDs within one credential fail closed. Field roles and
template IDs are open strings so compatible readers can preserve unfamiliar
presentation semantics.

## Content Digest

`content_digest` is SHA-256 over a domain-separated canonical binary stream.
Every count or byte-string length is unsigned 64-bit big-endian. `bytes(x)` is
`u64be(len(x)) || x`; `text(x)` applies `bytes` to UTF-8. Optional text is one
marker byte (`0` for absent, `1` for present) followed by text when present.

The stream is:

1. `bytes("KeptNear credential content digest v1")`
2. `bytes(raw_vault_id_16)`
3. `bytes(raw_credential_id_16)`
4. `text(title)`
5. optional `template_id`
6. field count, then each ordered field:
   - `text(role)`
   - optional `label`
   - marker `0` plus `text(value)` for text, or marker `1` plus
     `bytes(raw_secret_field_id_16)`, `text(secret_kind)`, and `bytes(secret)`
7. tag count, then each ordered tag as text
8. one favorite marker byte (`0` or `1`)

The result is encoded as `sha256_` plus 64 lowercase hexadecimal characters.
Lifecycle, ancestry, revision ID, device ID, file name, and timestamps are not
credential-content inputs.

## Migration From v1

Migration is one-way and explicit:

1. Open and authenticate every v1 item and tombstone revision.
2. Create a portable encrypted v1 backup at a separate path.
3. Compare structure, lengths, and streamed SHA-256 file digests and decrypt
   every copied record before accepting the backup.
4. Allocate one v2 vault ID, one credential ID per legacy item, one revision ID
   per legacy revision, and stable secret-field IDs across retained history.
5. Build and verify a hidden v2 sibling directory on the same filesystem.
6. Fsync it and replace the source through a recoverable two-rename exchange.

The backup excludes `local_unlock.enc` and is retained after success. If
verification, staging, or replacement fails, the source remains in place or is
restored on the next open. Automatic downgrade is unsupported after a v2 vault
has been edited.

## Security Boundary

The sync provider is untrusted and may observe directory structure, opaque
stable IDs, encrypted bytes, file sizes, and timestamps. Parent ancestry,
content digest, device ID, lifecycle, titles, tags, field metadata, and values
remain encrypted.

The format does not protect against a compromised device, malicious keyboard
capture, privileged memory inspection, an authorized malicious client, weak
master-password choices, or supply-chain compromise. KeptNear is currently
experimental and unaudited; do not use this source preview for production
credentials.

## Sanitized Compatibility Evidence

Checked-in fixtures contain synthetic test data only:

- `fixtures/vaults/supported-source-versions.json`
- `fixtures/vaults/released-format-fixtures.json`
- `fixtures/vaults/golden-vault-manifest.json`
- `fixtures/vaults/golden-vault-v2-manifest.json`
- `fixtures/vaults/golden-vault-v1.pswvault/`
- `fixtures/vaults/golden-vault-v2.pswvault/`
- `fixtures/vaults/sync-scenarios.json`
- `crates/psw-core/tests/two_device_sync.rs`

The v1 registry is the migration-source inventory. The released-format registry
points to the current v2 fixture. Golden tests open and unlock both fixtures,
verify expected synthetic values only after authentication, reject plaintext
needles in repository files, exercise v1-to-v2 migration and current v2 writes,
and reject future versions. The two-device matrix creates distinct local paths
from portable encrypted copies, exchanges only encrypted revision files, and
checks migrated-vault identity continuity, independent edits, same-Secret-Field
conflicts, delete-edit conflicts, and descendants arriving before their parent
revisions. The readiness gate also confirms that the Broker refuses to register
both portable paths with the same `vault_id`.

Run:

```sh
script/verify_vault_format_readiness.sh
```

This verifier is local evidence. It is not an external security audit or a
binary release approval.
