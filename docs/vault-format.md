# Experimental Vault Format

This document describes the current experimental PSW vault format. It is not stable yet and must not be treated as a long-term compatibility contract before a public alpha format freeze.

## Directory Shape

```text
Example.pswvault/
  vault.json
  keys.enc
  items/
    item_<item-id>_<revision-id>.enc
  attachments/
  tombstones/
    tombstone_<item-id>_<revision-id>.enc
```

## Public Metadata

`vault.json` is public metadata. It intentionally contains only format information and an optional display name:

- `format_name`
- `vault_format_version`
- `record_format_version`
- `display_name`

Clients must refuse to write vaults whose vault or record format version is newer than the client supports.

## Key Envelope

`keys.enc` stores an encrypted vault key envelope:

- master password key derivation: Argon2id
- current Argon2id parameters: 64 MiB memory, 3 iterations, 1 lane
- key envelope AEAD: XChaCha20-Poly1305
- each envelope has an independent random salt and nonce

The master password unwraps the vault key. Item records are encrypted with the vault key.
New key-envelope writes reject empty master password material at the Rust core
boundary; existing key envelopes remain unlockable with the password that
created them.

## Item Records

Each item revision is an independent encrypted JSON record under `items/`. The current item record header includes:

- record format marker
- record format version
- item ID
- revision ID
- XChaCha20-Poly1305 nonce
- ciphertext

The record header is authenticated as AEAD associated data. Decrypted item content includes the parent revision, status, typed item content, tags, favorite state, and encrypted-in-record secrets.

## Tombstones

Deletion is represented by encrypted tombstone records under `tombstones/`. A tombstone masks older item revisions when its revision is newer than the item revision. This lets cloud file providers synchronize deletion markers without rewriting or deleting every old item record immediately.

## Conflict Model

Concurrent edits are detected when multiple item revisions share the same item ID and parent revision. The current MVP marks the item as conflicted and preserves all candidate revisions. Conflict resolution writes a new active revision.

## Security Assumptions

The vault assumes the sync provider is untrusted. Providers may observe encrypted bytes, opaque filenames, file sizes, timestamps, and directory structure. Providers must not receive plaintext item data, master passwords, or vault keys from the application.

The format does not protect against a fully compromised device, malicious keyboard capture, privileged memory inspection, or a malicious client that already runs with user privileges.

## Current Test Vectors

Golden and hardening tests live in:

- `fixtures/vaults/golden-vault-manifest.json`
- `fixtures/vaults/golden-vault-v1.pswvault/`
- `fixtures/vaults/sync-scenarios.json`
- `crates/psw-core/tests/golden_vectors.rs`
- `crates/psw-core/tests/property_hardening.rs`

`golden-vault-v1.pswvault` is a sanitized, encrypted fixture containing only
synthetic test data. The Rust golden vector tests open it with a test-only
master password to prove current clients can still read the checked-in format
artifact.

## Local Readiness Verification

Run the local vault-format readiness verifier before treating format behavior as
ready for a public alpha freeze decision:

```sh
script/verify_vault_format_readiness.sh
```

The verifier checks that required golden and sync fixtures are present, runs the
targeted Rust golden vector tests, parser hardening tests, sync scenario fixture
coverage. Passing this command is readiness evidence only; it does not freeze
the experimental format, approve production use, or replace external security
review.
