# Local Security Review

Review date: 2026-07-31

Status: Completed for the current source-preview candidate. This is a local,
maintainer-directed review, not an external security audit or a production-use
approval.

## Scope

The review covered:

- master-password KDF and vault-key wrapping
- recovery and local convenience-unlock envelopes
- vault metadata, record, import, and export parsing
- vault, backup, migration, and plaintext-export path handling
- Broker framing, Unix socket ownership, peer identity, authentication, grants,
  pause, revocation, and encrypted device state
- brokered HTTPS and direct child-process secret delivery
- MCP, CLI, FFI, App diagnostics, clipboard, audit, and error-output boundaries
- release FFI loading, component manifests, DMG packaging, and update policy
- current and reachable historical publishable files
- dependency licenses and known RustSec advisories in the available database

The review used source inspection, focused regressions, the repository's local
verification scripts, Clippy, and `cargo-audit`. It did not use Codex Security.
It also did not use UI automation, a real user vault, live user Keychain
material, an installed long-running Broker, or a network sync provider.

## Closed Findings

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| LSR-001 | High | Untrusted `keys.enc` KDF costs could request excessive Argon2 memory or CPU before password authentication. | Version-one envelopes now require the exact documented Argon2id version, 64 MiB memory cost, three iterations, one lane, fixed salt/nonce/ciphertext lengths, lowercase canonical hex, and closed schemas. Derived wrapping keys and failure-path key buffers are cleared. |
| LSR-002 | High | Vault control files, encrypted records, and plaintext imports could be read without a byte limit, and required vault entries could resolve through symbolic links. | Core reads now require regular non-symbolic-link files, use `O_NOFOLLOW` on Unix, and enforce 64 KiB control-file, 16 MiB encrypted-record, and 64 MiB plaintext-import limits. Vault roots and required entries reject symbolic links. Migration, refresh, quarantine, and CLI Doctor use the same fail-closed boundary. |
| LSR-003 | High | Plaintext export followed an existing symbolic-link destination and inherited ambient file permissions. | Export rejects non-regular and symbolic-link destinations, opens with `O_NOFOLLOW` on Unix, applies mode `0600` before writing secret bytes, syncs the file, and clears the serialized plaintext buffer on drop. |
| LSR-004 | High | A release App could honor `PSW_FFI_LIBRARY` or current-working-directory debug dylib candidates. | Release builds now load `libpsw_ffi.dylib` only from the App bundle. Environment and working-directory overrides remain available only in debug builds and are regression tested. |
| LSR-005 | High | The lockfile selected `rustls-webpki 0.102.8`, which matched four RustSec advisories. | `rustls` is pinned to `0.23.43` and the lockfile selects `rustls-webpki 0.103.13`; both declare an MSRV of Rust 1.71 and build with the workspace's Rust 1.75 toolchain. The available 1,169-advisory database reports no known vulnerability in the resulting lockfile. |
| LSR-006 | Medium | `keptnear vault doctor` could describe symbolic-link structure as valid and read unbounded metadata even though Core would reject it. | Doctor now rejects symbolic-link roots and entries, limits `vault.json` to 64 KiB, uses no-follow opening on Unix, and has focused regressions. |
| LSR-007 | Medium | The App FFI command decoder accepted unknown JSON fields, weakening the closed bridge contract. | The command enum now rejects unknown fields, including its empty `version` command shape, and a seeded private value is verified absent from the error response. |

No unresolved Critical or High issue was identified in this bounded review.
That statement describes review results only; it does not prove that no such
issue exists.

## Boundary Results

### Cryptography

- The portable vault key remains random and is wrapped independently by the
  master-password, optional recovery, and local convenience-unlock envelopes.
- Version-one KDF metadata is no longer a caller-controlled resource parameter.
- XChaCha20-Poly1305 nonces and wrapped-key ciphertexts have fixed canonical
  encodings before decryption.
- Recovery identity and authenticated record identity checks remain fail
  closed. Existing encrypted items are not rewritten during password recovery
  or password rotation.

### Parsing And Paths

- Control, record, import, MCP, Broker-frame, HTTP-body, and child-output
  boundaries are byte limited before unbounded parsing or allocation.
- Vault roots and required entries are regular local filesystem objects rather
  than symbolic links. Backup traversal rejects links and special files.
- Plaintext imports and exports remain explicit secret-bearing operations.
  Their raw Rust byte buffers are cleared, but higher-level parser values and
  Swift `String`/`Data` copies do not have deterministic zeroization.

### Broker, Grants, And Delivery

- Broker frames are length-prefixed and bounded before payload allocation.
- Protocol and MCP JSON reject duplicate keys and unknown closed-contract
  fields without reflecting private input.
- The Unix socket, runtime directory, database, and sidecars enforce local
  ownership and restrictive modes; the Broker checks the peer effective user.
- Pairing uses an Ed25519 proof over a fresh, single-use, expiring challenge.
- Access Rules, Use Grants, vault sessions, stable field identity, capability,
  pause, expiry, and revocation are checked as exact dimensions. One-operation
  grant consumption is transactional.
- HTTPS delivery requires TLS, rejects URL credentials and redirects, ignores
  proxy environment variables, bounds request/response material, and redacts
  an exact secret echo.
- Process delivery starts an absolute direct executable without inserting a
  shell, clears inherited environment, bounds all inputs and outputs, and
  terminates/reaps the direct child on timeout or cancellation.

### Output, Packaging, And Publication

- Seeded private markers are scanned across Broker audit output, every MCP tool
  error path, CLI success/error output, and App diagnostics.
- Current App diagnostics are an allowlisted local support snapshot and are not
  uploaded automatically.
- Release FFI lookup is bundle-only. The package manifest binds the App,
  Broker, MCP adapter, CLI, FFI, component metadata, paths, versions, and
  SHA-256 hashes.
- Public-source checks covered 232 candidate files and 367 reachable historical
  Git blobs for this candidate. OpenSpec, EchoPath, Codex state, real vaults,
  plaintext exports, signing material, DMGs, and build products remain
  excluded.

## Validation Evidence

- Rust 1.75.0 built and passed 522 tests across Core, FFI, Broker, shared
  client, MCP, CLI, migration, recovery, two-device sync, parser hardening, and
  package-manifest targets.
- SwiftPM passed 234 macOS workflow tests and a debug build.
- Workspace Clippy passed for all targets and features with warnings denied.
- The cross-adapter seeded-secret gate passed for Broker, MCP, CLI, and App.
- Dependency-license review passed for 116 registry packages under the
  repository's GPLv3 compatibility policy.
- `cargo-audit 0.22.2 --no-fetch --stale` reported zero vulnerabilities against
  the available 1,169-advisory snapshot after the TLS upgrade. Its online
  database refresh did not complete in the review window, and the local
  snapshot did not expose a last-update timestamp; this is a recorded evidence
  limitation, not a claim of a live online scan.
- The strict local-alpha readiness workflow repeated the full checks, frozen
  vault-format and two-device suites, vault Doctor checks, macOS clipboard and
  lock-state suites, Release-config packaging, DMG integrity verification, and
  Launch Services registration checks. The resulting unsigned, dirty-worktree
  `local-test` DMG is arm64-only, uses manual updates, and has SHA-256
  `b3393d84256a329a79e2b5facf961e0284b3c72e6b746f85e3eea0a2620f2ab6`.
  It remains non-distributable test evidence until the exact artifact receives
  human workflow acceptance; public packaging also requires a clean committed
  source revision and the dedicated unsigned profile.

## Decision

The source is suitable for an experimental, explicitly unaudited preview after
a clean public commit is prepared. It is not approved for production secrets.
An unsigned DMG remains a separate profile and requires its own clean-source
gate, checksum, manifest, installation warnings, and human acceptance of the
exact artifact. See [Release Readiness](release-readiness.md) for the remaining
limitations and [Security Review Evidence](security-review-evidence.md) for the
external-review and accepted-risk distinction.
