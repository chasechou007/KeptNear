# Controller Authority Contract

This document freezes the version 1 cryptographic and macOS Keychain contract
for the KeptNear App's human-control authority. The Broker-side Keychain
adapter, public trust record, challenge manager, and dispatcher are implemented
and tested in source. The App client, final entitlement-qualified packaging,
and installed service activation are not implemented.

The executable source contract is defined in
`crates/psw-broker/src/controller_authority_contract.rs`, `controller_key.rs`,
and `controller_authentication.rs`.

## Contract Identity

- Contract: `keptnear.controller-authority.v1`
- Human-control protocol: `keptnear.human-control` version 1.0
- Human-control schema: `keptnear.human-control.schema.v1`
- Role: `human-controller`
- Signing algorithm: Ed25519
- Private seed: 32 bytes
- Public key: 32 bytes
- Signature: 64 bytes
- Controller identity: 32-byte SHA-256 digest

The controller authority is separate from every Consumer identity, Pairing,
Access Rule, Use Grant, and Usage Profile. Possessing this key permits only the
closed human-control catalog. It never grants a Consumer capability or returns
a Secret Field.

Negotiation accepts a compatible version only when the typed offer also
retains and supplies the exact `human-controller` role and the current schema
identity. An unknown role or schema closes the connection before a controller
challenge can be issued.

The controller identity is:

```text
SHA-256(
  u32be(len("KeptNear human controller identity v1"))
  || "KeptNear human controller identity v1"
  || u32be(32)
  || ed25519_public_key
)
```

The public key and derived identity are non-secret. The 32-byte seed is secret
controller material and must remain in zeroizing memory only for the duration
of a Keychain operation or signature.

## Keychain Identity

The controller seed is one Data Protection Keychain generic-password item:

| Attribute | Required value |
| --- | --- |
| `kSecClass` | `kSecClassGenericPassword` |
| `kSecAttrService` | `app.keptnear.human-controller-key.v1` |
| `kSecAttrAccount` | `primary-v1` |
| `kSecAttrLabel` | `KeptNear Human Controller key` |
| `kSecUseDataProtectionKeychain` | `true` |
| `kSecAttrSynchronizable` | `false` |
| `kSecAttrAccessible` | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| `kSecAttrAccessGroup` | `<signing-prefix>.app.keptnear.human-controller` |

Controller removal uses a second generic-password item in the same service and
access group. Its account is `removal-pending-v1` and its fixed non-secret value
is `keptnear.controller-removal.v1`. It is removal provenance, not signing
material, and never leaves the Keychain. It uses the same Data Protection,
non-synchronizing, device-only, create-only, and exact-query rules as the seed.

The label is presentation metadata and is not part of item identity. Add,
load, update, and delete queries must all include class, service, account,
Data Protection Keychain, non-synchronizing state, and the exact access group.
There is no query that omits the access group and no plaintext file fallback.

Initial creation uses `SecItemAdd`. A duplicate item is preserved and reported;
it is never overwritten with a generated replacement. Key bytes are read back
and checked for exact length before use.

`AfterFirstUnlockThisDeviceOnly` is the least permissive accessibility class
compatible with the per-user Broker running after login without an interactive
prompt for every signature. The item does not sync through iCloud Keychain and
does not migrate to another device.

## App And Broker Access Requirement

Only these packaged executable principals may declare the controller access
group:

1. the KeptNear macOS App executable;
2. the nested `keptnear-broker` executable.

The MCP adapter, CLI, updater, test tools, and unrelated same-team applications
must not declare it. Both allowed executables must have the same concrete
ten-character Apple application-identifier prefix and the exact fully
qualified group in their `keychain-access-groups` entitlement. Every Keychain
query also names that group explicitly.

An activation-qualified artifact must verify all of the following before
creating or loading controller authority:

- the App and Broker have valid signatures for the claimed artifact profile;
- both signatures carry the same application-identifier prefix;
- both carry the exact controller access group;
- no other packaged executable carries that group;
- the Broker is the manifest-declared nested component of that App;
- the runtime query's group equals the verified manifest value.

An unsigned or ad-hoc profile without a verified concrete signing prefix and
shared entitlement is not controller-authority eligible. Owner-only socket
permissions, current-user peer checks, bundle location, and process identity
are defense in depth; none substitutes for the Keychain access group and proof.

The Broker is allowed to load the same seed so it can derive the expected
public key during first bootstrap and reject a substituted public key. The App
must still sign the connection-bound bootstrap or authentication transcript.
This proves that the connecting process also has the restricted Keychain
authority rather than merely running as the same user.

## Transcript Encoding

Bootstrap and authentication use the same fixed fields with different domain
separators. Each field is encoded as an unsigned 32-bit big-endian byte length
followed by exactly that many bytes. Numeric fields first use their fixed
big-endian representation and are then length-prefixed.

| Order | Field | Encoded bytes |
| --- | --- | --- |
| 1 | domain | bootstrap or authentication domain below |
| 2 | contract | `keptnear.controller-authority.v1` |
| 3 | protocol | `keptnear.human-control` |
| 4 | selected version | `u16be(major) || u16be(minor)` |
| 5 | schema | `keptnear.human-control.schema.v1` |
| 6 | algorithm | `ed25519` |
| 7 | role | `human-controller` |
| 8 | controller identity | 32 bytes |
| 9 | controller public key | 32 bytes |
| 10 | Broker instance identity | 16 bytes |
| 11 | controller session identity | 16 bytes |
| 12 | App client nonce | 32 bytes |
| 13 | Broker nonce | 32 bytes |
| 14 | deadline token | `u64be` opaque Broker monotonic token |

The bootstrap domain is:

```text
KeptNear human controller bootstrap v1
```

The ordinary authentication domain is:

```text
KeptNear human controller auth v1
```

A signature from one domain cannot be accepted in the other. JSON binary
fields use the protocol's canonical Base64 representation, but signing always
uses the decoded fixed-length bytes above. The Broker rejects an identity that
is not derived from the submitted public key before signature verification.

The wire `deadline` is an opaque unsigned 64-bit value from the running
Broker's monotonic clock domain. The App copies and signs it but does not
interpret or extend it. The Broker stores the exact token together with its
process-local monotonic deadline and uses only that retained deadline for the
expiry decision. No wall-clock change can extend a challenge.

## Bootstrap

Bootstrap is allowed only after explicit Enable Machine Access or explicit
repair. Ordinary installation and first App launch never create controller
authority. Bootstrap is prohibited while the `removal-pending-v1` marker
exists; enable or repair must resume removal instead.

The fail-closed sequence is:

1. verify the exact activation artifact, signatures, entitlements, access group,
   Broker component, and stopped or fresh service state;
2. inspect the Keychain seed and Broker controller public record separately;
3. if both are absent, create the Keychain seed once with `SecItemAdd`;
4. if only the seed exists after an interrupted attempt and no removal marker
   exists, reuse it without generating a replacement;
5. start the Broker, which loads the same Keychain seed and derives the expected
   public key and controller identity;
6. negotiate human-control v1 and issue a `controller.challenge` whose purpose
   is `bootstrap`;
7. the App signs the bootstrap transcript and submits it through
   `controller.authenticate`;
8. the Broker consumes the challenge, verifies the signature and exact derived
   identity, then inserts the public controller record in one SQLCipher
   transaction;
9. only after commit may the connection become an authenticated controller.

Seed creation in step 3 is available only through the non-Wire trusted App
enablement boundary after step 1. An unauthenticated `controller.challenge`
never creates or replaces Keychain state; it can only load authority already
prepared by explicit enablement or resume a permitted key-only bootstrap.

There is no cross-store claim of atomicity between Keychain and SQLCipher. A
crash after Keychain creation leaves `key-only`, which is not ready but may
resume the signed bootstrap only when the removal marker is absent. Marker
presence takes precedence over every seed-and-record combination and permits
only continuation of removal. `record-only` and mismatched complete authority
are rejected and never repaired by generating a key or replacing a record.
They require explicit device-access clearing.

The Broker record contains only contract version, algorithm, controller
identity, public key, and fixed lifecycle metadata. It contains no seed,
signature, nonce, transcript, request body, label, path, or Keychain query.

## Ordinary Authentication

For complete matching authority, `controller.challenge` returns purpose
`authenticate`, algorithm, controller identity, public key, Broker instance,
fresh controller session, echoed client nonce, fresh Broker nonce, and the
opaque deadline token. The App signs the authentication transcript and returns
the fixed 64-byte proof through `controller.authenticate`.

The request cannot nominate a controller session identity. The Broker generates
that identity independently for every challenge, including replacement
challenges on the same connection.

Successful proof authenticates only that connection and starts the separately
bounded controller lease. It does not authenticate another connection, unlock
a Vault, resume Machine Access Pause, grant credential scope, or survive a
Broker restart.

## Replay And Failure Bounds

- Client and Broker nonces are independently generated 32-byte CSPRNG values.
- Broker instance and controller session identities are independent 16-byte
  CSPRNG values.
- A challenge expires at 30 seconds; equality with the deadline is expired.
- At most one challenge exists on a human-control connection.
- Issuing a replacement challenge consumes the prior challenge.
- Every proof attempt consumes its challenge, whether it succeeds or fails.
- Disconnect, session change, Broker restart, and deadline expiry consume it.
- A proof is valid only for the exact protocol, schema, role, identity, public
  key, Broker instance, session, nonces, deadline, and domain.
- Five failures for one controller identity within 60 seconds are rate-limited.
- Sixty-four failures globally within 60 seconds are rate-limited.
- Failure counters and challenges are process-local and contain no proof bytes.

Every failure maps to the fixed human-control errors. Logs, audit, diagnostics,
UI errors, crash annotations, and support copies contain no key, nonce,
signature, transcript, Keychain value, or submitted identity material.

## Persistence, Rotation, And Removal

Disable Machine Access, App moves, compatible App replacement, Broker restart,
and reinstall preserve complete controller authority. They do not rotate the
key. Re-enable authenticates the preserved key after verifying the current
artifact still has the exact access boundary.

Version 1 has no in-place, scheduled, age-based, or update-triggered controller
rotation. The only supported rotation is:

1. reauthenticate the human user and confirm Clear Device Access Data;
2. stop and unregister the Broker;
3. create the `removal-pending-v1` marker with `SecItemAdd` before mutating
   either authority side; a duplicate marker means removal is being resumed;
4. remove the Broker public controller record with the protected device state;
5. only after that succeeds, delete the exact Keychain seed;
6. verify both authority sides are absent without generating replacement
   authority;
7. delete the removal marker last;
8. perform a later explicit Enable Machine Access to create and bootstrap a
   fresh key.

If marker creation fails, removal does not begin. If protected-record removal
fails, the Keychain seed and marker are retained. If Keychain deletion fails
after the public record is gone, the marker is retained and the clear remains
incomplete. Any later enable or repair that sees the marker resumes removal of
that same authority and cannot enter bootstrap. The marker is removed only
after both authority sides are verified absent. No failure silently initializes
a new record or seed. Every `.pswvault` remains untouched.

## Current Implementation Boundary

The constants, transcript construction, controller-ID derivation, presence
matrix, removal provenance, rotation policy, and removal order are frozen and
tested in source. Runtime Keychain queries always name the Data Protection
Keychain, exact account, synchronization policy, and verified access group.
The non-cloneable seed is cleared on drop; SQLCipher schema version 2 stores
only the matching public record. Key-only bootstrap resumes without rotation;
record-only, mismatch, malformed seed, and removal-pending states fail closed.
Challenges are single-use, expire by retained monotonic `Instant`, bind the
Broker instance and controller session, use strict Ed25519 verification, and
enforce process-local per-controller and global failure budgets.

Entitlement-qualified App integration, timed controller lease behavior, final
signing, and service activation are subsequent work. Public capability status
therefore remains Bundled But Not Activated.
