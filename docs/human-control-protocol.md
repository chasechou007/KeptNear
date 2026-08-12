# Human-Control Protocol

This document freezes the source-level version 1 contract for the authenticated
App-to-Broker management channel. It does not mean the installed Broker service
or end-user machine access is active. The current App still uses its in-process
Apps & Tools bridge until the external controller client and service lifecycle
are implemented and accepted. The Broker-side typed dispatcher, strict wire
envelope validator, controller authentication, process ownership, and readiness
projection are implemented and tested in source but are not connected to an
installed App client.

The executable contract is defined in
`crates/psw-broker/src/human_control_protocol.rs`,
`human_control_wire.rs`, and `human_control_dispatcher.rs`.

## Boundary

Protocol identity: `keptnear.human-control`

Schema identity: `keptnear.human-control.schema.v1`

Current version: `1.0`

The human controller is a separate role. It is not a Consumer and receives no
Consumer capability through this channel. In particular, the operation catalog
does not contain `credential.search`, `access.request`, `grant.status`,
`http.request`, `process.run`, `secret.get`, or whole-Vault export.

Only `vault.unlock` accepts a Vault unlock credential. Controller challenge and
proof operations accept bounded authentication material. Every successful
result is secret-free metadata or a fixed control receipt. No result contains a
password, token, Secret Field value, controller private key, Consumer key,
unlock credential, request body, command argument, full local path, or arbitrary
diagnostic text.

## Framing And Envelopes

The transport uses the existing Broker framing shape: one unsigned 32-bit
big-endian payload length followed by exactly that many UTF-8 JSON bytes.

- Maximum frame: 1 MiB.
- Maximum `hello` request or response: 16 KiB.
- Maximum controller challenge, proof, or lease message: 64 KiB.
- Maximum ordinary authenticated request: 64 KiB.
- Maximum `vault.unlock` request: 128 KiB.
- Maximum decoded unlock credential: 64 KiB.
- Maximum secret-free response: 1 MiB.
- Maximum collection entries: 256.
- Maximum audit events per page or export: 256.

Requests use this closed envelope:

```json
{
  "protocol": "keptnear.human-control",
  "version": { "major": 1, "minor": 0 },
  "requestId": "<canonical control request id>",
  "operation": "readiness.get",
  "body": {}
}
```

Successful responses use the selected version and matching request identity:

```json
{
  "protocol": "keptnear.human-control",
  "version": { "major": 1, "minor": 0 },
  "requestId": "<matching control request id>",
  "result": {}
}
```

Failures replace `result` with a closed error object:

```json
{
  "protocol": "keptnear.human-control",
  "version": { "major": 1, "minor": 0 },
  "requestId": "<matching control request id>",
  "error": {
    "code": "authentication-failed",
    "retryable": false,
    "requiredAction": "authenticate-controller"
  }
}
```

Unknown or duplicate fields at any depth, duplicate object keys, invalid UTF-8,
unknown operations, incompatible schema identities, non-canonical identities,
invalid union variants, and messages beyond the applicable bound are rejected.
Errors never echo submitted bytes or include a free-form `message`, `detail`,
path, or underlying operating-system error.

The initial `hello` envelope may declare any minor version supported by the
running Broker within the current major. After `Hello` selects a version, every
request, challenge transcript, success, and failure on that connection uses
that exact selected version; a different envelope version is incompatible.

## Negotiation

`hello` is the only operation allowed before negotiation. Its body is:

```json
{
  "role": "human-controller",
  "protocolVersions": [
    { "major": 1, "minimumMinor": 0, "maximumMinor": 0 }
  ],
  "schemaIds": ["keptnear.human-control.schema.v1"]
}
```

At most eight ranges are accepted, and each major version may appear once. The
Broker selects the highest mutually supported minor version within its current
major. No shared major produces `protocol-incompatible`. Operations whose
`introducedMinor` exceeds the selected minor are unavailable. Version 1.0
negotiates the complete catalog below rather than a Consumer capability set.
The typed offer retains the bounded role and schema list as well as the version
ranges. Wire validation checks only their closed structure, bounds, canonical
identity shape, and uniqueness. The Broker dispatcher requires the exact
`human-controller` role and requires the current schema identity to be present
before moving the connection into the negotiated phase; a shared version alone
is insufficient. A structurally valid unsupported role or schema therefore
receives `protocol-incompatible` with `update-component`, not `malformed-frame`.

A successful result contains only the selected version, schema identity,
ephemeral Broker instance identity, global limits, and ordered operation names.
The closed `limits` object contains `maximumFrameLength` (`1048576`),
`maximumCollectionItems` (`256`), `maximumAuditEvents` (`256`), and
`maximumInputTextBytes` (`128`). These values are fixed by the selected
protocol version rather than supplied by the client.
It does not expose protected device state. After negotiation, only
`controller.challenge` and `controller.authenticate` are accepted until the
dedicated controller proof succeeds. Every later operation requires a live
authenticated controller session and bounded lease.

## Request Schemas

Every body is a closed object. Optional fields are explicitly noted; all other
fields are required. Stable identity fields are typed, canonical identifiers
rather than labels or paths. Validation covers scalar types, nested closed
objects, fixed values, tagged unions, canonical identifiers, and decoded byte
bounds before a validated envelope can reach typed dispatch.

| Schema | Fields |
| --- | --- |
| `Hello` | `role`, `protocolVersions`, `schemaIds` |
| `ControllerChallenge` | `controllerId`, `clientNonce` |
| `ControllerProof` | `controllerId`, `controllerSessionId`, `brokerInstanceId`, `clientNonce`, `brokerNonce`, `deadline`, `proof` |
| `ControllerLease` | `controllerSessionId`, `brokerInstanceId` |
| `Empty` | no fields |
| `PauseUpdate` | `paused` |
| `VaultUnlock` | `vaultId`, exactly one `credential` union |
| `VaultIdentity` | `vaultId` |
| `PendingDecision` | `pendingRequestId`, fixed `decision` |
| `PairingApproval` | `pendingRequestId`, bounded `label` |
| `UnlockApproval` | `pendingRequestId`, `vaultId` |
| `CredentialReview` | `pendingRequestId` |
| `CredentialSelection` | `pendingRequestId`, `credentialId`, `secretFieldId` |
| `CredentialAuthorization` | selection fields plus `capability`, `confirmationPolicy`, `ruleLifetime` |
| `AuthorizationSnapshot` | `vaultId` |
| `ConsumerIdentity` | `consumerId` |
| `UsageProfileCatalog` | `consumerId`, optional bounded `executableName` |
| `UsageProfileCreate` | `consumerId`, `templateId`, bounded `label`, typed `technicalField` |
| `UsageProfileRemove` | `consumerId`, `usageProfileId` |
| `FieldAccessRevoke` | `consumerId`, `vaultId`, `credentialId`, `secretFieldId` |
| `GrantRevoke` | `consumerId`, `useGrantId` |
| `ConsumerRevoke` | `consumerId`, fixed `scope` |
| `AuditPage` | typed `filter`, optional `cursor`, bounded `limit` |
| `AuditClear` | explicit bounded `selection`, `confirmationId` |
| `AuditExport` | typed `filter`, bounded `limit` |
| `RepairPrepare` | `expectedComponent`, `expectedProtocol` |
| `Shutdown` | fixed `reason` |

`ControllerChallenge` retains exactly its two wire fields. The Broker derives
the bootstrap or authentication purpose, selected protocol, controller role,
and public key from the negotiated connection and protected Controller
authority only after the shared failure-budget check. A decoder never invents
those fields and never loads protected authority before dispatch admission.
The successful challenge response projects the derived `controllerId` and
non-secret Ed25519 `publicKey` together with the selected mode, protocol,
Broker instance, session, nonces, and opaque deadline needed to construct the
exact proof transcript; it never exposes the Controller seed.

Every `ControllerProof` binding is retained by the typed request and compared
exactly with the outstanding single-use challenge before signature
verification, including `controllerId`. The Broker can reconstruct the typed
proof directly from every validated closed wire binding plus the 64-byte
signature; this path never needs the App's controller seed and grants no trust
until the outstanding challenge is consumed and verified.

Successful authentication starts a 30-second process-local connection lease.
Every authenticated operation checks the monotonic deadline before dispatch;
expiry closes the connection and requires a fresh authenticated connection.
Only a renewal carrying the exact authenticated `controllerSessionId` and
running `brokerInstanceId` advances the deadline by another 30 seconds. This
connection bound does not implement the App-termination Vault-lock lifecycle,
which remains a separate activation task.

`ControllerAuthenticated` returns `controllerId`, `controllerSessionId`, and
`leaseDurationMs`; `ControllerLease` returns `controllerSessionId` and
`leaseDurationMs`. Version 1 fixes `leaseDurationMs` at `30000`. It is a client
scheduling hint, not an absolute clock or authorization assertion; the Broker's
private monotonic deadline remains authoritative.

The fixed `ConsumerRevoke.scope` value is `consumer-and-authorization`, and the
fixed graceful `Shutdown.reason` value is `controller-request`. A controller
lease renewal must echo both the authenticated `controllerSessionId` and the
running `brokerInstanceId`; either mismatch is rejected.

The `credential` union is exactly one of:

```json
{"kind":"master-password","valueBase64":"<canonical padded Base64>"}
{"kind":"local-material","valueBase64":"<canonical padded Base64>"}
```

The master-password value decodes to 1 through 65,536 bytes; local material
decodes to exactly 32 bytes. The union accepts no file path, Keychain query,
environment variable, command argument, or credential reference. Encoded and
decoded bounds are checked before dispatch, decoded temporary buffers are
zeroized, the frame reader returns an owning payload that is zeroized on every
success, parse-failure, or early-drop path, validated envelope bodies have
redacted debug output, and retained JSON strings are zeroized when the envelope
is dropped. `ControllerProof.proof`
is canonical padded Base64 of exactly one 64-byte Ed25519 signature.

Nested version 1 values are also closed:

- `capability` is `{"name":"<fixed-capability>","version":<nonzero-u16>}`.
- `ruleLifetime` is either `{"kind":"persistent"}` or
  `{"kind":"until","expiresAtMs":<nonnegative-i64>}`.
- `technicalField` is `null` or a non-empty string of at most 128 UTF-8 bytes;
  the selected bundled template validates whether it is absent, optional, or
  required and validates the resulting header or environment-variable name.
- `filter` and `selection` accept only optional `eventKind`, `decision`,
  `consumerId`, `vaultId`, `fieldScope`, `capability`,
  `occurredAtOrAfterMs`, and `occurredBeforeMs`. `fieldScope` is exactly
  `vaultId`, `credentialId`, and `secretFieldId`; duplicate Vault scopes and
  time windows must be consistent.
- `cursor` is exactly `occurredAtMs` plus canonical `auditEventId`; those two
  validated values reconstruct the typed newest-first continuation cursor.
- `expectedComponent` is one closed packaged-component enum value, and
  `expectedProtocol` is a closed, structurally valid `major` and `minor`
  integer pair. The dispatcher compares both with the running Broker so a
  stale or mismatched client receives `protocol-incompatible` with
  `update-component` rather than a malformed-frame result.

The controller algorithm, Keychain identity, transcript encoding, nonce sizes,
proof size, deadline semantics, replay bounds, and authority lifecycle are
frozen separately in
`docs/controller-authority-contract.md`. These fields keep their closed wire
positions. The runtime challenge manager and access-group Keychain adapter are
implemented in source; entitlement-qualified App integration remains later work.

## Operation Catalog

All operations were introduced in minor version 0.

### Negotiation And Controller Session

| Operation | Authentication | Request | Response |
| --- | --- | --- | --- |
| `hello` | none | `Hello` | `Hello` |
| `controller.challenge` | negotiated | `ControllerChallenge` | `ControllerChallenge` |
| `controller.authenticate` | negotiated | `ControllerProof` | `ControllerAuthenticated` |
| `controller.lease.renew` | authenticated | `ControllerLease` | `ControllerLease` |
| `readiness.get` | authenticated | `Empty` | `Readiness` |

`Readiness` contains bounded component identity, negotiated protocol and schema,
protected-state category, Machine Access Pause, and machine Vault lock state. It
contains no full path, key identity, credential metadata, or service log.
The protocol and schema are copied from the authenticated connection's `Hello`
selection; they are not recomputed from the running Broker's current version.

### Pause And Vault State

| Operation | Request | Response |
| --- | --- | --- |
| `machine-access.pause.set` | `PauseUpdate` | `PauseState` |
| `vault.unlock` | `VaultUnlock` | `VaultState` |
| `vault.lock` | `VaultIdentity` | `VaultState` |

Pause does not lock the human App session, and service repair does not resume a
paused Broker. `VaultState` returns only Vault identity, locked or unlocked
state, and an optional machine unlock-session identity.

### Pending Human Decisions

| Operation | Request | Response |
| --- | --- | --- |
| `pending.list` | `Empty` | `PendingQueue` |
| `pending.deny` | `PendingDecision` | `DecisionReceipt` |
| `pairing.approve` | `PairingApproval` | `DecisionReceipt` |
| `unlock.approve` | `UnlockApproval` | `DecisionReceipt` |
| `credential.review` | `CredentialReview` | `CredentialReview` |
| `credential.allow-once` | `CredentialSelection` | `DecisionReceipt` |
| `credential.authorize` | `CredentialAuthorization` | `DecisionReceipt` |

Pending results may contain bounded labels, path-free process identity evidence,
stable identities, capability names, Secret Field kinds, human-review titles,
and expiry metadata. Process-local pairing entries include the comparison code,
short pairing-key fingerprint, remaining lifetime, and path-free observed
executable and signing evidence needed to identify the requester. The stable
pairing-first queue is truncated to 256 entries; resolving visible entries
exposes any remainder on a subsequent read. Results never contain a Secret
Field value or submitted unlock credential. Pairing approval establishes
identity only and grants no credential access.

`pending.deny` retains and requires the exact fixed `deny` decision before it
changes the pending request. Both credential approval operations retain the
submitted Credential and Secret Field identities. Existing-field approvals
compare those identities with the immutable pending target, while
new-Credential approvals compare them with the current human-reviewed
candidate. A mismatch leaves the request pending.

Each successful `audit.list` response returns the bounded page plus a fresh
`clearConfirmationId` bound to that request's exact non-secret filter. The
Broker retains at most 16 such tickets on that authenticated human-controller
connection, evicting the oldest; connection close clears all of them. After an
explicit local confirmation, the App sends the exact selection and ticket ID
in `audit.clear`. The Broker removes the identified ticket before validating
its selection, rejects arbitrary, evicted, cross-connection, changed-selection,
or replayed IDs, and deletes no audit event unless the retained exact-selection
token also passes the runtime transaction boundary.

Credential-review metadata uses a shared half-response byte budget in addition
to the candidate-count bound. Individual titles, template identities, tags,
field roles, and labels are UTF-8-safely bounded; Secret Field metadata is
retained ahead of presentation tags. Omitted metadata or candidates set the
review's `truncated` flag.

### Authorization And Usage Profiles

| Operation | Request | Response |
| --- | --- | --- |
| `authorization.snapshot` | `AuthorizationSnapshot` | `AuthorizationSnapshot` |
| `consumer.detail` | `ConsumerIdentity` | `ConsumerDetail` |
| `usage-profile.catalog` | `UsageProfileCatalog` | `UsageProfileCatalog` |
| `usage-profile.create` | `UsageProfileCreate` | `UsageProfile` |
| `usage-profile.remove` | `UsageProfileRemove` | `RemovalReceipt` |
| `access.field.revoke` | `FieldAccessRevoke` | `RevocationSummary` |
| `grant.revoke` | `GrantRevoke` | `RevocationSummary` |
| `consumer.revoke` | `ConsumerRevoke` | `RevocationSummary` |
| `access.all.revoke` | `Empty` | `RevocationSummary` |

Authorization projections contain stable identities, field kinds, capability
versions, confirmation policy, rule lifetime, profile placement metadata,
counts, and fixed state. Credential, Consumer, Access Rule, and Usage Profile
collections are each truncated to 256 entries and carry a corresponding
truncation flag. A Usage Profile remains declarative placement and grants no
access. Revocation prevents future KeptNear delivery and cannot erase material
already received by a compatible child or remote service.

### Audit, Repair, And Shutdown

| Operation | Request | Response |
| --- | --- | --- |
| `audit.list` | `AuditPage` | `AuditPage` plus `clearConfirmationId` |
| `audit.clear` | `AuditClear` | `AuditClearSummary` |
| `audit.export` | `AuditExport` | `AuditExport` |
| `repair.prepare` | `RepairPrepare` | `RepairReadiness` |
| `shutdown` | `Shutdown` | `ShutdownReceipt` |

Audit results use only existing fixed audit fields and stable identities. Audit
pages and exports reject limits outside 1 through 256. A Human Control export
uses the exact accepted request limit and remains independently byte-bounded.
`unlock.approve` compares the submitted Vault identity with the immutable
pending subject before resolving it. `credential.authorize` likewise compares
the submitted capability name and version before creating an Access Rule; a
stale or confused controller request leaves the pending decision unchanged.
`repair.prepare` and `shutdown` first lock machine Vault sessions and invalidate
live Grants. Before any quiescence, `repair.prepare` requires the expected
component to be the Broker and the expected Human Control protocol to equal the
running version. After either operation succeeds, the dispatcher becomes
permanently quiesced for that Broker process: every current or new Human Control
connection is closed before dispatch and receives `repair-required` with
`repair-service`, so no authenticated lease can mutate quiesced state.
Neither operation clears protected device state, resumes
pause, changes portable Vaults, removes host configuration, or edits Agent
policy.

## Fixed Failures

The only version 1 failure codes are:

```text
protocol-incompatible       malformed-frame
oversized-frame             negotiation-required
authentication-required     authentication-failed
replay-rejected             controller-unavailable
unsupported-operation       invalid-request
vault-locked                unlock-failed
request-unavailable         conflict
protected-state-unavailable repair-required
rate-limited                operation-failed
```

Optional `requiredAction` values are limited to:

```text
update-component       send-hello
authenticate-controller reauthenticate
unlock-vault           review-request
retry-later            repair-service
disable-machine-access
```

The Broker maps internal failures to these values. A wrong controller proof,
wrong unlock credential, missing pending request, revoked identity, corrupt
state, socket problem, database error, or operating-system failure cannot add
free-form details to the wire response.

## Versioning Rule

Changing a field type, removing or renaming an operation or field, weakening a
bound, changing result secrecy, or reinterpreting an existing fixed value is a
major-version change. A later minor may add an operation or optional response
metadata only when version negotiation keeps it unavailable to older clients.
No minor version may add a secret-returning result or turn the human controller
into a Consumer.
