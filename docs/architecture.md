# Architecture

KeptNear is evolving from a native-client and shared-core password manager into
a local password and token manager. This document distinguishes the implemented
pre-alpha architecture from the approved first-version target.

## Current Architecture

Implemented today:

```text
macOS SwiftUI/AppKit client
  - windows, menus, search UI, clipboard, local unlock UX
  - explicit offline-recovery kit save, print, confirmation, and rotation UX
  - locked recovery and post-recovery Keychain convenience-unlock cleanup
  - no custom vault cryptography
        |
        v
Rust core
  - vault format
  - key derivation and key wrapping
  - offline-recovery envelopes, locked rewrap, kit rendering, and rotation
  - authenticated record encryption
  - item model and search
  - sync metadata and conflict handling
  - direct typed import and structured export conversion
        |
        v
Local filesystem vault directory
        |
        v
External sync provider
  - untrusted file transport only
```

The current `psw-cli` retains the non-secret `psw doctor` diagnostic interface
and exposes the same local workflow under the public
`keptnear vault doctor` namespace. Separately, `keptnear` defines seven
machine-command families for status, authorized search, access request, grant
status and revocation, brokered HTTP, and direct child execution. Help,
version, strict typed argument parsing, and redacted failures are implemented.
The source-level machine commands connect through the owner-only Broker socket
and shared first-party authentication client. Status
negotiates compatibility and reads only the ephemeral Broker identity without
creating a Consumer key. Other commands load or create an independent
device-only CLI signing key, complete pairing and connection authentication,
then dispatch the same typed requests as MCP. They do not open or decrypt a
Vault directly. Results use one versioned JSON envelope; HTTP bodies and child
streams are represented as base64 rather than written as unframed terminal
bytes. `keptnear run` supplies no raw field or substitution placeholder in its
request: the Broker resolves placement from the exact target and Usage Profile.
Local help discloses the compatibility boundary, and every run result includes
only a fixed `compatibilityDelivery` object describing child retention,
future-delivery-only revocation, and required upstream rotation. `psw-broker`
provides the private `~/.keptnear` directory boundary plus explicit creation
and loading of an opaque 256-bit device root key in the non-synchronizing macOS
Data Protection Keychain. Its encrypted device-state database, versioned
protocol dispatcher, and owner-only macOS Unix socket transport primitives are
implemented in Rust. A process-owned vault-session manager also implements
current-format vault open, master-password and local-material unlock, manual
lock, monotonic idle auto-lock, close, and shutdown. Broker protocol v1 exposes
typed `credential.search`, `access.request`, `grant.status`, `grant.revoke`,
`http.request`, and `process.run` messages. Every such request requires its
exact negotiated capability and a connection-authenticated Consumer; the
dispatcher derives `consumer_id` from that connection rather than accepting it
from request JSON. A local-data coordinator can reopen
preserved Keychain and SQLCipher state after reinstall without implicit
initialization, or perform an explicitly confirmed, ordered, verified clear of
the managed database files and device root key. It never removes portable
vaults. The macOS App now exposes the local Apps & Tools control plane through
the in-process FFI boundary.

That FFI boundary synchronizes each successful human unlock by presenting both
the selected path and the authenticated stable `vault_id` to the Broker. It
never reuses a Broker session from `vault_id` lookup alone. The Broker
canonicalizes and reopens the path before reuse or insertion. A duplicate-copy
or changed-identity conflict locks the older machine session and makes its
grants unusable, while the separate human core session stays unlocked. Swift
receives only a Boolean conflict signal, clears the Apps & Tools projection,
and does not receive either canonical path from the Broker.

The Broker protocol now exposes Consumer pairing and per-connection
authentication through its runtime-aware dispatcher. Pairing start is
idempotent for one public key while a request remains pending, so an adapter
can resume after the user approves it. A completed pairing still creates no
Access Rule or Use Grant. Authentication then requires a separate,
connection-bound Ed25519 challenge and proof before the connection stores its
Consumer identity.

The separate App-to-Broker human-control protocol is frozen in source as
`keptnear.human-control` version 1.0. Its 29-operation catalog covers controller
session negotiation, readiness, pause, machine Vault lock state, pending human
decisions, authorization inventory, Usage Profiles, revocation, audit, repair,
and shutdown. It contains none of the six Consumer machine capabilities. Only
the Vault unlock request can carry a bounded unlock credential, while every
result is secret-free. The related `keptnear.controller-authority.v1` source
contract freezes Ed25519, the shared App-and-Broker Data Protection Keychain
access group, bootstrap and authentication transcripts, replay bounds, and a
marker-backed fail-closed removal lifecycle. The external dispatcher, runtime
Keychain adapter, SQLCipher public trust record, challenge manager, closed wire
validator, process lock, and readiness projection are implemented and tested in
source. The App human-control client and ServiceManagement lifecycle remain
unimplemented, so installation still does not activate the service.
See `docs/human-control-protocol.md`.
The controller authority details are in
`docs/controller-authority-contract.md`.

`keptnear-client` holds the shared first-party Ed25519 identity, Data Protection
Keychain, protocol negotiation, pairing, connection authentication, and framed
request client used by MCP and CLI. MCP and CLI use distinct stable Keychain
services, so a same-named profile does not accidentally share authorization
across adapters. The MCP service and account layout remains backward
compatible.

`keptnear-mcp` is a local newline-delimited stdio MCP adapter. It implements
the finalized 2025-11-25 and 2025-06-18 initialization lifecycle, stores each
selected Consumer signing seed in a separate non-synchronizing macOS Data
Protection Keychain account, negotiates Broker protocol v1, starts or resumes
local pairing, and completes the Broker authentication challenge. After
authentication it exposes six closed-schema MCP tools matching the Broker
capability names; while pairing is pending or the Broker is unavailable it
advertises no tools. Tool results
contain structured bounded operation results plus equivalent text content for
compatible hosts; they never intentionally return the selected field, and there
is no `secret.get`. The existing `access.request` tool also accepts
Consumer-scoped status, resume, and bounded wait operations for a stable
approval identity. Those receipts contain only status and time boundaries;
foreign and absent identities are indistinguishable. Separate pairing
profiles can be selected with one bounded canonical `--profile <id>` argument:
the no-argument default retains the legacy `default-v1` Keychain account,
while each named profile has a different key and therefore a different Broker
Consumer permission set. The profile label never crosses the Broker protocol.
The stdio parser rejects duplicate object keys at any depth, accepts standard
`_meta` objects without treating them as credential input, and keeps the same
six-tool contract for both frozen MCP revisions. Cancellation notifications are
silent and their free-form reasons are discarded. Because this adapter executes
one bounded Broker request synchronously, a notification does not preempt work
already handed to the Broker; approval waits and process execution remain
bounded to five minutes and HTTP uses its fixed Broker timeout. The public CLI
uses the same access lifecycle: submission waits once through the five-minute
Broker bound by default, while one valueless `--no-wait` flag returns the
secret-free submission receipt immediately. It writes one versioned JSON
result, reports a pending timeout without polling indefinitely, and retains the
approval identity in a fixed post-submission wait error. Its process command
now preserves Broker compatibility delivery without command-line credential
expansion or unframed child-stream output and repeats the fixed trust boundary
in help and machine output. It accepts only a response matching the requested
capability, writes one JSON result, and propagates numeric child statuses from
0 through 255. A missing, signaled, or out-of-range child status maps to
generic failure while remaining represented in JSON. Native terminal
interruption closes the Unix socket; a non-consuming peer probe connects that
closure to the process cancellation token, which closes secret input and kills
and reaps the direct child. It does not claim cleanup of independently
surviving descendants. End-user host activation and packaging the installed
long-running Broker service remain planned. The provider-neutral local host
configuration contract and current packaging limitation are documented in
`docs/mcp-setup.md`. Human shell, script, and Agent subprocess use are
documented separately in `docs/cli-usage.md`. That guide uses capability calls
and synthetic stable IDs rather than credential retrieval examples, leaves all
pairing and access decisions in the local human control plane, and treats
returned service or child output as untrusted.

The process-local Consumer pairing state machine is implemented behind the
runtime boundary. It holds at most 64 pending requests for five minutes using
monotonic time, derives a ten-character Crockford Base32 comparison code from
the request identity, Ed25519 public key, and fresh client and Broker nonces,
and allocates an immutable `consumer_id` only after explicit local approval.
The Consumer must then sign the fixed-order, length-prefixed
`KeptNear pairing v1` transcript. Only a strict Ed25519 verification creates
the encrypted device-local Consumer row, and it creates no Access Rule or Use
Grant. Invalid proofs are consumed to prevent replay.

`BrokerRuntime` is the only public pairing facade. The process-local pairing
manager and direct Consumer insertion remain crate-internal, and the runtime
pairing methods accept no vault, credential, field, capability, rule, or grant
input. A completion explicitly reports that authorization was unchanged.
Pairing and unlock approval subjects cannot project an authorization target;
only a separately typed access approval can do so.

After pairing, the Broker issues a fresh random session identity and 32-byte
nonce with a 30-second monotonic deadline. The Consumer signs the fixed-order,
length-prefixed `KeptNear broker auth v1` transcript containing the negotiated
protocol, session, Consumer identity, pairing public key, and nonce. Completion
consumes the challenge, verifies that the Consumer still exists with the same
key, rate-limits failures, and records only stable non-secret audit state.
Authentication identifies one connection; it does not create or imply
credential authorization.

Labels and OS-observed evidence are never authorization joins. Two Consumers
with the same label, executable basename, bundle identifier, or signing
evidence remain distinct when their pairing keys differ, and neither inherits
the other's rules or grants. Completing a pairing does not mutate either
Consumer's authorization state. Protocol capabilities are negotiated
independently, and every capability request still requires connection
authentication plus its own Access Rule and Use Grant checks.

`BrokerRuntime` is the current pre-listener startup boundary. It prepares
current-user paths, reopens existing Keychain and SQLCipher state, restores the
global machine-access gate, removes grants tied to sessions from a previous
process, and only then creates a fresh process core. A restart never restores
unlocked vault sessions, pending pairing requests, or a prior process identity.
Graceful shutdown cancels pending pairings, ends sessions, and removes grants
transactionally; abrupt-exit cleanup runs before the next runtime can be
returned.

## First-Version Target

```text
macOS App
  - human vault workflows
  - typed credential editors and smart views
  - Apps & Tools management
  - approvals, audit, and recovery
             |
             v
Local Broker
  - machine-facing unlocked vault sessions
  - Consumer pairing and identity
  - Access Rules and Use Grants
  - asynchronous approvals and global pause
  - brokered HTTP and compatibility execution
             |
             v
Rust core
  - key envelopes and cryptography
  - authenticated typed records
  - migration, import, export, and conflict logic
             |
             v
.pswvault

MCP adapter ----\
                 > current-device local IPC -> Broker
KeptNear CLI ---/
```

## Trust Boundaries

### Rust core

The Rust core is the only layer allowed to interpret encrypted vault records.
UI and adapter clients must not parse, decrypt, merge, or rewrite vault records
independently.

Current-format refresh derives logical heads from authenticated parent
ancestry. With exactly two heads, it may write a two-parent merge revision only
when one unique known semantic base and stable component identities prove the
changes independent. Same-Secret-Field edits, the aggregate unstable text
component, field-shape or lifecycle changes, missing or ambiguous ancestry,
rejected records, and larger head sets remain conflicts. Equivalent offline
multi-parent merge revisions converge only when complete content, lifecycle,
and exact parents match; ordinary single-parent edits remain distinct and
random revision and device IDs remain intact. Unsafe refresh never rewrites,
moves, or deletes authenticated head records. Manual resolution is also
append-only and names every resolved head as a parent.

The Core also owns the current-format conflict candidate projection. It returns
open typed text fields plus redacted Secret Field descriptors and internal
change flags, including deleted heads, without returning secret bytes. FFI maps
that closed projection directly into Swift. The App may compare candidates and
select one complete Revision ID, but it cannot parse records or synthesize a
secret merge. Core revalidates the selected logical head and writes a fresh
descendant with the selected Credential and lifecycle. The legacy explicit
non-secret field merge is advertised only when all candidates convert
losslessly to a supported built-in item.

Supported import adapters produce the extensible credential schema directly.
Current-format commits allocate fresh local Credential and Secret Field
identities and persist them in authenticated encrypted revisions; external
provider IDs are never authorization identities. Import preview writes
nothing. Duplicate discovery reads current typed heads without forcing custom
templates through the frozen v1 model and never compares secret values.

For plaintext export, the interactive App passes the current master password
through FFI as secret input. The Rust core reopens the current key envelope,
unwraps it with that password, and verifies that the resulting Vault Key
matches the active unlocked session before building a snapshot or touching the
destination. A session ID by itself is insufficient. The default
`keptnear-json` serializer preserves ordered fields, provider-neutral secret
kinds, arbitrary secret bytes, status, tags, favorite state, and source
identities for provenance. It excludes deleted credentials and reports
conflicted credentials and rejected encrypted records as structured omissions.
Compatibility serializers such as `bitwarden-json` may emit only credentials
they can represent completely; an unsupported template or field skips the
whole credential instead of producing a partial item.

The structured export schema is a closed credential snapshot, not a device
state container. It reads neither `~/.keptnear` nor Keychain trust material and
has no fields for Consumers, Access Rules, Use Grants, Usage Profiles,
approvals, audit, machine-access settings, runtime state, or convenience
unlock. Source Vault, Credential, and Secret Field identities are provenance,
not transferable authorization.

### Local Broker

The first-version Broker is the only machine-facing layer allowed to own
unlocked vault sessions, evaluate Consumer access, issue grants, and execute
credential-use capabilities. MCP and CLI are adapters, not independent vault
clients. The dispatcher now routes all six version-one machine capabilities to
the Broker runtime only after capability negotiation and Consumer
authentication.

The macOS transport binds only
`~/.keptnear/runtime/broker-v1.sock`. It requires an owner-only `0700` runtime
directory and `0600` socket, rejects unsafe endpoint entries, and accepts only
peers whose OS-observed effective user matches the Broker user. This
same-user check does not replace Consumer pairing authentication. No public,
LAN, or ordinary localhost TCP control port exists.

### Machine interfaces

MCP and CLI share a versioned capability model. They do not return raw secret
fields through tool results, standard output, diagnostics, logs, or audit.
The closed Broker v1 model contains only `credential.search`,
`access.request`, `grant.status`, `grant.revoke`, `http.request`, and
`process.run`; complete plaintext export is not representable by a Consumer,
Access Rule, or Use Grant. MCP advertises the same six tools and no export
tool.
The CLI parser has no get, reveal, copy, print, dump, plaintext-backup, or
whole-Vault export branch, and rejects equivalent raw-output options before
Consumer identity or Broker access. Known command interpreters and environment
launchers fail direct-process validation; shell-like text passed to another
executable is literal because KeptNear performs no interpolation.
The public CLI guide preserves this boundary for both human and Agent callers:
it never suggests moving a field into shell state, Agent context, project
files, or persistent configuration, and it does not present documentation as
Agent-policy enforcement.

`keptnear vault doctor [--json] <vault-path>` is outside that machine
capability catalog. It reuses the legacy read-only `psw doctor` inspection,
does not accept a pairing profile, and touches neither the Consumer Keychain
nor the Broker. It reads only local portable structure and public format
metadata, counts encrypted records, reports local unlock-envelope presence,
omits the supplied full path, and does not unlock or decrypt item records.

`http.request` keeps credential placement inside the Broker and is reachable
through the authenticated Broker protocol, MCP tool, and source-level public
CLI. The macOS App does not yet expose machine execution actions.
`process.run` is explicit compatibility delivery to a child process; after
delivery, that process can retain the secret and upstream rotation is required
for complete invalidation. A child or remote service can transform delivered
material beyond exact-echo redaction, so the closed first-party command model
is not a sandbox or general data-loss-prevention claim.

### Local filesystem and sync

The local filesystem is storage, not an integrity authority. Record
authentication must detect tampering or partial sync corruption before
plaintext is exposed.

Sync providers are untrusted. They may observe filenames, file sizes,
timestamps, directory shape, and encrypted bytes. They must never receive
plaintext vault contents, vault keys, master passwords, recovery keys, or
device-local Consumer trust from KeptNear.

Machine-facing Vault registration maintains at most one canonical path for one
stable `vault_id` in a Broker process. This is an encounter-time invariant, not
a filesystem-wide duplicate scanner. A second registered path with the same ID
or a tracked path with a changed ID fails closed before machine unlock.

## Data Boundaries

Portable `.pswvault` data:

- encrypted credentials and secret fields
- stable vault, credential, and field identities
- key and recovery envelopes
- authenticated revisions, tombstones, and attachments

Device-local `~/.keptnear` state:

- Consumer identities
- Access Rules and Use Grants
- Usage Profiles and pending approvals
- encrypted audit records
- runtime IPC and a reserved private logs directory

Device-local trust does not sync with `.pswvault`. App removal or reinstall does
not delete `~/.keptnear` unless the user explicitly clears local data.
The root key that encrypts this state is not stored in that directory. It uses
a separate `ThisDeviceOnly` Keychain item and is exposed only as an opaque,
zeroizing type inside `psw-broker`.

Portable backup copies an exact allowlist from `.pswvault`: `vault.json`,
`keys.enc`, optional `recovery.enc`, `items/`, `attachments/`, and
`tombstones/`. It excludes the vault-local `local_unlock.enc`, every
`~/.keptnear` entry, the Keychain device root, Consumer signing identities, and
local convenience-unlock keys. Restore copies the same allowlist and does not
recreate or modify device-local trust. Plaintext export separately serializes
only the closed authenticated credential snapshot described above.

`~/.keptnear/state/device-v1.db` is an implemented SQLCipher 4 database with
encrypted headers, page HMAC authentication, WAL mode, schema version 2, and
owner-only database, WAL, and shared-memory files. Schema version 2 adds one
singleton controller-authority table containing only the contract, algorithm,
derived controller identity, public key, and creation time. Authenticated
version 1 state migrates transactionally; future versions fail closed. The
Broker derives its raw
database key from the device root with HKDF-SHA-256 and the domain
`KeptNear device state SQLCipher v1`, then calls `sqlite3_key_v2` through one
narrow audited FFI module. The key is never placed in SQL, a command line, an
environment variable, a preference, or a file.

The schema stores strong typed identities and bounded non-secret state for
Consumers, Access Rules, Use Grants, Usage Profiles, approvals, device pause
settings, audit events, and the singleton public controller authority. It has
no columns for vault keys, controller seeds, master passwords,
recovery keys, Consumer private keys, raw credential fields, request or
response bodies, URLs, command arguments, standard streams, or full paths.

Audit writes and retention changes use one immediate SQLCipher transaction.
The policy defaults to 90 days, accepts 1 through 3650 days, and independently
caps retained history at the newest 10,000 events. Broker startup advances a
persisted monotonic retention watermark and prunes before exposing the runtime;
clock rollback therefore cannot extend earlier retention. Audit remains in
device-local state and is never written into or synchronized with a
`.pswvault`.

The trusted local runtime can read audit through newest-first pages capped at
500 events. Exact typed filters cover event kind, decision, Consumer, Vault,
Secret Field, capability, and time window. A timestamp-plus-event-ID cursor
keeps continuation stable when newer events arrive. Confirmed clearing removes
only the filtered SQLCipher rows and reports counts. Troubleshooting export is
a bounded versioned JSON projection of the same fixed non-secret fields; it is
not a Consumer protocol capability and does not write a destination itself.

The macOS support report uses a separate closed snapshot schema. In
particular, Rust core availability maps to `connected` or `unavailable`; the
report never forwards the Core service's free-form status string. Regression
coverage seeds a real encrypted credential and adversarial request, command,
path, stream, and response markers, then scans audit view/debug/export and App
diagnostics for those markers. This proves the implemented audit and
diagnostic projections; later MCP and CLI output scanning remains a separate
adapter-level gate.

The public runtime's outbound-operation boundary accepts only
`http.request` and `process.run`. It authorizes the exact Use Grant, commits a
non-secret pending audit event, and only then returns an opaque,
single-finalization authorization. Finalization consumes that value and
records success or failure with the same Consumer, field, capability, and
Grant identities. Paused and denied attempts are recorded without returning
an authorization; non-outbound capabilities fail before Grant consumption.
The lower raw Use Grant authorization helper is crate-internal so future
external adapters cannot bypass this attribution contract.

The attribution layer itself contains no destination, payload, telemetry,
template-download, or background-network configuration. Both `http.request`
and `process.run` executors connect through that boundary and are exposed only
through authenticated, capability-negotiated Broker protocol requests. The MCP
adapter and source-level CLI delegate their corresponding operations to those
requests; the App cannot yet invoke either executor.

The HTTP executor resolves one exact Consumer-owned Usage Profile and capability
before consuming a Use Grant. It then commits the pending audit event, reads
only the exact active Secret Field named by the target and expected kind, and
places it in either `Authorization: Bearer` or one validated custom header. A
caller cannot override the placement header.

Version 1 accepts only bounded HTTPS URLs without URL credentials or fragments,
at most 32 bounded non-framing headers, and at most a 1 MiB request body. It
uses a fixed 30-second timeout, follows no redirects, ignores environment proxy
settings, and creates a fresh cookie-free transport agent for each operation.
Transport logging is compiled out so dependency debug output cannot retain URLs
or custom secret headers.

The response contract contains only a numeric status code, at most 1 MiB of
body, and a truncation flag. Response headers and reason phrases are omitted,
and exact occurrences of the placed secret are replaced before return,
including an occurrence that crosses the capture boundary. Errors collapse
validation, placement, unavailable-field, and network failures into fixed
non-reflective categories. The remote service still receives the secret and
controls the response; exact-echo redaction cannot detect transformed or
encoded derivatives.

The Unix `process.run` executor accepts one absolute dot-segment-free executable
path, at most 128 bounded non-secret arguments, an optional absolute working
directory, at most 64 explicit non-secret environment entries, and a timeout
from greater than zero through five minutes. It calls the OS process API
directly, rejects common shell launchers and `/usr/bin/env`, clears inherited
environment state, defaults the working directory to `/`, connects no terminal
or PTY, and always pipes stdout and stderr.

A Consumer-owned Usage Profile selects exactly one placement. Text secrets may
enter one validated child-only environment variable. Binary secrets may be
written to secret-only stdin with an optional newline, or to the anonymous
stdin pipe remapped inside the child to descriptor 3; an optional environment
reference contains only `3` or `/dev/fd/3`. The Broker creates no named pipe,
temporary file, or persistent plaintext artifact. It also rejects a request
whose path, arguments, working directory, or explicit environment already
contains the exact selected secret.

Secret writers and child output are non-blocking so writes, reads,
cancellation, timeout, and child status are advanced together without pipe
deadlock. Each returned stream is capped at 1 MiB and passed through a
chunk-boundary-safe exact-secret redactor. Timeout or cancellation closes the
writer and kills and reaps the directly launched child. Controlled placement,
capture, and returned-output buffers are zeroized on drop. A nonzero child exit
is still a completed execution and is returned as a numeric exit code. The
public CLI writes the structured result and propagates valid numeric child
statuses from 0 through 255; signal termination or a missing or invalid status
maps to exit 1. Native CLI interruption closes the local connection, whose
non-consuming readiness probe triggers the same direct-child cancellation and
reap path without consuming a pipelined frame. Spawn, delivery, capture, wait,
timeout, and cancellation failures use fixed non-reflective categories.

This compatibility boundary deliberately trusts the selected child with the
delivered value. Exact matching cannot detect transformed output, a value
reconstructed across stdout and stderr, or downstream transmission. KeptNear
terminates only the direct child, not an independently surviving descendant;
revocation prevents future delivery but complete invalidation still requires
upstream credential rotation.

The current runtime also has no general-purpose persistent log writer. The
owner-only `~/.keptnear/logs` directory is reserved layout, not an active data
collection surface. Encrypted audit and user-copied App diagnostics are
separate closed projections governed by `docs/logging-policy.md`.

Network-adjacent flows do not share an implicit channel. The App performs local
file I/O against the selected `.pswvault`; an external file provider may sync
those encrypted files. Built-in Usage Profile templates are bundled offline,
and the current manual-update alpha does not contact an update server. Opening
a selected website delegates to the default browser. The local Unix socket is
current-device IPC and there is no public, LAN, or ordinary localhost TCP
listener.

The transport-independent Broker process core implements protocol v1 framing,
strict JSON parsing, `hello` compatibility negotiation, connection-level
dispatch state, and non-secret process status. Frames use a four-byte unsigned
big-endian length followed by one JSON object and are rejected before payload
allocation when the declared length exceeds 16 MiB. Duplicate object keys,
invalid UTF-8, unknown message types, unknown capability names, non-canonical
identifiers, incompatible versions, and fields outside the explicit
`extensions` object fail closed. Responses are typed and never echo request
payloads or parser diagnostics.

The macOS Unix transport validates the runtime directory and socket without
following symbolic links, refuses a live existing Broker, and removes a stale
socket only after owner, type, mode, and file-identity checks. Listener cleanup
removes only the unchanged socket it created. Accepted and connected streams
record `getpeereid` identity and reject a different effective user before the
protocol loop starts. The transport exposes accept, serve, and explicit
shutdown primitives.

The process core shares one vault-session manager across connection-loop
clones. It tracks only current-format vaults with stable `vault_id` values,
rejects duplicate identities at different paths and path replacement with a
different identity, and keeps canonical paths private. Unlock delegates to
`psw-core` with either a master password or device-local convenience material;
every successful unlock creates a fresh random `vault_session_id`. Public
snapshots expose only stable IDs and lock state.

One background worker uses monotonic time to lock idle sessions without waiting
for another request. Accepted human or credential operations may refresh the
idle deadline; rejected, unauthenticated, and polling requests must not.
Manual lock, close, timeout, and shutdown drop the unlocked core object and
emit the ended session identity. Shutdown cancels publication of concurrent
unlock results and waits until those results have been discarded. Every ended
session enters one bounded event queue. A checkpoint remains pending until a
SQLCipher grant-deletion transaction commits; events added during processing
remain queued, and overflow deletes every Use Grant rather than trusting an
incomplete list.

The grant-invalidation coordinator deletes grants by the exact
`vault_id + vault_session_id` pair. Consumer removal transactionally cascades
its rules, sourced and Allow Once grants, Usage Profiles, and approvals. Field
deletion removes the exact field's rules, every grant source, and approvals
while retaining non-secret audit history. Device-data reset preparation first
shuts down all vault sessions and then removes every grant; task 4.9 still owns
the confirmed database and Keychain deletion workflow. Worker startup is
fallible, so the process cannot silently run without automatic locking. None
of these controls is reachable from the current unauthenticated `hello` and
status protocol surface; Use Grant issuance is implemented internally but is
not protocol-accessible.

Explicit revocation uses three Runtime entry points. Consumer-field revocation
removes all capability rules, grants, and exact Access approvals for one
Consumer and one Secret Field. Consumer revocation removes that pairing
identity and all of its rules, grants, profiles, approvals, approved pending
pairings, and new-Credential context. Global revocation removes every Consumer
and all machine authorization plus all pending pairings and new-Credential
context.

Each durable deletion is one immediate SQLCipher transaction. Completion
reconciles process-local approval state and wakes status waiters. The scopes
are idempotent and return only removal counts. They preserve audit history,
pause state, the device root, portable vaults, and current human unlock
sessions. Operations admitted before the transaction may finish; future use
fails. Secrets already delivered to external processes require upstream
rotation and cannot be recalled by local revocation.

The machine-access gate loads the authenticated `apps_tools_paused` setting at
Broker startup. Every MCP, CLI, or third-party credential operation must
pass this gate before authorization or grant consumption. Pause and resume hold
one process-local mutex across the SQLCipher write, so a concurrent new
operation observes either the complete old state or the complete new state.
Failed persistence keeps the prior state, and an unreadable startup state
prevents gate construction. Pause returns the stable `broker-paused` protocol
error, but it does not lock a human vault session, revoke rules or grants,
consume a one-use grant, or erase pending approvals. Operations admitted before
pause began may finish; later operations are denied. All six current machine
protocol handlers pass through this gate before their runtime operation.

Accepted macOS Unix connections add path-minimized operating-system evidence
to the effective-user check. The transport reads the peer audit token, verifies
that its effective user agrees with `getpeereid`, keeps the process identifier
only for the live connection, and asks `proc_name` for an executable basename.
It never reads or stores the executable path. A narrow Security.framework
adapter may add a validated bundle identifier, team identifier, and
code-directory digest while explicitly disabling network checks. Missing,
unsigned, ad-hoc-signed, or otherwise unavailable signing evidence does not
reject the peer or prevent pairing.

Pairing snapshots expose only display-safe supporting evidence: the sanitized
executable basename and signing identifiers, a short code-signature
fingerprint when available, and a separate short fingerprint of the proposed
Ed25519 pairing key. These values help the user compare a request with the tool
they intended to pair, but they are not authorization inputs. The verified
pairing key and immutable `consumer_id` remain the durable Consumer identity;
the operating-system evidence is neither accepted from the client nor used as
a substitute for possession proof.

The runtime owns Access Rule creation and evaluation behind a typed manager.
Only an explicit human approval may create a rule, and the target is the exact
Consumer, vault, credential, Secret Field, capability name, and capability
version. The rule records confirmation policy and persistent or bounded
lifetime. Trusted Broker code derives the Secret Field kind from authenticated
vault content and validates capability compatibility at approval and operation
time; kind is not a Consumer-selected or separately persisted authorization
identity. Rule creation remains a human control-plane action while Apps &
Tools are paused; machine evaluation must pass the global pause gate before it
can inspect authorization state.

Rule creation requires an existing paired Consumer and checks the capability
against the Secret Field kind. `credential.search` is field scoped for
metadata authorization, while `http.request` and `process.run` use the shared
core compatibility matrix. Unsupported, non-field-scoped, or unknown
capability versions fail closed. An identical active rule is idempotent; a
different active policy or lifetime for the same target is rejected rather
than silently overwritten. Bounded rules are active only from their creation
instant up to, but not including, their expiry. An expired rule can be removed
and replaced by a fresh explicit approval, with insertion failure leaving the
target denied.

Evaluation requires the Secret Field kind obtained by trusted Broker code from
authenticated vault content, never a Consumer assertion. It matches every
target identity and the capability version exactly, then returns either no
rule or the matching policy. It returns no credential metadata or secret,
does not unlock a vault, and does not create or consume a Use Grant. Commands,
repositories, hosts, URLs, tasks, prompts, and Agent policy are intentionally
outside the Access Rule target.

`BrokerRuntime` is also the only public Use Grant facade; direct grant
insertion, removal, and consumption remain crate-internal. An explicit
`Allow Once` approval creates a source-less one-operation grant and no Access
Rule. Confirming an `every-use` rule creates a rule-sourced one-operation
grant. Confirming a `once-per-unlock-session` rule creates or reuses a
rule-sourced unlock-session grant, while an `automatic-while-unlocked` rule may
create or reuse that same session scope without another human confirmation.
Automatic issuance and every grant use pass the machine-access pause gate
first; explicit local approvals remain human control-plane actions while
paused.

Every grant binds the exact authorization target and current random
`vault_session_id`. It is active from creation until, but not including, its
absolute expiry, and a rule-sourced grant expires no later than its Access
Rule. Session-grant reuse requires the same rule, target, and unlock session;
a new unlock identity never inherits the prior grant. One-operation
authorization removes the exact grant with a checked SQL delete, so concurrent
SQLCipher connections can produce only one successful consumption. Target or
session mismatches do not consume the grant.

The runtime checks that the vault session is current both around issuance and
around authorization. A lock or session rotation therefore makes a stale grant
unusable even before the existing lock-event invalidation transaction removes
its row. Grant authorization returns only typed non-secret state; secret
retrieval, HTTP, and process execution remain separate capability tasks.

Automatic issuance preflights the exact active rule, and grant use preflights
the exact Consumer, target, Grant, and Grant session, before querying the
requested vault session. This non-mutating ordering prevents real or guessed
Vault identities from becoming an open-session oracle. Final authorization
still rechecks and atomically consumes one-operation Grants, preserving
revocation and concurrent-use behavior.

Authorized credential search is a narrow operation on top of that boundary,
not a full-vault query followed by Broker-side filtering. A request first
passes the machine-access gate and consumes or validates an exact
`credential.search` version 1 Use Grant. While holding the matching active
vault session, the Broker asks `psw-core` for the one current Credential
identified by the grant and rejects missing, archived, deleted, or conflicting
revision state.

The result is limited to zero or one Credential and contains only its stable
vault and Credential identities, title, and the one authorized Secret Field
descriptor: stable field identity, role, optional label, and authenticated
kind. Template, tags, favorite state, usernames, URLs, notes, other field
descriptors, every field value, and vault paths are excluded. The bounded
query matches only the returned title and authorized field role or label, so
omitted metadata cannot become an enumeration side channel. A changed or
missing authorized field, kind mismatch, wrong target, stale session, or
machine pause fails closed before any broader projection is returned.

The regression suite covers the complete known capability/Secret Field matrix,
same-presentation Consumer spoofing, pairing and one-operation replay, stale
Grant use across unlock and Broker identities, and indistinguishable denial
for real unrelated, random, and other-Vault metadata probes.

This search path exposes no secret value and is available through authenticated
Broker protocol, MCP requests, and the source-level CLI. It is not exposed as a
macOS machine-operation action.

New-credential matching uses a separate three-step boundary. A machine request
first passes the global pause gate and paired-Consumer lookup, then becomes a
process-local admitted request containing only the Consumer, Vault, requested
field-scoped capability, and a bounded display-safe description. Admission
does not read a Vault and provides no candidate accessor or serialization
contract.

The trusted human control plane may turn that admitted request into a review
for one exact current unlock session. `psw-core` may match the description
against authenticated non-secret text, including title, template, tags,
field roles and labels, usernames, URLs, and notes, but never against a Secret
Field value. The returned human-only candidates omit those matched text values
and contain only title, template, tags, favorite state, stable identities, and
Secret Field descriptors compatible with the requested capability. Reviews
are capped at 50 candidates and report truncation so the user can refine the
description rather than rendering an unbounded Vault catalog.

Human confirmation names one candidate and one compatible Secret Field. Before
returning the approved scope, the runtime confirms that the Consumer still
exists, the same unlock session is current, and every displayed candidate
attribute still matches freshly authenticated metadata. Any session or
displayed-metadata change makes the review stale. The result contains only the
exact authorization target, authenticated field kind, and the same minimal
single-field metadata used after approval; it creates no Access Rule or Use
Grant.

The internal asynchronous approval manager gives each request a stable random
identity. SQLCipher stores only its immutable secret-free subject, status,
creation and expiry times, and a coalescing digest keyed from the device root.
Machine-facing submit, poll, wait, and resume receipts contain status and
timing only. The trusted human queue has a separate projection.

Equivalent pending requests coalesce to the first identity and expiry.
Submission is serialized, pending state is capped at 256, request lifetime at
15 minutes, and one blocking wait at five minutes. Expiry and human decisions
share one conditional SQL update, so exactly one terminal state wins.
Consumer-scoped waits use monotonic elapsed time and continue after unrelated
approval notifications.

Exact Access and Unlock requests remain resumable after restart. Pairing and
new-Credential requests are cancelled because their proof, description, or
candidate context is deliberately process-local. New-Credential descriptions
are zeroizing and never enter SQLCipher or Consumer receipts. These
foundations are available through `BrokerRuntime`. `access.request` exposes
bounded submission, Consumer-scoped status, restart resumption, and waits of
one millisecond through five minutes through both Broker protocol and MCP.
These adapter receipts never include the approval subject, candidate metadata,
request description, or secret values.

## Modules

Implemented:

- `crates/psw-broker`: current-user device-path resolution, permission
  validation, opaque device-root-key lifecycle, and macOS Data Protection
  Keychain adapter, plus the authenticated SQLCipher device-state schema and
  typed repository, versioned Broker protocol, dispatcher,
  transport-independent connection loop, and permission-restricted macOS Unix
  socket transport, plus process-shared vault open, unlock, lock, idle
  auto-lock, close, and shutdown lifecycle with transactional grant
  invalidation for lock, Consumer removal, field deletion, and reset
  preparation, plus a persisted fail-closed global machine-access pause gate,
  Consumer pairing, resumable pairing protocol messages, connection-bound
  Ed25519 authentication, path-minimized macOS peer evidence, and exact
  field-scoped Access Rule creation and evaluation, plus Consumer- and
  unlock-session-bound Use Grant issuance and authorization, plus exact
  Grant-authorized
  single-Credential metadata search with a minimal field-scoped projection,
  plus process-local machine admission and human-only candidate matching for
  previously unauthorized Credentials, plus stable bounded asynchronous
  approvals with encrypted status persistence, Consumer-scoped polling and
  resumption, monotonic waiting, exact expiry, coalescing, and restart
  reconciliation, plus exact Consumer-field, Consumer-wide, and global
  transactional revocation with process-local cleanup, plus typed
  human-controller identities, restricted Keychain seed loading, SQLCipher
  public-record bootstrap, single-use challenge authentication, closed
  human-control wire and request dispatch, path-free readiness, and a
  process-lifetime single-Broker lock acquired before protected state or IPC.
- `crates/psw-core`: Rust vault core.
- `crates/psw-ffi`: macOS bridge.
- `crates/keptnear-client`: shared first-party Consumer identity, Keychain,
  Broker negotiation, pairing, authentication, and framed request client.
- `crates/psw-cli`: current diagnostic CLI plus the Broker-connected stable
  public machine-command contract.
- `crates/keptnear-mcp`: local stdio MCP lifecycle, device-local Consumer
  identity, Broker pairing and authentication, and six structured
  credential-capability tools.
- `apps/macos`: native macOS client.
- `fixtures`: sanitized import and vault fixtures.

Planned:

- installed Broker executable and long-running peer service

Additional module names selected during implementation must not change these
boundaries.
