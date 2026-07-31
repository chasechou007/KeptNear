# KeptNear Product Requirements

Review date: 2026-07-30

Document status: approved product direction; implementation status is stated
per section.

## Product Summary

KeptNear is a **local password and token manager**. It gives people one
user-controlled encrypted vault for passwords, tokens, keys, certificates, and
secure notes, plus an explicit local authorization layer for approved
applications and tools.

The product has three surfaces:

```text
macOS App       human control plane
Local Broker    unlock and authorization boundary
MCP + CLI       machine credential-use interfaces
```

KeptNear does not require a hosted account or vendor-operated sync service. A
vault remains an encrypted `.pswvault` selected by the user and may be copied by
untrusted file-sync tools such as iCloud Drive, Dropbox, or Syncthing.

The first complete product targets macOS on Apple Silicon. The public category
and data model are platform-neutral so a future Windows client does not require
a new product identity.

## Public Positioning

Brand:

```text
KeptNear
```

Chinese descriptor:

```text
本地密码与令牌管理器
```

English descriptor:

```text
Local Password & Token Manager
```

Public repository documentation defaults to English and provides a complete
Simplified Chinese README and product-overview mirror. Translation must not
promote a source-only or bundled capability into a released end-user claim.

Public summary:

> Keep passwords, tokens, and keys in a local encrypted vault, and decide which
> applications and tools may use them.

KeptNear is not positioned as an "AI password manager." Codex, Claude Code,
other Agents, CLI tools, MCP hosts, and ordinary applications are all generic
credential Consumers.

## Product Problem

Local-first password managers give people custody of a file but generally do
not offer a modern, explicit way for local development tools to use selected
credentials. Tokens consequently spread across shell profiles, `.env` files,
tool configuration, project documentation, and conversations.

Returning a token directly to an Agent is not an acceptable default because the
value may enter model context, tool results, logs, or terminal output. Requiring
the user to preconfigure a detailed provider connection for every token creates
too much setup.

KeptNear therefore needs to solve two related jobs:

1. Provide a polished local password manager for people.
2. Broker selected credential operations for paired local applications and
   tools without granting access to the rest of the vault.

## Target Users

Primary users:

- Individuals who want a local encrypted password vault instead of a mandatory
  vendor-hosted password account.
- Developers who keep long-lived or short-lived tokens for GitHub, GitLab,
  hosted APIs, infrastructure tools, and local automation.
- Users of Codex, Claude Code, MCP hosts, or similar tools who want controlled
  credential use without pasting secrets into conversations.
- Technical users who want an open format, file-based sync, and a native macOS
  control surface.

The first complete version is not designed for:

- Teams, shared vaults, organization administration, or enterprise policy.
- Hosted recovery, web access, billing, or a KeptNear cloud account.
- Remote Agents or remote Broker access.
- Browser autofill, passkeys, iOS, or family sharing.
- Users who require a third-party security audit or signed binary before any
  evaluation of the experimental project.

## Product Principles

### User custody

The user chooses where `.pswvault` lives and which external file transport, if
any, copies it. KeptNear does not operate the sync service.

### One product and one vault

Human passwords and developer credentials use one extensible item model, one
root unlock boundary, and one recovery boundary. They are organized with
templates and smart views rather than separate Apps or mandatory vaults.

### Default-deny machine access

Pairing a local application or tool does not grant credential access. Every
machine authorization is explicit and scoped to selected secret fields.

### Access, not intent

KeptNear controls which Consumer may use which secret field. It does not inspect
or modify Agent instruction files, judge task intent, or enforce repository,
command, domain, or prompt policy.

### No raw machine retrieval

MCP and CLI do not return passwords, tokens, TOTP seeds, private keys, or
generic secrets through tool results, standard output, diagnostics, logs, or
audit events.

### Progressive cognitive exposure

Saving a token requires a name and secret value. KeptNear introduces field
types, environment variables, headers, and other technical placement details
only when needed, with friendly templates before advanced configuration.

### Honest security boundaries

Local storage reduces hosted-service exposure but does not make a compromised
device, malicious authorized Consumer, weak master password, unsafe
compatibility delivery, or software supply-chain compromise harmless.

### No data lock-in

The encrypted format and migration behavior are documented. KeptNear supports
encrypted backup and explicitly confirmed plaintext export.

## Current Implemented Baseline

The following capabilities exist in the current macOS pre-alpha:

- Create, open, unlock, lock, close, switch, and reopen local `.pswvault`
  directories.
- New vaults use the documented v2 schema with stable vault, credential,
  secret-field, revision, and ancestry identities; frozen v1 vaults have an
  explicit verified-backup migration path.
- Argon2id master-password derivation, random vault-key wrapping, authenticated
  encrypted item records, tombstones, and local unlock envelopes.
- Login, secure-note, credit-card, and software-license workflows.
- Search, favorites, tags, item-type filters, archive, restore, duplicate, and
  conflict navigation.
- Login URLs, password generation, TOTP editing and code generation.
- Explicit secret reveal and managed clipboard clearing.
- Auto-lock on inactivity, sleep, session lock, app termination, and
  last-window close.
- Local Keychain convenience unlock without storing the master password.
- Offline-recovery setup with an explicit PDF or print destination,
  hidden-source full-code confirmation, two-phase recovery-key rotation, and
  locked-vault recovery to a confirmed new master password.
- Post-recovery removal of current and known legacy Keychain
  convenience-unlock entries, with explicit partial-success reporting if the
  operating system rejects cleanup.
- A Rust `psw-broker` foundation that resolves the operating-system account
  home without trusting `HOME`, creates the canonical device directories with
  mode `0700`, and rejects symlinks, unexpected owners, and insecure
  permissions.
- Explicit creation and loading of one opaque 256-bit device root key from the
  non-synchronizing macOS Data Protection Keychain, with no file fallback or
  silent replacement when the key is missing.
- Authenticated encrypted SQLCipher device-state storage for typed Consumers,
  Access Rules, Use Grants, declarative Usage Profiles, approvals, pause
  settings, and secret-free audit events.
- A transport-independent Broker process core with 16 MiB bounded framing,
  strict JSON parsing, protocol and capability negotiation, connection-level
  dispatch state, sanitized errors, and non-secret status.
- A macOS Unix socket transport at the private device runtime path with exact
  owner-only permissions, safe stale-endpoint recovery, OS-observed peer
  identity, replacement-safe cleanup, and no TCP control listener.
- A process-shared Broker vault-session manager for current-format stable vault
  identities, explicit master-password or local-material unlock, fresh unlock
  session identities, manual lock, monotonic idle auto-lock, close, and
  shutdown. This lifecycle remains internal and is not a machine credential
  API.
- Transactional invalidation of persisted Use Grants after any vault session
  ends, with retryable event checkpoints and fail-closed all-grant deletion on
  queue overflow. Consumer removal, field deletion, and reset preparation also
  revoke the corresponding authorization state without deleting audit history.
- An authenticated, persisted global Apps & Tools pause gate that rejects new
  machine operations with a stable error while preserving human vault
  sessions, rules, grants, approvals, and resume behavior. The management UI
  and all six current machine capability protocol handlers enforce this gate.
- Load-existing-only reinstall recovery for the device-bound key and SQLCipher
  state, plus explicitly confirmed local-state clearing that revokes sessions
  and grants before deleting verified managed files and then the Keychain root.
  Corrupt or missing-key recovery is supported without deleting portable
  vaults; the macOS confirmation surface remains planned.
- A fail-closed pre-listener Broker runtime that authenticates paths, key,
  SQLCipher state, and the persisted pause gate before creating a fresh process
  instance. Restart removes all grants tied to the prior process while
  preserving durable rules and control state; graceful shutdown ends sessions
  and removes grants transactionally.
- A Consumer pairing lifecycle with explicit local approval, strict Ed25519
  possession proof, path-minimized macOS recognition evidence, resumable
  versioned protocol messages, and no authorization side effect. A separate
  connection-bound challenge authenticates the paired Consumer before
  Consumer-scoped dispatch.
- A local `keptnear-mcp` stdio adapter implementing finalized MCP initialization
  revisions, a default device-only Consumer identity in the non-synchronizing
  macOS Data Protection Keychain, Broker pairing resumption, and per-connection
  authentication. After authentication it advertises closed-schema
  `credential.search`, `access.request`, `grant.status`, `grant.revoke`,
  `http.request`, and `process.run` tools and delegates them to the Broker
  without returning a raw secret. The `access.request` tool returns stable
  approval identities and supports Consumer-scoped status, restart resumption,
  and bounded wait results containing no approval subject or candidate data.
  A bounded `--profile <id>` selector stores a distinct device-only Keychain
  signing key for each named host profile, so separate profiles become
  separate Consumers and do not inherit each other's authorization. Omitting
  the selector preserves the original default identity. Duplicate JSON keys
  are rejected at every depth, both frozen MCP revisions share the same
  six-tool contract, standard `_meta` is accepted outside credential arguments,
  and schema/runtime parity plus private-input marker tests cover every tool.
  Cancellation notifications produce no output and their reasons are not
  retained, but the synchronous adapter does not preempt a Broker call already
  in progress; approval waits and process calls remain bounded to five minutes.
- A separate `keptnear` executable with a stable provider-neutral command
  parser for `status`, `search`, `access request`, `grant status`, `revoke`,
  `http request`, and `run`. It validates canonical typed identities and
  operation arguments, supports bounded device-local CLI profiles, requires an
  explicit direct-child separator, keeps HTTP body content out of process
  arguments, and uses fixed non-reflective failures. The source-level CLI now
  negotiates and authenticates over the owner-only Broker socket with an
  independent device-only Keychain identity, then returns versioned JSON
  results. Access requests wait once for up to five minutes by default or
  return an immediate secret-free receipt with `--no-wait`. Broker status does
  not create a Consumer key. The same executable also exposes the separate
  local-only `keptnear vault doctor` namespace. The existing `psw doctor`
  entrypoint remains compatible and the package default.
- Exact field-scoped Access Rule creation and evaluation plus Consumer- and
  unlock-session-bound Use Grant issuance. Allow Once, every-use confirmation,
  once-per-unlock-session confirmation, automatic-while-unlocked reuse,
  exclusive expiry, pause ordering, and atomic one-operation consumption are
  implemented behind the runtime. Machine access requests plus Consumer-scoped
  grant status and revocation are exposed through the Broker protocol and MCP;
  rule decisions remain in the local human control plane.
- Exact Grant-authorized metadata search for one stable Credential and one
  Secret Field. It returns only the Credential title and authorized field
  descriptor, searches no omitted metadata, exposes no value or vault catalog,
  and is exposed through authenticated Broker and MCP requests.
- A fail-closed outbound-operation audit boundary for `http.request` and
  `process.run` execution. It records pending, denied, paused, succeeded, and
  failed decisions using only stable attribution, while accepting no
  destination or payload fields.
- An internal Broker `http.request` executor with exact Consumer-owned Usage
  Profile binding, exact active Secret Field lookup, HTTPS-only bounded input,
  redirects and environment proxies disabled, internal Bearer or custom-header
  placement, fixed sanitized errors, compile-time-disabled transport logging,
  and a numeric-status plus bounded exact-echo-redacted response. It is exposed
  through authenticated Broker protocol, MCP, and the source-level CLI, but
  not the App.
- An internal Broker `process.run` executor with exact Consumer-owned Usage
  Profile binding, direct shell-free process spawn, bounded absolute paths,
  arguments and explicit child environment, child-only environment, stdin, or
  anonymous-descriptor placement, bounded exact-echo-redacted stdout and
  stderr, and direct-child timeout and cancellation cleanup. Authenticated
  Broker protocol, MCP, and the source-level CLI can invoke it. The CLI
  propagates valid numeric child statuses after its structured result and uses
  socket-disconnect cancellation to close secret input and kill and reap the
  direct child. App exposure remains.
- Three-step new-Credential matching with pause-gated paired-Consumer
  admission, a capped human-only review over authenticated non-secret text,
  capability-compatible field disambiguation, and confirmation-time session
  plus metadata revalidation. Candidate metadata is never returned at
  admission, and confirmation creates neither an Access Rule nor a Use Grant.
- Bitwarden JSON and generic CSV import converts supported records directly to
  typed fields with fresh local Credential and Secret Field identities. The
  warned default plaintext export preserves the authenticated typed model,
  requires current-master-password reauthentication enforced by Core before
  any destination write, and reports conflicts, rejected records, and
  compatibility losses as structured omissions. Complete plaintext export is
  available only through the interactive App; Broker, MCP, CLI, Consumers,
  Access Rules, and Use Grants cannot represent it.
- Encrypted backup and restore.
- Local file-sync refresh, rejected-record handling, quarantine,
  ancestry-aware conservative three-way merge, conflict candidates, manual
  safe non-secret merge, and stale-edit protection.
- Local password-health checks and non-secret diagnostics.
- English, Simplified Chinese, and Japanese interfaces.
- Apple Silicon unsigned DMG packaging plus optional signing and notarization
  tooling.

The following adopted capabilities are **not implemented yet**:

- macOS typed-credential templates and editors beyond the current supported
  login, secure-note, credit-card, and software-license surfaces.
- Installed Broker executable and long-running peer service.
- Authenticated protocol exposure of Broker vault-session controls.

No public documentation may describe those planned capabilities as currently
available.

## Domain Model

### Stable identity

Authorization uses immutable identities:

```text
consumer_id
+ vault_id
+ credential_id
+ secret_field_id
+ capability
```

Names, labels, tags, file paths, commands, URLs, and provider names are not
authorization identities.

### Credential model

A Credential groups related metadata and fields. Every secret-bearing field has
its own immutable identity and a provider-neutral kind:

- `password`
- `api-token`
- `api-key`
- `totp-seed`
- `private-key`
- `certificate`
- `generic-secret`

Templates such as GitHub Token or GitHub CLI are user-experience aids, not core
provider types.

### Consumer

A Consumer is a paired local application, CLI profile, MCP adapter instance, or
other tool. Pairing establishes a durable local identity and grants no
credential metadata or capability by itself.

Separate tools that share one pairing profile also share one permission set.
KeptNear identifies the paired integration, not the language model behind a
shared process. MCP hosts that need separate permission sets select different
canonical profile IDs; the profile label itself is local configuration rather
than an authorization attribute.

### Access Rule

An Access Rule is a durable device-local decision that permits one Consumer to
request one or more capabilities for selected secret fields.

The default rule does not restrict purpose, repository, host, URL, command, or
task. A persistent no-prompt rule means the user trusts that Consumer to use the
selected field for any purpose while the vault is available.

### Use Grant

A Use Grant is a revocable, Consumer-bound authorization for a bounded
operation or time window. Grants expire on their configured boundary and are
invalidated by vault lock, rule revocation, Consumer removal, or field deletion.

### Usage Profile

A Usage Profile is declarative device-local configuration describing how an
approved secret is placed into an operation, for example:

```text
HTTP header: Authorization: Bearer <secret>
Environment: GH_TOKEN=<secret>
```

Usage Profiles are not authorization rules and cannot contain executable
scripts.

## Authorization Experience

### First connection

```text
1. CLI, MCP, or App connects to the local Broker.
2. KeptNear creates a pending pairing request.
3. The user approves and names the Consumer.
4. KeptNear records its local pairing identity.
5. The Consumer still has no credential access.
```

### First credential request

The primary prompt is:

```text
[Deny] [Allow Once] [Configure Long-Term Access...]
```

Long-term confirmation policies are:

- confirm on every use
- confirm once after each vault unlock
- allow automatically while the vault is unlocked

Persistent permission never bypasses vault unlock. Locking invalidates active
Use Grants even when the Broker remains available.

### Pending requests

Approval is asynchronous:

- The Broker returns a pending request identity.
- The App uses notifications, badges, and an in-app queue without stealing
  focus.
- MCP can poll, resume, or wait for that Consumer-owned identity without
  receiving the approval subject or secret values.
- CLI may wait interactively or use non-waiting behavior.
- Equivalent requests are coalesced and all pending requests expire.

### Metadata privacy

A Consumer may search metadata only inside its authorized scope. When it needs a
new Credential, matching and disambiguation happen in the local human UI before
the Consumer receives identifiers or metadata.

## Credential-Use Interfaces

MCP and CLI share one versioned Broker capability model:

```text
credential.search
access.request
grant.status
grant.revoke
http.request
process.run
```

There is no `secret.get`.

### MCP

MCP is the structured interface for compatible AI and application hosts. The
local MCP adapter authenticates as its paired Consumer and delegates operations
to the Broker.

`docs/mcp-setup.md` documents one provider-neutral local stdio launch contract
and host-specific configuration syntax for Codex, Claude Code, and generic
compatible hosts. Host configuration contains only an absolute executable path,
arguments, and a non-secret pairing profile; it never bootstraps authorization
with a credential value. The Broker binary is bundled in the alpha App but its
installed service lifecycle remains unshipped, so the documented commands do
not constitute a complete end-user installation.

For brokered use, KeptNear places the secret into an HTTP request and returns a
sanitized response contract rather than the secret.

### CLI

CLI is a first-class interface for terminal workflows, scripts, diagnostics,
and existing command-line tools.

The stable `keptnear` command tree and typed parser are implemented, including
`status`, `search`, `access request`, `grant status`, `revoke`, `http request`,
and `run` as seven machine-use command families. It also provides
`vault doctor` as a separate local diagnostic action. That action accepts no
pairing profile, does not access the Consumer Keychain or Broker, and inspects
Vault structure without unlocking or decrypting records. The legacy
`psw doctor` entrypoint remains available. Neither command tree has a
raw-secret retrieval or whole-Vault export command.
Get, reveal, copy, print, dump, plaintext-backup, Vault-export aliases, and
raw-output options on otherwise valid commands fail with one fixed
non-reflective parse error before CLI identity or Broker access. Known command
interpreters and environment launchers also fail request validation.
The same boundary is structural in the Broker: its closed v1 capability set is
limited to credential search, access request, grant status and revocation,
bounded HTTP request, and direct process execution. Therefore no Consumer,
Access Rule, or Use Grant can authorize a complete plaintext export.
Shell-like argument text is never evaluated by KeptNear; it remains literal
caller-owned non-secret input to a permitted direct executable.
Source-level commands negotiate Broker protocol v1 over the owner-only Unix
socket. Status reads only non-secret process state; other commands select an
independent CLI profile key from the non-synchronizing Data Protection
Keychain, complete pairing and per-connection authentication, and dispatch
typed capability requests without parsing a Vault. Results use a
`schemaVersion: 1` JSON envelope. HTTP body files must be regular,
non-symbolic-link files bounded to one MiB, and HTTP response bodies plus child
streams are returned as base64 fields. Access requests wait once through the
five-minute Broker bound by default; `--no-wait` returns the submission
receipt immediately. Both paths write one secret-free result, and timeout
remains a pending state with the same approval identity. `keptnear run` help
now identifies the operation as compatibility delivery, states that KeptNear
does not expand the approved credential into the executable, arguments, or its
standard output, and explains the child-retention and upstream-rotation
boundary. Every completed run repeats that boundary through a fixed
`compatibilityDelivery` object while keeping bounded child streams in base64
fields rather than writing them as unframed terminal bytes. It then propagates
a numeric child status from 0 through 255. Signal termination, a missing
numeric status, or an invalid status maps to exit 1 while the JSON result keeps
the child-state distinction. Completed non-run operations exit 0, pairing
pending and runtime failures exit 1, and syntax failures exit 2. `Ctrl-C`
retains native terminal interruption behavior, normally observed as status 130
by a POSIX shell. Closing the owner-only socket triggers Broker cancellation,
which closes secret input and kills and waits for the direct child; KeptNear
does not claim to terminate independently surviving descendants. The CLI also
rejects a validly decoded but operation-mismatched response and keeps query,
description, URL, header, body path or content, executable argument,
environment, and working-directory markers out of success and fixed-error
projections.

`docs/cli-usage.md` is the source-level usage contract for human shells,
scripts, and Agents. It uses only synthetic stable IDs and non-secret inputs,
directs callers to request and invoke capabilities instead of retrieving a
credential value, and keeps pairing and access approval in the local human
control plane. It distinguishes native MCP hosts from CLI subprocess callers
without changing the Consumer permission model, treats returned service or
child output as untrusted, and states that KeptNear does not manage Agent
instruction files or infer intent. A repository gate prevents the guide from
regressing into common plaintext token retrieval or shell-persistence examples.
The protocol-verified component package exists, but Broker service activation
and the complete end-user machine workflow remain incomplete.

Compatibility execution follows this conceptual form:

```text
keptnear run <target-options> --usage-profile <id> -- <absolute-executable> [arg...]
```

The secret is delivered only through an approved non-output channel. The child
process can observe and retain it, so KeptNear can revoke only future delivery;
complete invalidation requires rotating the upstream credential.

This command boundary does not make an authorized child a secret-isolation
sandbox. A child can transform, encode, retain, or transmit a delivered field,
and exact-echo redaction cannot detect every derivative. That disclosed
compatibility limitation does not create a first-party `get` or export result.

The macOS control plane presents this compatibility warning on process requests,
long-term process authorization, command-line Usage Profile setup, saved
process profiles, field revocation, and Consumer unpairing. The warning states
that a child or descendant can read, retain, transform, or transmit the
credential; local revocation or unpairing stops only future KeptNear delivery;
and the user must rotate the credential with its provider to invalidate a
delivered copy. The CLI help preserves the same meaning before use, and the
closed JSON result records that a child or descendant may retain or transmit
the credential, revocation stops future delivery only, and upstream rotation
is required for complete invalidation. These fixed disclosures contain no
secret value or private process input.

## Usage Profile Experience

Usage Profile setup has three levels:

1. Recognized recommendation, such as GitHub CLI.
2. Natural-language selection such as Command-Line Tool or Web API.
3. Advanced header, prefix, environment variable, or other placement fields.

Built-in templates are bundled offline. User-created templates remain
declarative and device-local.

## Architecture Boundary

Planned first-version architecture:

```text
macOS App
  - human vault workflows
  - Apps & Tools management
  - recovery and approvals
             |
             v
Local Broker
  - machine-facing unlocked vault sessions
  - pairing, rules, grants, pause, and audit
  - brokered HTTP and child-process execution
             |
             v
Rust Core
  - key envelopes and cryptography
  - authenticated parsing and typed records
  - migration, import, export, and conflict logic
             |
             v
.pswvault

MCP adapter ----\
                 > local IPC -> Broker
KeptNear CLI ---/
```

The Broker accepts only current-device operating-system IPC. It does not expose
a public, LAN, or ordinary localhost TCP control port.

## Data Ownership And Storage

### Portable vault data

`.pswvault` contains:

- encrypted Credentials and secret fields
- stable vault, credential, and field identities
- key envelopes
- authenticated revisions and tombstones
- portable encrypted attachments

It does not contain device Consumer trust.

### Device-local state

The canonical local root is:

```text
~/.keptnear/
├── config/
├── state/
├── runtime/
└── logs/
```

It contains encrypted Consumers, Access Rules, Use Grants, Usage Profiles,
approval state, and audit events. Device-bound private material remains
protected by the operating-system credential store.

Deleting or reinstalling the App does not remove `~/.keptnear` unless the user
explicitly chooses to clear local KeptNear data.

The implemented root-key boundary keeps the 32-byte key out of this directory.
`psw-broker` has separate initialize-new and load-existing operations; it has
no load-or-create path that could generate a replacement over existing
encrypted state. The macOS adapter uses a local-only Data Protection Keychain
generic-password item with
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.

Reinstall recovery loads that existing Keychain item and authenticates the
existing SQLCipher database without initializing either one. Explicit local
device-state clearing requires confirmation, revokes sessions and grants when
state is readable, removes and verifies only `device-v1.db` plus its WAL and
shared-memory files, and then deletes and verifies the Keychain root. A state
removal failure retains the root key; a later Keychain failure is reported as
partial completion and can be retried. Corrupt or missing-key state has a
separate confirmed recovery path. These operations preserve the directory
layout and do not delete any `.pswvault`.

### Audit

Local encrypted audit records may include:

- event time
- stable Consumer and credential identities
- requested capability
- allow or deny result
- confirmation method
- grant identity

They exclude secrets, credential titles, request bodies, URLs, command
arguments, full paths, standard streams, and API response bodies.

Audit and machine-use events do not modify `.pswvault` and therefore do not
create file-sync churn.

The trusted local control plane can inspect audit in bounded newest-first pages
and filter by typed event fields and stable identities. Clearing is an explicit
confirmed action scoped to the current filter. Troubleshooting export is
versioned JSON containing only the same non-secret audit fields. These
capabilities are not exposed as Consumer credential operations.

## Recovery

Every new-format vault has:

- a random vault key
- an independent master-password envelope
- an independent offline-recovery envelope

The recovery key is high entropy, displayed for explicit external custody, and
never stored in plaintext in `.pswvault`, `~/.keptnear`, logs, or automatically
on the clipboard.

A valid recovery key allows the user to set a new master password without
rewriting every item record. Recovery-key rotation invalidates the old recovery
envelope. Keychain convenience unlock is not recovery.

If the master password and valid recovery key are both lost and convenience
unlock is unavailable, KeptNear cannot recover the vault.

## Sync And Conflict Requirements

Each durable revision records authenticated identity, parent ancestry, content
digest, and device identity.

- Modification time is not authoritative.
- Last-writer-wins is prohibited.
- Changes to provably independent stable IDs may be merged automatically from a
  known common base.
- Same-field, delete-edit, and ancestry-unknown conflicts preserve both
  authenticated encrypted versions.
- Secret conflicts require unlocked human resolution and are never silently
  merged.
- The unlocked macOS conflict view compares open typed Credentials without
  converting them through the closed legacy item model. Secret Field rows expose
  only role, label, immutable field ID, kind, presence, and whether the complete
  field differs. They never expose secret bytes or automatically compose a
  secret from multiple candidates.
- Whole-version resolution supports active, archived, and deleted heads. It
  preserves the chosen complete typed Credential and lifecycle in a new
  multi-parent descendant. Explicit safe non-secret field merge remains
  available only when every candidate has a lossless built-in legacy mapping.
- Unsafe refresh never rewrites, moves, or deletes either authenticated head.
  Delete-edit keeps both the item and tombstone records, and manual resolution
  appends a descendant naming all resolved heads.
- Automatic merge requires exactly two logical heads and one unique known
  authenticated base. It treats title, template, tags, and favorite as separate
  components; each Secret Field is separate by immutable field ID; all text
  fields are one component because they have no stable identities. Field shape
  changes, lifecycle differences, ambiguous ancestry, rejected records, and
  three-or-more-head conflicts remain manual.
- Independently authored multi-parent merge revisions with identical complete
  credential content, lifecycle, and exact parent IDs are equivalent logical
  heads despite their random revision and device IDs. Ordinary single-parent
  concurrent edits remain distinct. This convergence rule never equates
  different content or parent sets.
- Two paths with the same `vault_id` are treated as copies or a possible sync
  conflict. Machine-facing registration canonicalizes and reopens every
  presented path with the human-authenticated ID as an expected value; it never
  reuses a session from ID lookup alone.
- If a Broker process encounters a second path with the same ID or a tracked
  path with a changed ID, Apps & Tools fails closed while the human Vault
  remains unlocked. The App receives only a Boolean conflict signal, and
  Consumers receive only a generic protocol failure without either path or the
  identity-conflict reason.

Migration to a new vault format requires a verified encrypted backup and atomic
replacement. Older clients fail closed on unsupported future versions.

## Import, Export, And Portability

KeptNear supports:

- portable encrypted backup and restore
- explicitly confirmed structured plaintext export
- adapters for common password-manager formats
- public `.pswvault` format and migration documentation

Import preview is non-mutating. Import commit assigns fresh local Credential
and Secret Field identities rather than trusting provider record IDs.
Intentionally retained duplicate imports remain independently authorizable.
Duplicate detection uses non-secret semantics and must continue when the vault
contains open typed templates that have no frozen v1 representation.

The default human plaintext export uses the documented `keptnear-json` version
1 format. It preserves open template identifiers, ordered typed fields,
optional labels, provider-neutral secret kinds, active or archived status,
tags, favorite state, and arbitrary secret bytes encoded as Base64. Base64 is
reversible and provides no confidentiality, so the resulting file is
plaintext-equivalent.

Source Vault, Credential, and Secret Field identities are retained only as
snapshot provenance and field relationships. They carry no Consumers, Access
Rules, Use Grants, or other authorization, and a future plaintext importer must
allocate fresh local identities. Deleted credentials are excluded. Authenticated
conflicts and rejected encrypted records are omitted and reported with
structured reason codes and counts. A selected compatibility format must skip
an entire credential when it cannot represent every field rather than silently
emitting a partial secret-bearing item.

Complete plaintext export is available only from the interactive human control
surface after reauthentication and destination confirmation. MCP, CLI, Access
Rules, and Use Grants cannot export the complete vault.

Backups and exports are vault-data portability surfaces, not device-trust
migration. Their fixed allowlists exclude `~/.keptnear`, Consumers, Access
Rules, Use Grants, Usage Profiles, approvals, audit, machine-access settings,
runtime state, Keychain device and Consumer keys, and `local_unlock.enc`.
Restore or import must not recreate those relationships or enable convenience
unlock, and producing either output must not modify existing device-local
state.

## Privacy And Network Commitment

KeptNear:

- requires no KeptNear account
- operates no KeptNear cloud sync
- uploads no vault, metadata, Device State, audit, telemetry, or crash report
- bundles Usage Profile templates offline
- produces network traffic only for an explicit credential operation or a
  separately disclosed and configurable update check

An external file provider may transport encrypted vault files. An approved
`http.request` may contact an external service on the Consumer's behalf. Those
facts are disclosed rather than summarized as "KeptNear never uses a network."

For the current alpha, updates are manual and there is no automatic update
check. Authenticated Broker protocol, MCP, and the source-level CLI can invoke
the attributed `http.request` and `process.run` executors; the App cannot. The
App performs local file I/O against `.pswvault`; iCloud Drive, Dropbox,
Syncthing, or another provider owns any file-transfer traffic. Built-in Usage
Profile templates are never refreshed in the background.

An explicit credential operation is an authenticated named capability admitted
by the user's Access Rule and Use Grant policy. It does not necessarily require
a prompt on every use, and it cannot be repurposed as telemetry, support upload,
template delivery, or an unrelated background task.

Opening a selected website delegates to the user's default browser. An approved
`process.run` operation delegates the secret to a child that may independently
use the network; that downstream traffic is outside KeptNear's execution and
revocation boundary.

## Security Non-Claims

KeptNear cannot protect secrets from:

- a fully compromised operating system or privileged process
- keyboard or screen capture
- a malicious Consumer after the user grants it access
- an external child process after compatibility delivery
- an external service after an approved HTTP operation
- browser or child-process network behavior after explicit delegation
- theft of both a vault copy and valid recovery authority
- malicious build or dependency supply chain
- weak user-selected master passwords

Local audit proves the Broker's authorization decision. It does not prove user
intent, remote endpoint integrity, safe process behavior, or successful
upstream credential revocation.

Local-first is a custody and architecture choice, not an automatic security
guarantee.

## macOS First-Version Closure

The first complete KeptNear version requires all three areas.

### Human control plane

- Daily vault and typed Credential workflows.
- Templates, smart views, search, copy, reveal, and auto-lock.
- Offline recovery.
- Import, encrypted backup, controlled export, and conflict resolution.
- Apps & Tools management and local audit.

### Authorization core

- Local Broker and device-state encryption.
- Pairing, Access Rules, Use Grants, asynchronous approval, and global pause.
- Protected metadata and field-scoped authorization.
- Explicit network and audit boundaries.

### Machine interfaces

- MCP adapter.
- Public KeptNear CLI.
- Shared capability schema.
- Guided Usage Profiles.
- `http.request` and `process.run`.
- No raw secret output.

The following remain outside the macOS first-version closure:

- Windows implementation, while preserving a platform-neutral core
- iOS and browser extensions
- passkeys
- teams, sharing, and enterprise policy
- remote Broker and remote MCP control
- Agent behavior or project-instruction management
- KeptNear cloud accounts or hosted recovery

## Delivery Order

The complete product scope is fixed, but implementation follows dependency
order:

1. Freeze the current format baseline and fixtures.
2. Add stable identities, typed fields, revision ancestry, migration, and
   offline recovery.
3. Add `~/.keptnear`, device-key protection, and the local Broker.
4. Add Consumer pairing, field authorization, grants, approvals, audit, and
   pause.
5. Add the macOS typed-credential and Apps & Tools control surfaces.
6. Add Usage Profiles, brokered HTTP, and compatibility execution.
7. Add MCP and CLI adapters over the shared capability contract.
8. Complete import/export, three-way sync handling, packaging, documentation,
   and acceptance validation.

Sequencing is an architectural dependency plan, not removal of MCP or CLI from
the product.

## Acceptance Criteria

The macOS first-version closure is accepted only when:

- A user can create, recover, migrate, back up, restore, and deliberately
  export a typed vault.
- A user can pair two Consumers and give them different field-level access.
- An unauthorized Consumer cannot enumerate vault metadata.
- Locking the vault invalidates every active Use Grant.
- MCP can perform an approved brokered request without receiving the raw
  secret.
- CLI can launch an approved compatibility process without printing the secret.
- Revocation prevents future Broker delivery and accurately explains prior raw
  delivery limits.
- Device State survives App reinstall but does not silently transfer trust to a
  second device.
- Sync tests preserve both sides of unsafe conflicts and merge only provably
  independent changes.
- Seeded secret markers never appear in machine results, logs, diagnostics, or
  audit output.
- Source, unsigned DMG, and optional signed distribution readiness are reported
  as distinct profiles.

## Success Measures

- A user can complete normal password-manager work without terminal commands.
- A non-expert can save a token and approve a recognized Usage Profile without
  configuring raw headers or environment variables.
- A user can explain which Consumers can use which secret fields from the Apps
  & Tools view.
- An MCP or CLI workflow no longer requires pasting a token into a conversation
  or persistent shell configuration.
- Vault movement and external file sync do not break stable authorization
  identities.
- Recovery, migration, conflict, and export failures preserve the original
  encrypted data.

## Publication Policy

- The initial public project remains personal-interest, experimental, and
  unaudited.
- Source publication does not require an external audit or Apple signing.
- An unsigned Apple Silicon DMG may be published when its local build,
  integrity, disclosure, license, privacy, and installation checks pass.
- Signed and notarized distribution has separate stricter evidence gates.
- No source or binary profile claims suitability for production secrets during
  pre-alpha.
- GitHub Issues are accepted on a best-effort basis.
- External pull requests are not currently accepted.
- Security reports use the private reporting channel.
- The license is `GPL-3.0-only`.
- AI development records, OpenSpec history, and local Agent governance remain
  excluded from the public product-source repository.

## Related Public Documents

- `README.md`
- `README.zh-CN.md`
- `docs/product-overview.md`
- `docs/product-overview.zh-CN.md`
- `docs/architecture.md`
- `docs/security-model.md`
- `docs/vault-format.md`
- `docs/sync.md`
- `docs/logging-policy.md`
- `docs/release-readiness.md`
- `docs/macos-alpha-packaging.md`
