# KeptNear Product Overview

[English](product-overview.md) | [简体中文](product-overview.zh-CN.md)

- Document status: approved product direction
- Current release maturity: experimental pre-alpha
- Current binary preview: `v0.1.0-prealpha.2`

## In One Sentence

KeptNear is a local password and token manager that keeps credentials in a
user-controlled encrypted vault and lets the user decide which local
applications and tools may use selected secret fields.

## Why KeptNear Exists

KeptNear began with a simple conviction: if a vault belongs to the user, the
user should be able to keep it in a location they control and choose how its
encrypted files move between their own devices.

Local-first password managers preserve that custody, but many do not combine it
with a polished native experience. At the same time, developer credentials now
spread across shell profiles, `.env` files, tool-specific settings, project
notes, and Agent conversations. Copying a token into an AI conversation or
returning it through a tool result creates a new disclosure surface.

KeptNear therefore joins two related jobs in one product:

1. A modern local password manager for people.
2. A local credential-use broker for applications and tools.

The product is not positioned as an "AI password manager." Codex, Claude Code,
other Agents, MCP hosts, CLI tools, and ordinary desktop applications are all
credential Consumers. KeptNear controls credential access; it does not control
their intent or edit their instruction files.

## Product Promise

KeptNear is designed around five promises:

1. **User custody:** the portable vault remains a user-selected encrypted
   directory, not a record in a KeptNear cloud account.
2. **One product and one vault:** human passwords and developer credentials use
   the same extensible item model and root unlock boundary.
3. **Default-deny machine access:** pairing identifies a Consumer but grants no
   credential access by itself.
4. **Operations instead of raw retrieval:** machine interfaces request a
   scoped action; they do not expose a generic `secret.get`.
5. **No hidden lock-in:** format, backup, export, migration, release, and
   security boundaries are documented.

Local-first is a custody and architecture decision, not an automatic security
guarantee.

## The Product Model

KeptNear has three cooperating surfaces:

| Surface | Responsibility | Current delivery state |
| --- | --- | --- |
| macOS App | Human vault work, unlock, approval, settings, recovery, and audit control | Available in source and the unsigned experimental DMG |
| Local Broker | Device trust, Consumer authentication, authorization, grants, and credential operations | Implemented and tested in source |
| MCP and CLI | Structured machine interfaces over the same Broker protocol | Developer preview; bundled but not activated for end users |

```text
Human control
  macOS App ───────────────────────┐
                                   ├─ portable encrypted vault
Machine use                        │
  MCP host or CLI ─ Local Broker ─┘
                       ├─ exact Consumer identity
                       ├─ exact credential and field identity
                       ├─ approved capability
                       └─ bounded authorization lifetime
```

### The portable vault

A `.pswvault` is an encrypted directory containing portable credential data,
authenticated revisions, tombstones, attachments, and recovery envelopes.
Users can keep it in a normal local folder or inside a folder transported by
iCloud Drive, Dropbox, Syncthing, WebDAV, or another file tool.

KeptNear does not operate those providers, inspect their account state, or
claim that their delivery succeeded. They are untrusted transports for
encrypted files.

### Device-local trust

Consumer identities, Access Rules, Use Grants, approvals, pause settings, and
secret-free audit events are device-local. They are not part of the portable
vault and do not silently transfer to another Mac.

The device root key and machine Consumer identities use the non-synchronizing
macOS Data Protection Keychain. Managed state under `~/.keptnear` is encrypted
and remains after the App is removed so a normal reinstall can recover the
same local trust state. Explicit reset is a separate confirmed operation.

### Credential Consumers

A Consumer is any local application or tool asking KeptNear to perform a
credential operation. It may be an MCP host, CLI profile, development tool, or
ordinary application. KeptNear does not grant special trust because a
Consumer is described as an Agent.

Each Consumer has a cryptographic identity. Display names help the user
recognize it, but authorization binds stable identities rather than mutable
names, process labels, or natural-language descriptions.

## Human Experience

The macOS App is intended to cover normal password-manager work without a
terminal:

- create, open, unlock, lock, close, and reopen local vaults
- manage logins, secure notes, cards, software licenses, tokens, keys,
  certificates, and custom credentials
- search, filter, favorite, archive, duplicate, reveal, and copy
- generate passwords and TOTP codes
- clear managed clipboard values and auto-lock on security events
- inspect password health locally without a breach-service upload
- create and rotate offline recovery kits
- import, deliberately export, back up, restore, and resolve sync conflicts
- manage paired applications and tools from one human control surface

The experience should remain quiet, native, and understandable to users who do
not know Broker or MCP terminology.

## Machine Credential Use

The machine-access design reduces secret distribution without pretending that
an authorized operation is harmless.

### Simple first, advanced when needed

Saving an API token should require only a human-readable name and the token.
KeptNear generates stable internal identities automatically. Technical
placement such as an HTTP bearer header or child-process environment variable
is introduced later through guided Usage Profiles.

Usage Profiles are declarative, provider-neutral recipes. A built-in template
can offer a friendly default; advanced users can create a precise profile.
They contain no executable script and no secret value.

### MCP and CLI have different entry points

- **MCP** is the structured interface for a compatible host that already
  understands tools and typed results.
- **CLI** is the interface for human shell workflows, scripts, diagnostics, and
  direct child-process compatibility.

Both use the same Broker identity, authorization, operation, and audit model.
Neither interface owns a separate vault or policy system.

### Capabilities, not generic secret output

The source-level protocol currently defines:

- `credential.search`
- `access.request`
- `grant.status`
- `grant.revoke`
- `http.request`
- `process.run`

`credential.search` returns only authorized non-secret projections.
`http.request` places an approved credential inside a specific outbound
request. `process.run` can place an approved credential into a direct child
process for compatibility. That child can retain or disclose the value after
delivery, so KeptNear records and explains that boundary rather than claiming
revocation can erase an already delivered secret.

## Authorization Model

The intended end-user authorization flow is:

1. A local Consumer proves possession of its identity key.
2. The user confirms pairing in the macOS App.
3. The Consumer requests one capability against an exact credential field or
   asks for human-assisted matching.
4. KeptNear shows only bounded candidate metadata to the user.
5. The user denies, allows once, or creates an explicit reusable rule.
6. A Use Grant admits the exact operation for its permitted lifetime.
7. KeptNear records a secret-free local audit event.

Pairing is not authorization. A name match is not authorization. A previous
operation against another field is not authorization.

Users may choose convenience-oriented reusable rules or require confirmation
for each operation. KeptNear enforces the configured credential scope; users
remain responsible for deciding how much autonomy to grant each Consumer.

## Privacy And Network Boundary

KeptNear requires no account and currently:

- operates no hosted vault or sync service
- uploads no vault, metadata, device state, audit, telemetry, or diagnostics
- bundles Usage Profile templates offline
- uses manual application updates

Network traffic may still occur when:

- an external file provider transports encrypted vault files
- the user opens a saved website in their browser
- an approved `http.request` contacts a selected service
- an approved child process independently uses the network

Those actions are disclosed instead of being hidden behind the inaccurate claim
that local-first software "never uses the network."

## Security Boundary

KeptNear is designed to reduce exposure to a file-sync provider, accidental
plaintext persistence, broad local credential access, and raw secret output
through normal machine-interface results.

KeptNear cannot protect secrets from:

- a fully compromised operating system or privileged process
- keyboard, clipboard, memory, or screen capture outside its process boundary
- a malicious Consumer after the user authorizes access
- a child process or external service after an approved credential operation
- theft of both a vault copy and valid recovery authority
- a weak master password
- a compromised build or dependency supply chain

The project has not completed an external security audit. The current unsigned
experimental release is not recommended for production credentials.

## Current Scope

### In the macOS first-version closure

- complete native human password and token workflows
- portable file-sync vaults and explicit conflict handling
- offline recovery, backup, restore, controlled export, and migration
- local Broker, encrypted device trust, pairing, authorization, approvals,
  grants, pause, and audit
- supported MCP and CLI installation and lifecycle
- guided Usage Profiles, brokered HTTPS, and compatibility process execution

### Outside the first-version closure

- iOS and browser extensions
- passkeys
- teams, shared vaults, and enterprise policy
- remote Broker or remote MCP control
- hosted accounts, hosted recovery, or a KeptNear sync service
- Agent prompt, instruction, repository, command, or intent management

The first complete client is macOS-first. A future Windows client is compatible
with the product identity and platform-neutral Rust core, but is not part of
the current delivery plan.

## Road To 1.0

The product direction is stable; the compatibility promise is not yet stable.
The milestones below describe closure order, not release dates.

| Milestone | Definition |
| --- | --- |
| `v0.2.0-alpha.1` | Refine the macOS human vault, token workflows, navigation, and public product experience. |
| `v0.3.0-alpha.1` | Deliver high-fidelity KeePassXC migration with preview, explicit loss reporting, and fresh local identities. |
| `v0.4.0-beta.1` | Activate a supported Broker, MCP, CLI, pairing, approval, upgrade, and uninstall lifecycle. |
| `v0.9.0-rc.1` | Freeze vault and protocol compatibility, validate upgrade and recovery paths, and complete signed/notarized distribution. |
| `v1.0.0` | Commit to stable vault-format, protocol, migration, and core behavior compatibility. |

External review is valuable and remains required before recommending production
credential use, but open source publication and bounded experimental previews
do not claim that review has happened.

## What Success Looks Like

KeptNear reaches its first complete product when:

- normal password-manager work requires no terminal
- a non-expert can save a token and approve a guided usage profile
- users can see exactly which Consumers may use which secret fields
- MCP and CLI workflows no longer require pasting tokens into conversations or
  persistent shell configuration
- moving or synchronizing a vault does not silently transfer device trust
- migration, recovery, sync, and export failures preserve the original
  encrypted data
- source, unsigned, signed, and production recommendations remain separate and
  honest

## Related Documents

- [Product Requirements](product-requirements.md)
- [Brand](brand.md)
- [Capability Status](capability-status.md)
- [Architecture](architecture.md)
- [Security Model](security-model.md)
- [Vault Format](vault-format.md)
- [Local File Sync](sync.md)
- [Import And Export Formats](import-formats.md)
- [Logging Policy](logging-policy.md)
- [Release Readiness](release-readiness.md)
