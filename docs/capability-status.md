# Capability Status

Review date: 2026-08-12

KeptNear uses four public status labels. A feature moving between labels
requires implementation evidence, applicable tests, and an updated public-copy
gate. Source implementation is not the same as a shipped product capability.

## Available In The macOS Source Build

The current macOS source build provides the human password and token manager:

- local typed credentials for logins, secure notes, cards, software licenses,
  API tokens, API keys, SSH keys, certificates, and custom fields
- local search, TOTP, clipboard timeout, automatic lock, password health,
  recovery kits, import, deliberate plaintext export, encrypted backup, restore,
  and conflict handling
- encrypted directory vaults that users may place in an external file-sync
  folder
- English, Simplified Chinese, and Japanese presentation

These claims are covered by the Rust, FFI, and Swift suites run through
`scripts/check.sh`. External providers transport encrypted files; KeptNear does
not operate provider accounts or claim provider delivery behavior.

## Implemented And Tested In Source

The repository implements a device-local Broker, encrypted local trust state,
paired Consumer authentication, field-scoped rules and grants, approvals,
audit, machine pause, brokered HTTPS, and direct child-process compatibility
delivery. The MCP adapter and CLI use the same authenticated
`keptnear.broker/1.0` protocol and expose exactly:

- `credential.search`
- `access.request`
- `grant.status`
- `grant.revoke`
- `http.request`
- `process.run`

There is no raw secret retrieval command. MCP and CLI remain developer
interfaces that require a compatible Broker process; they are not labeled as
released end-user machine access.

The source also implements the separate `keptnear.human-control/1.0` controller
path: closed request and secret-free success/fixed-failure codecs, strict
Consumer-versus-Human-Control first-frame routing on the existing owner-only
socket, one authenticated server connection loop with lease and disconnect
cleanup, and a bounded Rust macOS client that uses an injected controller
signer and an existing restricted Keychain item. Deterministic tests cover both
connection classes, protocol ambiguity and incompatibility, full controller
authentication and management dispatch, EOF and timeout behavior, `0600`
temporary socket transport, and private-marker exclusion without a real user
Keychain or Vault.

This remains a source harness. The product Broker entry point does not activate
the router, the App FFI still owns its in-process Apps & Tools runtime, and no
installed artifact uses the shared controller Keychain path.

## Bundled But Not Activated

The local Apple Silicon packaging workflow bundles the App, Broker, MCP
adapter, CLI, FFI library, and component metadata. The artifact verifier checks
their post-signing hashes, executable presence, architecture, fixed
installation paths, and exact Broker protocol declaration.

Copying `KeptNear.app` to `/Applications` provides those executables inside the
bundle. It does not activate a long-running Broker service, merge the App's
in-process human-control runtime with the external Broker, or complete the
pairing, approval, operation, restart, upgrade, and uninstall lifecycle.

A dedicated ServiceManagement feasibility probe proves that an ad-hoc signed
local test bundle can register and run a per-user LaunchAgent on the recorded
test machine. A genuinely unsigned bundle is rejected with
`kSMErrorInvalidSignature`. This evidence does not change the shipped state:
the current product bundle contains no LaunchAgent and activates no Broker.

## Not Shipped

- The published Apple Silicon DMG is unsigned, not notarized, externally
  unaudited, and not recommended for production secrets.
- No end-user Broker service or supported MCP/CLI installation flow is
  released.
- No signed and notarized artifact has passed the optional distribution
  profile.
- No external security review is complete.
- No profile recommends production-secret use.
- No hosted vault, telemetry upload, automatic update, or provider sync service
  is operated by KeptNear.

## Promotion Rule

Public copy may promote a capability only after its implementation and tests
exist and the release profile for the claimed delivery state passes. A bundled
executable cannot be described as an activated service. A source command cannot
be described as an installed end-user workflow. A local or accepted-risk review
cannot be described as an external audit.
