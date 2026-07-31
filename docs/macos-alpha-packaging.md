# macOS Alpha Packaging

This project can create an Apple Silicon (`arm64`) DMG for local alpha testing.
The generated app targets macOS 13 or newer. By default the DMG is unsigned. If
Developer ID credentials are available, the same workflow can optionally sign
the nested Rust library, Broker, MCP adapter, CLI, app bundle, and disk image,
then notarize and staple the DMG.

Intel Macs are not supported by this first binary distribution target.

The alpha package is not a full public release decision even when signed and
notarized.

## Verify Local Alpha Readiness

Run the local alpha readiness verifier before sharing an alpha build with
trusted testers:

```sh
script/verify_local_alpha_readiness.sh
```

This command runs the broad repository checks, vault-format readiness verifier,
vault doctor readiness verifier, macOS security-state verifier, unsigned alpha
packaging workflow, alpha artifact verifier, Launch Services vault-type smoke
test. It generates the default unsigned alpha artifact under
`dist/releases/`.

Passing this command is local automated evidence only. The approved publication
policy has separate profiles for source preview, an explicitly unsigned and
unaudited experimental DMG, and optional signed distribution. Use the dedicated
profile commands below; a default `local-test` artifact is not publication
evidence.

On managed workspaces or automation agents where Launch Services registration
may be blocked, use report mode to run the local gate sequence and list current
blockers without approving local alpha readiness:

```sh
script/verify_local_alpha_readiness.sh --allow-missing
```

Report mode exits after printing blocker status and always states that local
alpha readiness is not approved. Strict mode is still required before sharing an
alpha build with trusted testers.

## Verify Publication Profiles

Verify source-only readiness without creating a DMG:

```sh
script/verify_source_preview_ready.sh
```

Verify an explicitly unsigned and unaudited experimental Apple Silicon DMG:

```sh
script/verify_unsigned_alpha_release_ready.sh
```

The unsigned command requires a clean source revision, AR-002 policy evidence,
all local quality and install checks, `RELEASE_MODE=unsigned-experimental`, and
strict artifact verification. It does not require or claim Developer ID,
notarization, Gatekeeper trust, or external review.

For a release operator with Developer ID credentials, notarization credentials,
signed-install verification, and completed external-review or maintainer
accepted-risk evidence, run the strict public-alpha release gate:

```sh
script/verify_public_alpha_release_ready.sh
```

On ordinary development machines, use report mode to list current blockers
without generating signed artifacts, contacting Apple notarization services, or
approving public alpha:

```sh
script/verify_public_alpha_release_ready.sh --allow-missing
```

Strict mode composes local alpha readiness, security review handoff package
generation and checksum verification, distribution environment preflight,
signed and notarized package generation, signed install verification, security
decision evidence verification. Report mode also runs the local handoff package
step, but it remains non-approving and does not complete external security
review. Passing strict mode is public-alpha release evidence only;
production-use recommendation remains a separate decision.

This is the signed-distribution profile. Source publication does not require
this command, and the unsigned profile must not reuse its result.

## Build The Alpha Package

```sh
script/package_macos_alpha.sh
```

The script requires an Apple Silicon build host and builds:

- Rust FFI dylib in release mode
- local `keptnear-broker`, `keptnear-mcp`, and `keptnear` executables
- SwiftPM macOS executable in release mode
- `dist/alpha-staging/KeptNear.app` with `.pswvault` document/package metadata
- `dist/releases/KeptNear-0.1.0-alpha-macos-arm64.dmg`
- `dist/releases/KeptNear-0.1.0-alpha-macos-arm64.dmg.sha256`
- `dist/releases/KeptNear-0.1.0-alpha-macos-arm64-manifest.txt`
- `dist/releases/KeptNear-0.1.0-alpha-macos-arm64-protocol-manifest.json`

The DMG contains `KeptNear.app`, `KeptNear-Protocol-Manifest.json`,
`KeptNear-SQLCipher-Distribution-Evidence.json`, and an `Applications` link for
drag-to-install. The App bundle keeps the Broker, MCP adapter, and CLI under
`Contents/Helpers`; the FFI remains under `Contents/Frameworks`. Packaging
fails if any executable or the FFI is not arm64-only, if any component declares
a different Broker protocol, or if a required component is absent.

Non-local packaging routes every Cargo command through
`script/run_reviewed_distribution_cargo.sh`. That runner resolves and hashes
the exact Rust/Cargo and Xcode native tools recorded in the SQLCipher receipt,
removes ambient compiler, wrapper, flags, linker, SDK, OpenSSL, and SQLite build
overrides, starts Cargo from an empty process environment, and supplies the
reviewed Apple Clang, SDK, deployment target, and C flags explicitly. It also
runs Cargo from `/` with an absolute workspace manifest, a private temporary
`HOME` and `CARGO_HOME`, the reviewed dependency archive/index cache in offline
mode, and a system-only `PATH`. Registry sources are re-extracted into that
temporary Cargo home so Cargo rechecks the locked package archives instead of
trusting mutable previously extracted source. Tool and source hashes use the
fixed macOS `shasum` under a separate minimal environment so Perl loader
variables cannot alter the result. User, workspace, and parent Cargo
configuration therefore cannot inject forced build-script environment values.
`local-test` remains a development-only path and does not claim this
distribution evidence.

The protocol manifest records the exact App, Broker, MCP, CLI, and FFI paths
and SHA-256 values, their component versions, the shared
`keptnear.broker/1.0` declaration, and fixed paths below
`/Applications/KeptNear.app`. It is generated only after nested code signing
and remains outside the signed App bundle to avoid a self-referential
signature/hash cycle. The text manifest records whether the source worktree
was clean; signed packaging fails unless it is built from a clean Git
worktree.

Bundling the Broker executable does not by itself install or activate a
long-running service. Until the App/Broker service lifecycle and human control
path pass end-to-end acceptance, the machine adapters remain a developer
preview rather than a complete end-user setup.

Set `VERSION` to override the alpha version label:

```sh
VERSION=0.1.0-alpha.2 script/package_macos_alpha.sh
```

## Optional Signing And Notarization

Before attempting a signed alpha package, run the strict distribution
environment preflight with the same signing and notarization variables you plan
to use for packaging:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
NOTARIZE=1 \
NOTARY_KEYCHAIN_PROFILE="psw-notary" \
  script/verify_macos_distribution_environment.sh
```

On a development machine without release credentials, report missing
prerequisites without claiming readiness:

```sh
script/verify_macos_distribution_environment.sh --allow-missing
```

The preflight checks the arm64 build host, local DMG and architecture tools, the
configured Developer ID Application identity, and notarization credential
mode. It does not store credentials, print app-specific passwords, upload an
app, or replace signed package generation, artifact verification, clean install
testing, or security review and accepted-risk decisions.

To sign the nested Rust FFI dylib and app bundle with hardened runtime, then
sign the DMG, set `SIGNING_IDENTITY` to a local Developer ID Application
identity. Without a release mode this remains a local-test artifact:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
  script/package_macos_alpha.sh
```

For an experimental public pre-release, set
`RELEASE_MODE=experimental-pre-release`, `NOTARIZE=1`, and provide one
notarytool credential mode. This mode also runs the strict security decision
evidence verifier and requires a clean Git worktree.

Use a stored notarytool keychain profile:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
RELEASE_MODE=experimental-pre-release \
NOTARIZE=1 \
NOTARY_KEYCHAIN_PROFILE="psw-notary" \
  script/package_macos_alpha.sh
```

Or use Apple ID credentials from the environment:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
RELEASE_MODE=experimental-pre-release \
NOTARIZE=1 \
APPLE_ID="developer@example.com" \
APPLE_TEAM_ID="TEAMID" \
APPLE_APP_SPECIFIC_PASSWORD="app-specific-password" \
  script/package_macos_alpha.sh
```

The script signs the completed DMG, submits it to `xcrun notarytool`, staples
the accepted ticket to the DMG, validates the staple, then creates the checksum
and manifest.

After creating a signed and notarized alpha DMG, run the signed install
verifier:

```sh
script/verify_macos_signed_install.sh dist/releases/KeptNear-0.1.0-alpha-macos-arm64.dmg
```

The verifier first runs the alpha artifact verifier, then requires an
`experimental-pre-release` manifest with distribution readiness, valid app and
DMG signing, notarization acceptance, hardened runtime, and a valid staple. It
verifies the DMG with `codesign`, Gatekeeper, and `stapler`, mounts the image
read-only, copies the app into a temporary clean install directory, then
verifies the app with `codesign`, Gatekeeper, and Launch Services `.pswvault`
registration. Unsigned or local-test DMGs fail this verifier by design.

## Inspect The Artifact

Verify the generated DMG from the repository root:

```sh
script/verify_macos_alpha_artifact.sh
```

Or pass an explicit DMG path:

```sh
script/verify_macos_alpha_artifact.sh dist/releases/KeptNear-0.1.0-alpha-macos-arm64.dmg
```

The verifier checks the DMG checksum, image integrity, mounted app and
Applications link, exact adjacent/in-DMG protocol-manifest equality, the
in-DMG SQLCipher distribution receipt and its source digest, arm64-only App,
Broker, MCP, CLI, and FFI architectures, component executability, runtime
component declarations, every component hash, and the fixed local installation
paths. Release-mode verification also requires the protocol-manifest Git
revision to match the current clean checkout. It verifies the text-manifest
checksum, size, protocol-manifest hash, app and DMG signing status, manual update
channel, release boundary, and `.pswvault` package document metadata.

## Install An Unsigned Experimental DMG

An unsigned package is suitable only for explicit experimental testing. Before
opening it, obtain the DMG, adjacent `.sha256` file, text manifest, and protocol
manifest from the same trusted source. From the directory containing those
files, verify the checksum:

```sh
shasum -a 256 -c KeptNear-0.1.0-alpha-macos-arm64.dmg.sha256
```

Open the DMG, drag `KeptNear.app` to Applications, and launch that installed
copy. Because the App has no Developer ID signature or notarization ticket,
macOS may block the first launch. Review the artifact source and checksum first,
then use Finder's explicit Open action or the Open Anyway control in System
Settings > Privacy & Security if the current macOS version offers it. Do not
disable Gatekeeper globally or remove quarantine metadata for unrelated files.

The unsigned package is unaudited, experimental, and not suitable for
production secrets. Installing the App does not activate the bundled Broker,
MCP adapter, or CLI as services and does not add those helpers to the shell
`PATH`. Their end-user lifecycle is not shipped. Uninstalling the App does not
delete user-selected `.pswvault` directories, Keychain entries, or
device-local `~/.keptnear` state; review and remove those separately only when
their data is no longer needed.

## Verify Vault Doctor Readiness

Run the vault doctor readiness verifier independently when changing the support
CLI, vault format, or local sync troubleshooting paths:

```sh
script/verify_vault_doctor_readiness.sh
```

The verifier creates temporary vault cases, runs the public
`keptnear vault doctor` and legacy `psw doctor` entrypoints in text and JSON
modes, checks non-zero failure behavior for incomplete and unsupported future
formats, and verifies known item plaintext stays out of output. This is a local
filesystem readiness check only; it does not inspect provider sync state.

## Vault Document Metadata

Generated app bundles declare `.pswvault` as a local vault package type. This
lets Launch Services route vault paths to KeptNear once the app bundle is
registered on a Mac. Runtime handling still opens the vault locked and requires
normal unlock credentials before item data is shown.

The local run bundle and the alpha package use the same Info.plist generation
helper, so document metadata stays consistent between development testing and
alpha artifacts.

To smoke-test local Launch Services registration for a generated app bundle,
run:

```sh
script/verify_macos_launch_services_vault_type.sh
```

Or pass an explicit app bundle:

```sh
script/verify_macos_launch_services_vault_type.sh dist/alpha-staging/KeptNear.app
```

This command registers the app bundle with the current user's Launch Services
database, then checks that Launch Services lists the project-owned vault UTI,
`.pswvault` tag, package conformance, document role, owner rank, package flag,
and vault binding. It is a local smoke test, not a substitute for installing and
testing a signed/notarized public distribution artifact on a clean Mac.

Because registration mutates the current user's Launch Services database,
managed workspace sandboxes or automation agents may block this step. In that
case the verifier fails with the original macOS registration error plus a
KeptNear diagnostic; rerun the command from an unsandboxed terminal or grant
explicit agent approval for user-level Launch Services access.

## Manual Alpha Updates

The public alpha update channel is manual. KeptNear does not contact an update
server or include an automatic updater in this phase.

Testers update by downloading the newer alpha DMG, verifying the checksum,
quitting KeptNear, opening the DMG, dragging `KeptNear.app` to Applications,
and reopening their existing local `.pswvault`. See `docs/update-policy.md` for
the full workflow and rationale.

## Distribution Boundary

The default `local-test` DMG is unsigned and records
`Distribution ready: false`. It is suitable only for local testing and trusted
testers who understand macOS Gatekeeper prompts.

An `unsigned-experimental` DMG records `Distribution ready: true` only after a
clean source revision, the AR-002 review-policy path, and all local packaging,
integrity, disclosure, and installation gates pass. Its manifest remains
explicitly `unsigned`, `unaudited`, and not suitable for production secrets.

An `experimental-pre-release` DMG records `Distribution ready: true` only after
the security decision path passes and signed, notarized packaging completes.
Every alpha manifest records `Production ready: false`.

Signed public distribution still requires:

- generated and checksum-verified security review handoff materials
- external security review evidence or explicit accepted-risk records
- Developer ID signing, hardened runtime, notarization, and signed-install
  verification; accepted risk does not bypass these controls

The unsigned experimental profile requires local build and test gates,
dependency-license and public-tree checks, artifact checksum and protocol
manifest verification, explicit Gatekeeper installation instructions, and
adjacent `unsigned`, `unaudited`, and `not for production secrets` warnings. It
does not require Apple credentials or external review evidence.
