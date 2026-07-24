# macOS Alpha Packaging

This project can create a local alpha package for test distribution. By default
the package is unsigned. If Developer ID credentials are available, the same
workflow can optionally sign, notarize, and staple the app bundle.

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

Passing this command is local automated evidence only. Public alpha still
requires separate security review handoff package generation, Developer ID
signing/notarization decisions, clean signed/notarized install behavior checks,
and external security review evidence.

On managed workspaces or automation agents where Launch Services registration
may be blocked, use report mode to run the local gate sequence and list current
blockers without approving local alpha readiness:

```sh
script/verify_local_alpha_readiness.sh --allow-missing
```

Report mode exits after printing blocker status and always states that local
alpha readiness is not approved. Strict mode is still required before sharing an
alpha build with trusted testers.

## Verify Public Alpha Release Readiness

For a release operator with Developer ID credentials, notarization credentials,
signed-install verification, and completed security review evidence, run the
strict public-alpha release gate:

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
review evidence verification. Report mode also runs the local handoff package
step, but it remains non-approving and does not
complete external security review. Passing strict mode is public-alpha release
evidence only; production-use recommendation remains a separate decision.

## Build The Alpha Package

```sh
script/package_macos_alpha.sh
```

The script builds:

- Rust FFI dylib in release mode
- SwiftPM macOS executable in release mode
- `dist/alpha-staging/KeptNear.app` with `.pswvault` document/package metadata
- `dist/releases/KeptNear-0.1.0-alpha-macos-alpha.zip`
- `dist/releases/KeptNear-0.1.0-alpha-macos-alpha.zip.sha256`
- `dist/releases/KeptNear-0.1.0-alpha-macos-alpha-manifest.txt`

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

The preflight checks local tool availability, the configured Developer ID
Application identity, and notarization credential mode. It does not store
credentials, print app-specific passwords, upload an app, or replace signed
package generation, artifact verification, clean install testing, or external
security review.

To sign the nested Rust FFI dylib and the app bundle with hardened runtime, set
`SIGNING_IDENTITY` to a local Developer ID Application identity:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
  script/package_macos_alpha.sh
```

To notarize and staple the app after signing, also set `NOTARIZE=1` and provide
one notarytool credential mode.

Use a stored notarytool keychain profile:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
NOTARIZE=1 \
NOTARY_KEYCHAIN_PROFILE="psw-notary" \
  script/package_macos_alpha.sh
```

Or use Apple ID credentials from the environment:

```sh
SIGNING_IDENTITY="Developer ID Application: Example, Inc. (TEAMID)" \
NOTARIZE=1 \
APPLE_ID="developer@example.com" \
APPLE_TEAM_ID="TEAMID" \
APPLE_APP_SPECIFIC_PASSWORD="app-specific-password" \
  script/package_macos_alpha.sh
```

The script submits a temporary pre-staple zip to `xcrun notarytool`, staples the
accepted ticket to `KeptNear.app`, validates the staple, then creates the final
release archive and checksum.

After creating a signed and notarized alpha archive, run the signed install
verifier:

```sh
script/verify_macos_signed_install.sh dist/releases/KeptNear-0.1.0-alpha-macos-alpha.zip
```

The verifier first runs the alpha artifact verifier, then requires manifest
evidence for valid signing, notarization acceptance, hardened runtime, and a
valid staple. It extracts the archive into a temporary clean install directory
and verifies `codesign`, Gatekeeper assessment with `spctl`, stapled ticket
validation, and Launch Services `.pswvault` registration from the extracted app
bundle. Unsigned archives fail this verifier by design.

## Inspect The Artifact

Verify the generated archive from the repository root:

```sh
script/verify_macos_alpha_artifact.sh
```

Or pass an explicit archive path:

```sh
script/verify_macos_alpha_artifact.sh dist/releases/KeptNear-0.1.0-alpha-macos-alpha.zip
```

The verifier checks the archive checksum, required bundle files, manifest
SHA-256 and size metadata, signing status, manual update channel, and release
distribution boundary. It also checks that `Contents/Info.plist` advertises
`.pswvault` as a package-style document type using the project-owned
`app.psw.local.vault` type identifier. The manifest records the bundle
identifier, minimum macOS version, checksum, signing status, notarization
status, staple validation status, update channel, and validation command used
for the artifact.

## Verify Vault Doctor Readiness

Run the vault doctor readiness verifier independently when changing the support
CLI, vault format, or local sync troubleshooting paths:

```sh
script/verify_vault_doctor_readiness.sh
```

The verifier creates temporary vault cases, runs `psw doctor` in text and JSON
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

Testers update by downloading the newer alpha archive, verifying the checksum,
quitting KeptNear, replacing `KeptNear.app`, and reopening their existing local
`.pswvault`. See `docs/update-policy.md` for the full workflow and rationale.

## Distribution Boundary

The default alpha package is unsigned. It is suitable for local testing and
trusted testers who understand macOS Gatekeeper prompts.

A signed and notarized alpha package improves Gatekeeper behavior, but the
manifest still records `Distribution ready: false` until the project has made
the remaining release decisions.

Public distribution still requires:

- generated and checksum-verified security review handoff materials
- external security review evidence or explicit accepted-risk records
