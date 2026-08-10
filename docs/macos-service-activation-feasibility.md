# macOS Service Activation Feasibility

## Scope

This document records the reproducible ServiceManagement feasibility boundary
for KeptNear's planned per-user Broker. It does not activate the product Broker,
install MCP or CLI tools, or promote machine access beyond Bundled But Not
Activated.

The probe is intentionally separate from the real App and Broker:

- `tools/macos-service-management-probe/Controller.swift` calls
  `SMAppService.agent(plistName:)` through a minimal App bundle.
- `tools/macos-service-management-probe/Agent.swift` writes one temporary
  generation marker and remains alive for launchd lifecycle checks.
- `script/verify_macos_service_management_probe.sh` builds, signs, registers,
  moves, replaces, unregisters, and cleans up a unique probe LaunchAgent.

The default script mode is build-only and does not change Login Items.

## Verified Environment

The first runtime check completed on 2026-08-10 with:

- macOS 26.5.2 build 25F84
- Apple Silicon `arm64`
- Xcode 26.6 build 17F113
- minimum probe deployment target macOS 13.0

This is one-machine feasibility evidence, not a supported-version acceptance
matrix.

## Profile Results

| Profile | Result | Machine-service eligibility |
| --- | --- | --- |
| Source build-only probe | Both unsigned and ad-hoc bundles compile as arm64 | Build evidence only |
| Current unsigned `local-test` package shape | App bundle has no valid containing-App signature | Ineligible |
| `unsigned-experimental` | Registration returned `SMAppServiceErrorDomain` code 3 (`kSMErrorInvalidSignature`) | Ineligible |
| Ad-hoc probe | Registration reached `enabled`; Agent launched; bundle-relative execution followed an App move; unregister, replacement, and generation-2 re-registration passed | Eligible for local development evidence only |
| `experimental-pre-release` with Developer ID | No valid code-signing identity was available on the verification machine | Unverified and ineligible for claims |

The ad-hoc result does not provide a verified publisher identity, Gatekeeper
acceptance, notarization, signing continuity across another machine, or public
distribution readiness. It just permits further local implementation against a
real ServiceManagement boundary.

The probe maps `requires-approval`, but this state was not observed during the
first run. System-approval denial and recovery remain required acceptance work.

## Commands

Build-only validation:

```sh
script/verify_macos_service_management_probe.sh
script/verify_macos_service_management_probe.sh --signing-mode adhoc
```

Explicit runtime validation changes the current user's Login Items state for a
unique test label and then unregisters it:

```sh
script/verify_macos_service_management_probe.sh --run --signing-mode unsigned
script/verify_macos_service_management_probe.sh --run --signing-mode adhoc
```

An identity-backed check requires an installed code-signing identity:

```sh
script/verify_macos_service_management_probe.sh \
  --run \
  --signing-mode identity \
  --signing-identity "Developer ID Application: Example (TEAMID)"
```

When the current user has disabled the probe in Login Items, an explicit
interactive run can wait for approval without making CI interactive:

```sh
script/verify_macos_service_management_probe.sh \
  --run \
  --signing-mode adhoc \
  --approval-timeout 300
```

Do not use a real identity example as proof that the signed profile passed. The
exact identity-backed artifact and acceptance result must exist before that
profile becomes eligible.

## Cleanup And Failure Rules

- Every runtime uses a unique label below
  `com.chasechou.keptnear.service-probe.*`.
- The script refuses to proceed if that exact launchd job already exists.
- Exit cleanup attempts to unregister the service, terminate the marker process,
  and remove the temporary App bundle.
- Unsigned rejection is an expected negative result, but the command exits
  nonzero so automation cannot mistake it for service eligibility.
- A `requires-approval` result exits separately and requires explicit user
  action before runtime acceptance can continue.
- The probe never falls back to writing `~/Library/LaunchAgents` directly.

## Product Boundary

The production App does not yet bundle a LaunchAgent plist, register the real
Broker, authenticate a human-control channel, or install adapter links. The
current DMG therefore remains Bundled But Not Activated even though the ad-hoc
probe proved that local ServiceManagement implementation can proceed.
