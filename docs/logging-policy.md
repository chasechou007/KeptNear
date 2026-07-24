# Logging, Telemetry, And Crash Report Policy

KeptNear is a local-first password manager. Logging, telemetry,
diagnostics, and crash handling must preserve that boundary.

## Current Alpha Behavior

The macOS alpha does not automatically upload diagnostics, telemetry, logs,
vault records, or crash reports. There is no bundled crash reporter, analytics
SDK, telemetry client, or remote logging service.

The only support payload is the diagnostics report that a user explicitly copies
from Settings > Diagnostics. That report is local until the user chooses to
share it.

Settings > Security also includes a static trust-boundary summary. That summary
must describe the current no-automatic-upload and user-copied-diagnostics
boundary without adding telemetry, logging, crash reporting, or support upload
behavior.

## Allowed Local Diagnostics

User-copied diagnostics may include non-secret support context:

- app name, version, and build string
- Rust core availability and status
- whether a vault is selected and unlocked
- selected vault basename
- visible item count
- plaintext import/export cleanup state without file names or paths
- sync refresh counts
- clipboard and auto-lock preference values
- selected interface language

## Forbidden Data

Diagnostics, logs, telemetry, crash reports, analytics, and support payloads
must not include:

- master passwords
- local unlock material
- vault keys
- item titles
- usernames
- passwords
- URLs
- notes
- tags
- TOTP secrets or generated codes
- credit card numbers or verification codes
- software license keys
- clipboard contents
- plaintext import source names or paths
- plaintext export destination names or paths
- full local vault paths
- encrypted vault record contents
- plaintext export contents

## Future Integrations

Any future crash reporting, remote logging, telemetry, analytics, or support
upload integration must be reviewed before it is enabled for users. The review
must document:

- exact fields collected
- disabled provider features and breadcrumbs
- redaction behavior before data leaves the process
- user controls and opt-in or opt-out behavior
- retention period
- provider access boundary
- validation evidence that forbidden data is excluded

Provider-side scrubbing is not sufficient by itself. Secret exclusion must be
enforced before data leaves the app process whenever collection is enabled.

## Alpha Release Boundary

For the current alpha, the release policy is no automatic collection. Debugging
relies on user-copied diagnostics and direct tester feedback.
