# Logging, Diagnostics, Audit, And Network Policy

KeptNear is a local-first password and token manager. This policy separates
device-local audit, user-copied support diagnostics, runtime output, and network
activity so that one category cannot silently expand another.

## Current Implemented Boundary

The current macOS alpha has no KeptNear account, hosted sync, analytics SDK,
telemetry client, remote logger, bundled crash reporter, support uploader,
automatic updater, or background template downloader.

`~/.keptnear/logs` is a reserved owner-only directory in the Broker layout. The
current code does not write a persistent general-purpose App or Broker log
there. Creating that directory is not permission to start collecting runtime
payloads later.

Two intentionally local observability surfaces exist:

- authenticated encrypted device-local audit for typed machine-access events
- a fixed support snapshot copied only when the user requests diagnostics

The outbound-operation attribution boundary and its internal HTTP and direct
child-process executors are implemented. The Broker pairing and authentication
protocol plus local stdio MCP adapter expose six authenticated capability tools.
The adapter delegates HTTP and process execution to the Broker; it does not
write protocol frames, tool arguments, tool results, request material, or child
output to a persistent log. An attributed `Pending` event proves authorization
admission; a later `Allowed` or `Failed` event records the non-secret operation
outcome without recording the destination, executable, payload, environment,
or child streams.

## Device-Local Audit

Machine-access audit is stored in the authenticated SQLCipher device-state
database under `~/.keptnear/state`. It is not a general-purpose log, is not
written into `.pswvault`, and is not synchronized by KeptNear.

The closed audit schema may contain:

- event time and event kind
- stable Consumer, Vault, Credential, and Secret Field identities
- capability name and version
- `Pending`, `Allowed`, `Denied`, `Paused`, or `Failed` decision
- confirmation method and Use Grant identity

It contains no arbitrary message, destination, request, response, command, or
error text. Retention defaults to 90 days, is configurable from 1 through 3650
days, and is independently capped at the newest 10,000 events. Retention is
enforced during writes, setting changes, and Broker startup.

Only the trusted local control plane can page and filter audit, explicitly clear
the filtered selection, or assemble the bounded versioned troubleshooting JSON.
The export API returns a fixed projection and does not choose or write a
destination. Audit is not included in the macOS support diagnostics report.

## User-Copied Diagnostics

The macOS support report is assembled and copied only when the user presses the
copy button in Settings > Diagnostics. KeptNear does not upload or automatically
share it.

The report contains an approved support-field projection documented in
`docs/diagnostics.md`. Core state is mapped to the closed values `connected` or
`unavailable`; free-form Core status and errors are not forwarded. The selected
vault basename is included and can contain user-chosen text, so users should
review the report before sharing it.

The report is placed on the system clipboard. Other software with clipboard
access may observe it after the explicit copy action.

## Runtime Output And Crash Handling

The current App and Broker do not persist operational logs. Stable errors and
debug representations must remain bounded and sanitized rather than echoing
input, decrypted content, SQL, or local paths.

Third-party HTTP and TLS logging is compiled out of the Broker dependency graph.
This prevents transport debug output from recording a request URL or a
secret-bearing custom header if a logger is added elsewhere in the process.

The current `keptnear vault doctor` and legacy `psw doctor` commands write only
format-readiness information and sanitized usage or error text to standard
output and standard error. They omit the supplied full path, do not unlock or
decrypt records, and do not access the Consumer Keychain, Broker, or a sync
provider.
`keptnear-mcp` reserves standard output exclusively for compact
newline-delimited JSON-RPC. Its six tools return only their bounded schemas;
they never intentionally return the selected Secret Field, and errors use fixed
codes rather than reflected input. Access-approval status, wait, and resume
results contain only a stable request identity, state, time boundaries, and
wait timeout state; they omit the approval subject and candidate data. HTTP
response bodies and process output are untrusted operation results and may
still be sensitive even after exact-secret redaction. Standard error contains
only fixed startup or transport-failure sentences. A selected MCP pairing
profile is non-secret local configuration used to choose a Keychain account;
its label is not written to output, a persistent log, Broker protocol frames,
or authorization audit. Invalid profile arguments are rejected without
reflecting the supplied value. MCP cancellation reasons and arbitrary `_meta`
values are also discarded rather than logged or reflected. Unit regressions
scan all six MCP success and error projections for seeded private-input
markers. The source-level `keptnear` CLI writes one versioned JSON envelope per
machine command and keeps KeptNear secrets out of ordinary results and standard
streams. Access submission and bounded wait results contain only
the stable approval identity, status, time boundaries, coalescing and timeout
state; `--no-wait` adds no separate log. A wait failure after submission may
retain that stable approval identity in its fixed error, but never the approval
subject, request description, candidate metadata, authorization target, or
Secret Field value. CLI regressions also seed query, request description, URL,
header, body path and content, child argument, environment, and
working-directory markers and verify that metadata-only successes, fixed
Broker failures, and protocol failures do not reflect them. Child and HTTP
response bytes remain untrusted operation results and are not made logging-safe
by base64. Native terminal interruption synthesizes no diagnostic containing
request material; closing the socket causes the Broker to cancel and reap only
the direct child. The real-secret, cross-adapter Broker/MCP/CLI/App marker scan
remains a separate release gate.

The current alpha has no automatic crash-report collection or upload. Operating
system crash artifacts are controlled by macOS, not uploaded by KeptNear, and
may still contain process metadata outside KeptNear's report schema.

## Forbidden Data

Audit, diagnostics, logs, crash payloads, analytics, support payloads, and
ordinary non-operation tool output must not contain:

- master passwords, vault keys, local unlock material, or recovery authority
- raw credential values, TOTP seeds or codes, card data, or license keys
- credential titles, usernames, URLs, notes, tags, or encrypted record contents
- request URLs, headers, query values, bodies, or API response bodies
- executable full paths, command arguments, environment values, or standard
  input, output, and error
- clipboard contents
- plaintext import or export contents, names, or paths
- rejected record names or paths
- full local vault paths
- free-form internal errors, SQL, parser diagnostics, or provider responses

The bounded body explicitly returned by `http.request` is operation output, not
diagnostics or audit. It omits response headers and replaces exact echoes of the
placed secret, but the remote service controls all other response bytes and may
return sensitive or transformed data. Consumers must treat that body as
untrusted sensitive content and must not route it into logs or diagnostics.

An explicitly documented basename or logical path label is not a full path, but
it must still be bounded and must not become an authorization identity.

## Network Boundary

The phrase "explicit credential operation" means a named capability requested
by an authenticated Consumer and admitted by the configured Access Rule and Use
Grant policy. A persistent rule can avoid a prompt on every use; it does not
turn the operation into telemetry, an update check, or an unrelated background
task.

Current and planned network-adjacent flows are distinct:

- File sync: KeptNear reads and writes the selected encrypted `.pswvault`
  directory. iCloud Drive, Dropbox, Syncthing, or another file provider may
  transport those encrypted files outside KeptNear.
- Updates: the current alpha uses manual downloads and does not contact an
  update server. A future check must be separately disclosed and configurable.
- Usage Profile templates: built-in templates are bundled offline. KeptNear
  does not fetch or refresh them in the background.
- Support: diagnostics, audit, logs, telemetry, and crash reports are not
  uploaded automatically.
- Human URL action: opening a selected website is an explicit handoff to the
  user's default browser. KeptNear does not make that browser request.
- Broker IPC: the owner-only Unix socket is current-device IPC, not Internet,
  LAN, or localhost TCP exposure.
- `http.request`: the internal executor accepts one explicitly authorized,
  bounded HTTPS request, places the exact field according to the owning Usage
  Profile, disables redirects and environment proxies, and returns only numeric
  status, a bounded exact-echo-redacted body, and truncation state. Authenticated
  Broker protocol, MCP requests, and the source-level CLI can invoke it.
- `process.run`: the internal executor directly launches one bounded absolute
  executable path with no inserted shell, clears the inherited environment,
  and places one exact field through a child-only environment variable,
  secret-only standard input, or anonymous descriptor 3. It captures both
  output streams, replaces exact secret echoes, and kills and reaps the direct
  child on timeout or cancellation. Authenticated Broker protocol, MCP
  requests, and the source-level CLI can invoke it; the App cannot. An approved
  child or descendant may independently use the network or retain the secret;
  KeptNear cannot observe or revoke that external use. The CLI does not expand
  the approved field into the command line or unframed standard output. It
  returns bounded Broker-redacted streams only as base64 JSON fields together
  with fixed compatibility-boundary booleans; base64 is encoding, not
  encryption or a logging-safe transformation.

No network activity may be hidden inside diagnostics, crash handling, template
loading, sync metadata, or an unrelated background task.

## Outbound Attribution

Only `http.request` and `process.run` can enter the current outbound-operation
attribution boundary. The Broker consumes or validates the exact authorized Use
Grant and commits `Pending` before returning a non-cloneable opaque
authorization. Finalization consumes that authorization and records exactly one
`Allowed` or `Failed` outcome. Denied and globally paused attempts are recorded
without returning an authorization; non-outbound capabilities fail before
Grant consumption.

Attribution includes only stable scope identities, capability, grant, decision,
and confirmation method. It includes no payload, destination, response,
executable, stream, full path, telemetry endpoint, template URL, or background
network configuration.

## Threat Boundary And Non-Claims

This policy does not claim protection against:

- a compromised operating system or privileged process
- keyboard, screen, memory, or clipboard capture
- a malicious Consumer after the user authorizes its access
- a child process after compatibility delivery
- an external service after an approved request sends a credential
- sync-provider observation of encrypted file metadata and directory shape
- a user intentionally sharing a copied diagnostics or audit export
- malicious builds, dependencies, update artifacts, or upstream services

An audit event proves KeptNear's local authorization decision, not Consumer
intent, remote endpoint integrity, successful credential revocation, or safety
of a response. Local-first is a custody and architecture choice, not a complete
security guarantee.

## Future Integrations

Any future crash reporting, remote logging, telemetry, analytics, support
upload, updater, or template-delivery integration requires review before it is
enabled. The review must document:

- exact fields collected or transmitted
- trigger, destination, and user controls
- disabled provider features and breadcrumbs
- redaction before data leaves the process
- retention and provider access boundaries
- failure and offline behavior
- validation evidence that forbidden data is excluded

Provider-side scrubbing is not sufficient. Secret exclusion must be enforced
before data leaves the KeptNear process.
