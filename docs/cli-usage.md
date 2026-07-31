# Local CLI Usage

## Current Availability

This guide defines the source-level contract for the public `keptnear` CLI. It
is currently a developer preview, not an end-user installation guide.

The alpha DMG now bundles the CLI and Broker executables under
`KeptNear.app/Contents/Helpers` and verifies them against one protocol
manifest. Copying the App to `/Applications` provides an installed KeptNear Broker executable
inside the bundle, but it does not activate that executable as a long-running
service. A machine command needs a compatible Broker on the current user's
owner-only local socket. The separate `keptnear vault doctor` command remains
local and read-only and does not contact the Broker.

Build and inspect the CLI from the repository root:

```sh
cargo build --locked --release -p psw-cli --bin keptnear
target/release/keptnear help
```

## Choose An Interface

Use MCP when a compatible host already supports structured MCP tools. Use the
CLI for a human terminal workflow, a script that can consume versioned JSON, an
Agent that can invoke a local subprocess, or compatibility delivery to an
existing command-line tool.

MCP and CLI are adapters over the same local Broker capabilities:

```text
credential.search
access.request
grant.status
grant.revoke
http.request
process.run
```

The interface choice does not change pairing, field authorization, approval,
audit, pause, or revocation semantics. MCP and CLI keep separate device-local
Consumer signing keys, even when their non-secret profile labels are equal.
There is no `secret.get`, and neither interface returns the selected Secret
Field.

## Pairing And Authorization

`keptnear status` checks Broker compatibility and returns only non-secret
process status. It does not create or load a Consumer identity.

Every other machine command selects the default CLI profile or one explicit
`--profile <id>`. On first use, that profile creates a device-only signing key
and may return a `pairing-pending` result containing a request ID and comparison
code. The user must verify and approve that pairing in KeptNear's local
Apps & Tools view, then retry the command.

Pairing establishes one Consumer identity only. It does not authorize metadata
or a Secret Field. A separate access request and local user decision establish
the exact field, capability, confirmation policy, and lifetime. The Agent or
script cannot approve its own pairing or access request.

Use a separate profile for each permission boundary:

```text
release-shell
release-agent
local-automation
```

Reusing a CLI profile reuses one Consumer identity and permission set. Removing
a script or Agent configuration does not unpair that Consumer or revoke its
access. Use Apps & Tools to pause or revoke machine access.

## Human Shell Use

The examples below contain synthetic stable IDs, not credentials. Replace them
with the exact IDs supplied by the local control-plane and approval workflow.
Stable IDs are non-secret authorization metadata, but they still should not be
published without a reason.

Check the local Broker:

```sh
target/release/keptnear status
```

Request access by a human-readable description when the exact Credential and
Secret Field are not already authorized:

```sh
target/release/keptnear --profile release-shell access request \
  --capability http.request \
  --vault vault_00000000000000000000000000000000 \
  --description 'Use the release API credential'
```

The command waits once for up to five minutes by default. Add `--no-wait` to
receive the secret-free submission receipt immediately. A pending result is not
an approval. Retry the same request after completing the local decision; the
Broker coalesces an equivalent pending request.

Perform a brokered HTTPS request with an applicable current Use Grant and Usage
Profile:

```sh
target/release/keptnear --profile release-shell http request \
  --grant use_grant_11111111111111111111111111111111 \
  --vault vault_00000000000000000000000000000000 \
  --credential credential_22222222222222222222222222222222 \
  --field secret_field_33333333333333333333333333333333 \
  --kind api-token \
  --session vault_session_44444444444444444444444444444444 \
  --usage-profile usage_profile_55555555555555555555555555555555 \
  --method post \
  --url https://api.example.test/releases \
  --header 'Accept: application/json'
```

The Usage Profile places the selected field inside the Broker. The command line
contains no credential value. If `--body-file` is used, the file must be a
regular non-symlink entry no larger than one MiB and must not be used as an
alternate place to store the selected Secret Field.

Run one approved executable directly:

```sh
target/release/keptnear --profile release-shell run \
  --grant use_grant_11111111111111111111111111111111 \
  --vault vault_00000000000000000000000000000000 \
  --credential credential_22222222222222222222222222222222 \
  --field secret_field_33333333333333333333333333333333 \
  --kind api-token \
  --session vault_session_44444444444444444444444444444444 \
  --usage-profile usage_profile_55555555555555555555555555555555 \
  --env MODE=release \
  --timeout-ms 30000 \
  -- /absolute/path/to/release-tool publish
```

KeptNear invokes the executable without a shell. The Usage Profile selects
child-only environment, secret-only standard input, or anonymous descriptor 3
placement. The selected field is not expanded into the executable, arguments,
or KeptNear standard output.

Inspect or revoke one Consumer-owned Use Grant:

```sh
target/release/keptnear --profile release-shell grant status \
  use_grant_11111111111111111111111111111111
target/release/keptnear --profile release-shell revoke \
  use_grant_11111111111111111111111111111111
```

## Agent Use

Give an Agent an operation, profile, and non-secret target context. Do not give
it a credential value. A suitable instruction is:

```text
Use the local KeptNear profile release-agent. Request the http.request
capability for the release credential, wait while I approve it in KeptNear,
then perform the brokered HTTPS operation. Do not request, display, copy, or
persist the credential value. Stop if pairing, approval, or authorization is
unavailable.
```

For a host with native MCP support, configure `keptnear-mcp` as described in
[Local MCP Host Setup](mcp-setup.md). For an Agent using the CLI, require it to:

- call only the documented `keptnear` command tree;
- parse the single `schemaVersion: 1` JSON result instead of scraping prose;
- preserve the selected profile and exact stable identities between retries;
- leave pairing, matching, and authorization decisions to the local user;
- use `http request` or `run` for the approved action instead of trying to
  retrieve a value;
- stop on an unexpected schema, operation, protocol, or nonzero status; and
- avoid placing command output in conversations, project files, or persistent
  logs unless the user explicitly needs and reviews that output.

These instructions guide the caller; KeptNear does not edit Agent instruction
files or infer task intent. The enforceable boundary is the paired Consumer,
field-scoped Access Rule, Use Grant, Usage Profile, global pause, and local
Broker capability.

## Output And Exit Status

Each completed machine command writes one `schemaVersion: 1` JSON envelope.
KeptNear never writes the selected Secret Field as a result.

HTTP bodies and child standard streams are bounded and represented as base64
fields. Base64 is reversible framing, not encryption or a logging-safe
transformation. An authorized service or child can return encoded, split, or
otherwise transformed sensitive data that exact-secret redaction cannot
recognize. Treat operation output as untrusted and potentially sensitive.

Exit status is:

- `0` for a completed non-`run` command;
- `1` for a KeptNear failure, pending pairing, or a `run` result without a
  usable numeric child status;
- `2` for invalid CLI arguments; and
- the direct child's numeric status from `0` through `255` after a completed
  `run` result is written.

Native `Ctrl-C` normally appears as status 130 in a POSIX shell. Socket closure
causes the Broker to close secret input and kill and reap the directly launched
child. KeptNear does not claim to terminate independently surviving descendants
or erase a credential already delivered outside the Broker.

## Prohibited Patterns

Do not:

- ask a human or Agent to retrieve, reveal, print, copy, dump, or export a
  credential through MCP or CLI;
- use command substitution to place a credential in a shell variable;
- place a credential in a command argument, explicit non-secret `--env` value,
  request body file, project file, shell profile, or `.env` file;
- wrap `keptnear run` in a command interpreter or environment launcher;
- treat a profile label as authorization or let a caller self-approve access;
  or
- treat local revocation as recall after an authorized process or service has
  received a credential.

For complete invalidation after compatibility delivery, rotate the credential
with its upstream provider.
