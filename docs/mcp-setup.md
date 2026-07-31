# Local MCP Host Setup

## Current Availability

This document defines the local host configuration contract for the
`keptnear-mcp` adapter. It is currently a developer preview, not an end-user
installation guide.

The alpha DMG now bundles the Broker and MCP executables under
`KeptNear.app/Contents/Helpers` and verifies them against one protocol
manifest. Copying the App to `/Applications` provides an installed KeptNear Broker executable
inside the bundle, but it does not activate that executable as a long-running
service. Without a compatible Broker already running on the owner-only local
socket, the adapter initializes with no credential tools and reports only a
fixed local recovery instruction. Do not interpret a configured host entry as
a complete machine-credential installation until the App/Broker service
lifecycle and human approval path pass end-to-end acceptance.

## Shared Host Model

Every compatible host launches the same local stdio process:

```text
command: /absolute/path/to/keptnear-mcp
arguments: --profile <profile-id>
transport: stdio
```

Host-specific configuration syntax changes only how that process is launched.
It does not change KeptNear pairing, authorization, approval, audit, or
credential-use semantics.

Use an absolute executable path. Do not configure a URL, remote MCP server,
shell wrapper, token environment variable, or secret-bearing argument.
`keptnear-mcp` uses newline-delimited MCP messages over standard input and
standard output and connects separately to the current user's local Broker
socket.

## Build The Adapter

From the repository root on macOS:

```sh
cargo build --locked --release -p keptnear-mcp
```

The resulting executable is:

```text
<repository>/target/release/keptnear-mcp
```

Replace the placeholder paths below with that executable's absolute path. Do
not launch the binary in a normal interactive terminal: its standard input and
standard output are reserved for the MCP host.

## Codex

The following command configures a local stdio server using a dedicated
`codex` pairing profile:

```sh
codex mcp add keptnear -- /absolute/path/to/keptnear-mcp --profile codex
```

Inspect or remove the host entry with:

```sh
codex mcp get keptnear
codex mcp list
codex mcp remove keptnear
```

These commands were checked against `codex-cli 0.144.6`. Consult the installed
`codex mcp add --help` output if a later Codex release changes its configuration
syntax.

## Claude Code

The following command configures the same stdio adapter for the current user
with a separate `claude-code` pairing profile:

```sh
claude mcp add --scope user keptnear -- /absolute/path/to/keptnear-mcp --profile claude-code
```

Use `--scope local` instead when the entry should apply only to the current
project. Avoid project-shared configuration containing a developer-specific
absolute path unless the project intentionally owns and documents that path.

Inspect or remove the host entry with:

```sh
claude mcp get keptnear
claude mcp list
claude mcp remove --scope user keptnear
```

These commands were checked against Claude Code `2.1.205`. Consult the
installed `claude mcp add --help` output if a later release changes its
configuration syntax.

## Generic Stdio Hosts

Many compatible hosts use a JSON shape similar to this:

```json
{
  "mcpServers": {
    "keptnear": {
      "command": "/absolute/path/to/keptnear-mcp",
      "args": ["--profile", "generic-host"]
    }
  }
}
```

The container and field names are not standardized across host configuration
files. Follow the host's documentation while preserving the same command,
arguments, and local stdio transport. KeptNear has no provider-specific core
mode and does not require a host to identify itself as Codex, Claude Code, or
an Agent.

## Pairing And First Access

Once a packaged compatible Broker is available, the first connection for a new
profile follows this sequence:

1. The host launches `keptnear-mcp`.
2. The adapter creates or loads that profile's device-local signing key.
3. The Broker creates a pending Consumer pairing request.
4. KeptNear shows the pending request and comparison code in Apps & Tools.
5. The user verifies the code and approves or denies pairing locally.
6. The host reconnects after approval and the adapter authenticates as that
   Consumer.
7. Credential operations still require their own field-scoped Access Rule and
   Use Grant.

Pairing grants identity only. It does not reveal a vault catalog, authorize a
credential field, or bypass vault unlock.

## Pairing Profiles

Use one explicit profile per permission boundary:

```text
codex
claude-code
automation.release
```

Profile IDs contain 1 through 64 ASCII characters, are normalized to lowercase,
must begin and end with a letter or digit, and may contain `.`, `_`, or `-`
inside. A profile ID is local, non-secret configuration and never becomes a
Broker authorization identity.

Reusing a profile reuses one device-local signing key, Consumer identity, and
permission set. Different profiles create independent keys and require
independent pairing and authorization. Omitting `--profile` uses the legacy
`default` profile; explicit profiles are recommended for new host
configurations.

Removing an entry from a host does not unpair its Consumer, revoke its grants,
or delete its Keychain signing key. Pause or unpair the Consumer from
KeptNear's Apps & Tools controls. Automatic cleanup of every MCP profile key is
not implemented yet.

## Available Tools

After Broker authentication, the adapter exposes exactly:

```text
credential.search
access.request
grant.status
grant.revoke
http.request
process.run
```

There is no `secret.get`. Search and approval results contain bounded
non-secret metadata. `http.request` places an approved field inside a Brokered
HTTPS request. `process.run` is an explicit compatibility path in which the
launched child can observe and retain the delivered value; revoking KeptNear
access stops future delivery, while invalidating an existing copy requires
upstream credential rotation.

## Troubleshooting

**The host shows no KeptNear tools:** The Broker may be unavailable, pairing
may still be pending, the vault may be locked, or the adapter and Broker may
not share a compatible protocol. In the current source preview, the usual
cause is that no packaged Broker service exists.

**Pairing never completes:** Confirm that Apps & Tools shows the same comparison
code, approve it locally, then restart the host connection. Pairing does not
auto-approve.

**An existing permission is missing:** Confirm that the host uses the same
profile ID as before. `codex`, `claude-code`, and `default` are intentionally
different Consumers.

**The adapter exits immediately:** Verify the absolute executable path, use
only one optional `--profile <id>` argument, and check whether macOS denied
access to the device-local Data Protection Keychain item.

## Security Rules

- Keep credential values out of MCP host configuration, environment variables,
  arguments, logs, and project files.
- Treat the configured host and its profile as one Consumer permission
  boundary.
- Review pairing and access requests in the local KeptNear App.
- Use separate profiles when hosts should not share permissions.
- Use Apps & Tools to pause all machine access without locking human vault use.
- Rotate an upstream credential after a child process or external service may
  have retained it.

The MCP transport specification is maintained by the
[Model Context Protocol project](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio).
KeptNear deliberately supports only its local stdio boundary.
