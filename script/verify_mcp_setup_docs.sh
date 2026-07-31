#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC_PATH="$ROOT_DIR/docs/mcp-setup.md"
violations=0

report_violation() {
  printf 'MCP setup documentation violation: %s\n' "$1" >&2
  violations=$((violations + 1))
}

require_literal() {
  local literal="$1"

  if ! grep -F -q -- "$literal" "$DOC_PATH"; then
    report_violation "docs/mcp-setup.md is missing: $literal"
  fi
}

reject_literal() {
  local literal="$1"

  if grep -F -q -- "$literal" "$DOC_PATH"; then
    report_violation "docs/mcp-setup.md contains prohibited setup text: $literal"
  fi
}

if [[ ! -f "$DOC_PATH" ]]; then
  report_violation "required document is missing: docs/mcp-setup.md"
fi

if [[ "$violations" -eq 0 ]]; then
  require_literal "## Current Availability"
  require_literal "installed KeptNear Broker executable"
  require_literal "## Codex"
  require_literal "codex mcp add keptnear -- /absolute/path/to/keptnear-mcp --profile codex"
  require_literal "## Claude Code"
  require_literal "claude mcp add --scope user keptnear -- /absolute/path/to/keptnear-mcp --profile claude-code"
  require_literal "## Generic Stdio Hosts"
  require_literal '"command": "/absolute/path/to/keptnear-mcp"'
  require_literal '"args": ["--profile", "generic-host"]'
  require_literal "There is no \`secret.get\`."
  require_literal "Removing an entry from a host does not unpair its Consumer"
  require_literal "Keep credential values out of MCP host configuration"

  reject_literal "/Users/"
  reject_literal "transport: http"
  reject_literal "transport: sse"
  reject_literal "API_KEY="
  reject_literal "TOKEN="
fi

if [[ "$violations" -ne 0 ]]; then
  printf 'MCP setup documentation verification failed with %d violation(s).\n' \
    "$violations" >&2
  exit 1
fi

printf 'MCP setup documentation verification passed.\n'
