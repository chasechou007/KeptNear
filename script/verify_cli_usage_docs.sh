#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOC_PATH="$ROOT_DIR/docs/cli-usage.md"
violations=0

report_violation() {
  printf 'CLI usage documentation violation: %s\n' "$1" >&2
  violations=$((violations + 1))
}

require_literal() {
  local path="$1"
  local literal="$2"

  if ! grep -F -q -- "$literal" "$ROOT_DIR/$path"; then
    report_violation "$path is missing: $literal"
  fi
}

reject_literal() {
  local literal="$1"

  if grep -F -q -- "$literal" "$DOC_PATH"; then
    report_violation "docs/cli-usage.md contains prohibited credential retrieval pattern: $literal"
  fi
}

if [[ ! -f "$DOC_PATH" ]]; then
  report_violation "required document is missing: docs/cli-usage.md"
fi

if [[ "$violations" -eq 0 ]]; then
  require_literal docs/cli-usage.md "## Current Availability"
  require_literal docs/cli-usage.md "installed KeptNear Broker executable"
  require_literal docs/cli-usage.md "## Choose An Interface"
  require_literal docs/cli-usage.md "Use MCP when a compatible host already supports structured MCP tools."
  require_literal docs/cli-usage.md "CLI for a human terminal workflow"
  require_literal docs/cli-usage.md "There is no \`secret.get\`"
  require_literal docs/cli-usage.md "## Human Shell Use"
  require_literal docs/cli-usage.md "keptnear --profile release-shell access request"
  require_literal docs/cli-usage.md "keptnear --profile release-shell http request"
  require_literal docs/cli-usage.md "keptnear --profile release-shell run"
  require_literal docs/cli-usage.md "## Agent Use"
  require_literal docs/cli-usage.md "The Agent or"
  require_literal docs/cli-usage.md "script cannot approve its own pairing or access request."
  require_literal docs/cli-usage.md "Do not give"
  require_literal docs/cli-usage.md "it a credential value."
  require_literal docs/cli-usage.md "parse the single \`schemaVersion: 1\` JSON result"
  require_literal docs/cli-usage.md "## Output And Exit Status"
  require_literal docs/cli-usage.md "Base64 is reversible framing, not encryption"
  require_literal docs/cli-usage.md "## Prohibited Patterns"
  require_literal docs/cli-usage.md "rotate the credential"
  require_literal README.md "[Local CLI Usage](docs/cli-usage.md)"
  require_literal docs/build.md "[Local CLI Usage](cli-usage.md)"

  reject_literal "keptnear get"
  reject_literal "keptnear secret get"
  reject_literal "TOKEN=\$("
  reject_literal "API_KEY=\$("
  reject_literal "PASSWORD=\$("
  reject_literal "export TOKEN="
  reject_literal "export API_KEY="
  reject_literal "curl -H"
  reject_literal "| pbcopy"
fi

if [[ "$violations" -ne 0 ]]; then
  printf 'CLI usage documentation verification failed with %d violation(s).\n' \
    "$violations" >&2
  exit 1
fi

printf 'CLI usage documentation verification passed.\n'
