#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
violations=0

report_violation() {
  printf 'privacy boundary documentation violation: %s\n' "$1" >&2
  violations=$((violations + 1))
}

require_literal() {
  local path="$1"
  local literal="$2"

  if ! grep -F -q -- "$literal" "$ROOT_DIR/$path"; then
    report_violation "$path is missing required statement: $literal"
  fi
}

reject_exact_line() {
  local path="$1"
  local literal="$2"

  if grep -F -x -q -- "$literal" "$ROOT_DIR/$path"; then
    report_violation "$path contains prohibited blanket claim: $literal"
  fi
}

required_files=(
  docs/logging-policy.md
  docs/diagnostics.md
  docs/architecture.md
  docs/security-model.md
  docs/product-requirements.md
  docs/update-policy.md
)

for path in "${required_files[@]}"; do
  if [[ ! -f "$ROOT_DIR/$path" ]]; then
    report_violation "required document is missing: $path"
  fi
done

if [[ "$violations" -ne 0 ]]; then
  exit 1
fi

require_literal docs/logging-policy.md "## Device-Local Audit"
require_literal docs/logging-policy.md "## User-Copied Diagnostics"
require_literal docs/logging-policy.md "## Runtime Output And Crash Handling"
require_literal docs/logging-policy.md "## Network Boundary"
require_literal docs/logging-policy.md "## Threat Boundary And Non-Claims"
require_literal docs/logging-policy.md "\`~/.keptnear/logs\` is a reserved owner-only directory"
require_literal docs/logging-policy.md "internal HTTP and direct"
require_literal docs/logging-policy.md "child-process executors are implemented"
require_literal docs/logging-policy.md "built-in templates are bundled offline"
require_literal docs/logging-policy.md "does not contact an"
require_literal docs/logging-policy.md "Pending"
require_literal docs/logging-policy.md "http.request"
require_literal docs/logging-policy.md "process.run"

require_literal docs/diagnostics.md "copied only when the user presses the copy button"
require_literal docs/diagnostics.md "closed \`connected\` or \`unavailable\` status"
require_literal docs/diagnostics.md "does not contain audit history"
require_literal docs/diagnostics.md "free-form Core status, errors, parser diagnostics, or provider responses"

require_literal docs/architecture.md "no general-purpose persistent log writer"
require_literal docs/architecture.md "Built-in Usage Profile templates are bundled offline"
require_literal docs/architecture.md "does not contact an update server"
require_literal docs/architecture.md "follows no redirects"
require_literal docs/architecture.md "whole-Vault export branch"

require_literal docs/security-model.md "persistent general-purpose log writer"
require_literal docs/security-model.md "Both internal executors exist"
require_literal docs/security-model.md "An audit event proves a local authorization decision"
require_literal docs/security-model.md "Exact redaction is not general data-loss"

require_literal docs/product-requirements.md "updates are manual"
require_literal docs/product-requirements.md "\`http.request\` and \`process.run\` executors"
require_literal docs/product-requirements.md "another provider owns any file-transfer traffic"
require_literal docs/product-requirements.md "It does not necessarily require"
require_literal docs/product-requirements.md "raw-output options on otherwise valid commands"

require_literal docs/update-policy.md "contact an update server"
require_literal docs/update-policy.md "Built-in templates remain offline"
require_literal docs/update-policy.md "separately disclosed and configurable network flow"

for path in "${required_files[@]}"; do
  reject_exact_line "$path" "KeptNear never uses a network."
  reject_exact_line "$path" "KeptNear never uses the network."
done

if [[ "$violations" -ne 0 ]]; then
  printf 'Privacy boundary documentation verification failed with %d violation(s).\n' "$violations" >&2
  exit 1
fi

printf 'Privacy boundary documentation verification passed: %d documents checked.\n' "${#required_files[@]}"
