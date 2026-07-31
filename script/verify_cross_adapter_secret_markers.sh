#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/swiftpm_local_env.sh"

BROKER_SOURCE="$ROOT_DIR/crates/psw-broker/src/integration_tests.rs"
MCP_SOURCE="$ROOT_DIR/crates/keptnear-mcp/src/mcp.rs"
CLI_SOURCE="$ROOT_DIR/crates/psw-cli/src/machine.rs"
APP_TEST_SOURCE="$ROOT_DIR/apps/macos/Tests/PSWMacTests/PSWMacWorkflowTests.swift"

BROKER_TEST="trusted_audit_view_export_and_confirmed_clear_never_modify_the_portable_vault"
MCP_TEST="every_tool_error_path_excludes_seeded_private_input_markers"
CLI_TEST="private_request_markers_do_not_cross_success_or_error_outputs"
APP_TEST="testDiagnosticsReportIncludesSupportContextAndExcludesSecrets"

require_test() {
  local source_path="$1"
  local test_name="$2"
  if [[ ! -f "$source_path" ]]; then
    echo "missing secret-marker test source: $source_path" >&2
    exit 1
  fi
  if ! grep -F "$test_name" "$source_path" >/dev/null; then
    echo "missing secret-marker regression: $test_name" >&2
    exit 1
  fi
}

require_test "$BROKER_SOURCE" "$BROKER_TEST"
require_test "$MCP_SOURCE" "$MCP_TEST"
require_test "$CLI_SOURCE" "$CLI_TEST"
require_test "$APP_TEST_SOURCE" "$APP_TEST"

cd "$ROOT_DIR"

echo "Running Broker seeded-secret output regression..."
cargo test --locked -p psw-broker "$BROKER_TEST"

echo "Running MCP seeded-secret output regression..."
cargo test --locked -p keptnear-mcp "$MCP_TEST"

echo "Running CLI seeded-secret output regression..."
cargo test --locked -p psw-cli "$CLI_TEST"

echo "Running App diagnostics seeded-secret output regression..."
swiftpm_test \
  --package-path "$ROOT_DIR/apps/macos" \
  --filter "PSWMacTests.PSWMacWorkflowTests/$APP_TEST"

echo "Cross-adapter seeded-secret output regressions passed."
