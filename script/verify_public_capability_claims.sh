#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README_PATH="$ROOT_DIR/README.md"
STATUS_PATH="$ROOT_DIR/docs/capability-status.md"
BRAND_PATH="$ROOT_DIR/docs/brand.md"
MCP_TOOLS_PATH="$ROOT_DIR/crates/keptnear-mcp/src/tools.rs"
PACKAGE_PATH="$ROOT_DIR/script/package_macos_alpha.sh"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "public capability claim violation: missing ${path#$ROOT_DIR/}" >&2
    exit 1
  fi
}

require_literal() {
  local path="$1"
  local expected="$2"
  if ! grep -F "$expected" "$path" >/dev/null; then
    echo "public capability claim violation: ${path#$ROOT_DIR/} is missing: $expected" >&2
    exit 1
  fi
}

reject_literal() {
  local path="$1"
  local forbidden="$2"
  if grep -Fi "$forbidden" "$path" >/dev/null; then
    echo "public capability claim violation: ${path#$ROOT_DIR/} contains forbidden claim: $forbidden" >&2
    exit 1
  fi
}

for path in \
  "$README_PATH" \
  "$STATUS_PATH" \
  "$BRAND_PATH" \
  "$MCP_TOOLS_PATH" \
  "$PACKAGE_PATH" \
  "$ROOT_DIR/crates/psw-broker/src/main.rs" \
  "$ROOT_DIR/crates/keptnear-mcp/src/main.rs" \
  "$ROOT_DIR/crates/psw-cli/src/keptnear.rs"; do
  require_file "$path"
done

require_literal "$README_PATH" "Local Password &amp; Token Manager"
require_literal "$README_PATH" "## Capability Status"
require_literal "$README_PATH" "### Available In The macOS Source Build"
require_literal "$README_PATH" "### Implemented And Tested In Source"
require_literal "$README_PATH" "### Bundled But Not Activated"
require_literal "$README_PATH" "### Not Shipped"
require_literal "$README_PATH" "No installable binary or GitHub Release is currently published."
require_literal "$README_PATH" "does not install or activate a"
require_literal "$README_PATH" "End-user MCP or CLI machine credential access is not a released product"
require_literal "$README_PATH" "Do not use it to store production"

require_literal "$STATUS_PATH" "Source implementation is not the same as a shipped product capability."
require_literal "$STATUS_PATH" "There is no raw secret retrieval command."
require_literal "$STATUS_PATH" "It does not activate a long-running Broker service"
require_literal "$STATUS_PATH" "No external security review is complete."
require_literal "$STATUS_PATH" "No profile recommends production-secret use."
require_literal "$BRAND_PATH" "**Approved public descriptor:** Local Password & Token Manager"

for capability in \
  credential.search \
  access.request \
  grant.status \
  grant.revoke \
  http.request \
  process.run; do
  require_literal "$MCP_TOOLS_PATH" "\"$capability\""
  require_literal "$STATUS_PATH" "\`$capability\`"
done

require_literal "$PACKAGE_PATH" 'PACKAGED_BROKER="$APP_HELPERS/keptnear-broker"'
require_literal "$PACKAGE_PATH" 'PACKAGED_MCP="$APP_HELPERS/keptnear-mcp"'
require_literal "$PACKAGE_PATH" 'PACKAGED_CLI="$APP_HELPERS/keptnear"'

for path in "$README_PATH" "$STATUS_PATH"; do
  reject_literal "$path" "production-ready password manager"
  reject_literal "$path" "externally audited"
  reject_literal "$path" "automatic cloud sync"
  reject_literal "$path" "end-to-end encrypted cloud service"
  reject_literal "$path" "MCP and CLI are available to end users"
done

echo "Public capability claim verification passed."
