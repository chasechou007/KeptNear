#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "public documentation violation: missing ${path#$ROOT_DIR/}" >&2
    exit 1
  fi
}

require_literal() {
  local path="$1"
  local expected="$2"
  if ! grep -F "$expected" "$path" >/dev/null; then
    echo "public documentation violation: ${path#$ROOT_DIR/} is missing: $expected" >&2
    exit 1
  fi
}

reject_literal() {
  local path="$1"
  local forbidden="$2"
  if grep -F "$forbidden" "$path" >/dev/null; then
    echo "public documentation violation: ${path#$ROOT_DIR/} contains stale text: $forbidden" >&2
    exit 1
  fi
}

BUILD_PATH="$ROOT_DIR/docs/build.md"
INSTALL_PATH="$ROOT_DIR/docs/macos-alpha-packaging.md"
RECOVERY_PATH="$ROOT_DIR/docs/backup.md"
PRIVACY_PATH="$ROOT_DIR/docs/diagnostics.md"
LOGGING_PATH="$ROOT_DIR/docs/logging-policy.md"
SYNC_PATH="$ROOT_DIR/docs/sync.md"
IMPORT_EXPORT_PATH="$ROOT_DIR/docs/import-formats.md"
README_PATH="$ROOT_DIR/README.md"

for path in \
  "$BUILD_PATH" \
  "$INSTALL_PATH" \
  "$RECOVERY_PATH" \
  "$PRIVACY_PATH" \
  "$LOGGING_PATH" \
  "$SYNC_PATH" \
  "$IMPORT_EXPORT_PATH" \
  "$README_PATH"; do
  require_file "$path"
done

require_literal "$BUILD_PATH" "cargo clippy --workspace --all-targets --all-features -- -D warnings"
require_literal "$BUILD_PATH" "## Package Components"
require_literal "$BUILD_PATH" "does not install or activate a long-running"

require_literal "$INSTALL_PATH" "## Install An Unsigned Experimental DMG"
require_literal "$INSTALL_PATH" "shasum -a 256 -c"
require_literal "$INSTALL_PATH" "disable Gatekeeper globally"
require_literal "$INSTALL_PATH" "does not activate the bundled Broker"
require_literal "$INSTALL_PATH" "not suitable for production secrets"

require_literal "$RECOVERY_PATH" 'locked-vault'
require_literal "$RECOVERY_PATH" 'valid recovery kit'
require_literal "$RECOVERY_PATH" 'cannot decrypt the restored vault'
reject_literal "$RECOVERY_PATH" "The current macOS client does not yet expose that workflow."

require_literal "$PRIVACY_PATH" "Diagnostics are copied only when the user presses the copy button."
require_literal "$PRIVACY_PATH" "never uploads it automatically"
require_literal "$PRIVACY_PATH" "## Troubleshooting"
require_literal "$PRIVACY_PATH" "support diagnostics are not the encrypted machine-access audit"
require_literal "$LOGGING_PATH" "untrusted sensitive content"

require_literal "$SYNC_PATH" "keptnear vault doctor"
require_literal "$SYNC_PATH" "does not contact"
require_literal "$SYNC_PATH" "does not prove clean-install acceptance"
reject_literal "$SYNC_PATH" "Packaged document type registration"

require_literal "$IMPORT_EXPORT_PATH" 'KeptNear does not currently import `keptnear-json`.'
require_literal "$IMPORT_EXPORT_PATH" "always allocate fresh local Credential and Secret Field IDs"
require_literal "$IMPORT_EXPORT_PATH" "current master password"
require_literal "$IMPORT_EXPORT_PATH" "unavailable to MCP, CLI"

for link in \
  "docs/build.md" \
  "docs/macos-alpha-packaging.md" \
  "docs/backup.md" \
  "docs/logging-policy.md" \
  "docs/sync.md" \
  "docs/import-formats.md" \
  "docs/diagnostics.md"; do
  require_literal "$README_PATH" "$link"
done

echo "Public documentation set verification passed."
