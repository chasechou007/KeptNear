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

extract_release_tag() {
  local path="$1"
  local tags

  tags="$(grep -Eo 'releases/tag/v[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.]*' "$path" \
    | sed 's#releases/tag/##' \
    | sort -u \
    || true)"

  if [[ -z "$tags" || "$(printf '%s\n' "$tags" | wc -l | tr -d ' ')" -ne 1 ]]; then
    echo "public documentation violation: ${path#$ROOT_DIR/} must reference exactly one current release tag" >&2
    exit 1
  fi

  printf '%s' "$tags"
}

extract_sha256() {
  local path="$1"
  local checksums

  checksums="$(grep -E '^[[:xdigit:]]{64}$' "$path" \
    | tr '[:upper:]' '[:lower:]' \
    | sort -u \
    || true)"

  if [[ -z "$checksums" || "$(printf '%s\n' "$checksums" | wc -l | tr -d ' ')" -ne 1 ]]; then
    echo "public documentation violation: ${path#$ROOT_DIR/} must contain exactly one release SHA-256" >&2
    exit 1
  fi

  printf '%s' "$checksums"
}

BUILD_PATH="$ROOT_DIR/docs/build.md"
INSTALL_PATH="$ROOT_DIR/docs/macos-alpha-packaging.md"
SERVICE_ACTIVATION_PATH="$ROOT_DIR/docs/macos-service-activation-feasibility.md"
HUMAN_CONTROL_PROTOCOL_PATH="$ROOT_DIR/docs/human-control-protocol.md"
RECOVERY_PATH="$ROOT_DIR/docs/backup.md"
PRIVACY_PATH="$ROOT_DIR/docs/diagnostics.md"
LOGGING_PATH="$ROOT_DIR/docs/logging-policy.md"
SYNC_PATH="$ROOT_DIR/docs/sync.md"
IMPORT_EXPORT_PATH="$ROOT_DIR/docs/import-formats.md"
RELEASE_PATH="$ROOT_DIR/docs/release-readiness.md"
SQLCIPHER_EVIDENCE_PATH="$ROOT_DIR/docs/sqlcipher-distribution-evidence.json"
README_PATH="$ROOT_DIR/README.md"
README_ZH_PATH="$ROOT_DIR/README.zh-CN.md"
PRODUCT_OVERVIEW_PATH="$ROOT_DIR/docs/product-overview.md"
PRODUCT_OVERVIEW_ZH_PATH="$ROOT_DIR/docs/product-overview.zh-CN.md"
VAULT_SCREENSHOT_PATH="$ROOT_DIR/assets/screenshots/keptnear-vault-overview.png"
APPS_TOOLS_SCREENSHOT_PATH="$ROOT_DIR/assets/screenshots/keptnear-apps-tools.png"

for path in \
  "$BUILD_PATH" \
  "$INSTALL_PATH" \
  "$SERVICE_ACTIVATION_PATH" \
  "$HUMAN_CONTROL_PROTOCOL_PATH" \
  "$RECOVERY_PATH" \
  "$PRIVACY_PATH" \
  "$LOGGING_PATH" \
  "$SYNC_PATH" \
  "$IMPORT_EXPORT_PATH" \
  "$RELEASE_PATH" \
  "$SQLCIPHER_EVIDENCE_PATH" \
  "$README_PATH" \
  "$README_ZH_PATH" \
  "$PRODUCT_OVERVIEW_PATH" \
  "$PRODUCT_OVERVIEW_ZH_PATH" \
  "$VAULT_SCREENSHOT_PATH" \
  "$APPS_TOOLS_SCREENSHOT_PATH"; do
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
require_literal "$SERVICE_ACTIVATION_PATH" 'code 3 (`kSMErrorInvalidSignature`)'
require_literal "$SERVICE_ACTIVATION_PATH" "Eligible for local development evidence only"
require_literal "$SERVICE_ACTIVATION_PATH" "current DMG therefore remains Bundled But Not Activated"
require_literal "$README_PATH" "docs/macos-service-activation-feasibility.md"
require_literal "$README_ZH_PATH" "docs/macos-service-activation-feasibility.md"
require_literal "$HUMAN_CONTROL_PROTOCOL_PATH" 'Protocol identity: `keptnear.human-control`'
require_literal "$HUMAN_CONTROL_PROTOCOL_PATH" 'Schema identity: `keptnear.human-control.schema.v1`'
require_literal "$HUMAN_CONTROL_PROTOCOL_PATH" 'Maximum frame: 1 MiB.'
require_literal "$HUMAN_CONTROL_PROTOCOL_PATH" '`secret.get`'
require_literal "$HUMAN_CONTROL_PROTOCOL_PATH" 'No minor version may add a secret-returning result'
require_literal "$ROOT_DIR/docs/architecture.md" 'See `docs/human-control-protocol.md`.'

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

require_literal "$RELEASE_PATH" "script/verify_sqlcipher_distribution_gate.sh"
require_literal "$RELEASE_PATH" "docs/sqlcipher-distribution-evidence.json"
require_literal "$README_PATH" "docs/sqlcipher-distribution-evidence.json"
require_literal "$README_PATH" "README.zh-CN.md"
require_literal "$README_PATH" "docs/product-overview.md"
require_literal "$README_PATH" "assets/screenshots/keptnear-vault-overview.png"
require_literal "$README_PATH" "assets/screenshots/keptnear-apps-tools.png"
require_literal "$README_ZH_PATH" "README.md"
require_literal "$README_ZH_PATH" "docs/product-overview.zh-CN.md"
require_literal "$README_ZH_PATH" "AR-002"
require_literal "$README_ZH_PATH" "assets/screenshots/keptnear-vault-overview.png"
require_literal "$README_ZH_PATH" "assets/screenshots/keptnear-apps-tools.png"
require_literal "$PRODUCT_OVERVIEW_PATH" "product-overview.zh-CN.md"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "product-overview.md"

CURRENT_RELEASE="$(extract_release_tag "$README_PATH")"
for path in \
  "$README_ZH_PATH" \
  "$PRODUCT_OVERVIEW_PATH" \
  "$PRODUCT_OVERVIEW_ZH_PATH"; do
  release="$(extract_release_tag "$path")"
  if [[ "$release" != "$CURRENT_RELEASE" ]]; then
    echo "public documentation violation: ${path#$ROOT_DIR/} references $release; expected $CURRENT_RELEASE" >&2
    exit 1
  fi
done

README_SHA256="$(extract_sha256 "$README_PATH")"
README_ZH_SHA256="$(extract_sha256 "$README_ZH_PATH")"
if [[ "$README_ZH_SHA256" != "$README_SHA256" ]]; then
  echo "public documentation violation: README release SHA-256 values do not match" >&2
  exit 1
fi

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
