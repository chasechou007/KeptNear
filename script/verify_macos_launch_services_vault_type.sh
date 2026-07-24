#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
BUNDLE_ID="app.psw.local.PSWMac"
VAULT_TYPE_IDENTIFIER="app.psw.local.vault"
VAULT_EXTENSION="pswvault"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_BUNDLE="${1:-$ROOT_DIR/dist/alpha-staging/$APP_NAME.app}"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

if [[ "$APP_BUNDLE" != /* ]]; then
  APP_BUNDLE="$PWD/$APP_BUNDLE"
fi

INFO_PLIST="$APP_BUNDLE/Contents/Info.plist"

require_directory() {
  local path="$1"
  local description="$2"
  if [[ ! -d "$path" ]]; then
    echo "missing $description: $path" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  local description="$2"
  if [[ ! -f "$path" ]]; then
    echo "missing $description: $path" >&2
    exit 1
  fi
}

require_contains() {
  local label="$1"
  local pattern="$2"
  if ! grep -F "$pattern" "$DUMP_PATH" >/dev/null; then
    echo "Launch Services dump missing $label: $pattern" >&2
    exit 1
  fi
}

register_app_bundle() {
  local status=0

  "$LSREGISTER" -f "$APP_BUNDLE" >"$REGISTER_OUTPUT_PATH" 2>&1 || status=$?
  if [[ "$status" -eq 0 ]]; then
    return
  fi

  if [[ -s "$REGISTER_OUTPUT_PATH" ]]; then
    cat "$REGISTER_OUTPUT_PATH" >&2
    printf '\n' >&2
  fi

  {
    echo "Launch Services registration failed for: $APP_BUNDLE"
    echo "Command: $LSREGISTER -f $APP_BUNDLE"
    echo "This verifier updates the current user's Launch Services database."
    echo "If this is running in a managed workspace sandbox or automation agent, rerun it from an unsandboxed terminal or grant explicit approval for user-level Launch Services access."
    echo "The app bundle was not registered, so vault-type readiness cannot be claimed."
  } >&2

  exit "$status"
}

require_directory "$APP_BUNDLE" "app bundle"
require_file "$INFO_PLIST" "Info.plist"
require_file "$LSREGISTER" "lsregister"

DUMP_PATH="$(mktemp "${TMPDIR:-/tmp}/psw-lsregister.XXXXXX")"
REGISTER_OUTPUT_PATH="$(mktemp "${TMPDIR:-/tmp}/psw-lsregister-register.XXXXXX")"
trap 'rm -f "$DUMP_PATH" "$REGISTER_OUTPUT_PATH"' EXIT

register_app_bundle
"$LSREGISTER" -dump >"$DUMP_PATH"

require_contains "bundle identifier" "identifier:                 $BUNDLE_ID"
require_contains "claimed vault UTI" "claimed UTIs:               $VAULT_TYPE_IDENTIFIER"
require_contains "vault type identifier" "uti:                        $VAULT_TYPE_IDENTIFIER"
require_contains "vault package conformance" "conforms to:                com.apple.package"
require_contains "vault filename extension tag" "tags:                       .$VAULT_EXTENSION"
require_contains "vault document role" "roles:                      Editor"
require_contains "vault document rank" "rank:                       Owner"
require_contains "vault package document flags" "flags:                      package  doc-type"
require_contains "vault UTI binding" "bindings:                   $VAULT_TYPE_IDENTIFIER"

echo "Verified Launch Services vault type for: $APP_BUNDLE"
echo "Bundle ID: $BUNDLE_ID"
echo "Vault UTI: $VAULT_TYPE_IDENTIFIER"
echo "Extension: .$VAULT_EXTENSION"
