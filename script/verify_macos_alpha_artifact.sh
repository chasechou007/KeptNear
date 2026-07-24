#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
VERSION="${VERSION:-0.1.0-alpha}"
VAULT_TYPE_IDENTIFIER="app.psw.local.vault"
VAULT_EXTENSION="pswvault"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ARCHIVE="$ROOT_DIR/dist/releases/$APP_NAME-$VERSION-macos-alpha.zip"
ARCHIVE_PATH="${1:-$DEFAULT_ARCHIVE}"

if [[ "$ARCHIVE_PATH" != /* ]]; then
  ARCHIVE_PATH="$PWD/$ARCHIVE_PATH"
fi

ARCHIVE_DIR="$(cd "$(dirname "$ARCHIVE_PATH")" && pwd)"
ARCHIVE_BASENAME="$(basename "$ARCHIVE_PATH")"
ARCHIVE_STEM="${ARCHIVE_BASENAME%.zip}"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
MANIFEST_PATH="$ARCHIVE_DIR/$ARCHIVE_STEM-manifest.txt"

require_file() {
  local path="$1"
  local description="$2"
  if [[ ! -f "$path" ]]; then
    echo "missing $description: $path" >&2
    exit 1
  fi
}

manifest_field() {
  local field="$1"
  awk -F': ' -v key="$field" '$1 == key { print $2; exit }' "$MANIFEST_PATH"
}

require_manifest_field() {
  local field="$1"
  local value
  value="$(manifest_field "$field")"
  if [[ -z "$value" ]]; then
    echo "manifest missing field: $field" >&2
    exit 1
  fi
  printf '%s' "$value"
}

assert_equals() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "$label mismatch: expected '$expected', got '$actual'" >&2
    exit 1
  fi
}

assert_manifest_value() {
  local field="$1"
  local expected="$2"
  local actual
  actual="$(require_manifest_field "$field")"
  assert_equals "manifest $field" "$actual" "$expected"
}

plist_value() {
  local key_path="$1"
  local value
  if ! value="$(/usr/libexec/PlistBuddy -c "Print $key_path" "$INFO_PLIST" 2>/dev/null)"; then
    echo "Info.plist missing key: $key_path" >&2
    exit 1
  fi
  printf '%s' "$value"
}

assert_plist_value() {
  local key_path="$1"
  local expected="$2"
  local actual
  actual="$(plist_value "$key_path")"
  assert_equals "Info.plist $key_path" "$actual" "$expected"
}

require_file "$ARCHIVE_PATH" "archive"
require_file "$CHECKSUM_PATH" "checksum"
require_file "$MANIFEST_PATH" "manifest"

(
  cd "$ARCHIVE_DIR"
  shasum -a 256 -c "$(basename "$CHECKSUM_PATH")" >/dev/null
)

ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
MANIFEST_SHA256="$(require_manifest_field "SHA-256")"
assert_equals "manifest SHA-256" "$MANIFEST_SHA256" "$ACTUAL_SHA256"

ACTUAL_SIZE_BYTES="$(wc -c <"$ARCHIVE_PATH" | tr -d ' ')"
MANIFEST_SIZE_BYTES="$(require_manifest_field "Size bytes")"
assert_equals "manifest size" "$MANIFEST_SIZE_BYTES" "$ACTUAL_SIZE_BYTES"

assert_manifest_value "Channel" "manual"
assert_manifest_value "Automatic updates" "false"
assert_manifest_value "Distribution ready" "false"

unzip -l "$ARCHIVE_PATH" | grep -F "$APP_NAME.app/Contents/MacOS/$APP_NAME" >/dev/null
unzip -l "$ARCHIVE_PATH" | grep -F "$APP_NAME.app/Contents/Info.plist" >/dev/null
unzip -l "$ARCHIVE_PATH" | grep -F "$APP_NAME.app/Contents/Frameworks/libpsw_ffi.dylib" >/dev/null
unzip -l "$ARCHIVE_PATH" | grep -F "$APP_NAME.app/Contents/Resources/KeptNear.icns" >/dev/null

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/psw-alpha-verify.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

/usr/bin/ditto -x -k "$ARCHIVE_PATH" "$TMP_DIR"

APP_BUNDLE="$TMP_DIR/$APP_NAME.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"
INFO_PLIST="$APP_BUNDLE/Contents/Info.plist"
FFI_DYLIB="$APP_BUNDLE/Contents/Frameworks/libpsw_ffi.dylib"
APP_ICON="$APP_BUNDLE/Contents/Resources/KeptNear.icns"

require_file "$APP_BINARY" "app executable"
require_file "$INFO_PLIST" "Info.plist"
require_file "$FFI_DYLIB" "Rust FFI dylib"
require_file "$APP_ICON" "app icon"

if [[ ! -x "$APP_BINARY" ]]; then
  echo "app executable is not executable: $APP_BINARY" >&2
  exit 1
fi

assert_plist_value ":CFBundleDisplayName" "KeptNear"
assert_plist_value ":CFBundleIconFile" "KeptNear"
assert_plist_value ":CFBundleName" "KeptNear"
assert_plist_value ":CFBundleDocumentTypes:0:CFBundleTypeName" "KeptNear Vault"
assert_plist_value ":CFBundleDocumentTypes:0:CFBundleTypeRole" "Editor"
assert_plist_value ":CFBundleDocumentTypes:0:LSHandlerRank" "Owner"
assert_plist_value ":CFBundleDocumentTypes:0:LSItemContentTypes:0" "$VAULT_TYPE_IDENTIFIER"
assert_plist_value ":CFBundleDocumentTypes:0:LSTypeIsPackage" "true"
assert_plist_value ":UTExportedTypeDeclarations:0:UTTypeIdentifier" "$VAULT_TYPE_IDENTIFIER"
assert_plist_value ":UTExportedTypeDeclarations:0:UTTypeDescription" "KeptNear Vault"
assert_plist_value ":UTExportedTypeDeclarations:0:UTTypeConformsTo:0" "com.apple.package"
assert_plist_value ":UTExportedTypeDeclarations:0:UTTypeTagSpecification:public.filename-extension" "$VAULT_EXTENSION"

MANIFEST_SIGNING_STATUS="$(require_manifest_field "Status")"
if codesign --verify --deep --strict "$APP_BUNDLE" >/dev/null 2>&1; then
  ACTUAL_SIGNING_STATUS="valid"
else
  ACTUAL_SIGNING_STATUS="unsigned"
fi
assert_equals "signing status" "$ACTUAL_SIGNING_STATUS" "$MANIFEST_SIGNING_STATUS"

STAPLE_STATUS="$(require_manifest_field "Staple status")"
if [[ "$STAPLE_STATUS" == "valid" ]]; then
  xcrun stapler validate "$APP_BUNDLE" >/dev/null
fi

echo "Verified alpha artifact: $ARCHIVE_PATH"
echo "SHA-256: $ACTUAL_SHA256"
echo "Signing status: $ACTUAL_SIGNING_STATUS"
echo "Update channel: manual"
