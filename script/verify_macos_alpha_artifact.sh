#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
VERSION="${VERSION:-0.1.0-alpha}"
ARCHITECTURE="arm64"
VAULT_TYPE_IDENTIFIER="app.psw.local.vault"
VAULT_EXTENSION="pswvault"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ARCHIVE="$ROOT_DIR/dist/releases/$APP_NAME-$VERSION-macos-arm64.dmg"
ARCHIVE_PATH="${1:-$DEFAULT_ARCHIVE}"

if [[ "$ARCHIVE_PATH" != /* ]]; then
  ARCHIVE_PATH="$PWD/$ARCHIVE_PATH"
fi

ARCHIVE_DIR="$(cd "$(dirname "$ARCHIVE_PATH")" && pwd)"
ARCHIVE_BASENAME="$(basename "$ARCHIVE_PATH")"
if [[ "$ARCHIVE_BASENAME" != *.dmg ]]; then
  echo "expected a .dmg artifact, got: $ARCHIVE_BASENAME" >&2
  exit 1
fi
ARCHIVE_STEM="${ARCHIVE_BASENAME%.dmg}"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
MANIFEST_PATH="$ARCHIVE_DIR/$ARCHIVE_STEM-manifest.txt"
PROTOCOL_MANIFEST_PATH="$ARCHIVE_DIR/$ARCHIVE_STEM-protocol-manifest.json"
PROTOCOL_MANIFEST_FILENAME="$APP_NAME-Protocol-Manifest.json"
PACKAGE_MANIFEST_TOOL="$ROOT_DIR/target/release/keptnear-package-manifest"
SQLCIPHER_EVIDENCE_PATH="$ROOT_DIR/docs/sqlcipher-distribution-evidence.json"
SQLCIPHER_EVIDENCE_FILENAME="$APP_NAME-SQLCipher-Distribution-Evidence.json"
SQLCIPHER_GATE="$ROOT_DIR/script/verify_sqlcipher_distribution_gate.sh"

require_file() {
  local path="$1"
  local description="$2"
  if [[ ! -f "$path" || -L "$path" ]]; then
    echo "missing regular $description: $path" >&2
    exit 1
  fi
}

require_directory() {
  local path="$1"
  local description="$2"
  if [[ ! -d "$path" || -L "$path" ]]; then
    echo "missing real $description: $path" >&2
    exit 1
  fi
}

require_executable_file() {
  local path="$1"
  local description="$2"
  require_file "$path" "$description"
  if [[ ! -x "$path" ]]; then
    echo "$description is not executable: $path" >&2
    exit 1
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 1
  fi
}

manifest_field() {
  local field="$1"
  awk -F': ' -v key="$field" '$1 == key { print $2; exit }' "$MANIFEST_PATH"
}

manifest_section_field() {
  local section="$1"
  local field="$2"
  awk -F': ' -v section="$section" -v key="$field" '
    $0 == section { in_section = 1; next }
    in_section && $0 == "" { in_section = 0; next }
    in_section && $1 == key {
      sub("^[^:]+: ", "")
      print
      exit
    }
  ' "$MANIFEST_PATH"
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

require_arm64_binary() {
  local path="$1"
  local description="$2"
  local architectures
  architectures="$(lipo -archs "$path")"
  if [[ "$architectures" != "$ARCHITECTURE" ]]; then
    echo "$description must be arm64-only, got: $architectures" >&2
    exit 1
  fi
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

require_file "$ARCHIVE_PATH" "disk image"
require_file "$CHECKSUM_PATH" "checksum"
require_file "$MANIFEST_PATH" "manifest"
require_file "$PROTOCOL_MANIFEST_PATH" "protocol manifest"
require_file "$SQLCIPHER_EVIDENCE_PATH" "SQLCipher distribution evidence"
require_command codesign
require_command cmp
require_command cargo
require_command git
require_command hdiutil
require_command lipo
require_command python3
require_command xcrun

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

ACTUAL_PROTOCOL_MANIFEST_SHA256="$(shasum -a 256 "$PROTOCOL_MANIFEST_PATH" | awk '{print $1}')"
MANIFEST_PROTOCOL_MANIFEST_SHA256="$(require_manifest_field "Protocol manifest SHA-256")"
assert_equals \
  "protocol manifest SHA-256" \
  "$MANIFEST_PROTOCOL_MANIFEST_SHA256" \
  "$ACTUAL_PROTOCOL_MANIFEST_SHA256"

ACTUAL_SQLCIPHER_EVIDENCE_SHA256="$(shasum -a 256 "$SQLCIPHER_EVIDENCE_PATH" | awk '{print $1}')"
MANIFEST_SQLCIPHER_EVIDENCE_SHA256="$(require_manifest_field "SQLCipher distribution evidence SHA-256")"
assert_equals \
  "SQLCipher distribution evidence SHA-256" \
  "$MANIFEST_SQLCIPHER_EVIDENCE_SHA256" \
  "$ACTUAL_SQLCIPHER_EVIDENCE_SHA256"
assert_manifest_value "SQLCipher distribution evidence in DMG" "$SQLCIPHER_EVIDENCE_FILENAME"

assert_manifest_value "Channel" "manual"
assert_manifest_value "Automatic updates" "false"
assert_manifest_value "Architecture" "$ARCHITECTURE"
assert_manifest_value "Format" "DMG"
assert_manifest_value "Method" "Drag KeptNear.app to Applications"
assert_manifest_value "Supported architecture" "Apple Silicon arm64 only"
assert_manifest_value "Production ready" "false"

RELEASE_MODE="$(require_manifest_field "Release mode")"
if [[ "$RELEASE_MODE" != "local-test" ]]; then
  require_executable_file "$SQLCIPHER_GATE" "SQLCipher distribution gate"
fi
case "$RELEASE_MODE" in
  local-test)
    assert_manifest_value "Security decision" "not requested for local-test artifact"
    assert_manifest_value "Distribution ready" "false"
    ;;
  unsigned-experimental)
    "$SQLCIPHER_GATE"
    "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile unsigned
    assert_manifest_value "Security decision" "unaudited; AR-002 accepted-risk path verified"
    assert_manifest_value "Distribution ready" "true"
    assert_equals "unsigned release app signing status" "$(manifest_section_field "Signing" "Status")" "unsigned"
    assert_equals "unsigned release DMG signing status" "$(manifest_section_field "Signing" "Disk image signature")" "unsigned"
    assert_equals "unsigned release hardened runtime status" "$(manifest_section_field "Signing" "Hardened runtime")" "not requested"
    assert_equals "unsigned release notarization request" "$(manifest_section_field "Notarization" "Requested")" "0"
    assert_equals "unsigned release notarization status" "$(manifest_section_field "Notarization" "Status")" "skipped"
    assert_equals "unsigned release staple status" "$(manifest_section_field "Notarization" "Staple status")" "skipped"
    ;;
  experimental-pre-release)
    "$SQLCIPHER_GATE"
    "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile signed
    assert_manifest_value "Security decision" "external-review or maintainer accepted-risk path verified"
    assert_manifest_value "Distribution ready" "true"
    assert_equals "release app signing status" "$(manifest_section_field "Signing" "Status")" "valid"
    assert_equals "release DMG signing status" "$(manifest_section_field "Signing" "Disk image signature")" "valid"
    assert_equals "release hardened runtime status" "$(manifest_section_field "Signing" "Hardened runtime")" "requested"
    assert_equals "release notarization request" "$(manifest_section_field "Notarization" "Requested")" "1"
    assert_equals "release notarization status" "$(manifest_section_field "Notarization" "Status")" "accepted"
    assert_equals "release staple status" "$(manifest_section_field "Notarization" "Staple status")" "valid"
    ;;
  *)
    echo "invalid manifest Release mode value: $RELEASE_MODE" >&2
    exit 1
    ;;
esac

SOURCE_WORKTREE_STATUS="$(require_manifest_field "Source worktree")"
case "$SOURCE_WORKTREE_STATUS" in
  clean|dirty|unavailable) ;;
  *)
    echo "invalid manifest Source worktree value: $SOURCE_WORKTREE_STATUS" >&2
    exit 1
    ;;
esac
if [[ "$RELEASE_MODE" != "local-test" && "$SOURCE_WORKTREE_STATUS" != "clean" ]]; then
  echo "$RELEASE_MODE must come from a clean source worktree" >&2
  exit 1
fi
if [[ "$RELEASE_MODE" != "local-test" ]]; then
  CURRENT_GIT_REVISION="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || true)"
  if [[ -z "$CURRENT_GIT_REVISION" ]]; then
    echo "distribution artifact verification requires a Git checkout" >&2
    exit 1
  fi
  assert_equals \
    "distribution artifact source revision" \
    "$(require_manifest_field "Git revision")" \
    "$CURRENT_GIT_REVISION"
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]]; then
    echo "distribution artifact verification requires a clean Git worktree" >&2
    exit 1
  fi
fi

hdiutil verify "$ARCHIVE_PATH" >/dev/null

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/psw-alpha-verify.XXXXXX")"
MOUNT_DIR="$TMP_DIR/mount"
COPIED_ROOT="$TMP_DIR/package-root"
COPIED_APP="$COPIED_ROOT/$APP_NAME.app"
COPIED_PROTOCOL_MANIFEST="$TMP_DIR/$PROTOCOL_MANIFEST_FILENAME"
COPIED_SQLCIPHER_EVIDENCE="$TMP_DIR/$SQLCIPHER_EVIDENCE_FILENAME"
MOUNTED=0

cleanup() {
  if [[ "$MOUNTED" == "1" ]]; then
    hdiutil detach "$MOUNT_DIR" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$MOUNT_DIR" "$COPIED_ROOT"
hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_DIR" "$ARCHIVE_PATH" >/dev/null
MOUNTED=1

require_directory "$MOUNT_DIR/$APP_NAME.app" "app bundle in disk image"
require_file "$MOUNT_DIR/$PROTOCOL_MANIFEST_FILENAME" "protocol manifest in disk image"
require_file "$MOUNT_DIR/$SQLCIPHER_EVIDENCE_FILENAME" "SQLCipher distribution evidence in disk image"
if [[ ! -L "$MOUNT_DIR/Applications" ]]; then
  echo "disk image is missing Applications link" >&2
  exit 1
fi
assert_equals "Applications link" "$(readlink "$MOUNT_DIR/Applications")" "/Applications"

/usr/bin/ditto "$MOUNT_DIR/$APP_NAME.app" "$COPIED_APP"
cp "$MOUNT_DIR/$PROTOCOL_MANIFEST_FILENAME" "$COPIED_PROTOCOL_MANIFEST"
cp "$MOUNT_DIR/$SQLCIPHER_EVIDENCE_FILENAME" "$COPIED_SQLCIPHER_EVIDENCE"
hdiutil detach "$MOUNT_DIR" >/dev/null
MOUNTED=0

if ! cmp -s "$PROTOCOL_MANIFEST_PATH" "$COPIED_PROTOCOL_MANIFEST"; then
  echo "disk image protocol manifest does not match the adjacent artifact" >&2
  exit 1
fi
if ! cmp -s "$SQLCIPHER_EVIDENCE_PATH" "$COPIED_SQLCIPHER_EVIDENCE"; then
  echo "disk image SQLCipher distribution evidence does not match the current source receipt" >&2
  exit 1
fi
if [[ "$RELEASE_MODE" != "local-test" ]]; then
  "$SQLCIPHER_GATE" --evidence "$COPIED_SQLCIPHER_EVIDENCE"
fi

PROTOCOL_GIT_REVISION="$(
  python3 - "$COPIED_PROTOCOL_MANIFEST" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)
revision = manifest.get("product", {}).get("git_revision")
if not isinstance(revision, str) or not revision:
    raise SystemExit("protocol manifest is missing product.git_revision")
print(revision)
PY
)"
assert_equals \
  "protocol and package manifest Git revision" \
  "$PROTOCOL_GIT_REVISION" \
  "$(require_manifest_field "Git revision")"

APP_BUNDLE="$COPIED_APP"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"
INFO_PLIST="$APP_BUNDLE/Contents/Info.plist"
FFI_DYLIB="$APP_BUNDLE/Contents/Frameworks/libpsw_ffi.dylib"
APP_ICON="$APP_BUNDLE/Contents/Resources/KeptNear.icns"
APP_COMPONENT_METADATA="$APP_BUNDLE/Contents/Resources/KeptNear-App-Component.json"
BROKER_BINARY="$APP_BUNDLE/Contents/Helpers/keptnear-broker"
MCP_BINARY="$APP_BUNDLE/Contents/Helpers/keptnear-mcp"
CLI_BINARY="$APP_BUNDLE/Contents/Helpers/keptnear"

require_executable_file "$APP_BINARY" "app executable"
require_file "$INFO_PLIST" "Info.plist"
require_file "$FFI_DYLIB" "Rust FFI dylib"
require_file "$APP_ICON" "app icon"
require_file "$APP_COMPONENT_METADATA" "App component metadata"
require_executable_file "$BROKER_BINARY" "Broker executable"
require_executable_file "$MCP_BINARY" "MCP adapter executable"
require_executable_file "$CLI_BINARY" "CLI executable"
require_arm64_binary "$APP_BINARY" "app executable"
require_arm64_binary "$FFI_DYLIB" "Rust FFI dylib"
require_arm64_binary "$BROKER_BINARY" "Broker executable"
require_arm64_binary "$MCP_BINARY" "MCP adapter executable"
require_arm64_binary "$CLI_BINARY" "CLI executable"

if [[ ! -x "$PACKAGE_MANIFEST_TOOL" ]]; then
  cargo build \
    --locked \
    --release \
    -p psw-ffi \
    --bin keptnear-package-manifest >/dev/null
fi
require_executable_file "$PACKAGE_MANIFEST_TOOL" "protocol manifest verifier"
PACKAGE_VERSION="$(require_manifest_field "Version")"
PROTOCOL_DECLARATION="$(
  "$PACKAGE_MANIFEST_TOOL" \
    verify \
    --manifest "$PROTOCOL_MANIFEST_PATH" \
    --root "$COPIED_ROOT" \
    --product-version "$PACKAGE_VERSION" \
    --architecture "$ARCHITECTURE"
)"
assert_equals \
  "manifest Broker protocol" \
  "$(manifest_section_field "Component compatibility" "Broker protocol")" \
  "$PROTOCOL_DECLARATION"

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

MANIFEST_SIGNING_STATUS="$(manifest_section_field "Signing" "Status")"
MANIFEST_DMG_SIGNING_STATUS="$(manifest_section_field "Signing" "Disk image signature")"
if codesign --verify --deep --strict "$APP_BUNDLE" >/dev/null 2>&1; then
  ACTUAL_SIGNING_STATUS="valid"
else
  ACTUAL_SIGNING_STATUS="unsigned"
fi
assert_equals "signing status" "$ACTUAL_SIGNING_STATUS" "$MANIFEST_SIGNING_STATUS"

if codesign --verify --strict "$ARCHIVE_PATH" >/dev/null 2>&1; then
  ACTUAL_DMG_SIGNING_STATUS="valid"
else
  ACTUAL_DMG_SIGNING_STATUS="unsigned"
fi
assert_equals "disk image signing status" "$ACTUAL_DMG_SIGNING_STATUS" "$MANIFEST_DMG_SIGNING_STATUS"

STAPLE_STATUS="$(manifest_section_field "Notarization" "Staple status")"
if [[ "$STAPLE_STATUS" == "valid" ]]; then
  xcrun stapler validate "$ARCHIVE_PATH" >/dev/null
fi

echo "Verified alpha artifact: $ARCHIVE_PATH"
echo "SHA-256: $ACTUAL_SHA256"
echo "Signing status: $ACTUAL_SIGNING_STATUS"
echo "Disk image signing status: $ACTUAL_DMG_SIGNING_STATUS"
echo "Architecture: $ARCHITECTURE"
echo "Source worktree: $SOURCE_WORKTREE_STATUS"
echo "Release mode: $RELEASE_MODE"
echo "Update channel: manual"
echo "Broker protocol: $PROTOCOL_DECLARATION"
