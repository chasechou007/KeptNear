#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
VERSION="${VERSION:-0.1.0-alpha}"

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
MANIFEST_PATH="$ARCHIVE_DIR/$ARCHIVE_STEM-manifest.txt"

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

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 1
  fi
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

manifest_field() {
  local field="$1"
  awk -F': ' -v key="$field" '$1 == key { print $2; exit }' "$MANIFEST_PATH"
}

require_manifest_value() {
  local field="$1"
  local expected="$2"
  local actual
  actual="$(manifest_field "$field")"
  if [[ "$actual" != "$expected" ]]; then
    echo "manifest $field mismatch: expected '$expected', got '$actual'" >&2
    exit 1
  fi
}

require_manifest_section_value() {
  local section="$1"
  local field="$2"
  local expected="$3"
  local actual
  actual="$(manifest_section_field "$section" "$field")"
  if [[ -z "$actual" ]]; then
    echo "manifest missing $section/$field" >&2
    exit 1
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "manifest $section/$field mismatch: expected '$expected', got '$actual'" >&2
    exit 1
  fi
}

require_command codesign
require_command hdiutil
require_command spctl
require_command xcrun

require_file "$ARCHIVE_PATH" "disk image"
require_file "$MANIFEST_PATH" "manifest"

echo "Verifying base alpha artifact..."
"$ROOT_DIR/script/verify_macos_alpha_artifact.sh" "$ARCHIVE_PATH"

require_manifest_section_value "Signing" "Status" "valid"
require_manifest_section_value "Signing" "Disk image signature" "valid"
require_manifest_section_value "Signing" "Hardened runtime" "requested"
require_manifest_section_value "Notarization" "Requested" "1"
require_manifest_section_value "Notarization" "Status" "accepted"
require_manifest_section_value "Notarization" "Staple status" "valid"
require_manifest_value "Source worktree" "clean"

echo "Verifying disk image signature..."
codesign --verify --strict --verbose=2 "$ARCHIVE_PATH"

echo "Verifying disk image Gatekeeper assessment..."
spctl --assess --type open --context context:primary-signature --verbose=4 "$ARCHIVE_PATH"

echo "Validating stapled notarization ticket..."
xcrun stapler validate "$ARCHIVE_PATH"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/psw-signed-install.XXXXXX")"
MOUNT_DIR="$TMP_DIR/mount"
APP_BUNDLE="$TMP_DIR/$APP_NAME.app"
MOUNTED=0

cleanup() {
  if [[ "$MOUNTED" == "1" ]]; then
    hdiutil detach "$MOUNT_DIR" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$MOUNT_DIR"
hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT_DIR" "$ARCHIVE_PATH" >/dev/null
MOUNTED=1
require_directory "$MOUNT_DIR/$APP_NAME.app" "app bundle in disk image"
if [[ ! -L "$MOUNT_DIR/Applications" ]]; then
  echo "disk image is missing Applications link" >&2
  exit 1
fi
/usr/bin/ditto "$MOUNT_DIR/$APP_NAME.app" "$APP_BUNDLE"
hdiutil detach "$MOUNT_DIR" >/dev/null
MOUNTED=0

APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"
INFO_PLIST="$APP_BUNDLE/Contents/Info.plist"
FFI_DYLIB="$APP_BUNDLE/Contents/Frameworks/libpsw_ffi.dylib"

require_directory "$APP_BUNDLE" "extracted app bundle"
require_file "$APP_BINARY" "app executable"
require_file "$INFO_PLIST" "Info.plist"
require_file "$FFI_DYLIB" "Rust FFI dylib"

echo "Verifying code signature..."
codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"

echo "Verifying Gatekeeper assessment..."
spctl --assess --type execute --verbose=4 "$APP_BUNDLE"

echo "Verifying Launch Services vault document registration..."
"$ROOT_DIR/script/verify_macos_launch_services_vault_type.sh" "$APP_BUNDLE"

echo "Verified signed macOS install readiness for: $ARCHIVE_PATH"
echo "Disk image and copied app passed codesign, Gatekeeper, staple, and Launch Services checks."
