#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
BUILD_PRODUCT_NAME="PSWMac"
BUNDLE_ID="app.psw.local.PSWMac"
MIN_SYSTEM_VERSION="13.0"
VERSION="${VERSION:-0.1.0-alpha}"
UPDATE_CHANNEL="manual"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
NOTARIZE="${NOTARIZE:-0}"
NOTARY_KEYCHAIN_PROFILE="${NOTARY_KEYCHAIN_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/macos_info_plist.sh"
source "$ROOT_DIR/script/swiftpm_local_env.sh"

DIST_DIR="$ROOT_DIR/dist"
RELEASES_DIR="$DIST_DIR/releases"
STAGING_DIR="$DIST_DIR/alpha-staging"
APP_BUNDLE="$STAGING_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_FRAMEWORKS="$APP_CONTENTS/Frameworks"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_BINARY="$APP_MACOS/$APP_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
FFI_DYLIB="$ROOT_DIR/target/release/libpsw_ffi.dylib"
APP_ICON="$ROOT_DIR/assets/brand/KeptNear.icns"
ARCHIVE_BASENAME="$APP_NAME-$VERSION-macos-alpha"
ARCHIVE_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME.zip"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
MANIFEST_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME-manifest.txt"
NOTARY_SUBMISSION_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME-notary-submission.zip"

if [[ "$NOTARIZE" != "0" && "$NOTARIZE" != "1" ]]; then
  echo "NOTARIZE must be 0 or 1" >&2
  exit 1
fi

require_file() {
  local path="$1"
  local description="$2"
  if [[ ! -f "$path" ]]; then
    echo "missing $description: $path" >&2
    exit 1
  fi
}

require_executable() {
  local path="$1"
  local description="$2"
  if [[ ! -x "$path" ]]; then
    echo "missing executable $description: $path" >&2
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

cd "$ROOT_DIR"

echo "Building Rust FFI dylib..."
cargo build -p psw-ffi --release

echo "Building Swift macOS app..."
swiftpm_build --package-path "$ROOT_DIR/apps/macos" -c release
BUILD_BINARY="$(swiftpm_bin_path --package-path "$ROOT_DIR/apps/macos" -c release)/$BUILD_PRODUCT_NAME"

rm -rf "$STAGING_DIR"
mkdir -p "$APP_MACOS" "$APP_FRAMEWORKS" "$APP_RESOURCES" "$RELEASES_DIR"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$FFI_DYLIB" "$APP_FRAMEWORKS/libpsw_ffi.dylib"
cp "$APP_ICON" "$APP_RESOURCES/KeptNear.icns"
chmod +x "$APP_BINARY"

write_pswmac_info_plist "$INFO_PLIST" "$APP_NAME" "$BUNDLE_ID" "$MIN_SYSTEM_VERSION" "$VERSION"

require_executable "$APP_BINARY" "app binary"
require_file "$INFO_PLIST" "Info.plist"
require_file "$APP_FRAMEWORKS/libpsw_ffi.dylib" "Rust FFI dylib"
require_file "$APP_RESOURCES/KeptNear.icns" "app icon"

SIGNING_STATUS="unsigned"
SIGNING_DETAIL="no signing identity provided"
SIGNING_IDENTITY_DETAIL="not provided"
HARDENED_RUNTIME_STATUS="not requested"
NOTARIZATION_STATUS="skipped"
NOTARIZATION_DETAIL="NOTARIZE is 0"
NOTARIZATION_AUTH_DETAIL="not provided"
STAPLE_STATUS="skipped"
STAPLE_DETAIL="notarization skipped"

if [[ -n "$SIGNING_IDENTITY" ]]; then
  require_command codesign
  SIGNING_IDENTITY_DETAIL="$SIGNING_IDENTITY"
  HARDENED_RUNTIME_STATUS="requested"
  echo "Signing Rust FFI dylib..."
  codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$APP_FRAMEWORKS/libpsw_ffi.dylib"
  echo "Signing app bundle..."
  codesign --force --timestamp --options runtime --deep --sign "$SIGNING_IDENTITY" "$APP_BUNDLE"
fi

if codesign --verify --deep --strict "$APP_BUNDLE" >/dev/null 2>&1; then
  SIGNING_STATUS="valid"
  SIGNING_DETAIL="codesign verification passed"
elif [[ -n "$SIGNING_IDENTITY" ]]; then
  echo "codesign verification failed after signing" >&2
  exit 1
else
  SIGNING_DETAIL="codesign verification failed or no signature is present"
fi

if [[ "$NOTARIZE" == "1" ]]; then
  require_command xcrun
  if [[ -z "$SIGNING_IDENTITY" || "$SIGNING_STATUS" != "valid" ]]; then
    echo "NOTARIZE=1 requires SIGNING_IDENTITY and a valid signed app bundle" >&2
    exit 1
  fi

  NOTARY_ARGS=()
  if [[ -n "$NOTARY_KEYCHAIN_PROFILE" ]]; then
    NOTARY_ARGS=(--keychain-profile "$NOTARY_KEYCHAIN_PROFILE")
    NOTARIZATION_AUTH_DETAIL="keychain profile: $NOTARY_KEYCHAIN_PROFILE"
  elif [[ -n "$APPLE_ID" && -n "$APPLE_TEAM_ID" && -n "$APPLE_APP_SPECIFIC_PASSWORD" ]]; then
    NOTARY_ARGS=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD")
    NOTARIZATION_AUTH_DETAIL="Apple ID: $APPLE_ID, team ID: $APPLE_TEAM_ID"
  else
    echo "NOTARIZE=1 requires NOTARY_KEYCHAIN_PROFILE or APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_SPECIFIC_PASSWORD" >&2
    exit 1
  fi

  echo "Creating notarization submission archive..."
  rm -f "$NOTARY_SUBMISSION_PATH"
  (
    cd "$STAGING_DIR"
    COPYFILE_DISABLE=1 /usr/bin/ditto -c -k --norsrc --keepParent "$APP_NAME.app" "$NOTARY_SUBMISSION_PATH"
  )

  echo "Submitting app for notarization..."
  xcrun notarytool submit "$NOTARY_SUBMISSION_PATH" --wait "${NOTARY_ARGS[@]}"
  NOTARIZATION_STATUS="accepted"
  NOTARIZATION_DETAIL="notarytool submit --wait completed"

  echo "Stapling notarization ticket..."
  xcrun stapler staple "$APP_BUNDLE"
  xcrun stapler validate "$APP_BUNDLE"
  STAPLE_STATUS="valid"
  STAPLE_DETAIL="stapler validate passed"
fi

rm -f "$ARCHIVE_PATH" "$CHECKSUM_PATH" "$MANIFEST_PATH"
(
  cd "$STAGING_DIR"
  COPYFILE_DISABLE=1 /usr/bin/ditto -c -k --norsrc --keepParent "$APP_NAME.app" "$ARCHIVE_PATH"
)

require_file "$ARCHIVE_PATH" "release archive"
ARCHIVE_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$(basename "$ARCHIVE_PATH")" >"$CHECKSUM_PATH"

BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_REVISION="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'uncommitted')"
ARCHIVE_SIZE_BYTES="$(wc -c <"$ARCHIVE_PATH" | tr -d ' ')"

cat >"$MANIFEST_PATH" <<MANIFEST
KeptNear Alpha Package Manifest
===============================

App name: $APP_NAME
Bundle ID: $BUNDLE_ID
Version: $VERSION
Minimum macOS: $MIN_SYSTEM_VERSION
Build timestamp UTC: $BUILD_TIMESTAMP
Git revision: $GIT_REVISION

Artifact
--------
Archive path: ${ARCHIVE_PATH#$ROOT_DIR/}
Checksum path: ${CHECKSUM_PATH#$ROOT_DIR/}
SHA-256: $ARCHIVE_SHA256
Size bytes: $ARCHIVE_SIZE_BYTES

Bundle validation
-----------------
App executable: present
Info.plist: present
Rust FFI dylib: present
App icon: present

Signing
-------
Status: $SIGNING_STATUS
Identity: $SIGNING_IDENTITY_DETAIL
Hardened runtime: $HARDENED_RUNTIME_STATUS
Detail: $SIGNING_DETAIL

Notarization
------------
Requested: $NOTARIZE
Status: $NOTARIZATION_STATUS
Auth: $NOTARIZATION_AUTH_DETAIL
Detail: $NOTARIZATION_DETAIL
Staple status: $STAPLE_STATUS
Staple detail: $STAPLE_DETAIL

Updates
-------
Channel: $UPDATE_CHANNEL
Automatic updates: false
Policy: Download the new alpha archive, verify the checksum, quit the app, and replace the app bundle manually.

Release boundary
----------------
Distribution ready: false
Reason: Alpha artifact; public release still requires review and distribution decisions.

Follow-up validation
--------------------
script/verify_macos_alpha_artifact.sh "${ARCHIVE_PATH#$ROOT_DIR/}"
MANIFEST

echo "Archive: $ARCHIVE_PATH"
echo "Checksum: $CHECKSUM_PATH"
echo "Manifest: $MANIFEST_PATH"
echo "Signing status: $SIGNING_STATUS"
