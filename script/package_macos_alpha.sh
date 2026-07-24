#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
BUILD_PRODUCT_NAME="PSWMac"
BUNDLE_ID="app.psw.local.PSWMac"
MIN_SYSTEM_VERSION="13.0"
ARCHITECTURE="arm64"
VERSION="${VERSION:-0.1.0-alpha}"
UPDATE_CHANNEL="manual"
RELEASE_MODE="${RELEASE_MODE:-local-test}"
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
DMG_STAGING_DIR="$DIST_DIR/dmg-staging"
APP_BUNDLE="$STAGING_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_FRAMEWORKS="$APP_CONTENTS/Frameworks"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_BINARY="$APP_MACOS/$APP_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
FFI_DYLIB="$ROOT_DIR/target/release/libpsw_ffi.dylib"
APP_ICON="$ROOT_DIR/assets/brand/KeptNear.icns"
ARCHIVE_BASENAME="$APP_NAME-$VERSION-macos-arm64"
ARCHIVE_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME.dmg"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
MANIFEST_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME-manifest.txt"
DMG_VOLUME_NAME="$APP_NAME $VERSION"

if [[ "$NOTARIZE" != "0" && "$NOTARIZE" != "1" ]]; then
  echo "NOTARIZE must be 0 or 1" >&2
  exit 1
fi

case "$RELEASE_MODE" in
  local-test|experimental-pre-release) ;;
  *)
    echo "RELEASE_MODE must be local-test or experimental-pre-release" >&2
    exit 1
    ;;
esac

if [[ "$RELEASE_MODE" == "experimental-pre-release" ]]; then
  if [[ -z "$SIGNING_IDENTITY" ]]; then
    echo "experimental-pre-release requires SIGNING_IDENTITY" >&2
    exit 1
  fi
  if [[ "$NOTARIZE" != "1" ]]; then
    echo "experimental-pre-release requires NOTARIZE=1" >&2
    exit 1
  fi
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

cd "$ROOT_DIR"

require_command codesign
require_command hdiutil
require_command lipo

HOST_ARCHITECTURE="$(uname -m)"
if [[ "$HOST_ARCHITECTURE" != "$ARCHITECTURE" ]]; then
  echo "Apple Silicon packaging requires an arm64 host, got: $HOST_ARCHITECTURE" >&2
  exit 1
fi

GIT_REVISION="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'unavailable')"
SOURCE_WORKTREE_STATUS="unavailable"
if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]]; then
    SOURCE_WORKTREE_STATUS="dirty"
  else
    SOURCE_WORKTREE_STATUS="clean"
  fi
fi

if [[ -n "$SIGNING_IDENTITY" && "$SOURCE_WORKTREE_STATUS" != "clean" ]]; then
  echo "signed packaging requires a clean Git worktree, got: $SOURCE_WORKTREE_STATUS" >&2
  exit 1
fi

DISTRIBUTION_READY="false"
PRODUCTION_READY="false"
SECURITY_DECISION="not requested for local-test artifact"
RELEASE_REASON="Local testing artifact; not approved for public distribution."

if [[ "$RELEASE_MODE" == "experimental-pre-release" ]]; then
  require_executable "$ROOT_DIR/script/verify_security_review_evidence.sh" "security decision verifier"
  echo "Verifying experimental pre-release security decision..."
  "$ROOT_DIR/script/verify_security_review_evidence.sh"
  DISTRIBUTION_READY="true"
  SECURITY_DECISION="external-review or maintainer accepted-risk path verified"
  RELEASE_REASON="Experimental pre-release only; production use is not recommended."
fi

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
require_arm64_binary "$APP_BINARY" "app executable"
require_arm64_binary "$APP_FRAMEWORKS/libpsw_ffi.dylib" "Rust FFI dylib"

SIGNING_STATUS="unsigned"
SIGNING_DETAIL="no signing identity provided"
SIGNING_IDENTITY_DETAIL="not provided"
DMG_SIGNING_STATUS="unsigned"
DMG_SIGNING_DETAIL="no signing identity provided"
HARDENED_RUNTIME_STATUS="not requested"
NOTARIZATION_STATUS="skipped"
NOTARIZATION_DETAIL="NOTARIZE is 0"
NOTARIZATION_AUTH_DETAIL="not provided"
STAPLE_STATUS="skipped"
STAPLE_DETAIL="notarization skipped"

if [[ -n "$SIGNING_IDENTITY" ]]; then
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

echo "Creating Apple Silicon disk image..."
rm -rf "$DMG_STAGING_DIR"
mkdir -p "$DMG_STAGING_DIR" "$RELEASES_DIR"
/usr/bin/ditto "$APP_BUNDLE" "$DMG_STAGING_DIR/$APP_NAME.app"
ln -s /Applications "$DMG_STAGING_DIR/Applications"
rm -f "$ARCHIVE_PATH" "$CHECKSUM_PATH" "$MANIFEST_PATH"
hdiutil create \
  -volname "$DMG_VOLUME_NAME" \
  -srcfolder "$DMG_STAGING_DIR" \
  -ov \
  -format UDZO \
  "$ARCHIVE_PATH"

require_file "$ARCHIVE_PATH" "release disk image"

if [[ -n "$SIGNING_IDENTITY" ]]; then
  echo "Signing disk image..."
  codesign --force --timestamp --sign "$SIGNING_IDENTITY" "$ARCHIVE_PATH"
fi

if codesign --verify --strict "$ARCHIVE_PATH" >/dev/null 2>&1; then
  DMG_SIGNING_STATUS="valid"
  DMG_SIGNING_DETAIL="disk image codesign verification passed"
elif [[ -n "$SIGNING_IDENTITY" ]]; then
  echo "disk image codesign verification failed after signing" >&2
  exit 1
else
  DMG_SIGNING_DETAIL="disk image signature is not present"
fi

if [[ "$NOTARIZE" == "1" ]]; then
  require_command xcrun
  if [[ -z "$SIGNING_IDENTITY" || "$SIGNING_STATUS" != "valid" || "$DMG_SIGNING_STATUS" != "valid" ]]; then
    echo "NOTARIZE=1 requires a valid Developer ID signature on both the app bundle and disk image" >&2
    exit 1
  fi

  NOTARY_ARGS=()
  if [[ -n "$NOTARY_KEYCHAIN_PROFILE" ]]; then
    NOTARY_ARGS=(--keychain-profile "$NOTARY_KEYCHAIN_PROFILE")
    NOTARIZATION_AUTH_DETAIL="keychain profile"
  elif [[ -n "$APPLE_ID" && -n "$APPLE_TEAM_ID" && -n "$APPLE_APP_SPECIFIC_PASSWORD" ]]; then
    NOTARY_ARGS=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD")
    NOTARIZATION_AUTH_DETAIL="Apple ID credential set"
  else
    echo "NOTARIZE=1 requires NOTARY_KEYCHAIN_PROFILE or APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_SPECIFIC_PASSWORD" >&2
    exit 1
  fi

  echo "Submitting disk image for notarization..."
  xcrun notarytool submit "$ARCHIVE_PATH" --wait "${NOTARY_ARGS[@]}"
  NOTARIZATION_STATUS="accepted"
  NOTARIZATION_DETAIL="notarytool submit --wait completed"

  echo "Stapling notarization ticket to disk image..."
  xcrun stapler staple "$ARCHIVE_PATH"
  xcrun stapler validate "$ARCHIVE_PATH"
  STAPLE_STATUS="valid"
  STAPLE_DETAIL="disk image stapler validation passed"
fi

ARCHIVE_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$(basename "$ARCHIVE_PATH")" >"$CHECKSUM_PATH"

BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
ARCHIVE_SIZE_BYTES="$(wc -c <"$ARCHIVE_PATH" | tr -d ' ')"

cat >"$MANIFEST_PATH" <<MANIFEST
KeptNear Alpha Package Manifest
===============================

App name: $APP_NAME
Bundle ID: $BUNDLE_ID
Version: $VERSION
Minimum macOS: $MIN_SYSTEM_VERSION
Architecture: $ARCHITECTURE
Build timestamp UTC: $BUILD_TIMESTAMP
Git revision: $GIT_REVISION
Source worktree: $SOURCE_WORKTREE_STATUS

Artifact
--------
Format: DMG
Disk image path: ${ARCHIVE_PATH#$ROOT_DIR/}
Checksum path: ${CHECKSUM_PATH#$ROOT_DIR/}
SHA-256: $ARCHIVE_SHA256
Size bytes: $ARCHIVE_SIZE_BYTES
Volume name: $DMG_VOLUME_NAME

Bundle validation
-----------------
App executable: present
App executable architecture: $ARCHITECTURE
Info.plist: present
Rust FFI dylib: present
Rust FFI architecture: $ARCHITECTURE
App icon: present
Applications link: present

Signing
-------
Status: $SIGNING_STATUS
Disk image signature: $DMG_SIGNING_STATUS
Identity: $SIGNING_IDENTITY_DETAIL
Hardened runtime: $HARDENED_RUNTIME_STATUS
App detail: $SIGNING_DETAIL
Disk image detail: $DMG_SIGNING_DETAIL

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
Policy: Download the DMG, verify the checksum, quit KeptNear, and drag KeptNear.app to Applications.

Installation
------------
Method: Drag KeptNear.app to Applications
Supported architecture: Apple Silicon arm64 only

Release boundary
----------------
Release mode: $RELEASE_MODE
Security decision: $SECURITY_DECISION
Distribution ready: $DISTRIBUTION_READY
Production ready: $PRODUCTION_READY
Reason: $RELEASE_REASON

Follow-up validation
--------------------
script/verify_macos_alpha_artifact.sh "${ARCHIVE_PATH#$ROOT_DIR/}"
MANIFEST

echo "Disk image: $ARCHIVE_PATH"
echo "Checksum: $CHECKSUM_PATH"
echo "Manifest: $MANIFEST_PATH"
echo "Signing status: $SIGNING_STATUS"
