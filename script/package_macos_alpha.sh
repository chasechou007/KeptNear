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
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_BINARY="$APP_MACOS/$APP_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
APP_COMPONENT_METADATA="$APP_RESOURCES/KeptNear-App-Component.json"
FFI_DYLIB="$ROOT_DIR/target/release/libpsw_ffi.dylib"
APP_METADATA_PROBE="$ROOT_DIR/target/release/keptnear-app-metadata"
PACKAGE_MANIFEST_TOOL="$ROOT_DIR/target/release/keptnear-package-manifest"
BROKER_BINARY="$ROOT_DIR/target/release/keptnear-broker"
MCP_BINARY="$ROOT_DIR/target/release/keptnear-mcp"
CLI_BINARY="$ROOT_DIR/target/release/keptnear"
PACKAGED_BROKER="$APP_HELPERS/keptnear-broker"
PACKAGED_MCP="$APP_HELPERS/keptnear-mcp"
PACKAGED_CLI="$APP_HELPERS/keptnear"
APP_ICON="$ROOT_DIR/assets/brand/KeptNear.icns"
ARCHIVE_BASENAME="$APP_NAME-$VERSION-macos-arm64"
ARCHIVE_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME.dmg"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
MANIFEST_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME-manifest.txt"
PROTOCOL_MANIFEST_PATH="$RELEASES_DIR/$ARCHIVE_BASENAME-protocol-manifest.json"
PROTOCOL_MANIFEST_FILENAME="$APP_NAME-Protocol-Manifest.json"
SQLCIPHER_EVIDENCE_PATH="$ROOT_DIR/docs/sqlcipher-distribution-evidence.json"
SQLCIPHER_EVIDENCE_FILENAME="$APP_NAME-SQLCipher-Distribution-Evidence.json"
SQLCIPHER_GATE="$ROOT_DIR/script/verify_sqlcipher_distribution_gate.sh"
DMG_VOLUME_NAME="$APP_NAME $VERSION"

if [[ "$NOTARIZE" != "0" && "$NOTARIZE" != "1" ]]; then
  echo "NOTARIZE must be 0 or 1" >&2
  exit 1
fi

case "$RELEASE_MODE" in
  local-test|unsigned-experimental|experimental-pre-release) ;;
  *)
    echo "RELEASE_MODE must be local-test, unsigned-experimental, or experimental-pre-release" >&2
    exit 1
    ;;
esac

if [[ "$RELEASE_MODE" == "unsigned-experimental" ]]; then
  if [[ -n "$SIGNING_IDENTITY" ]]; then
    echo "unsigned-experimental forbids SIGNING_IDENTITY" >&2
    exit 1
  fi
  if [[ "$NOTARIZE" != "0" ]]; then
    echo "unsigned-experimental requires NOTARIZE=0" >&2
    exit 1
  fi
fi

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

require_manifest_atom() {
  local value="$1"
  local description="$2"
  if [[ ! "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$ ]]; then
    echo "$description contains unsupported manifest characters" >&2
    exit 1
  fi
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

cd "$ROOT_DIR"

require_command codesign
require_command hdiutil
require_command lipo
require_command shasum
require_manifest_atom "$VERSION" "VERSION"
require_file "$SQLCIPHER_EVIDENCE_PATH" "SQLCipher distribution evidence"

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

if [[ "$RELEASE_MODE" != "local-test" && "$SOURCE_WORKTREE_STATUS" != "clean" ]]; then
  echo "$RELEASE_MODE packaging requires a clean Git worktree, got: $SOURCE_WORKTREE_STATUS" >&2
  exit 1
fi
if [[ -n "$SIGNING_IDENTITY" && "$SOURCE_WORKTREE_STATUS" != "clean" ]]; then
  echo "signed packaging requires a clean Git worktree, got: $SOURCE_WORKTREE_STATUS" >&2
  exit 1
fi

DISTRIBUTION_READY="false"
PRODUCTION_READY="false"
SECURITY_DECISION="not requested for local-test artifact"
RELEASE_REASON="Local testing artifact; not approved for public distribution."

if [[ "$RELEASE_MODE" != "local-test" ]]; then
  require_executable "$SQLCIPHER_GATE" "SQLCipher distribution gate"
  echo "Verifying SQLCipher dependency and source-bound revalidation evidence..."
  "$SQLCIPHER_GATE"
fi

if [[ "$RELEASE_MODE" == "unsigned-experimental" ]]; then
  require_executable "$ROOT_DIR/script/verify_security_review_evidence.sh" "security decision verifier"
  echo "Verifying unsigned experimental security policy..."
  "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile unsigned
  DISTRIBUTION_READY="true"
  SECURITY_DECISION="unaudited; AR-002 accepted-risk path verified"
  RELEASE_REASON="Unsigned and unaudited experimental pre-release; do not use production secrets."
elif [[ "$RELEASE_MODE" == "experimental-pre-release" ]]; then
  require_executable "$ROOT_DIR/script/verify_security_review_evidence.sh" "security decision verifier"
  echo "Verifying experimental pre-release security decision..."
  "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile signed
  DISTRIBUTION_READY="true"
  SECURITY_DECISION="external-review or maintainer accepted-risk path verified"
  RELEASE_REASON="Experimental pre-release only; production use is not recommended."
fi

echo "Building Rust FFI and package metadata tools..."
cargo build \
  -p psw-ffi \
  --release \
  --lib \
  --bin keptnear-app-metadata \
  --bin keptnear-package-manifest

echo "Building Broker, MCP adapter, and CLI components..."
cargo build \
  --release \
  -p psw-broker \
  -p keptnear-mcp \
  -p psw-cli \
  --bin keptnear-broker \
  --bin keptnear-mcp \
  --bin keptnear

echo "Building Swift macOS app..."
swiftpm_build --package-path "$ROOT_DIR/apps/macos" -c release
BUILD_BINARY="$(swiftpm_bin_path --package-path "$ROOT_DIR/apps/macos" -c release)/$BUILD_PRODUCT_NAME"

rm -rf "$STAGING_DIR"
mkdir -p \
  "$APP_MACOS" \
  "$APP_FRAMEWORKS" \
  "$APP_HELPERS" \
  "$APP_RESOURCES" \
  "$RELEASES_DIR"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$FFI_DYLIB" "$APP_FRAMEWORKS/libpsw_ffi.dylib"
cp "$BROKER_BINARY" "$PACKAGED_BROKER"
cp "$MCP_BINARY" "$PACKAGED_MCP"
cp "$CLI_BINARY" "$PACKAGED_CLI"
cp "$APP_ICON" "$APP_RESOURCES/KeptNear.icns"
"$APP_METADATA_PROBE" --component-metadata >"$APP_COMPONENT_METADATA"
chmod +x "$APP_BINARY" "$PACKAGED_BROKER" "$PACKAGED_MCP" "$PACKAGED_CLI"

write_pswmac_info_plist "$INFO_PLIST" "$APP_NAME" "$BUNDLE_ID" "$MIN_SYSTEM_VERSION" "$VERSION"

require_executable "$APP_BINARY" "app binary"
require_file "$INFO_PLIST" "Info.plist"
require_file "$APP_FRAMEWORKS/libpsw_ffi.dylib" "Rust FFI dylib"
require_file "$APP_RESOURCES/KeptNear.icns" "app icon"
require_file "$APP_COMPONENT_METADATA" "App component metadata"
require_executable "$APP_METADATA_PROBE" "App metadata probe"
require_executable "$PACKAGE_MANIFEST_TOOL" "protocol manifest generator"
require_executable "$PACKAGED_BROKER" "Broker"
require_executable "$PACKAGED_MCP" "MCP adapter"
require_executable "$PACKAGED_CLI" "CLI"
require_arm64_binary "$APP_BINARY" "app executable"
require_arm64_binary "$APP_FRAMEWORKS/libpsw_ffi.dylib" "Rust FFI dylib"
require_arm64_binary "$PACKAGED_BROKER" "Broker"
require_arm64_binary "$PACKAGED_MCP" "MCP adapter"
require_arm64_binary "$PACKAGED_CLI" "CLI"

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
  echo "Signing Broker, MCP adapter, and CLI..."
  codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$PACKAGED_BROKER"
  codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$PACKAGED_MCP"
  codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$PACKAGED_CLI"
  echo "Signing app bundle..."
  codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$APP_BUNDLE"
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

BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
rm -f "$PROTOCOL_MANIFEST_PATH"
BROKER_PROTOCOL_DECLARATION="$(
  "$PACKAGE_MANIFEST_TOOL" \
    generate \
    --product-version "$VERSION" \
    --architecture "$ARCHITECTURE" \
    --git-revision "$GIT_REVISION" \
    --source-worktree "$SOURCE_WORKTREE_STATUS" \
    --generated-at-utc "$BUILD_TIMESTAMP" \
    --output "$PROTOCOL_MANIFEST_PATH" \
    --app-executable "$APP_BINARY" \
    --app-metadata "$APP_METADATA_PROBE" \
    --app-metadata-file "$APP_COMPONENT_METADATA" \
    --broker "$PACKAGED_BROKER" \
    --mcp "$PACKAGED_MCP" \
    --cli "$PACKAGED_CLI" \
    --ffi "$APP_FRAMEWORKS/libpsw_ffi.dylib"
)"
require_file "$PROTOCOL_MANIFEST_PATH" "protocol manifest"
PROTOCOL_MANIFEST_SHA256="$(sha256_file "$PROTOCOL_MANIFEST_PATH")"
SQLCIPHER_EVIDENCE_SHA256="$(sha256_file "$SQLCIPHER_EVIDENCE_PATH")"

echo "Creating Apple Silicon disk image..."
rm -rf "$DMG_STAGING_DIR"
mkdir -p "$DMG_STAGING_DIR" "$RELEASES_DIR"
/usr/bin/ditto "$APP_BUNDLE" "$DMG_STAGING_DIR/$APP_NAME.app"
cp "$PROTOCOL_MANIFEST_PATH" "$DMG_STAGING_DIR/$PROTOCOL_MANIFEST_FILENAME"
cp "$SQLCIPHER_EVIDENCE_PATH" "$DMG_STAGING_DIR/$SQLCIPHER_EVIDENCE_FILENAME"
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
Protocol manifest path: ${PROTOCOL_MANIFEST_PATH#$ROOT_DIR/}
Protocol manifest SHA-256: $PROTOCOL_MANIFEST_SHA256
SQLCipher distribution evidence in DMG: $SQLCIPHER_EVIDENCE_FILENAME
SQLCipher distribution evidence SHA-256: $SQLCIPHER_EVIDENCE_SHA256

Bundle validation
-----------------
App executable: present
App executable architecture: $ARCHITECTURE
Info.plist: present
Rust FFI dylib: present
Rust FFI architecture: $ARCHITECTURE
App component metadata: present
Broker executable: present
Broker architecture: $ARCHITECTURE
MCP adapter executable: present
MCP adapter architecture: $ARCHITECTURE
CLI executable: present
CLI architecture: $ARCHITECTURE
App icon: present
Applications link: present

Component compatibility
-----------------------
Broker protocol: $BROKER_PROTOCOL_DECLARATION
Protocol manifest in DMG: $PROTOCOL_MANIFEST_FILENAME

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
echo "Protocol manifest: $PROTOCOL_MANIFEST_PATH"
echo "Signing status: $SIGNING_STATUS"
