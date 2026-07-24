#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="KeptNear"
BUILD_PRODUCT_NAME="PSWMac"
BUNDLE_ID="app.psw.local.PSWMac"
MIN_SYSTEM_VERSION="13.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/macos_info_plist.sh"
source "$ROOT_DIR/script/swiftpm_local_env.sh"

DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_FRAMEWORKS="$APP_CONTENTS/Frameworks"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_BINARY="$APP_MACOS/$APP_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
FFI_DYLIB="$ROOT_DIR/target/debug/libpsw_ffi.dylib"
APP_ICON="$ROOT_DIR/assets/brand/KeptNear.icns"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true

cd "$ROOT_DIR"

cargo build -p psw-ffi
swiftpm_build --package-path "$ROOT_DIR/apps/macos"
BUILD_BINARY="$(swiftpm_bin_path --package-path "$ROOT_DIR/apps/macos")/$BUILD_PRODUCT_NAME"

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_MACOS" "$APP_FRAMEWORKS" "$APP_RESOURCES"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$FFI_DYLIB" "$APP_FRAMEWORKS/libpsw_ffi.dylib"
cp "$APP_ICON" "$APP_RESOURCES/KeptNear.icns"
chmod +x "$APP_BINARY"

write_pswmac_info_plist "$INFO_PLIST" "$APP_NAME" "$BUNDLE_ID" "$MIN_SYSTEM_VERSION"

open_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    open_app
    sleep 1
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
