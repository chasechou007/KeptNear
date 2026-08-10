#!/bin/bash
set -euo pipefail

PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

ROOT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
SOURCE_DIR="$ROOT_DIR/tools/macos-service-management-probe"
CONTROLLER_SOURCE="$SOURCE_DIR/Controller.swift"
AGENT_SOURCE="$SOURCE_DIR/Agent.swift"
PLIST_NAME=""
SERVICE_LABEL=""
APP_NAME="KeptNearServiceProbe"
AGENT_NAME="KeptNearServiceProbeAgent"
SIGNING_MODE="unsigned"
SIGNING_IDENTITY=""
RUN_PROBE=0
KEEP_ARTIFACTS=0
APPROVAL_TIMEOUT=0
TMP_DIR=""
APP_BUNDLE=""
CONTROLLER=""
MARKER_PATH=""
REGISTERED=0

usage() {
  cat <<'USAGE'
usage: script/verify_macos_service_management_probe.sh [options]

Builds a minimal bundled SMAppService LaunchAgent probe. The default is a
build-only unsigned check that does not register a service or change Login
Items state.

Options:
  --run                    Register and exercise the probe service.
  --signing-mode MODE      unsigned, adhoc, or identity (default: unsigned).
  --signing-identity NAME  Required when MODE is identity.
  --approval-timeout SEC   Wait up to 600 seconds for required user approval.
  --keep-artifacts         Keep the temporary bundle and print its path.
  -h, --help               Show this help.

The --run path uses a dedicated test label, requires it to be initially
not-registered, and attempts to unregister and terminate the probe during
cleanup. It prints only bounded JSON status and profile evidence.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)
      RUN_PROBE=1
      shift
      ;;
    --signing-mode)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      SIGNING_MODE="$2"
      shift 2
      ;;
    --signing-identity)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      SIGNING_IDENTITY="$2"
      shift 2
      ;;
    --approval-timeout)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      APPROVAL_TIMEOUT="$2"
      shift 2
      ;;
    --keep-artifacts)
      KEEP_ARTIFACTS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

case "$SIGNING_MODE" in
  unsigned|adhoc) ;;
  identity)
    if [[ -z "$SIGNING_IDENTITY" ]]; then
      echo "identity signing mode requires --signing-identity" >&2
      exit 2
    fi
    ;;
  *)
    echo "signing mode must be unsigned, adhoc, or identity" >&2
    exit 2
    ;;
esac

if [[ "$SIGNING_MODE" != "identity" && -n "$SIGNING_IDENTITY" ]]; then
  echo "--signing-identity is valid only with identity signing mode" >&2
  exit 2
fi
if [[ ! "$APPROVAL_TIMEOUT" =~ ^[0-9]+$ || "$APPROVAL_TIMEOUT" -gt 600 ]]; then
  echo "--approval-timeout must be an integer from 0 through 600" >&2
  exit 2
fi
if [[ "$RUN_PROBE" != "1" && "$APPROVAL_TIMEOUT" != "0" ]]; then
  echo "--approval-timeout requires --run" >&2
  exit 2
fi

for source in "$CONTROLLER_SOURCE" "$AGENT_SOURCE"; do
  if [[ ! -f "$source" || -L "$source" ]]; then
    echo "missing regular probe source: ${source#$ROOT_DIR/}" >&2
    exit 1
  fi
done

for command in codesign id kill launchctl lipo mktemp plutil xcrun; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

cleanup() {
  local marker_pid=""

  if [[ "$REGISTERED" == "1" && -x "$CONTROLLER" ]]; then
    "$CONTROLLER" unregister >/dev/null 2>&1 || true
  fi
  if [[ -f "$MARKER_PATH" ]]; then
    marker_pid="$(/usr/bin/plutil -extract pid raw -o - "$MARKER_PATH" 2>/dev/null || true)"
    if [[ "$marker_pid" =~ ^[0-9]+$ ]]; then
      /bin/kill "$marker_pid" >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$KEEP_ARTIFACTS" == "1" ]]; then
    printf 'Probe artifacts: %s\n' "$TMP_DIR"
  elif [[ -n "$TMP_DIR" ]]; then
    /bin/rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

TMP_ROOT="${TMPDIR:-/tmp}"
TMP_ROOT="${TMP_ROOT%/}"
TMP_DIR="$(/usr/bin/mktemp -d "$TMP_ROOT/keptnear-service-probe.XXXXXX")"
RUN_ID="$(/usr/bin/basename "$TMP_DIR" | /usr/bin/tr '[:upper:]' '[:lower:]')"
RUN_ID="${RUN_ID##*.}"
SERVICE_LABEL="com.chasechou.keptnear.service-probe.$RUN_ID"
PLIST_NAME="$SERVICE_LABEL.plist"
export KEPTNEAR_SERVICE_PROBE_PLIST_NAME="$PLIST_NAME"
APP_BUNDLE="$TMP_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_LAUNCH_AGENTS="$APP_CONTENTS/Library/LaunchAgents"
CONTROLLER="$APP_MACOS/$APP_NAME"
AGENT="$APP_HELPERS/$AGENT_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
SERVICE_PLIST="$APP_LAUNCH_AGENTS/$PLIST_NAME"
MARKER_PATH="$TMP_DIR/agent-marker.json"
MODULE_CACHE="$TMP_DIR/module-cache"

/bin/mkdir -p "$APP_MACOS" "$APP_HELPERS" "$APP_LAUNCH_AGENTS" "$MODULE_CACHE"

/usr/bin/xcrun swiftc \
  -O \
  -target arm64-apple-macos13.0 \
  -module-cache-path "$MODULE_CACHE" \
  -framework ServiceManagement \
  "$CONTROLLER_SOURCE" \
  -o "$CONTROLLER"
/usr/bin/xcrun swiftc \
  -O \
  -target arm64-apple-macos13.0 \
  -module-cache-path "$MODULE_CACHE" \
  "$AGENT_SOURCE" \
  -o "$AGENT"

cat >"$INFO_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>com.chasechou.keptnear.service-probe</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSUIElement</key>
  <true/>
</dict>
</plist>
PLIST

write_service_plist() {
  local generation="$1"

  cat >"$SERVICE_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$SERVICE_LABEL</string>
  <key>BundleProgram</key>
  <string>Contents/Helpers/$AGENT_NAME</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>KEPTNEAR_SERVICE_PROBE_GENERATION</key>
    <string>$generation</string>
    <key>KEPTNEAR_SERVICE_PROBE_MARKER</key>
    <string>$MARKER_PATH</string>
  </dict>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
PLIST
}

write_service_plist "1"
/usr/bin/plutil -lint "$INFO_PLIST" "$SERVICE_PLIST" >/dev/null

sign_bundle() {
  case "$SIGNING_MODE" in
    unsigned)
      ;;
    adhoc)
      /usr/bin/codesign --force --sign - "$AGENT"
      /usr/bin/codesign --force --sign - "$CONTROLLER"
      /usr/bin/codesign --force --sign - "$APP_BUNDLE"
      ;;
    identity)
      /usr/bin/codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$AGENT"
      /usr/bin/codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$CONTROLLER"
      /usr/bin/codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$APP_BUNDLE"
      ;;
  esac
}

sign_bundle

if [[ "$(/usr/bin/lipo -archs "$CONTROLLER")" != "arm64" || "$(/usr/bin/lipo -archs "$AGENT")" != "arm64" ]]; then
  echo "service probe executables must be arm64-only" >&2
  exit 1
fi

SIGNATURE_STATE="unsigned"
if /usr/bin/codesign --verify --deep --strict "$APP_BUNDLE" >/dev/null 2>&1; then
  SIGNATURE_STATE="valid"
elif [[ "$SIGNING_MODE" != "unsigned" ]]; then
  echo "service probe signature verification failed" >&2
  exit 1
fi

printf '{"architecture":"arm64","bundle":"built","mode":"%s","run":%s,"signature":"%s"}\n' \
  "$SIGNING_MODE" \
  "$([[ "$RUN_PROBE" == "1" ]] && printf true || printf false)" \
  "$SIGNATURE_STATE"

if [[ "$RUN_PROBE" != "1" ]]; then
  exit 0
fi

if /bin/launchctl print "gui/$(/usr/bin/id -u)/$SERVICE_LABEL" >/dev/null 2>&1; then
  echo "probe service job already exists; refusing to alter existing Login Items state" >&2
  exit 1
fi

INITIAL_STATUS="$($CONTROLLER status)"
printf '%s\n' "$INITIAL_STATUS"
INITIAL_RESULT="$(/usr/bin/plutil -extract status raw -o - - <<<"$INITIAL_STATUS")"
if [[ "$INITIAL_RESULT" != "not-registered" && "$INITIAL_RESULT" != "not-found" ]]; then
  echo "probe service is already registered; refusing to alter existing Login Items state" >&2
  exit 1
fi

REGISTER_OUTPUT=""
REGISTER_STATUS=0
REGISTER_OUTPUT="$($CONTROLLER register)" || REGISTER_STATUS=$?
printf '%s\n' "$REGISTER_OUTPUT"

REGISTER_RESULT="$(/usr/bin/plutil -extract status raw -o - - <<<"$REGISTER_OUTPUT")"
if [[ "$REGISTER_RESULT" == "requires-approval" ]]; then
  REGISTERED=1
  if [[ "$APPROVAL_TIMEOUT" == "0" ]]; then
    printf '{"mode":"%s","registration":"requires-approval","status":"%s"}\n' \
      "$SIGNING_MODE" "$REGISTER_RESULT"
    exit 3
  fi

  APPROVAL_RESULT="$REGISTER_RESULT"
  for ((attempt = 0; attempt < APPROVAL_TIMEOUT; attempt += 1)); do
    APPROVAL_OUTPUT="$($CONTROLLER status)"
    APPROVAL_RESULT="$(/usr/bin/plutil -extract status raw -o - - <<<"$APPROVAL_OUTPUT")"
    if [[ "$APPROVAL_RESULT" == "enabled" ]]; then
      printf '%s\n' "$APPROVAL_OUTPUT"
      break
    fi
    /bin/sleep 1
  done
  if [[ "$APPROVAL_RESULT" != "enabled" ]]; then
    printf '{"mode":"%s","registration":"approval-timeout","status":"%s"}\n' \
      "$SIGNING_MODE" "$APPROVAL_RESULT"
    exit 3
  fi
elif [[ "$REGISTER_STATUS" -ne 0 ]]; then
  printf '{"mode":"%s","registration":"rejected","status":"%s"}\n' \
    "$SIGNING_MODE" "$REGISTER_RESULT"
  exit 1
else
  REGISTERED=1
fi
if [[ "$REGISTER_RESULT" != "enabled" && "${APPROVAL_RESULT:-}" != "enabled" ]]; then
  echo "probe registration returned an unexpected state" >&2
  exit 1
fi

wait_for_marker() {
  local expected_generation="$1"
  local attempt
  local observed=""

  for attempt in {1..300}; do
    if [[ -f "$MARKER_PATH" ]]; then
      observed="$(/usr/bin/plutil -extract generation raw -o - "$MARKER_PATH" 2>/dev/null || true)"
      if [[ "$observed" == "$expected_generation" ]]; then
        return 0
      fi
    fi
    /bin/sleep 0.1
  done
  return 1
}

if ! wait_for_marker "1"; then
  echo "probe agent did not publish initial generation 1" >&2
  exit 1
fi
FIRST_PID="$(/usr/bin/plutil -extract pid raw -o - "$MARKER_PATH")"
FIRST_EXECUTABLE="$(/usr/bin/plutil -extract executable raw -o - "$MARKER_PATH")"
case "$FIRST_EXECUTABLE" in
  "$APP_BUNDLE"/Contents/Helpers/$AGENT_NAME) ;;
  *)
    echo "probe agent launched outside the registered bundle" >&2
    exit 1
    ;;
esac

MOVED_BUNDLE="$TMP_DIR/Moved-$APP_NAME.app"
/bin/mv "$APP_BUNDLE" "$MOVED_BUNDLE"
APP_BUNDLE="$MOVED_BUNDLE"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_LAUNCH_AGENTS="$APP_CONTENTS/Library/LaunchAgents"
CONTROLLER="$APP_MACOS/$APP_NAME"
AGENT="$APP_HELPERS/$AGENT_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
SERVICE_PLIST="$APP_LAUNCH_AGENTS/$PLIST_NAME"

/bin/rm -f "$MARKER_PATH"
MOVE_STATUS="$($CONTROLLER status)"
printf '%s\n' "$MOVE_STATUS"
/bin/kill "$FIRST_PID"
MOVE_BEHAVIOR="automatic"
if ! wait_for_marker "1"; then
  MOVE_BEHAVIOR="reregister-required"
  "$CONTROLLER" unregister >/dev/null
  REGISTERED=0
  for attempt in {1..100}; do
    STATUS_OUTPUT="$($CONTROLLER status)"
    if [[ "$(/usr/bin/plutil -extract status raw -o - - <<<"$STATUS_OUTPUT")" == "not-registered" ]]; then
      break
    fi
    /bin/sleep 0.1
  done
  if [[ "$(/usr/bin/plutil -extract status raw -o - - <<<"$STATUS_OUTPUT")" != "not-registered" ]]; then
    echo "moved probe service did not unregister for repair" >&2
    exit 1
  fi

  MOVE_REGISTER_OUTPUT="$($CONTROLLER register)"
  printf '%s\n' "$MOVE_REGISTER_OUTPUT"
  REGISTERED=1
  if [[ "$(/usr/bin/plutil -extract status raw -o - - <<<"$MOVE_REGISTER_OUTPUT")" != "enabled" ]]; then
    echo "moved probe service did not re-register" >&2
    exit 1
  fi
  if ! wait_for_marker "1"; then
    echo "moved probe agent did not start after re-registration" >&2
    exit 1
  fi
fi
MOVED_EXECUTABLE="$(/usr/bin/plutil -extract executable raw -o - "$MARKER_PATH")"
MOVED_PID="$(/usr/bin/plutil -extract pid raw -o - "$MARKER_PATH")"
case "$MOVED_EXECUTABLE" in
  "$APP_BUNDLE"/Contents/Helpers/$AGENT_NAME) ;;
  *)
    echo "BundleProgram did not follow the relocated app" >&2
    exit 1
    ;;
esac

"$CONTROLLER" unregister >/dev/null
REGISTERED=0
for attempt in {1..100}; do
  STATUS_OUTPUT="$($CONTROLLER status)"
  if [[ "$(/usr/bin/plutil -extract status raw -o - - <<<"$STATUS_OUTPUT")" == "not-registered" ]]; then
    break
  fi
  /bin/sleep 0.1
done
if [[ "$(/usr/bin/plutil -extract status raw -o - - <<<"$STATUS_OUTPUT")" != "not-registered" ]]; then
  echo "probe service did not unregister" >&2
  exit 1
fi
for attempt in {1..100}; do
  if ! /bin/kill -0 "$MOVED_PID" >/dev/null 2>&1; then
    break
  fi
  /bin/sleep 0.1
done
if /bin/kill -0 "$MOVED_PID" >/dev/null 2>&1; then
  echo "probe agent did not exit after unregister" >&2
  exit 1
fi

write_service_plist "2"
sign_bundle
/bin/rm -f "$MARKER_PATH"
REPLACEMENT_OUTPUT="$($CONTROLLER register)"
printf '%s\n' "$REPLACEMENT_OUTPUT"
REGISTERED=1
if [[ "$(/usr/bin/plutil -extract status raw -o - - <<<"$REPLACEMENT_OUTPUT")" != "enabled" ]]; then
  echo "replacement probe did not become enabled" >&2
  exit 1
fi
if ! wait_for_marker "2"; then
  echo "replacement probe agent did not publish generation 2" >&2
  exit 1
fi

printf '{"mode":"%s","move":"%s","registration":"enabled","replacement":"passed","unregister":"passed"}\n' \
  "$SIGNING_MODE" "$MOVE_BEHAVIOR"
