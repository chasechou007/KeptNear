#!/usr/bin/env bash
set -euo pipefail

ALLOW_MISSING=0
NOTARIZE="${NOTARIZE:-1}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
NOTARY_KEYCHAIN_PROFILE="${NOTARY_KEYCHAIN_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
APPLE_APP_SPECIFIC_PASSWORD="${APPLE_APP_SPECIFIC_PASSWORD:-}"

usage() {
  cat <<'USAGE'
usage: script/verify_macos_distribution_environment.sh [--allow-missing]

Checks the local macOS Developer ID signing and notarization environment.

Environment:
  SIGNING_IDENTITY                 Developer ID Application identity name
  NOTARIZE                         1 by default; set 0 for signing-only preflight
  NOTARY_KEYCHAIN_PROFILE          notarytool keychain profile name
  APPLE_ID                         Apple ID for notarytool
  APPLE_TEAM_ID                    Apple team ID for notarytool
  APPLE_APP_SPECIFIC_PASSWORD      app-specific password; never printed

Options:
  --allow-missing                  report missing release prerequisites but exit 0
  -h, --help                       show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-missing)
      ALLOW_MISSING=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

FAILURES=()

add_failure() {
  FAILURES+=("$1")
}

status_line() {
  local status="$1"
  local label="$2"
  local detail="${3:-}"
  if [[ -n "$detail" ]]; then
    printf '  [%s] %s: %s\n' "$status" "$label" "$detail"
  else
    printf '  [%s] %s\n' "$status" "$label"
  fi
}

check_command() {
  local command_name="$1"
  if command -v "$command_name" >/dev/null 2>&1; then
    status_line ok "$command_name" "$(command -v "$command_name")"
    return 0
  fi
  status_line missing "$command_name"
  add_failure "missing command: $command_name"
  return 1
}

check_xcrun_tool() {
  local tool_name="$1"
  if command -v xcrun >/dev/null 2>&1 && xcrun --find "$tool_name" >/dev/null 2>&1; then
    status_line ok "xcrun $tool_name" "$(xcrun --find "$tool_name")"
    return 0
  fi
  status_line missing "xcrun $tool_name"
  add_failure "missing xcrun tool: $tool_name"
  return 1
}

developer_identity_present() {
  local identity="$1"
  security find-identity -v -p codesigning 2>/dev/null | grep -F "$identity" >/dev/null
}

printf 'macOS distribution environment preflight\n'
printf 'Mode: %s\n' "$(if [[ "$ALLOW_MISSING" == "1" ]]; then printf 'allow-missing report'; else printf 'strict'; fi)"
printf 'Requested notarization: %s\n\n' "$NOTARIZE"

if [[ "$NOTARIZE" != "0" && "$NOTARIZE" != "1" ]]; then
  status_line invalid NOTARIZE "expected 0 or 1"
  add_failure "invalid NOTARIZE value"
fi

printf 'Required tools\n'
check_command codesign || true
check_command security || true
check_command xcrun || true
if [[ "$NOTARIZE" == "1" ]]; then
  check_xcrun_tool notarytool || true
  check_xcrun_tool stapler || true
fi

printf '\nSigning identity\n'
if [[ -z "$SIGNING_IDENTITY" ]]; then
  status_line missing SIGNING_IDENTITY "set to a Developer ID Application identity"
  add_failure "missing SIGNING_IDENTITY"
elif [[ "$SIGNING_IDENTITY" != Developer\ ID\ Application:* ]]; then
  status_line invalid SIGNING_IDENTITY "must start with 'Developer ID Application:'"
  add_failure "SIGNING_IDENTITY is not a Developer ID Application identity"
elif developer_identity_present "$SIGNING_IDENTITY"; then
  status_line ok SIGNING_IDENTITY "$SIGNING_IDENTITY"
else
  status_line missing SIGNING_IDENTITY "$SIGNING_IDENTITY not found in local code signing identities"
  add_failure "SIGNING_IDENTITY not found in local keychain identities"
fi

printf '\nNotarization credentials\n'
if [[ "$NOTARIZE" == "0" ]]; then
  status_line skipped notarization "NOTARIZE=0; signing-only preflight"
  status_line warning public-alpha "public alpha still requires notarization and stapling"
elif [[ -n "$NOTARY_KEYCHAIN_PROFILE" ]]; then
  status_line ok credential-mode "notarytool keychain profile '$NOTARY_KEYCHAIN_PROFILE'"
  status_line note credential-validation "profile presence is not checked without contacting Apple"
elif [[ -n "$APPLE_ID" && -n "$APPLE_TEAM_ID" && -n "$APPLE_APP_SPECIFIC_PASSWORD" ]]; then
  status_line ok credential-mode "Apple ID '$APPLE_ID' with team '$APPLE_TEAM_ID'"
  status_line ok APPLE_APP_SPECIFIC_PASSWORD "present; value redacted"
else
  status_line missing credential-mode "set NOTARY_KEYCHAIN_PROFILE or APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_SPECIFIC_PASSWORD"
  if [[ -n "$APPLE_APP_SPECIFIC_PASSWORD" ]]; then
    status_line ok APPLE_APP_SPECIFIC_PASSWORD "present; value redacted"
  fi
  add_failure "missing notarization credential mode"
fi

printf '\nResult\n'
if [[ "${#FAILURES[@]}" -eq 0 ]]; then
  printf '  Ready for requested macOS distribution preflight.\n'
  printf '  Next: run script/package_macos_alpha.sh with the same signing environment.\n'
  exit 0
fi

for failure in "${FAILURES[@]}"; do
  printf '  missing: %s\n' "$failure"
done
printf '  Strict distribution readiness is not approved.\n'
printf '  This preflight does not replace signed packaging, artifact verification, clean install testing, or external security review.\n'

if [[ "$ALLOW_MISSING" == "1" ]]; then
  printf '  allow-missing mode: exiting 0 after reporting missing prerequisites.\n'
  exit 0
fi

exit 1
