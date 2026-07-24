#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
VERSION="${VERSION:-0.1.0-alpha}"
ALLOW_MISSING=0

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_PATH="$ROOT_DIR/dist/releases/$APP_NAME-$VERSION-macos-arm64.dmg"
APP_BUNDLE="$ROOT_DIR/dist/alpha-staging/$APP_NAME.app"

usage() {
  cat <<'USAGE'
usage: script/verify_local_alpha_readiness.sh [--allow-missing]

Strict mode verifies the full local alpha readiness gate:
  - broad repository checks
  - vault-format readiness
  - vault doctor readiness
  - macOS security-state readiness
  - unsigned Apple Silicon DMG generation
  - arm64 DMG artifact verification
  - Launch Services vault-type registration

Options:
  --allow-missing                  report current local blockers but do not approve readiness
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

run_step() {
  local label="$1"
  shift
  printf '\n==> %s\n' "$label"
  "$@"
}

report_step() {
  local label="$1"
  shift
  printf '\n==> %s\n' "$label"
  if "$@"; then
    printf 'Report step completed: %s\n' "$label"
  else
    printf 'Report step found blockers: %s\n' "$label"
  fi
}

require_executable "$ROOT_DIR/scripts/check.sh" "broad local check script"
require_executable "$ROOT_DIR/script/verify_vault_format_readiness.sh" "vault-format readiness verifier"
require_executable "$ROOT_DIR/script/verify_vault_doctor_readiness.sh" "vault doctor readiness verifier"
require_executable "$ROOT_DIR/script/verify_macos_security_state.sh" "macOS security-state verifier"
require_executable "$ROOT_DIR/script/package_macos_alpha.sh" "macOS alpha package script"
require_executable "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" "macOS alpha artifact verifier"
require_executable "$ROOT_DIR/script/verify_macos_launch_services_vault_type.sh" "Launch Services verifier"
require_file "$ROOT_DIR/docs/security-review-evidence.md" "security review evidence register"

cd "$ROOT_DIR"

if [[ "$ALLOW_MISSING" == "1" ]]; then
  cat <<'REPORT'
Local alpha readiness report mode.

This mode runs the local gates as report steps, including Launch Services
registration when the current environment allows it. It does not approve local
alpha readiness, public alpha, or production use.
REPORT

  report_step "Broad repository checks" "$ROOT_DIR/scripts/check.sh"
  report_step "Vault-format readiness" "$ROOT_DIR/script/verify_vault_format_readiness.sh"
  report_step "Vault doctor readiness" "$ROOT_DIR/script/verify_vault_doctor_readiness.sh"
  report_step "macOS security-state readiness" "$ROOT_DIR/script/verify_macos_security_state.sh"
  report_step "Unsigned Apple Silicon DMG" env VERSION="$VERSION" SIGNING_IDENTITY="" NOTARIZE=0 "$ROOT_DIR/script/package_macos_alpha.sh"
  report_step "Apple Silicon DMG verification" "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" "$ARCHIVE_PATH"
  report_step "Launch Services vault type verification" "$ROOT_DIR/script/verify_macos_launch_services_vault_type.sh" "$APP_BUNDLE"

  cat <<'SUMMARY'

Local alpha readiness is not approved in allow-missing report mode.

Strict local alpha readiness still requires:
- passing broad repository checks
- passing vault-format, vault doctor, and macOS security-state readiness
- generating and verifying the unsigned arm64 DMG artifact
- successful Launch Services vault-type registration in the current user's database

If Launch Services registration is blocked by a managed workspace sandbox or
automation agent, rerun strict mode from an unsandboxed terminal or grant
explicit approval for user-level Launch Services access.
SUMMARY
  exit 0
fi

run_step "Broad repository checks" "$ROOT_DIR/scripts/check.sh"
run_step "Vault-format readiness" "$ROOT_DIR/script/verify_vault_format_readiness.sh"
run_step "Vault doctor readiness" "$ROOT_DIR/script/verify_vault_doctor_readiness.sh"
run_step "macOS security-state readiness" "$ROOT_DIR/script/verify_macos_security_state.sh"
run_step "Unsigned Apple Silicon DMG" env VERSION="$VERSION" SIGNING_IDENTITY="" NOTARIZE=0 "$ROOT_DIR/script/package_macos_alpha.sh"
run_step "Apple Silicon DMG verification" "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" "$ARCHIVE_PATH"
run_step "Launch Services vault type verification" "$ROOT_DIR/script/verify_macos_launch_services_vault_type.sh" "$APP_BUNDLE"
cat <<'SUMMARY'

Verified local alpha readiness evidence.

Local readiness does not evaluate these separate public-alpha gates:
- Developer ID signing, hardened runtime, notarization, and stapling decisions
- Clean signed/notarized install and Finder double-click verification
- External-review or explicit maintainer accepted-risk decision verification

This command does not approve public alpha or production use.
SUMMARY
