#!/usr/bin/env bash
set -euo pipefail

APP_NAME="KeptNear"
VERSION="${VERSION:-0.1.0-alpha}"
ALLOW_MISSING=0

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_PATH="$ROOT_DIR/dist/releases/$APP_NAME-$VERSION-macos-arm64.dmg"

usage() {
  cat <<'USAGE'
usage: script/verify_public_alpha_release_ready.sh [--allow-missing]

Strict mode verifies the full public-alpha release gate:
  - local alpha readiness
  - security review handoff package generation and checksum verification
  - Developer ID / notarization environment preflight
  - signed and notarized Apple Silicon DMG generation
  - signed install verification
  - external security review evidence

Options:
  --allow-missing                  report current blockers without generating or notarizing artifacts
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

require_executable "$ROOT_DIR/script/verify_local_alpha_readiness.sh" "local alpha readiness verifier"
require_executable "$ROOT_DIR/script/package_security_review_materials.sh" "security review materials package script"
require_executable "$ROOT_DIR/script/verify_macos_distribution_environment.sh" "macOS distribution environment preflight"
require_executable "$ROOT_DIR/script/package_macos_alpha.sh" "macOS alpha package script"
require_executable "$ROOT_DIR/script/verify_macos_signed_install.sh" "signed install verifier"
require_executable "$ROOT_DIR/script/verify_security_review_evidence.sh" "security review evidence verifier"

cd "$ROOT_DIR"

if [[ "$ALLOW_MISSING" == "1" ]]; then
  cat <<'REPORT'
Public alpha release readiness report mode.

This mode does not generate signed artifacts, contact Apple notarization
services, approve public alpha, or recommend production use.
REPORT

  report_step "Distribution environment report" "$ROOT_DIR/script/verify_macos_distribution_environment.sh" --allow-missing
  report_step "Security review materials package" "$ROOT_DIR/script/package_security_review_materials.sh"
  report_step "Security review evidence report" "$ROOT_DIR/script/verify_security_review_evidence.sh" --allow-missing

  if [[ -f "$ARCHIVE_PATH" ]]; then
    report_step "Signed install verifier against current DMG" "$ROOT_DIR/script/verify_macos_signed_install.sh" "$ARCHIVE_PATH"
  else
    printf '\n==> Signed install verifier against current DMG\n'
    printf 'Report step found blockers: missing DMG %s\n' "$ARCHIVE_PATH"
  fi

  cat <<'SUMMARY'

Public alpha readiness is not approved in allow-missing report mode.

Strict public alpha readiness still requires:
- passing local alpha readiness
- generated and checksum-verified security review handoff materials
- Developer ID signing and notarization credentials
- signed and notarized Apple Silicon DMG generation
- signed install verification
- completed external security review evidence and release approval
SUMMARY
  exit 0
fi

cat <<'STRICT'
Public alpha release readiness strict gate.

This command may build, sign, notarize, and staple an Apple Silicon DMG using the
current signing environment. It exits non-zero until every public-alpha blocker
is cleared.
STRICT

run_step "Distribution environment preflight" "$ROOT_DIR/script/verify_macos_distribution_environment.sh"
run_step "Local alpha readiness" "$ROOT_DIR/script/verify_local_alpha_readiness.sh"
run_step "Security review materials package" "$ROOT_DIR/script/package_security_review_materials.sh"
run_step "Signed and notarized Apple Silicon DMG" env VERSION="$VERSION" NOTARIZE=1 "$ROOT_DIR/script/package_macos_alpha.sh"
run_step "Signed install verification" "$ROOT_DIR/script/verify_macos_signed_install.sh" "$ARCHIVE_PATH"
run_step "Security review evidence verification" "$ROOT_DIR/script/verify_security_review_evidence.sh"
cat <<'SUMMARY'

Verified public alpha release readiness.

Production-use recommendation remains a separate release decision.
SUMMARY
