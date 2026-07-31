#!/usr/bin/env bash
set -euo pipefail

ALLOW_MISSING=0
VERSION="${VERSION:-0.1.0-alpha}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
usage: script/verify_unsigned_alpha_release_ready.sh [--allow-missing]

Profile: unsigned-experimental.

Verifies an explicitly unsigned, unaudited Apple Silicon DMG. This profile does
not require Developer ID signing, notarization, or external security review.
It requires AR-002, a clean source revision, local quality and privacy gates,
artifact integrity, installation checks, and warnings against production use.

Options:
  --allow-missing                  report blockers without approving readiness
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
require_executable "$ROOT_DIR/script/verify_security_review_evidence.sh" "review-policy verifier"

cd "$ROOT_DIR"

if [[ "$ALLOW_MISSING" == "1" ]]; then
  cat <<'REPORT'
Unsigned experimental DMG readiness report mode.

This mode does not approve publication. It reports missing review evidence as
unaudited and does not convert absent Apple signing into a passing signed gate.
REPORT
  report_step "Unsigned review policy" "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile unsigned --allow-missing
  report_step "Unsigned local and artifact readiness" env VERSION="$VERSION" PACKAGE_RELEASE_MODE=unsigned-experimental "$ROOT_DIR/script/verify_local_alpha_readiness.sh" --allow-missing
  printf '\nUnsigned experimental DMG readiness is not approved in allow-missing report mode.\n'
  exit 0
fi

run_step "Unsigned review policy" "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile unsigned
run_step "Unsigned local and artifact readiness" env VERSION="$VERSION" PACKAGE_RELEASE_MODE=unsigned-experimental "$ROOT_DIR/script/verify_local_alpha_readiness.sh"
cat <<'SUMMARY'

Verified unsigned experimental Apple Silicon DMG readiness.
The artifact is unsigned and unaudited. It has no Developer ID, notarization,
Gatekeeper trust-chain, external-audit, or production-secret suitability claim.
SUMMARY
