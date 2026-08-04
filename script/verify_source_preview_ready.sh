#!/usr/bin/env bash
set -euo pipefail

ALLOW_MISSING=0
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
usage: script/verify_source_preview_ready.sh [--allow-missing]

Profile: source-preview.

Verifies the exact public source candidate without creating a DMG. This profile
does not require Apple signing or external security review, but it always
reports the audit status and never recommends production-secret use.

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

verify_clean_source() {
  if ! git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "source-preview requires a Git worktree" >&2
    return 1
  fi
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]]; then
    echo "source-preview requires a clean Git worktree" >&2
    return 1
  fi
}

require_executable "$ROOT_DIR/scripts/check.sh" "broad repository checks"
require_executable "$ROOT_DIR/script/verify_public_source_tree.sh" "public-source verifier"
require_executable "$ROOT_DIR/script/verify_dependency_licenses.sh" "dependency-license verifier"
require_executable "$ROOT_DIR/script/verify_security_review_evidence.sh" "review-policy verifier"

cd "$ROOT_DIR"

if [[ "$ALLOW_MISSING" == "1" ]]; then
  cat <<'REPORT'
Source-preview readiness report mode.

This mode does not approve publication. External review and Apple signing are
not prerequisites for this profile; missing review is reported as unaudited.
REPORT
  report_step "Clean source revision" verify_clean_source
  report_step "Broad repository checks" "$ROOT_DIR/scripts/check.sh"
  report_step "Public-source exclusions and secret scan" "$ROOT_DIR/script/verify_public_source_tree.sh"
  report_step "Dependency licenses" "$ROOT_DIR/script/verify_dependency_licenses.sh"
  report_step "Source review policy" "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile source --allow-missing
  printf '\nSource-preview readiness is not approved in allow-missing report mode.\n'
  exit 0
fi

run_step "Clean source revision" verify_clean_source
run_step "Broad repository checks" "$ROOT_DIR/scripts/check.sh"
run_step "Public-source exclusions and secret scan" "$ROOT_DIR/script/verify_public_source_tree.sh"
run_step "Dependency licenses" "$ROOT_DIR/script/verify_dependency_licenses.sh"
run_step "Source review policy" "$ROOT_DIR/script/verify_security_review_evidence.sh" --profile source
cat <<'SUMMARY'

Verified source-preview readiness.
Audit status remains whatever the review-policy gate reported above.
No binary distribution or production-secret suitability is approved.
SUMMARY
