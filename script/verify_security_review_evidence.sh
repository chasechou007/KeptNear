#!/usr/bin/env bash
set -euo pipefail

ALLOW_MISSING=0
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_PATH="$ROOT_DIR/docs/security-review-plan.md"
EVIDENCE_PATH="$ROOT_DIR/docs/security-review-evidence.md"

usage() {
  cat <<'USAGE'
usage: script/verify_security_review_evidence.sh [--allow-missing]

Verifies whether external security review evidence is complete enough for
public-alpha approval. The default strict mode exits non-zero when evidence is
missing or incomplete.

Options:
  --allow-missing                  report missing evidence but exit 0
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

require_file() {
  local path="$1"
  local label="$2"
  if [[ -f "$path" ]]; then
    status_line ok "$label" "${path#$ROOT_DIR/}"
  else
    status_line missing "$label" "${path#$ROOT_DIR/}"
    add_failure "missing $label"
  fi
}

require_contains() {
  local path="$1"
  local label="$2"
  local pattern="$3"
  if grep -F "$pattern" "$path" >/dev/null 2>&1; then
    status_line ok "$label"
  else
    status_line missing "$label" "$pattern"
    add_failure "missing $label"
  fi
}

is_missing_external_value() {
  local value="$1"
  case "$value" in
    ""|TBD|None|"None selected yet"|"None attached yet"|"None reviewed yet"|"None recorded yet"|"Not scheduled")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

summary_value() {
  local label="$1"
  awk -F': ' -v label="$label" '$0 ~ "^- " label ": " { print $2; exit }' "$EVIDENCE_PATH"
}

require_summary_value() {
  local label="$1"
  local value
  value="$(summary_value "$label")"
  if is_missing_external_value "$value"; then
    status_line missing "$label" "${value:-missing}"
    add_failure "$label is missing"
  else
    status_line ok "$label" "$value"
  fi
}

release_value() {
  local label="$1"
  awk -F': ' -v label="$label" '$0 ~ "^- " label ": " { print $2; exit }' "$EVIDENCE_PATH"
}

require_release_value() {
  local label="$1"
  local expected="$2"
  local value
  value="$(release_value "$label")"
  if [[ "$value" == "$expected" ]]; then
    status_line ok "$label" "$value"
  else
    status_line missing "$label" "expected '$expected', got '${value:-missing}'"
    add_failure "$label is not $expected"
  fi
}

printf 'Security review evidence gate\n'
printf 'Mode: %s\n\n' "$(if [[ "$ALLOW_MISSING" == "1" ]]; then printf 'allow-missing report'; else printf 'strict'; fi)"

printf 'Required documents\n'
require_file "$PLAN_PATH" "security review plan"
require_file "$EVIDENCE_PATH" "security review evidence register"

if [[ -f "$PLAN_PATH" ]]; then
  printf '\nReview plan boundaries\n'
  require_contains "$PLAN_PATH" "expected reviewer outputs" "## Expected Reviewer Outputs"
  require_contains "$PLAN_PATH" "severity taxonomy" "## Severity Taxonomy"
  require_contains "$PLAN_PATH" "follow-up handling" "## Follow-Up Handling"
  require_contains "$PLAN_PATH" "not completed claim" "It is not"
fi

if [[ -f "$EVIDENCE_PATH" ]]; then
  printf '\nEvidence register sections\n'
  require_contains "$EVIDENCE_PATH" "review summary" "## Review Summary"
  require_contains "$EVIDENCE_PATH" "reviewer reports" "## Reviewer Reports"
  require_contains "$EVIDENCE_PATH" "findings" "## Findings"
  require_contains "$EVIDENCE_PATH" "accepted risks" "## Accepted Risks"
  require_contains "$EVIDENCE_PATH" "validation evidence" "## Validation Evidence"
  require_contains "$EVIDENCE_PATH" "release decision" "## Release Decision"

  printf '\nExternal review evidence\n'
  require_summary_value "Review status"
  require_summary_value "Reviewer or firm"
  require_summary_value "Review window"
  require_summary_value "Reviewed commit or release artifact"

  final_report="$(summary_value "Final report")"
  finding_tracker="$(summary_value "Finding tracker")"
  if ! is_missing_external_value "$final_report"; then
    status_line ok "Final report" "$final_report"
  elif ! is_missing_external_value "$finding_tracker"; then
    status_line ok "Finding tracker" "$finding_tracker"
  else
    status_line missing "Final report or finding tracker" "at least one must be attached"
    add_failure "missing final report or finding tracker"
  fi

  if grep -F "TBD" "$EVIDENCE_PATH" >/dev/null; then
    status_line missing "placeholder scan" "TBD placeholders remain"
    add_failure "TBD placeholders remain in security review evidence register"
  else
    status_line ok "placeholder scan" "no TBD placeholders"
  fi

  if grep -E '^\|[[:space:]]*None[[:space:]]*\|[[:space:]]*None selected yet[[:space:]]*\|[[:space:]]*None reviewed yet[[:space:]]*\|[[:space:]]*None attached yet[[:space:]]*\|' "$EVIDENCE_PATH" >/dev/null; then
    status_line missing "Reviewer report rows" "no external reviewer report row attached"
    add_failure "missing external reviewer report row"
  else
    status_line ok "Reviewer report rows" "external reviewer report row attached"
  fi

  if grep -E '^\|[^|]*\|[[:space:]]*(Critical|High)[[:space:]]*\|[[:space:]]*Open[[:space:]]*\|' "$EVIDENCE_PATH" >/dev/null; then
    status_line missing "Critical/High findings" "open blocker finding exists"
    add_failure "open Critical or High finding remains"
  else
    status_line ok "Critical/High findings" "no open Critical/High finding rows detected"
  fi

  printf '\nValidation evidence\n'
  if grep -E '^\|[^|]*\|[[:space:]]*`scripts/check\.sh`[[:space:]]*\|[[:space:]]*Passed[[:space:]]*\|' "$EVIDENCE_PATH" >/dev/null; then
    status_line ok "scripts/check.sh validation" "Passed"
  else
    status_line missing "scripts/check.sh validation" "expected Passed row"
    add_failure "missing passed scripts/check.sh validation evidence"
  fi
  if grep -E '^\|[^|]*\|[[:space:]]*`script/package_macos_alpha\.sh`[[:space:]]*\|[[:space:]]*Passed[[:space:]]*\|' "$EVIDENCE_PATH" >/dev/null; then
    status_line ok "alpha package validation evidence" "Passed"
  else
    status_line missing "alpha package validation evidence" "expected Passed row"
    add_failure "missing passed alpha package validation evidence"
  fi

  printf '\nRelease decision\n'
  require_release_value "External review completed" "Yes"
  require_release_value "Critical findings fixed or explicitly accepted" "Yes"
  require_release_value "High findings fixed or explicitly accepted" "Yes"
  require_release_value "Medium findings fixed, mitigated, or tracked" "Yes"
  require_release_value "Validation after review-driven changes passed" "Yes"
  require_release_value "Security model or readiness claims updated after review" "Yes"
  require_release_value "Public alpha decision" "Approved"

  production_value="$(release_value "Production-use recommendation")"
  if [[ "$production_value" == "Recommended" ]]; then
    status_line missing "Production-use recommendation" "must remain separate from public alpha"
    add_failure "production use recommendation must not be conflated with public alpha"
  elif [[ -n "$production_value" ]]; then
    status_line ok "Production-use recommendation" "$production_value"
  else
    status_line missing "Production-use recommendation" "missing"
    add_failure "missing production-use recommendation"
  fi
fi

printf '\nResult\n'
if [[ "${#FAILURES[@]}" -eq 0 ]]; then
  printf '  Security review evidence gate passed for public-alpha review readiness.\n'
  printf '  Production-use recommendation remains a separate release decision.\n'
  exit 0
fi

for failure in "${FAILURES[@]}"; do
  printf '  missing: %s\n' "$failure"
done
printf '  Strict security review readiness is not approved.\n'
printf '  This gate verifies repository evidence completeness; it does not perform an external review.\n'

if [[ "$ALLOW_MISSING" == "1" ]]; then
  printf '  allow-missing mode: exiting 0 after reporting missing evidence.\n'
  exit 0
fi

exit 1
