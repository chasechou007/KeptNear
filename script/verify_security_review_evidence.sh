#!/usr/bin/env bash
set -euo pipefail

ALLOW_MISSING=0
PROFILE="signed"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_PATH="$ROOT_DIR/docs/security-review-plan.md"
EVIDENCE_PATH="$ROOT_DIR/docs/security-review-evidence.md"
README_PATH="$ROOT_DIR/README.md"
SQLCIPHER_GATE="$ROOT_DIR/script/verify_sqlcipher_distribution_gate.sh"

usage() {
  cat <<'USAGE'
usage: script/verify_security_review_evidence.sh [--profile source|unsigned|signed] [--allow-missing]

Verifies the review-policy evidence for one release profile. External review is
optional for source preview and the explicitly unsigned experimental profile.
The signed profile requires either external-review evidence or the AR-001
accepted-risk path. Distribution gates remain separate.

Options:
  --profile PROFILE               select source, unsigned, or signed (default: signed)
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
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "--profile requires a value" >&2
        usage >&2
        exit 2
      fi
      PROFILE="$2"
      shift 2
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

case "$PROFILE" in
  source|unsigned|signed) ;;
  *)
    echo "invalid profile: $PROFILE" >&2
    usage >&2
    exit 2
    ;;
esac

COMMON_FAILURES=()
EXTERNAL_REVIEW_FAILURES=()
ACCEPTED_RISK_FAILURES=()
COMMON_FAILURE_COUNT=0
EXTERNAL_REVIEW_FAILURE_COUNT=0
ACCEPTED_RISK_FAILURE_COUNT=0
FAILURE_SCOPE="common"

add_failure() {
  case "$FAILURE_SCOPE" in
    common)
      COMMON_FAILURES+=("$1")
      COMMON_FAILURE_COUNT=$((COMMON_FAILURE_COUNT + 1))
      ;;
    external)
      EXTERNAL_REVIEW_FAILURES+=("$1")
      EXTERNAL_REVIEW_FAILURE_COUNT=$((EXTERNAL_REVIEW_FAILURE_COUNT + 1))
      ;;
    accepted-risk)
      ACCEPTED_RISK_FAILURES+=("$1")
      ACCEPTED_RISK_FAILURE_COUNT=$((ACCEPTED_RISK_FAILURE_COUNT + 1))
      ;;
    *)
      echo "invalid failure scope: $FAILURE_SCOPE" >&2
      exit 2
      ;;
  esac
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

require_release_present() {
  local label="$1"
  local value
  value="$(release_value "$label")"
  if is_missing_external_value "$value"; then
    status_line missing "$label" "${value:-missing}"
    add_failure "$label is missing"
  else
    status_line ok "$label" "$value"
  fi
}

require_release_date() {
  local label="$1"
  local value
  value="$(release_value "$label")"
  if [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    status_line ok "$label" "$value"
  else
    status_line missing "$label" "expected YYYY-MM-DD, got '${value:-missing}'"
    add_failure "$label is not a valid date"
  fi
}

require_validation_on_date() {
  local validation_date="$1"
  local command_name="$2"
  local label="$3"
  if awk -F'|' -v expected_date="$validation_date" -v expected_command="\`$command_name\`" '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    trim($2) == expected_date && trim($3) == expected_command && trim($4) == "Passed" {
      found = 1
    }
    END {
      exit(found ? 0 : 1)
    }
  ' "$EVIDENCE_PATH"; then
    status_line ok "$label" "$validation_date"
  else
    status_line missing "$label" "expected Passed evidence dated $validation_date"
    add_failure "$label is missing for $validation_date"
  fi
}

require_accepted_risk_row() {
  local risk_id="$1"
  local expected_owner="$2"
  if [[ ! "$risk_id" =~ ^[A-Z0-9-]+$ ]]; then
    status_line missing "Accepted risk row" "invalid risk ID '$risk_id'"
    add_failure "accepted risk ID has an invalid format"
    return
  fi

  if awk -F'|' -v id="$risk_id" -v owner="$expected_owner" '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    {
      row_id = trim($2)
      if (row_id == id) {
        found = 1
        severity = trim($3)
        if (severity !~ /^(Critical|High|Medium|Low)$/) {
          invalid = 1
        }
        if (trim($8) != owner) {
          invalid = 1
        }
        for (column = 4; column <= 9; column++) {
          value = trim($column)
          if (value == "" || value == "None" || value == "TBD" || value ~ /^None /) {
            invalid = 1
          }
        }
      }
    }
    END {
      exit(found && !invalid ? 0 : 1)
    }
  ' "$EVIDENCE_PATH"; then
    status_line ok "Accepted risk row" "$risk_id has all required fields"
  else
    status_line missing "Accepted risk row" "$risk_id is missing or incomplete"
    add_failure "accepted risk row $risk_id is missing or incomplete"
  fi
}

printf 'Security review decision gate\n'
printf 'Profile: %s\n' "$PROFILE"
printf 'Mode: %s\n\n' "$(if [[ "$ALLOW_MISSING" == "1" ]]; then printf 'allow-missing report'; else printf 'strict'; fi)"

printf 'Required documents\n'
require_file "$PLAN_PATH" "security review plan"
require_file "$EVIDENCE_PATH" "security review evidence register"
require_file "$README_PATH" "public README"

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

  FAILURE_SCOPE="common"
  printf '\nRegister integrity\n'
  if grep -F "TBD" "$EVIDENCE_PATH" >/dev/null; then
    status_line missing "placeholder scan" "TBD placeholders remain"
    add_failure "TBD placeholders remain in security review evidence register"
  else
    status_line ok "placeholder scan" "no TBD placeholders"
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
  if [[ "$PROFILE" != "source" ]]; then
    if grep -E '^\|[^|]*\|[[:space:]]*`script/package_macos_alpha\.sh`[[:space:]]*\|[[:space:]]*Passed[[:space:]]*\|' "$EVIDENCE_PATH" >/dev/null; then
      status_line ok "alpha package validation evidence" "Passed"
    else
      status_line missing "alpha package validation evidence" "expected Passed row"
      add_failure "missing passed alpha package validation evidence"
    fi
  fi
  require_release_value "Production-use recommendation" "Not recommended"
  if [[ "$PROFILE" != "source" ]]; then
    FAILURE_SCOPE="common"
    printf '\nSQLCipher distribution dependency gate\n'
    if [[ ! -x "$SQLCIPHER_GATE" ]]; then
      status_line missing "SQLCipher distribution gate" "${SQLCIPHER_GATE#$ROOT_DIR/}"
      add_failure "missing executable SQLCipher distribution gate"
    elif SQLCIPHER_GATE_OUTPUT="$("$SQLCIPHER_GATE" 2>&1)"; then
      status_line ok "SQLCipher distribution gate" "$SQLCIPHER_GATE_OUTPUT"
    else
      status_line missing "SQLCipher distribution gate" "$SQLCIPHER_GATE_OUTPUT"
      add_failure "SQLCipher dependency version and source-bound revalidation are not approved"
    fi
  fi
  if [[ "$PROFILE" == "unsigned" ]]; then
    require_release_value "Unsigned experimental DMG artifact decision" "Approved"
  elif [[ "$PROFILE" == "signed" ]]; then
    require_release_value "Signed public alpha artifact decision" "Approved"
  fi

  FAILURE_SCOPE="external"
  printf '\nExternal review path\n'
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

  if grep -E '^\|[[:space:]]*None[[:space:]]*\|[[:space:]]*None selected yet[[:space:]]*\|[[:space:]]*None reviewed yet[[:space:]]*\|[[:space:]]*None attached yet[[:space:]]*\|' "$EVIDENCE_PATH" >/dev/null; then
    status_line missing "Reviewer report rows" "no external reviewer report row attached"
    add_failure "missing external reviewer report row"
  else
    status_line ok "Reviewer report rows" "external reviewer report row attached"
  fi

  printf '\nExternal review release decision\n'
  require_release_value "External review completed" "Yes"
  require_release_value "Critical findings fixed or explicitly accepted" "Yes"
  require_release_value "High findings fixed or explicitly accepted" "Yes"
  require_release_value "Medium findings fixed, mitigated, or tracked" "Yes"
  require_release_value "Validation after review-driven changes passed" "Yes"
  require_release_value "Security model or readiness claims updated after review" "Yes"
  require_release_value "Public alpha decision" "Approved"

  if [[ "$PROFILE" == "source" ]]; then
    FAILURE_SCOPE="common"
    printf '\nSource-preview review policy\n'
    require_release_value "External review required before source or unsigned experimental publication" "No"
    require_contains "$README_PATH" "unaudited source warning" "received an external security audit"
    require_contains "$README_PATH" "production-credential warning" "Do not use it to store production"
  else
    FAILURE_SCOPE="accepted-risk"
    printf '\nMaintainer accepted-risk path\n'
    require_release_value "Experimental pre-release risk accepted" "Yes"
    require_release_value "Risk acceptance owner" "Chase Chou"
    accepted_risk_owner="$(release_value "Risk acceptance owner")"

    if [[ "$PROFILE" == "unsigned" ]]; then
      require_release_present "Unsigned accepted risk ID"
      accepted_risk_id="$(release_value "Unsigned accepted risk ID")"
      require_release_date "Unsigned risk acceptance date"
      risk_acceptance_date="$(release_value "Unsigned risk acceptance date")"
      require_release_value "Unsigned accepted release scope" "v0.1.x pre-alpha macOS 13+ Apple Silicon DMG"
      require_release_value "Unsigned experimental security-policy decision" "Approved for the bounded unsigned profile"
      require_release_value "External review required before source or unsigned experimental publication" "No"
      require_contains "$README_PATH" "AR-002 user warning" "AR-002"
      require_contains "$README_PATH" "unsigned warning" "unsigned"
      require_contains "$README_PATH" "unaudited warning" "unaudited"
    else
      require_release_present "Accepted risk ID"
      accepted_risk_id="$(release_value "Accepted risk ID")"
      require_release_date "Risk acceptance date"
      risk_acceptance_date="$(release_value "Risk acceptance date")"
      require_release_value "Accepted release scope" "v0.1.x pre-alpha macOS 13+ Apple Silicon DMG"
      require_release_value "Public alpha security decision" "Approved for experimental pre-release"
      require_contains "$README_PATH" "AR-001 user warning" "AR-001"
    fi

    if ! is_missing_external_value "$accepted_risk_id" && ! is_missing_external_value "$accepted_risk_owner"; then
      require_accepted_risk_row "$accepted_risk_id" "$accepted_risk_owner"
    fi
    if [[ "$risk_acceptance_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      require_validation_on_date "$risk_acceptance_date" "scripts/check.sh" "Risk-date repository validation"
      require_validation_on_date "$risk_acceptance_date" "script/package_macos_alpha.sh" "Risk-date DMG packaging validation"
      require_validation_on_date "$risk_acceptance_date" "script/verify_macos_alpha_artifact.sh" "Risk-date DMG artifact validation"
      require_validation_on_date "$risk_acceptance_date" "script/verify_public_source_tree.sh" "Risk-date public-source validation"
    fi
    require_release_value "External review required before production use" "Yes"
    require_contains "$README_PATH" "production-credential warning" "Do not use it to store production"
  fi
fi

printf '\nResult\n'
if [[ "$(release_value "External review completed")" == "Yes" ]]; then
  printf '  Audit status: externally-reviewed\n'
else
  printf '  Audit status: unaudited\n'
fi

if [[ "$PROFILE" == "source" && "$COMMON_FAILURE_COUNT" -eq 0 ]]; then
  printf '  Source-preview review policy passed without requiring external review or Apple signing.\n'
  printf '  Production use is not recommended.\n'
  exit 0
fi

if [[ "$COMMON_FAILURE_COUNT" -eq 0 && "$EXTERNAL_REVIEW_FAILURE_COUNT" -eq 0 ]]; then
  printf '  External security review path passed for public-alpha security readiness.\n'
  printf '  Production-use recommendation remains separate.\n'
  exit 0
fi

if [[ "$COMMON_FAILURE_COUNT" -eq 0 && "$ACCEPTED_RISK_FAILURE_COUNT" -eq 0 ]]; then
  printf '  Maintainer accepted-risk path passed for the %s experimental profile.\n' "$PROFILE"
  printf '  External review remains incomplete and production use is not recommended.\n'
  exit 0
fi

if [[ "$COMMON_FAILURE_COUNT" -gt 0 ]]; then
  for failure in "${COMMON_FAILURES[@]}"; do
    printf '  common missing: %s\n' "$failure"
  done
fi
if [[ "$EXTERNAL_REVIEW_FAILURE_COUNT" -gt 0 ]]; then
  for failure in "${EXTERNAL_REVIEW_FAILURES[@]}"; do
    printf '  external path missing: %s\n' "$failure"
  done
fi
if [[ "$ACCEPTED_RISK_FAILURE_COUNT" -gt 0 ]]; then
  for failure in "${ACCEPTED_RISK_FAILURES[@]}"; do
    printf '  accepted-risk path missing: %s\n' "$failure"
  done
fi
printf '  Strict security decision readiness is not approved.\n'
printf '  This gate verifies documented evidence and accepted-risk completeness; it does not perform an external review.\n'

if [[ "$ALLOW_MISSING" == "1" ]]; then
  printf '  allow-missing mode: exiting 0 after reporting missing evidence.\n'
  exit 0
fi

exit 1
