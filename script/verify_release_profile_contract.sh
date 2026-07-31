#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_PROFILE="$ROOT_DIR/script/verify_source_preview_ready.sh"
UNSIGNED_PROFILE="$ROOT_DIR/script/verify_unsigned_alpha_release_ready.sh"
SIGNED_PROFILE="$ROOT_DIR/script/verify_public_alpha_release_ready.sh"
REVIEW_GATE="$ROOT_DIR/script/verify_security_review_evidence.sh"
SQLCIPHER_GATE="$ROOT_DIR/script/verify_sqlcipher_distribution_gate.sh"

require_executable() {
  local path="$1"
  if [[ ! -x "$path" ]]; then
    echo "release profile contract violation: missing executable ${path#$ROOT_DIR/}" >&2
    exit 1
  fi
}

require_text() {
  local text="$1"
  local expected="$2"
  local label="$3"
  if [[ "$text" != *"$expected"* ]]; then
    echo "release profile contract violation: $label is missing: $expected" >&2
    exit 1
  fi
}

for profile in "$SOURCE_PROFILE" "$UNSIGNED_PROFILE" "$SIGNED_PROFILE" "$REVIEW_GATE" "$SQLCIPHER_GATE"; do
  require_executable "$profile"
done

SOURCE_HELP="$("$SOURCE_PROFILE" --help)"
UNSIGNED_HELP="$("$UNSIGNED_PROFILE" --help)"
SIGNED_HELP="$("$SIGNED_PROFILE" --help)"
REVIEW_HELP="$("$REVIEW_GATE" --help)"
SQLCIPHER_HELP="$("$SQLCIPHER_GATE" --help)"

require_text "$SOURCE_HELP" "Profile: source-preview." "source profile"
require_text "$SOURCE_HELP" "does not require Apple signing or external security review" "source profile"
require_text "$UNSIGNED_HELP" "Profile: unsigned-experimental." "unsigned profile"
require_text "$UNSIGNED_HELP" "not require Developer ID signing, notarization, or external security review" "unsigned profile"
require_text "$SIGNED_HELP" "signed-experimental profile only" "signed profile"
require_text "$REVIEW_HELP" "--profile source|unsigned|signed" "review policy profile catalog"
require_text "$SQLCIPHER_HELP" "strict binary-distribution gate" "SQLCipher distribution gate"

grep -F 'local-test|unsigned-experimental|experimental-pre-release' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'unsigned-experimental)' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile unsigned' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile signed' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile unsigned' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile signed' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'verify_sqlcipher_distribution_gate.sh' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'verify_sqlcipher_distribution_gate.sh' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'verify_sqlcipher_distribution_gate.sh' "$ROOT_DIR/script/verify_security_review_evidence.sh" >/dev/null
grep -F 'SQLCipher distribution evidence SHA-256' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'distribution artifact source revision' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'SQLCIPHER_FFI_PATH=' "$SQLCIPHER_GATE" >/dev/null
grep -F 'script/verify_source_preview_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null
grep -F 'script/verify_unsigned_alpha_release_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null
grep -F 'script/verify_public_alpha_release_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null

PACKAGE_BUILD_COUNT="$(
  awk '$1 == "cargo" && $2 == "build" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/package_macos_alpha.sh"
)"
PACKAGE_LOCKED_COUNT="$(
  awk '$1 == "--locked" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/package_macos_alpha.sh"
)"
ARTIFACT_BUILD_COUNT="$(
  awk '$1 == "cargo" && $2 == "build" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/verify_macos_alpha_artifact.sh"
)"
ARTIFACT_LOCKED_COUNT="$(
  awk '$1 == "--locked" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/verify_macos_alpha_artifact.sh"
)"
if [[ "$PACKAGE_BUILD_COUNT" -ne 2 || "$PACKAGE_LOCKED_COUNT" -ne "$PACKAGE_BUILD_COUNT" ]]; then
  echo "release profile contract violation: every package Cargo build must use --locked" >&2
  exit 1
fi
if [[ "$ARTIFACT_BUILD_COUNT" -ne 1 || "$ARTIFACT_LOCKED_COUNT" -ne "$ARTIFACT_BUILD_COUNT" ]]; then
  echo "release profile contract violation: every artifact-verifier Cargo build must use --locked" >&2
  exit 1
fi

"$REVIEW_GATE" --profile source >/dev/null
if SQLCIPHER_GATE_OUTPUT="$("$SQLCIPHER_GATE" 2>&1)"; then
  echo "release profile contract violation: blocked SQLCipher dependency passed its independent gate" >&2
  exit 1
fi
require_text \
  "$SQLCIPHER_GATE_OUTPUT" \
  "libsqlite3-sys 0.28.0 bundles SQLCipher 4.5.3; upgrade and source-bound revalidation are required" \
  "independent SQLCipher dependency gate"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/keptnear-release-contract.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
TAMPERED_SQLCIPHER_EVIDENCE="$TMP_DIR/sqlcipher-approved.json"
python3 - \
  "$ROOT_DIR/docs/sqlcipher-distribution-evidence.json" \
  "$TAMPERED_SQLCIPHER_EVIDENCE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as source_file:
    evidence = json.load(source_file)
evidence["status"] = "approved"
evidence["approvedForDistribution"] = True
with open(sys.argv[2], "w", encoding="utf-8") as target_file:
    json.dump(evidence, target_file)
PY
if TAMPERED_GATE_OUTPUT="$("$SQLCIPHER_GATE" --evidence "$TAMPERED_SQLCIPHER_EVIDENCE" 2>&1)"; then
  echo "release profile contract violation: an edited receipt bypassed the blocked dependency mapping" >&2
  exit 1
fi
require_text \
  "$TAMPERED_GATE_OUTPUT" \
  "the reviewed dependency mapping is blocked but the receipt status is not blocked" \
  "blocked dependency mapping"

if UNSIGNED_REVIEW_OUTPUT="$("$REVIEW_GATE" --profile unsigned 2>&1)"; then
  echo "release profile contract violation: unsigned artifact gate ignored the current Not approved decision" >&2
  exit 1
fi
require_text \
  "$UNSIGNED_REVIEW_OUTPUT" \
  "Unsigned experimental DMG artifact decision: expected 'Approved', got 'Not approved'" \
  "unsigned artifact decision gate"
require_text \
  "$UNSIGNED_REVIEW_OUTPUT" \
  "libsqlite3-sys 0.28.0 bundles SQLCipher 4.5.3; upgrade and source-bound revalidation are required" \
  "unsigned SQLCipher dependency gate"

if SIGNED_REVIEW_OUTPUT="$("$REVIEW_GATE" --profile signed 2>&1)"; then
  echo "release profile contract violation: signed artifact gate ignored the current Not approved decision" >&2
  exit 1
fi
require_text \
  "$SIGNED_REVIEW_OUTPUT" \
  "Signed public alpha artifact decision: expected 'Approved', got 'Not approved'" \
  "signed artifact decision gate"
require_text \
  "$SIGNED_REVIEW_OUTPUT" \
  "libsqlite3-sys 0.28.0 bundles SQLCipher 4.5.3; upgrade and source-bound revalidation are required" \
  "signed SQLCipher dependency gate"

if "$REVIEW_GATE" --profile invalid >/dev/null 2>&1; then
  echo "release profile contract violation: invalid review profile was accepted" >&2
  exit 1
fi

echo "Release profile contract verification passed: source, unsigned, and signed remain separate."
