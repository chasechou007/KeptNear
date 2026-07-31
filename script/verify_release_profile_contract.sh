#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_PROFILE="$ROOT_DIR/script/verify_source_preview_ready.sh"
UNSIGNED_PROFILE="$ROOT_DIR/script/verify_unsigned_alpha_release_ready.sh"
SIGNED_PROFILE="$ROOT_DIR/script/verify_public_alpha_release_ready.sh"
REVIEW_GATE="$ROOT_DIR/script/verify_security_review_evidence.sh"

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

for profile in "$SOURCE_PROFILE" "$UNSIGNED_PROFILE" "$SIGNED_PROFILE" "$REVIEW_GATE"; do
  require_executable "$profile"
done

SOURCE_HELP="$("$SOURCE_PROFILE" --help)"
UNSIGNED_HELP="$("$UNSIGNED_PROFILE" --help)"
SIGNED_HELP="$("$SIGNED_PROFILE" --help)"
REVIEW_HELP="$("$REVIEW_GATE" --help)"

require_text "$SOURCE_HELP" "Profile: source-preview." "source profile"
require_text "$SOURCE_HELP" "does not require Apple signing or external security review" "source profile"
require_text "$UNSIGNED_HELP" "Profile: unsigned-experimental." "unsigned profile"
require_text "$UNSIGNED_HELP" "not require Developer ID signing, notarization, or external security review" "unsigned profile"
require_text "$SIGNED_HELP" "signed-experimental profile only" "signed profile"
require_text "$REVIEW_HELP" "--profile source|unsigned|signed" "review policy profile catalog"

grep -F 'local-test|unsigned-experimental|experimental-pre-release' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'unsigned-experimental)' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile unsigned' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile signed' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile unsigned' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'verify_security_review_evidence.sh" --profile signed' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'script/verify_source_preview_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null
grep -F 'script/verify_unsigned_alpha_release_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null
grep -F 'script/verify_public_alpha_release_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null

"$REVIEW_GATE" --profile source >/dev/null
if UNSIGNED_REVIEW_OUTPUT="$("$REVIEW_GATE" --profile unsigned 2>&1)"; then
  echo "release profile contract violation: unsigned artifact gate ignored the current Not approved decision" >&2
  exit 1
fi
require_text \
  "$UNSIGNED_REVIEW_OUTPUT" \
  "Unsigned experimental DMG artifact decision: expected 'Approved', got 'Not approved'" \
  "unsigned artifact decision gate"

if SIGNED_REVIEW_OUTPUT="$("$REVIEW_GATE" --profile signed 2>&1)"; then
  echo "release profile contract violation: signed artifact gate ignored the current Not approved decision" >&2
  exit 1
fi
require_text \
  "$SIGNED_REVIEW_OUTPUT" \
  "Signed public alpha artifact decision: expected 'Approved', got 'Not approved'" \
  "signed artifact decision gate"

if "$REVIEW_GATE" --profile invalid >/dev/null 2>&1; then
  echo "release profile contract violation: invalid review profile was accepted" >&2
  exit 1
fi

echo "Release profile contract verification passed: source, unsigned, and signed remain separate."
