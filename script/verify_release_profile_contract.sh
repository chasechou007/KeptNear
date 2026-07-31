#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_PROFILE="$ROOT_DIR/script/verify_source_preview_ready.sh"
UNSIGNED_PROFILE="$ROOT_DIR/script/verify_unsigned_alpha_release_ready.sh"
SIGNED_PROFILE="$ROOT_DIR/script/verify_public_alpha_release_ready.sh"
REVIEW_GATE="$ROOT_DIR/script/verify_security_review_evidence.sh"
SQLCIPHER_GATE="$ROOT_DIR/script/verify_sqlcipher_distribution_gate.sh"
DISTRIBUTION_TOOLCHAIN="$ROOT_DIR/script/reviewed_distribution_toolchain.sh"
DISTRIBUTION_CARGO_RUNNER="$ROOT_DIR/script/run_reviewed_distribution_cargo.sh"
RUN_DISTRIBUTION_TOOLCHAIN_SMOKE=0

usage() {
  cat <<'USAGE'
usage: script/verify_release_profile_contract.sh [--distribution-toolchain-smoke]

Checks the cross-host release profile contract. The optional smoke check also
requires this machine to match the source-bound Apple Silicon release toolchain.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --distribution-toolchain-smoke)
      RUN_DISTRIBUTION_TOOLCHAIN_SMOKE=1
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

for profile in \
  "$SOURCE_PROFILE" \
  "$UNSIGNED_PROFILE" \
  "$SIGNED_PROFILE" \
  "$REVIEW_GATE" \
  "$SQLCIPHER_GATE" \
  "$DISTRIBUTION_CARGO_RUNNER"; do
  require_executable "$profile"
done
if [[ ! -f "$DISTRIBUTION_TOOLCHAIN" || -L "$DISTRIBUTION_TOOLCHAIN" ]]; then
  echo "release profile contract violation: missing regular script/reviewed_distribution_toolchain.sh" >&2
  exit 1
fi

SOURCE_HELP="$("$SOURCE_PROFILE" --help)"
UNSIGNED_HELP="$("$UNSIGNED_PROFILE" --help)"
SIGNED_HELP="$("$SIGNED_PROFILE" --help)"
REVIEW_HELP="$("$REVIEW_GATE" --help)"
SQLCIPHER_HELP="$("$SQLCIPHER_GATE" --help)"
DISTRIBUTION_CARGO_HELP="$("$DISTRIBUTION_CARGO_RUNNER" --help)"

require_text "$SOURCE_HELP" "Profile: source-preview." "source profile"
require_text "$SOURCE_HELP" "does not require Apple signing or external security review" "source profile"
require_text "$UNSIGNED_HELP" "Profile: unsigned-experimental." "unsigned profile"
require_text "$UNSIGNED_HELP" "not require Developer ID signing, notarization, or external security review" "unsigned profile"
require_text "$SIGNED_HELP" "signed-experimental profile only" "signed profile"
require_text "$REVIEW_HELP" "--profile source|unsigned|signed" "review policy profile catalog"
require_text "$SQLCIPHER_HELP" "strict binary-distribution gate" "SQLCipher distribution gate"
require_text "$DISTRIBUTION_CARGO_HELP" "source-bound Apple Silicon Rust and native toolchains" "distribution Cargo runner"

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
grep -F 'BROKER_SOURCE_DIR=' "$SQLCIPHER_GATE" >/dev/null
grep -F 'RUST_WORKSPACE_SOURCE_DIR="$ROOT_DIR/crates"' "$SQLCIPHER_GATE" >/dev/null
grep -F 'RUST_TOOLCHAIN_PATH="$ROOT_DIR/rust-toolchain.toml"' "$SQLCIPHER_GATE" >/dev/null
grep -F 'CARGO_RUSTC_PROBE_TARGET_DIR="$ROOT_DIR/target/sqlcipher-toolchain-probe"' "$SQLCIPHER_GATE" >/dev/null
grep -F 'RUSTC_VERBOSE_VERSION="$(' "$SQLCIPHER_GATE" >/dev/null
grep -F '"${CARGO_RUSTC_PROBE[@]}"' "$SQLCIPHER_GATE" >/dev/null
grep -F 'keptnear_assert_reviewed_distribution_toolchain' "$SQLCIPHER_GATE" >/dev/null
grep -F 'reviewed_distribution_toolchain.sh' "$SQLCIPHER_GATE" >/dev/null
grep -F 'run_reviewed_distribution_cargo.sh' "$SQLCIPHER_GATE" >/dev/null
grep -F 'CARGO_TARGET_ROOT="$ROOT_DIR/target"' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F 'CARGO_TARGET_ROOT="$ROOT_DIR/target"' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F '"$SQLCIPHER_GATE" --distribution-host --release-target "$RUST_TARGET"' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F '"$SQLCIPHER_GATE" --distribution-host --release-target "$RUST_TARGET"' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F '"$DISTRIBUTION_CARGO_RUNNER" "$@"' "$ROOT_DIR/script/package_macos_alpha.sh" >/dev/null
grep -F '"$DISTRIBUTION_CARGO_RUNNER" "$@"' "$ROOT_DIR/script/verify_macos_alpha_artifact.sh" >/dev/null
grep -F 'KEPTNEAR_REVIEWED_RUSTC_BINARY_SHA256=' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'KEPTNEAR_REVIEWED_CARGO_BINARY_SHA256=' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'KEPTNEAR_REVIEWED_APPLE_CLANG_SHA256=' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'KEPTNEAR_REVIEWED_APPLE_AR_SHA256=' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'KEPTNEAR_REVIEWED_APPLE_RANLIB_SHA256=' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'KEPTNEAR_REVIEWED_XCODEBUILD_SHA256=' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F '"CC=$KEPTNEAR_ACTIVE_CLANG_PATH"' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F '"CFLAGS=$KEPTNEAR_ACTIVE_CFLAGS"' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'LIBSQLITE3_SYS_USE_PKG_CONFIG' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'SQLCIPHER_LIB_DIR' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F 'script/verify_source_preview_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null
grep -F 'script/verify_unsigned_alpha_release_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null
grep -F 'script/verify_public_alpha_release_ready.sh' "$ROOT_DIR/docs/release-readiness.md" >/dev/null

PACKAGE_BUILD_COUNT="$(
  awk '$1 == "package_cargo" && $2 == "build" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/package_macos_alpha.sh"
)"
PACKAGE_LOCKED_COUNT="$(
  awk '$1 == "--locked" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/package_macos_alpha.sh"
)"
PACKAGE_TARGET_DIR_COUNT="$(
  awk '$1 == "--target-dir" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/package_macos_alpha.sh"
)"
PACKAGE_TARGET_COUNT="$(
  awk '$1 == "--target" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/package_macos_alpha.sh"
)"
ARTIFACT_BUILD_COUNT="$(
  awk '$1 == "artifact_cargo" && $2 == "build" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/verify_macos_alpha_artifact.sh"
)"
ARTIFACT_LOCKED_COUNT="$(
  awk '$1 == "--locked" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/verify_macos_alpha_artifact.sh"
)"
ARTIFACT_TARGET_DIR_COUNT="$(
  awk '$1 == "--target-dir" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/verify_macos_alpha_artifact.sh"
)"
ARTIFACT_TARGET_COUNT="$(
  awk '$1 == "--target" { count += 1 } END { print count + 0 }' \
    "$ROOT_DIR/script/verify_macos_alpha_artifact.sh"
)"
if [[ \
  "$PACKAGE_BUILD_COUNT" -ne 2 || \
  "$PACKAGE_LOCKED_COUNT" -ne "$PACKAGE_BUILD_COUNT" || \
  "$PACKAGE_TARGET_DIR_COUNT" -ne "$PACKAGE_BUILD_COUNT" || \
  "$PACKAGE_TARGET_COUNT" -ne "$PACKAGE_BUILD_COUNT" \
]]; then
  echo "release profile contract violation: every package Cargo build must lock dependencies, target, and output directory" >&2
  exit 1
fi
if [[ \
  "$ARTIFACT_BUILD_COUNT" -ne 1 || \
  "$ARTIFACT_LOCKED_COUNT" -ne "$ARTIFACT_BUILD_COUNT" || \
  "$ARTIFACT_TARGET_DIR_COUNT" -ne "$ARTIFACT_BUILD_COUNT" || \
  "$ARTIFACT_TARGET_COUNT" -ne "$ARTIFACT_BUILD_COUNT" \
]]; then
  echo "release profile contract violation: every artifact-verifier Cargo build must lock dependencies, target, and output directory" >&2
  exit 1
fi

grep -F 'environment_command+=(-u "$variable_name")' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F '"RUSTC=$KEPTNEAR_ACTIVE_RUSTC_PATH"' "$DISTRIBUTION_TOOLCHAIN" >/dev/null
grep -F '"CARGO_BUILD_RUSTC=$KEPTNEAR_ACTIVE_RUSTC_PATH"' "$DISTRIBUTION_TOOLCHAIN" >/dev/null

"$REVIEW_GATE" --profile source >/dev/null
if SQLCIPHER_GATE_OUTPUT="$("$SQLCIPHER_GATE" 2>&1)"; then
  echo "release profile contract violation: blocked SQLCipher dependency passed its independent gate" >&2
  exit 1
fi
require_text \
  "$SQLCIPHER_GATE_OUTPUT" \
  "libsqlite3-sys 0.28.0 bundles SQLCipher 4.5.3; upgrade and source-bound revalidation are required" \
  "independent SQLCipher dependency gate"

for RUST_TOOLCHAIN_OVERRIDE in \
  RUSTC \
  CARGO_BUILD_RUSTC \
  RUSTC_WRAPPER \
  RUSTC_WORKSPACE_WRAPPER \
  CARGO_BUILD_RUSTC_WRAPPER \
  CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
  if RUST_OVERRIDE_OUTPUT="$(
    env "$RUST_TOOLCHAIN_OVERRIDE=/usr/bin/false" "$SQLCIPHER_GATE" 2>&1
  )"; then
    echo "release profile contract violation: resetting $RUST_TOOLCHAIN_OVERRIDE allowed the blocked dependency to pass" >&2
    exit 1
  fi
  require_text \
    "$RUST_OVERRIDE_OUTPUT" \
    "libsqlite3-sys 0.28.0 bundles SQLCipher 4.5.3; upgrade and source-bound revalidation are required" \
    "$RUST_TOOLCHAIN_OVERRIDE reset"
  if [[ "$RUST_OVERRIDE_OUTPUT" == *"Cargo-selected rustc identity probe failed"* ]]; then
    echo "release profile contract violation: $RUST_TOOLCHAIN_OVERRIDE executed during the isolated compiler probe" >&2
    exit 1
  fi
done

if [[ "$RUN_DISTRIBUTION_TOOLCHAIN_SMOKE" == "1" ]]; then
  ISOLATED_CARGO_VERSION="$(
    env \
      RUSTC=/usr/bin/false \
      CARGO_BUILD_RUSTC=/usr/bin/false \
      RUSTC_WRAPPER=/usr/bin/false \
      CC=/usr/bin/false \
      CFLAGS="-include /private/tmp/keptnear-untrusted.h" \
      CPPFLAGS="-I/private/tmp/keptnear-untrusted" \
      LIBSQLITE3_FLAGS="-DSQLITE_UNTRUSTED" \
      "$DISTRIBUTION_CARGO_RUNNER" -V
  )"
  require_text \
    "$ISOLATED_CARGO_VERSION" \
    "cargo 1.75.0 (1d8b05cdd 2023-11-20)" \
    "isolated Rust and native distribution environment"
fi

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
