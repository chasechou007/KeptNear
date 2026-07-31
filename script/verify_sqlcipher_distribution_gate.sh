#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_PATH="$ROOT_DIR/docs/sqlcipher-distribution-evidence.json"
LOCK_PATH="$ROOT_DIR/Cargo.lock"
BROKER_MANIFEST_PATH="$ROOT_DIR/crates/psw-broker/Cargo.toml"
STATE_STORE_PATH="$ROOT_DIR/crates/psw-broker/src/state_store.rs"
STATE_SCHEMA_PATH="$ROOT_DIR/crates/psw-broker/src/state_schema.rs"
INTEGRATION_TESTS_PATH="$ROOT_DIR/crates/psw-broker/src/integration_tests.rs"

usage() {
  cat <<'USAGE'
usage: script/verify_sqlcipher_distribution_gate.sh [--evidence PATH]

Validates the actual bundled SQLCipher dependency and its machine-readable,
source-bound revalidation receipt. This is a strict binary-distribution gate:
known blocked and unknown dependency versions always exit non-zero.

Options:
  --evidence PATH  validate this receipt instead of the repository default
  -h, --help       show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence)
      if [[ $# -lt 2 ]]; then
        echo "--evidence requires a path" >&2
        usage >&2
        exit 2
      fi
      EVIDENCE_PATH="$2"
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

require_file() {
  local path="$1"
  local description="$2"
  if [[ ! -f "$path" || -L "$path" ]]; then
    echo "SQLCipher distribution gate failed: missing regular $description at ${path#$ROOT_DIR/}" >&2
    exit 1
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "SQLCipher distribution gate failed: missing required command $command_name" >&2
    exit 1
  fi
}

for required_file in \
  "$EVIDENCE_PATH" \
  "$LOCK_PATH" \
  "$BROKER_MANIFEST_PATH" \
  "$STATE_STORE_PATH" \
  "$STATE_SCHEMA_PATH" \
  "$INTEGRATION_TESTS_PATH"; do
  require_file "$required_file" "distribution evidence input"
done
require_command python3
require_command shasum

if ! grep -E 'rusqlite[[:space:]]*=.*features[[:space:]]*=[[:space:]]*\[[^]]*"bundled-sqlcipher"' \
  "$BROKER_MANIFEST_PATH" >/dev/null; then
  echo "SQLCipher distribution gate failed: psw-broker does not declare the reviewed bundled-sqlcipher feature" >&2
  exit 1
fi

LIBSQLITE3_SYS_VERSIONS="$(
  awk '
    $0 == "[[package]]" {
      in_package = 0
      next
    }
    $0 == "name = \"libsqlite3-sys\"" {
      in_package = 1
      next
    }
    in_package && /^version = "/ {
      value = $0
      sub(/^version = "/, "", value)
      sub(/"$/, "", value)
      print value
      in_package = 0
    }
  ' "$LOCK_PATH"
)"

LIBSQLITE3_SYS_VERSION_COUNT="$(
  printf '%s\n' "$LIBSQLITE3_SYS_VERSIONS" |
    awk 'NF { count += 1 } END { print count + 0 }'
)"
if [[ "$LIBSQLITE3_SYS_VERSION_COUNT" -eq 0 ]]; then
  echo "SQLCipher distribution gate failed: Cargo.lock does not contain libsqlite3-sys" >&2
  exit 1
fi
if [[ "$LIBSQLITE3_SYS_VERSION_COUNT" -ne 1 ]]; then
  echo "SQLCipher distribution gate failed: Cargo.lock must contain exactly one reviewed libsqlite3-sys version" >&2
  exit 1
fi
LIBSQLITE3_SYS_VERSION="$LIBSQLITE3_SYS_VERSIONS"

# This reviewed mapping is intentionally code, not a mutable release conclusion.
# A dependency refresh must add a reviewed mapping before any receipt can pass.
case "$LIBSQLITE3_SYS_VERSION" in
  0.28.0)
    BUNDLED_SQLCIPHER_VERSION="4.5.3"
    VERSION_POLICY="blocked"
    ;;
  *)
    echo "SQLCipher distribution gate failed: libsqlite3-sys $LIBSQLITE3_SYS_VERSION has no reviewed bundled SQLCipher mapping" >&2
    exit 1
    ;;
esac

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

CARGO_LOCK_SHA256="$(sha256_file "$LOCK_PATH")"
BROKER_MANIFEST_SHA256="$(sha256_file "$BROKER_MANIFEST_PATH")"
STATE_STORE_SHA256="$(sha256_file "$STATE_STORE_PATH")"
STATE_SCHEMA_SHA256="$(sha256_file "$STATE_SCHEMA_PATH")"
INTEGRATION_TESTS_SHA256="$(sha256_file "$INTEGRATION_TESTS_PATH")"

python3 - \
  "$EVIDENCE_PATH" \
  "$LIBSQLITE3_SYS_VERSION" \
  "$BUNDLED_SQLCIPHER_VERSION" \
  "$CARGO_LOCK_SHA256" \
  "$BROKER_MANIFEST_SHA256" \
  "$STATE_STORE_SHA256" \
  "$STATE_SCHEMA_SHA256" \
  "$INTEGRATION_TESTS_SHA256" \
  "$VERSION_POLICY" <<'PY'
import datetime
import json
import re
import sys

(
    evidence_path,
    libsqlite3_sys_version,
    bundled_sqlcipher_version,
    cargo_lock_sha256,
    broker_manifest_sha256,
    state_store_sha256,
    state_schema_sha256,
    integration_tests_sha256,
    version_policy,
) = sys.argv[1:]


def fail(message):
    raise SystemExit(f"SQLCipher distribution gate failed: {message}")


try:
    with open(evidence_path, "r", encoding="utf-8") as evidence_file:
        evidence = json.load(evidence_file)
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    fail(f"invalid distribution evidence JSON: {error}")

expected_top_level = {
    "schemaVersion",
    "status",
    "approvedForDistribution",
    "dependency",
    "source",
    "revalidation",
    "blocker",
}
if not isinstance(evidence, dict) or set(evidence) != expected_top_level:
    fail("distribution evidence has an unexpected top-level schema")
if evidence["schemaVersion"] != 1:
    fail("distribution evidence schemaVersion must be 1")

dependency = evidence["dependency"]
if not isinstance(dependency, dict) or set(dependency) != {
    "libsqlite3SysVersion",
    "bundledSqlcipherVersion",
}:
    fail("distribution evidence dependency object has an unexpected schema")
if dependency["libsqlite3SysVersion"] != libsqlite3_sys_version:
    fail("distribution evidence does not match the libsqlite3-sys version in Cargo.lock")
if dependency["bundledSqlcipherVersion"] != bundled_sqlcipher_version:
    fail("distribution evidence does not match the reviewed bundled SQLCipher mapping")

source = evidence["source"]
expected_source = {
    "cargoLockSha256": cargo_lock_sha256,
    "brokerManifestSha256": broker_manifest_sha256,
    "stateStoreSha256": state_store_sha256,
    "stateSchemaSha256": state_schema_sha256,
    "brokerIntegrationTestsSha256": integration_tests_sha256,
}
if not isinstance(source, dict) or set(source) != set(expected_source):
    fail("distribution evidence source object has an unexpected schema")
for field, expected_value in expected_source.items():
    if source[field] != expected_value:
        fail(f"distribution evidence {field} does not match the current source")

revalidation = evidence["revalidation"]
expected_revalidation_keys = {"result", "commands", "reviewedBy", "reviewedAt"}
if not isinstance(revalidation, dict) or set(revalidation) != expected_revalidation_keys:
    fail("distribution evidence revalidation object has an unexpected schema")
if not isinstance(revalidation["commands"], list) or not all(
    isinstance(command, str) and command for command in revalidation["commands"]
):
    fail("distribution evidence revalidation commands must be non-empty strings")
if not isinstance(evidence["blocker"], str) or not evidence["blocker"]:
    fail("distribution evidence blocker must be a non-empty string")

required_commands = {
    "cargo test -p psw-broker state_store::tests::",
    "cargo test -p psw-broker integration_tests::ciphertext_corruption_blocks_runtime_without_replacing_state_or_key",
    "cargo test -p psw-broker integration_tests::wrong_device_key_blocks_runtime_without_overwriting_either_side",
    "cargo test -p psw-broker integration_tests::insecure_database_permissions_block_runtime_and_retain_authority",
    "cargo test -p psw-broker integration_tests::missing_database_blocks_runtime_without_silent_reinitialization",
    "cargo test -p psw-broker integration_tests::missing_device_key_blocks_runtime_without_generating_replacement",
    "script/verify_dependency_licenses.sh",
    "cargo clippy --workspace --all-targets --locked -- -D warnings",
}

if version_policy == "blocked":
    if evidence["status"] != "blocked":
        fail("the reviewed dependency mapping is blocked but the receipt status is not blocked")
    if evidence["approvedForDistribution"] is not False:
        fail("the reviewed dependency mapping is blocked but approvedForDistribution is not false")
    if revalidation["result"] != "not-run-for-distribution":
        fail("the blocked receipt must record not-run-for-distribution")
    if revalidation["commands"]:
        fail("the blocked receipt must not claim distribution revalidation commands")
    if revalidation["reviewedBy"] is not None or revalidation["reviewedAt"] is not None:
        fail("the blocked receipt must not claim a distribution reviewer or review date")
    print(
        "SQLCipher distribution gate blocked: "
        f"libsqlite3-sys {libsqlite3_sys_version} bundles SQLCipher "
        f"{bundled_sqlcipher_version}; upgrade and source-bound revalidation are required",
        file=sys.stderr,
    )
    raise SystemExit(1)

if version_policy != "eligible":
    fail(f"unsupported reviewed dependency policy {version_policy}")
if evidence["status"] != "approved" or evidence["approvedForDistribution"] is not True:
    fail("eligible dependency mapping still lacks an approved distribution receipt")
if revalidation["result"] != "passed":
    fail("approved distribution evidence must record a passed revalidation")
if (
    len(revalidation["commands"]) != len(required_commands)
    or set(revalidation["commands"]) != required_commands
):
    fail("approved distribution evidence does not contain the exact required command set")
if not isinstance(revalidation["reviewedBy"], str) or not revalidation["reviewedBy"].strip():
    fail("approved distribution evidence must name its reviewer")
if not isinstance(revalidation["reviewedAt"], str) or not re.fullmatch(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", revalidation["reviewedAt"]
):
    fail("approved distribution evidence must use a UTC reviewedAt timestamp")
try:
    reviewed_at = datetime.datetime.strptime(
        revalidation["reviewedAt"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=datetime.timezone.utc)
except ValueError as error:
    fail(f"approved distribution evidence has an invalid reviewedAt timestamp: {error}")
if reviewed_at > datetime.datetime.now(datetime.timezone.utc):
    fail("approved distribution evidence reviewedAt timestamp is in the future")
PY

echo "SQLCipher distribution gate passed for libsqlite3-sys $LIBSQLITE3_SYS_VERSION and bundled SQLCipher $BUNDLED_SQLCIPHER_VERSION."
