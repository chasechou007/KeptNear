#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_LIBRARY_PATH="$ROOT_DIR/script/reviewed_distribution_toolchain.sh"
DISTRIBUTION_CARGO_RUNNER_PATH="$ROOT_DIR/script/run_reviewed_distribution_cargo.sh"
source "$TOOLCHAIN_LIBRARY_PATH"

EVIDENCE_PATH="$ROOT_DIR/docs/sqlcipher-distribution-evidence.json"
RUST_TOOLCHAIN_PATH="$ROOT_DIR/rust-toolchain.toml"
WORKSPACE_MANIFEST_PATH="$ROOT_DIR/Cargo.toml"
LOCK_PATH="$ROOT_DIR/Cargo.lock"
CARGO_RUSTC_PROBE_TARGET_DIR="$ROOT_DIR/target/sqlcipher-toolchain-probe"
RUST_WORKSPACE_SOURCE_DIR="$ROOT_DIR/crates"
BROKER_MANIFEST_PATH="$ROOT_DIR/crates/psw-broker/Cargo.toml"
BROKER_SOURCE_DIR="$ROOT_DIR/crates/psw-broker/src"
SQLCIPHER_FFI_PATH="$ROOT_DIR/crates/psw-broker/src/sqlcipher_ffi.rs"
STATE_STORE_PATH="$ROOT_DIR/crates/psw-broker/src/state_store.rs"
STATE_SCHEMA_PATH="$ROOT_DIR/crates/psw-broker/src/state_schema.rs"
INTEGRATION_TESTS_PATH="$ROOT_DIR/crates/psw-broker/src/integration_tests.rs"
PACKAGE_SCRIPT_PATH="$ROOT_DIR/script/package_macos_alpha.sh"
ARTIFACT_VERIFIER_PATH="$ROOT_DIR/script/verify_macos_alpha_artifact.sh"
GATE_SCRIPT_PATH="$ROOT_DIR/script/verify_sqlcipher_distribution_gate.sh"
REQUIRE_DISTRIBUTION_HOST=0
REQUESTED_RELEASE_TARGET=""
REVIEWED_DISTRIBUTION_HOST="$KEPTNEAR_REVIEWED_DISTRIBUTION_HOST"
REVIEWED_RELEASE_TARGET="$KEPTNEAR_REVIEWED_RELEASE_TARGET"

usage() {
  cat <<'USAGE'
usage: script/verify_sqlcipher_distribution_gate.sh [--evidence PATH] [--distribution-host --release-target TARGET]

Validates the actual bundled SQLCipher dependency and its machine-readable,
source-bound revalidation receipt. This is a strict binary-distribution gate:
known blocked and unknown dependency versions always exit non-zero.

Options:
  --evidence PATH       validate this receipt instead of the repository default
  --distribution-host  require the reviewed release compiler host
  --release-target      require the named reviewed release target
  -h, --help            show this help
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
    --distribution-host)
      REQUIRE_DISTRIBUTION_HOST=1
      shift
      ;;
    --release-target)
      if [[ $# -lt 2 ]]; then
        echo "--release-target requires a value" >&2
        usage >&2
        exit 2
      fi
      REQUESTED_RELEASE_TARGET="$2"
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

if [[ "$REQUIRE_DISTRIBUTION_HOST" == "1" && -z "$REQUESTED_RELEASE_TARGET" ]]; then
  echo "--distribution-host requires --release-target" >&2
  exit 2
fi
if [[ "$REQUIRE_DISTRIBUTION_HOST" == "0" && -n "$REQUESTED_RELEASE_TARGET" ]]; then
  echo "--release-target requires --distribution-host" >&2
  exit 2
fi
if [[ \
  "$REQUIRE_DISTRIBUTION_HOST" == "1" && \
  "$REQUESTED_RELEASE_TARGET" != "$REVIEWED_RELEASE_TARGET" \
]]; then
  echo "SQLCipher distribution gate failed: release target must be $REVIEWED_RELEASE_TARGET, got $REQUESTED_RELEASE_TARGET" >&2
  exit 1
fi
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
  "$RUST_TOOLCHAIN_PATH" \
  "$WORKSPACE_MANIFEST_PATH" \
  "$LOCK_PATH" \
  "$BROKER_MANIFEST_PATH" \
  "$SQLCIPHER_FFI_PATH" \
  "$STATE_STORE_PATH" \
  "$STATE_SCHEMA_PATH" \
  "$INTEGRATION_TESTS_PATH" \
  "$PACKAGE_SCRIPT_PATH" \
  "$ARTIFACT_VERIFIER_PATH" \
  "$GATE_SCRIPT_PATH" \
  "$TOOLCHAIN_LIBRARY_PATH" \
  "$DISTRIBUTION_CARGO_RUNNER_PATH"; do
  require_file "$required_file" "distribution evidence input"
done
require_command python3
require_command shasum

if [[ "$REQUIRE_DISTRIBUTION_HOST" == "1" ]]; then
  if ! keptnear_assert_reviewed_distribution_toolchain \
    "$REQUESTED_RELEASE_TARGET" \
    "$KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET"; then
    echo "SQLCipher distribution gate failed: reviewed distribution toolchain validation failed" >&2
    exit 1
  fi
else
  if ! keptnear_resolve_active_rust_toolchain; then
    echo "SQLCipher distribution gate failed: active Rust toolchain resolution failed" >&2
    exit 1
  fi
fi

CARGO_RUSTC_PROBE=(
  rustc
  --quiet
  --locked
  --target-dir "$CARGO_RUSTC_PROBE_TARGET_DIR"
)
if [[ "$REQUIRE_DISTRIBUTION_HOST" == "1" ]]; then
  CARGO_RUSTC_PROBE+=(
    --target "$REQUESTED_RELEASE_TARGET"
    --release
  )
fi
CARGO_RUSTC_PROBE+=(
  -p psw-core
  --lib
  --
  -Vv
)
if [[ "$REQUIRE_DISTRIBUTION_HOST" == "1" ]]; then
  RUSTC_PROBE_RUNNER=(keptnear_run_reviewed_distribution_cargo)
else
  RUSTC_PROBE_RUNNER=(keptnear_run_current_rust_cargo)
fi
if ! RUSTC_VERBOSE_VERSION="$("${RUSTC_PROBE_RUNNER[@]}" "${CARGO_RUSTC_PROBE[@]}")"; then
  echo "SQLCipher distribution gate failed: Cargo-selected rustc identity probe failed" >&2
  exit 1
fi
RUSTC_RELEASE="$(
  printf '%s\n' "$RUSTC_VERBOSE_VERSION" |
    awk -F': ' '$1 == "release" { print $2; exit }'
)"
RUSTC_COMMIT_HASH="$(
  printf '%s\n' "$RUSTC_VERBOSE_VERSION" |
    awk -F': ' '$1 == "commit-hash" { print $2; exit }'
)"
RUSTC_HOST="$(
  printf '%s\n' "$RUSTC_VERBOSE_VERSION" |
    awk -F': ' '$1 == "host" { print $2; exit }'
)"
RUSTC_LLVM_VERSION="$(
  printf '%s\n' "$RUSTC_VERBOSE_VERSION" |
    awk -F': ' '$1 == "LLVM version" { print $2; exit }'
)"
if [[ -z "$RUSTC_RELEASE" || -z "$RUSTC_COMMIT_HASH" || -z "$RUSTC_HOST" || -z "$RUSTC_LLVM_VERSION" ]]; then
  echo "SQLCipher distribution gate failed: Cargo-selected rustc did not provide the required compiler identity" >&2
  exit 1
fi

CARGO_VERSION_OUTPUT="$("$KEPTNEAR_ACTIVE_CARGO_PATH" -V)"
if [[ "$CARGO_VERSION_OUTPUT" =~ ^cargo[[:space:]]+([^[:space:]]+)[[:space:]]+\(([0-9a-f]+)[[:space:]] ]]; then
  CARGO_RELEASE="${BASH_REMATCH[1]}"
  CARGO_COMMIT_HASH="${BASH_REMATCH[2]}"
else
  echo "SQLCipher distribution gate failed: cargo -V did not provide the required compiler identity" >&2
  exit 1
fi

if [[ "$REQUIRE_DISTRIBUTION_HOST" == "1" ]]; then
  if [[ "$RUSTC_HOST" != "$REVIEWED_DISTRIBUTION_HOST" ]]; then
    echo "SQLCipher distribution gate failed: release rustc host must be $REVIEWED_DISTRIBUTION_HOST, got $RUSTC_HOST" >&2
    exit 1
  fi
fi

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

source_tree_sha256() {
  local source_root="$1"
  local description="$2"
  local source_files
  local source_file
  local relative_path

  if [[ ! -d "$source_root" || -L "$source_root" ]]; then
    echo "SQLCipher distribution gate failed: $description source root must be a real directory" >&2
    return 1
  fi
  if find "$source_root" -type l -print -quit | grep -q .; then
    echo "SQLCipher distribution gate failed: $description source tree must not contain symbolic links" >&2
    return 1
  fi
  source_files="$(find "$source_root" -type f -print | LC_ALL=C sort)"
  if [[ -z "$source_files" ]]; then
    echo "SQLCipher distribution gate failed: $description source tree is empty" >&2
    return 1
  fi

  while IFS= read -r source_file; do
    relative_path="${source_file#$ROOT_DIR/}"
    printf '%s  %s\n' "$(sha256_file "$source_file")" "$relative_path"
  done <<<"$source_files" |
    shasum -a 256 |
    awk '{print $1}'
}

RUST_TOOLCHAIN_SHA256="$(sha256_file "$RUST_TOOLCHAIN_PATH")"
WORKSPACE_MANIFEST_SHA256="$(sha256_file "$WORKSPACE_MANIFEST_PATH")"
CARGO_LOCK_SHA256="$(sha256_file "$LOCK_PATH")"
RUST_WORKSPACE_SOURCE_TREE_SHA256="$(source_tree_sha256 "$RUST_WORKSPACE_SOURCE_DIR" "Rust workspace")"
BROKER_MANIFEST_SHA256="$(sha256_file "$BROKER_MANIFEST_PATH")"
BROKER_SOURCE_TREE_SHA256="$(source_tree_sha256 "$BROKER_SOURCE_DIR" "Broker")"
SQLCIPHER_FFI_SHA256="$(sha256_file "$SQLCIPHER_FFI_PATH")"
STATE_STORE_SHA256="$(sha256_file "$STATE_STORE_PATH")"
STATE_SCHEMA_SHA256="$(sha256_file "$STATE_SCHEMA_PATH")"
INTEGRATION_TESTS_SHA256="$(sha256_file "$INTEGRATION_TESTS_PATH")"
PACKAGE_SCRIPT_SHA256="$(sha256_file "$PACKAGE_SCRIPT_PATH")"
ARTIFACT_VERIFIER_SHA256="$(sha256_file "$ARTIFACT_VERIFIER_PATH")"
GATE_SCRIPT_SHA256="$(sha256_file "$GATE_SCRIPT_PATH")"
TOOLCHAIN_LIBRARY_SHA256="$(sha256_file "$TOOLCHAIN_LIBRARY_PATH")"
DISTRIBUTION_CARGO_RUNNER_SHA256="$(sha256_file "$DISTRIBUTION_CARGO_RUNNER_PATH")"

python3 - \
  "$EVIDENCE_PATH" \
  "$LIBSQLITE3_SYS_VERSION" \
  "$BUNDLED_SQLCIPHER_VERSION" \
  "$RUST_TOOLCHAIN_SHA256" \
  "$RUSTC_RELEASE" \
  "$RUSTC_COMMIT_HASH" \
  "$RUSTC_HOST" \
  "$RUSTC_LLVM_VERSION" \
  "$KEPTNEAR_REVIEWED_RUSTC_BINARY_SHA256" \
  "$CARGO_RELEASE" \
  "$CARGO_COMMIT_HASH" \
  "$KEPTNEAR_REVIEWED_CARGO_BINARY_SHA256" \
  "$REVIEWED_DISTRIBUTION_HOST" \
  "$REVIEWED_RELEASE_TARGET" \
  "$KEPTNEAR_REVIEWED_APPLE_CLANG_VERSION" \
  "$KEPTNEAR_REVIEWED_APPLE_CLANG_SHA256" \
  "$KEPTNEAR_REVIEWED_APPLE_AR_SHA256" \
  "$KEPTNEAR_REVIEWED_APPLE_RANLIB_SHA256" \
  "$KEPTNEAR_REVIEWED_XCODEBUILD_SHA256" \
  "$KEPTNEAR_REVIEWED_XCODE_VERSION" \
  "$KEPTNEAR_REVIEWED_XCODE_BUILD_VERSION" \
  "$KEPTNEAR_REVIEWED_MACOS_SDK_VERSION" \
  "$KEPTNEAR_REVIEWED_MACOS_SDK_BUILD_VERSION" \
  "$KEPTNEAR_REVIEWED_MACOS_SDK_NAME" \
  "$KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET" \
  "$KEPTNEAR_REVIEWED_CFLAGS" \
  "$REQUIRE_DISTRIBUTION_HOST" \
  "$REQUESTED_RELEASE_TARGET" \
  "$WORKSPACE_MANIFEST_SHA256" \
  "$CARGO_LOCK_SHA256" \
  "$RUST_WORKSPACE_SOURCE_TREE_SHA256" \
  "$BROKER_MANIFEST_SHA256" \
  "$BROKER_SOURCE_TREE_SHA256" \
  "$SQLCIPHER_FFI_SHA256" \
  "$STATE_STORE_SHA256" \
  "$STATE_SCHEMA_SHA256" \
  "$INTEGRATION_TESTS_SHA256" \
  "$PACKAGE_SCRIPT_SHA256" \
  "$ARTIFACT_VERIFIER_SHA256" \
  "$GATE_SCRIPT_SHA256" \
  "$TOOLCHAIN_LIBRARY_SHA256" \
  "$DISTRIBUTION_CARGO_RUNNER_SHA256" \
  "$VERSION_POLICY" <<'PY'
import datetime
import json
import re
import sys

(
    evidence_path,
    libsqlite3_sys_version,
    bundled_sqlcipher_version,
    rust_toolchain_sha256,
    rustc_release,
    rustc_commit_hash,
    rustc_host,
    rustc_llvm_version,
    reviewed_rustc_binary_sha256,
    cargo_release,
    cargo_commit_hash,
    reviewed_cargo_binary_sha256,
    reviewed_distribution_host,
    reviewed_release_target,
    reviewed_apple_clang_version,
    reviewed_apple_clang_sha256,
    reviewed_apple_ar_sha256,
    reviewed_apple_ranlib_sha256,
    reviewed_xcodebuild_sha256,
    reviewed_xcode_version,
    reviewed_xcode_build_version,
    reviewed_macos_sdk_version,
    reviewed_macos_sdk_build_version,
    reviewed_macos_sdk_name,
    reviewed_macos_deployment_target,
    reviewed_cflags,
    require_distribution_host,
    requested_release_target,
    workspace_manifest_sha256,
    cargo_lock_sha256,
    rust_workspace_source_tree_sha256,
    broker_manifest_sha256,
    broker_source_tree_sha256,
    sqlcipher_ffi_sha256,
    state_store_sha256,
    state_schema_sha256,
    integration_tests_sha256,
    package_script_sha256,
    artifact_verifier_sha256,
    gate_script_sha256,
    toolchain_library_sha256,
    distribution_cargo_runner_sha256,
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
    "toolchain",
    "nativeToolchain",
    "source",
    "revalidation",
    "blocker",
}
if not isinstance(evidence, dict) or set(evidence) != expected_top_level:
    fail("distribution evidence has an unexpected top-level schema")
if evidence["schemaVersion"] != 2:
    fail("distribution evidence schemaVersion must be 2")

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

toolchain = evidence["toolchain"]
expected_toolchain = {
    "rustToolchainSha256": rust_toolchain_sha256,
    "rustcRelease": rustc_release,
    "rustcCommitHash": rustc_commit_hash,
    "rustcLlvmVersion": rustc_llvm_version,
    "rustcBinarySha256": reviewed_rustc_binary_sha256,
    "cargoRelease": cargo_release,
    "cargoCommitHash": cargo_commit_hash,
    "cargoBinarySha256": reviewed_cargo_binary_sha256,
    "distributionHost": reviewed_distribution_host,
    "releaseTarget": reviewed_release_target,
}
if not isinstance(toolchain, dict) or set(toolchain) != set(expected_toolchain):
    fail("distribution evidence toolchain object has an unexpected schema")
for field, expected_value in expected_toolchain.items():
    if toolchain[field] != expected_value:
        fail(f"distribution evidence {field} does not match the active reviewed toolchain")
if require_distribution_host == "1":
    if rustc_host != toolchain["distributionHost"]:
        fail("the active rustc host does not match the reviewed distribution host")
    if requested_release_target != toolchain["releaseTarget"]:
        fail("the requested release target does not match the reviewed release target")

native_toolchain = evidence["nativeToolchain"]
expected_native_toolchain = {
    "appleClangVersion": reviewed_apple_clang_version,
    "appleClangSha256": reviewed_apple_clang_sha256,
    "appleArSha256": reviewed_apple_ar_sha256,
    "appleRanlibSha256": reviewed_apple_ranlib_sha256,
    "xcodebuildSha256": reviewed_xcodebuild_sha256,
    "xcodeVersion": reviewed_xcode_version,
    "xcodeBuildVersion": reviewed_xcode_build_version,
    "macosSdkVersion": reviewed_macos_sdk_version,
    "macosSdkBuildVersion": reviewed_macos_sdk_build_version,
    "macosSdkName": reviewed_macos_sdk_name,
    "deploymentTarget": reviewed_macos_deployment_target,
    "cFlags": reviewed_cflags,
}
if (
    not isinstance(native_toolchain, dict)
    or set(native_toolchain) != set(expected_native_toolchain)
):
    fail("distribution evidence nativeToolchain object has an unexpected schema")
for field, expected_value in expected_native_toolchain.items():
    if native_toolchain[field] != expected_value:
        fail(f"distribution evidence {field} does not match the reviewed native toolchain")

source = evidence["source"]
expected_source = {
    "workspaceManifestSha256": workspace_manifest_sha256,
    "cargoLockSha256": cargo_lock_sha256,
    "rustWorkspaceSourceTreeSha256": rust_workspace_source_tree_sha256,
    "brokerManifestSha256": broker_manifest_sha256,
    "brokerSourceTreeSha256": broker_source_tree_sha256,
    "sqlcipherFfiSha256": sqlcipher_ffi_sha256,
    "stateStoreSha256": state_store_sha256,
    "stateSchemaSha256": state_schema_sha256,
    "brokerIntegrationTestsSha256": integration_tests_sha256,
    "packageScriptSha256": package_script_sha256,
    "artifactVerifierSha256": artifact_verifier_sha256,
    "distributionGateSha256": gate_script_sha256,
    "distributionToolchainSha256": toolchain_library_sha256,
    "distributionCargoRunnerSha256": distribution_cargo_runner_sha256,
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

reviewed_cargo = "script/run_reviewed_distribution_cargo.sh"
required_commands = {
    f"{reviewed_cargo} rustc --quiet --locked --target-dir target/sqlcipher-toolchain-probe --target aarch64-apple-darwin --release -p psw-core --lib -- -Vv",
    f"{reviewed_cargo} -V",
    f"{reviewed_cargo} test --locked -p psw-broker state_store::tests::",
    f"{reviewed_cargo} test --locked -p psw-broker integration_tests::ciphertext_corruption_blocks_runtime_without_replacing_state_or_key",
    f"{reviewed_cargo} test --locked -p psw-broker integration_tests::wrong_device_key_blocks_runtime_without_overwriting_either_side",
    f"{reviewed_cargo} test --locked -p psw-broker integration_tests::insecure_database_permissions_block_runtime_and_retain_authority",
    f"{reviewed_cargo} test --locked -p psw-broker integration_tests::missing_database_blocks_runtime_without_silent_reinitialization",
    f"{reviewed_cargo} test --locked -p psw-broker integration_tests::missing_device_key_blocks_runtime_without_generating_replacement",
    "script/verify_dependency_licenses.sh",
    f"{reviewed_cargo} clippy --workspace --all-targets --locked -- -D warnings",
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
