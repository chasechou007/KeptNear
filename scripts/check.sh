#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/swiftpm_local_env.sh"

cd "$ROOT_DIR"

"$ROOT_DIR/script/verify_public_source_tree.sh"
"$ROOT_DIR/script/verify_repository_secrets.sh"
"$ROOT_DIR/script/verify_privacy_boundary_docs.sh"
"$ROOT_DIR/script/verify_compatibility_disclosures.sh"
"$ROOT_DIR/script/verify_mcp_setup_docs.sh"
"$ROOT_DIR/script/verify_cli_usage_docs.sh"
"$ROOT_DIR/script/verify_release_profile_contract.sh"
"$ROOT_DIR/script/verify_public_capability_claims.sh"
"$ROOT_DIR/script/verify_public_documentation_set.sh"
"$ROOT_DIR/script/verify_cross_adapter_secret_markers.sh"
cargo fmt --all --check
cargo test --workspace
cargo build -p psw-ffi
"$ROOT_DIR/script/verify_dependency_licenses.sh"

if command -v swift >/dev/null 2>&1; then
  swiftpm_test --package-path "$ROOT_DIR/apps/macos"
  swiftpm_build --package-path "$ROOT_DIR/apps/macos"
fi
