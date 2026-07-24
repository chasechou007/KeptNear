#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/swiftpm_local_env.sh"

cd "$ROOT_DIR"

"$ROOT_DIR/script/verify_public_source_tree.sh"
cargo fmt --all --check
cargo test --workspace
cargo build -p psw-ffi
"$ROOT_DIR/script/verify_dependency_licenses.sh"

if command -v swift >/dev/null 2>&1; then
  swiftpm_test --package-path "$ROOT_DIR/apps/macos"
  swiftpm_build --package-path "$ROOT_DIR/apps/macos"
fi
