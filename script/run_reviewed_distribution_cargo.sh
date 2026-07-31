#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/reviewed_distribution_toolchain.sh"

usage() {
  cat <<'USAGE'
usage: script/run_reviewed_distribution_cargo.sh CARGO_ARGS...

Runs Cargo with the source-bound Apple Silicon Rust and native toolchains.
Environment overrides, Rust compiler wrappers, custom compiler flags, and
SQLCipher build-script overrides are ignored and replaced.
USAGE
}

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 2
fi
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

cd "$ROOT_DIR"
keptnear_assert_reviewed_distribution_toolchain \
  "$KEPTNEAR_REVIEWED_RELEASE_TARGET" \
  "$KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET"
keptnear_run_reviewed_distribution_cargo "$@"
