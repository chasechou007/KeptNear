#!/bin/bash
set -euo pipefail

PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

ROOT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
source "$ROOT_DIR/script/reviewed_distribution_toolchain.sh"

usage() {
  cat <<'USAGE'
usage: script/run_reviewed_distribution_cargo.sh CARGO_ARGS...

Runs Cargo with the source-bound Apple Silicon Rust and native toolchains.
Environment overrides, Rust compiler wrappers, custom compiler flags, and
SQLCipher build-script overrides are ignored and replaced. Cargo runs from an
isolated HOME and CARGO_HOME with only the source-bound offline registry config.
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
