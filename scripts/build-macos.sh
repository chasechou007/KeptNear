#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/swiftpm_local_env.sh"

cd "$ROOT_DIR"

cargo build -p psw-ffi
swiftpm_build --package-path "$ROOT_DIR/apps/macos"
