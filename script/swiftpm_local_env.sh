#!/usr/bin/env bash

if [[ "${PSW_SWIFTPM_LOCAL_ENV_LOADED:-0}" == "1" ]]; then
  return 0
fi
PSW_SWIFTPM_LOCAL_ENV_LOADED=1

PSW_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PSW_SWIFTPM_CACHE_PATH="${PSW_SWIFTPM_CACHE_PATH:-$PSW_ROOT_DIR/.build/swiftpm-cache}"
PSW_SWIFTPM_CONFIG_PATH="${PSW_SWIFTPM_CONFIG_PATH:-$PSW_ROOT_DIR/.build/swiftpm-config}"
PSW_SWIFTPM_SECURITY_PATH="${PSW_SWIFTPM_SECURITY_PATH:-$PSW_ROOT_DIR/.build/swiftpm-security}"
PSW_SWIFTPM_SCRATCH_PATH="${PSW_SWIFTPM_SCRATCH_PATH:-$PSW_ROOT_DIR/.build/swiftpm-scratch}"
CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-$PSW_ROOT_DIR/.build/clang-module-cache}"
export CLANG_MODULE_CACHE_PATH

swiftpm_prepare_local_state() {
  mkdir -p "$PSW_SWIFTPM_CACHE_PATH" \
    "$PSW_SWIFTPM_CONFIG_PATH" \
    "$PSW_SWIFTPM_SECURITY_PATH" \
    "$PSW_SWIFTPM_SCRATCH_PATH" \
    "$CLANG_MODULE_CACHE_PATH"
}

swiftpm_common_args=(
  --cache-path "$PSW_SWIFTPM_CACHE_PATH"
  --config-path "$PSW_SWIFTPM_CONFIG_PATH"
  --security-path "$PSW_SWIFTPM_SECURITY_PATH"
  --scratch-path "$PSW_SWIFTPM_SCRATCH_PATH"
  --manifest-cache local
  --disable-sandbox
)

swiftpm_build() {
  swiftpm_prepare_local_state
  swift build "${swiftpm_common_args[@]}" "$@"
}

swiftpm_test() {
  swiftpm_prepare_local_state
  swift test "${swiftpm_common_args[@]}" "$@"
}

swiftpm_bin_path() {
  swiftpm_prepare_local_state
  swift build "${swiftpm_common_args[@]}" "$@" --show-bin-path | tail -n 1
}
