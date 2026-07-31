#!/usr/bin/env bash

KEPTNEAR_REVIEWED_DISTRIBUTION_HOST="aarch64-apple-darwin"
KEPTNEAR_REVIEWED_RELEASE_TARGET="aarch64-apple-darwin"
KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET="13.0"

KEPTNEAR_REVIEWED_RUSTC_BINARY_SHA256="2e5d8100af1c46dc9b9f2f8b644f085b7c099dce9f4237ecf304adc3e110c294"
KEPTNEAR_REVIEWED_CARGO_BINARY_SHA256="d92fdab3cc38e1952e00b04d6cf4c725a08fc8519399a3ba76b93932e4985803"
KEPTNEAR_REVIEWED_APPLE_CLANG_VERSION="Apple clang version 21.0.0 (clang-2100.1.1.101)"
KEPTNEAR_REVIEWED_APPLE_CLANG_SHA256="7def90dd8829726686213a747fc5bff1583df933dae5edc55d755479e0bfe00a"
KEPTNEAR_REVIEWED_APPLE_AR_SHA256="e49ffad64ad1cee722540fc5ecb00a230fd8071680682c60d9c851029d20e814"
KEPTNEAR_REVIEWED_APPLE_RANLIB_SHA256="229eb9d8027953d2aee0590f983eed587d52bdd1ebc21114a62ce693f77b03f1"
KEPTNEAR_REVIEWED_XCODEBUILD_SHA256="d508f0e1901151843804e4af512d4587ad0e422039e43e14abf22792360ad3d4"
KEPTNEAR_REVIEWED_XCODE_VERSION="26.6"
KEPTNEAR_REVIEWED_XCODE_BUILD_VERSION="17F113"
KEPTNEAR_REVIEWED_MACOS_SDK_VERSION="26.5"
KEPTNEAR_REVIEWED_MACOS_SDK_BUILD_VERSION="25F70"
KEPTNEAR_REVIEWED_MACOS_SDK_NAME="MacOSX26.5.sdk"
KEPTNEAR_REVIEWED_CFLAGS="-arch arm64 -mmacosx-version-min=13.0 -isysroot <reviewed-macos-sdk>"

keptnear_toolchain_fail() {
  echo "KeptNear distribution toolchain failed: $1" >&2
  return 1
}

keptnear_toolchain_require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    keptnear_toolchain_fail "missing required command $command_name"
    return 1
  fi
}

keptnear_toolchain_require_regular_executable() {
  local path="$1"
  local description="$2"
  local resolved_path

  keptnear_toolchain_require_command realpath || return 1
  if [[ "$path" != /* || ! -f "$path" || ! -x "$path" ]]; then
    keptnear_toolchain_fail "$description must be an absolute regular executable"
    return 1
  fi
  resolved_path="$(realpath "$path" 2>/dev/null)" ||
    {
      keptnear_toolchain_fail "$description could not be resolved"
      return 1
    }
  if [[ "$resolved_path" != /* || ! -f "$resolved_path" || -L "$resolved_path" || ! -x "$resolved_path" ]]; then
    keptnear_toolchain_fail "$description must resolve to an absolute regular executable"
    return 1
  fi
}

keptnear_toolchain_sha256() {
  shasum -a 256 "$1" | awk '{print $1}'
}

keptnear_distribution_override_names() {
  local variable_base

  printf '%s\n' \
    RUSTC \
    CARGO_BUILD_RUSTC \
    RUSTC_WRAPPER \
    RUSTC_WORKSPACE_WRAPPER \
    CARGO_BUILD_RUSTC_WRAPPER \
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER \
    RUSTFLAGS \
    CARGO_ENCODED_RUSTFLAGS \
    CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS \
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER \
    RUSTC_BOOTSTRAP \
    RUSTUP_TOOLCHAIN \
    SDKROOT \
    DEVELOPER_DIR \
    MACOSX_DEPLOYMENT_TARGET \
    CPATH \
    C_INCLUDE_PATH \
    CPLUS_INCLUDE_PATH \
    OBJC_INCLUDE_PATH \
    LIBRARY_PATH \
    COMPILER_PATH \
    DYLD_LIBRARY_PATH \
    DYLD_FALLBACK_LIBRARY_PATH \
    DYLD_INSERT_LIBRARIES \
    CRATE_CC_NO_DEFAULTS \
    CC_ENABLE_DEBUG_OUTPUT \
    CC_SHELL_ESCAPED_FLAGS \
    CC_FORCE_DISABLE \
    CC_KNOWN_WRAPPER_CUSTOM \
    LIBSQLITE3_SYS_USE_PKG_CONFIG \
    LIBSQLITE3_SYS_BUNDLING \
    LIBSQLITE3_FLAGS \
    SQLITE_MAX_VARIABLE_NUMBER \
    SQLITE_MAX_EXPR_DEPTH \
    SQLITE3_LIB_DIR \
    SQLITE3_INCLUDE_DIR \
    SQLITE3_STATIC \
    SQLCIPHER_LIB_DIR \
    SQLCIPHER_INCLUDE_DIR \
    SQLCIPHER_STATIC \
    OPENSSL_DIR \
    OPENSSL_LIB_DIR \
    OPENSSL_INCLUDE_DIR \
    OPENSSL_STATIC \
    OPENSSL_LIBS \
    OPENSSL_NO_VENDOR \
    OPENSSL_CONFIG_DIR

  for variable_base in \
    CC \
    CFLAGS \
    CPPFLAGS \
    CXX \
    CXXFLAGS \
    AR \
    ARFLAGS \
    RANLIB \
    RANLIBFLAGS \
    LDFLAGS; do
    printf '%s\n' \
      "$variable_base" \
      "${variable_base}_aarch64-apple-darwin" \
      "${variable_base}_aarch64_apple_darwin" \
      "TARGET_${variable_base}" \
      "HOST_${variable_base}"
  done
}

keptnear_resolve_active_rust_toolchain() {
  local cargo_home_candidate

  keptnear_toolchain_require_command rustup || return 1
  keptnear_toolchain_require_command shasum || return 1

  KEPTNEAR_ACTIVE_RUSTC_PATH="$(
    env -u RUSTUP_TOOLCHAIN rustup which rustc 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "rustup could not resolve rustc"
      return 1
    }
  KEPTNEAR_ACTIVE_CARGO_PATH="$(
    env -u RUSTUP_TOOLCHAIN rustup which cargo 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "rustup could not resolve cargo"
      return 1
    }
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_RUSTC_PATH" \
    "resolved rustc" || return 1
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_CARGO_PATH" \
    "resolved cargo" || return 1

  KEPTNEAR_ACTIVE_RUSTC_BINARY_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_RUSTC_PATH"
  )"
  KEPTNEAR_ACTIVE_CARGO_BINARY_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_CARGO_PATH"
  )"

  cargo_home_candidate="${KEPTNEAR_ACTIVE_CARGO_PATH%%/toolchains/*}"
  if [[ \
    "$cargo_home_candidate" == "$KEPTNEAR_ACTIVE_CARGO_PATH" || \
    ! -d "$cargo_home_candidate/registry" \
  ]]; then
    cargo_home_candidate="$HOME/.cargo"
  fi
  if [[ "$cargo_home_candidate" != /* || ! -d "$cargo_home_candidate" ]]; then
    keptnear_toolchain_fail "could not resolve an absolute Cargo home"
    return 1
  fi
  KEPTNEAR_ACTIVE_CARGO_HOME="$(cd "$cargo_home_candidate" && pwd -P)"
}

keptnear_resolve_active_apple_toolchain() {
  local reported_sdk_path
  local xcode_version_output

  keptnear_toolchain_require_command xcrun || return 1
  keptnear_toolchain_require_command xcode-select || return 1

  KEPTNEAR_ACTIVE_DEVELOPER_DIR="$(xcode-select -p 2>/dev/null)" ||
    {
      keptnear_toolchain_fail "xcode-select could not resolve the active developer directory"
      return 1
    }
  if [[ \
    "$KEPTNEAR_ACTIVE_DEVELOPER_DIR" != /* || \
    ! -d "$KEPTNEAR_ACTIVE_DEVELOPER_DIR" || \
    -L "$KEPTNEAR_ACTIVE_DEVELOPER_DIR" \
  ]]; then
    keptnear_toolchain_fail "active Xcode developer directory must be an absolute real directory"
    return 1
  fi

  KEPTNEAR_ACTIVE_CLANG_PATH="$(
    env -u DEVELOPER_DIR -u SDKROOT xcrun --sdk macosx --find clang 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve Apple Clang"
      return 1
    }
  KEPTNEAR_ACTIVE_AR_PATH="$(
    env -u DEVELOPER_DIR -u SDKROOT xcrun --sdk macosx --find ar 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve Apple ar"
      return 1
    }
  KEPTNEAR_ACTIVE_RANLIB_PATH="$(
    env -u DEVELOPER_DIR -u SDKROOT xcrun --sdk macosx --find ranlib 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve Apple ranlib"
      return 1
    }
  KEPTNEAR_ACTIVE_XCODEBUILD_PATH="$(
    env -u DEVELOPER_DIR -u SDKROOT xcrun --find xcodebuild 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve xcodebuild"
      return 1
    }
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_CLANG_PATH" \
    "resolved Apple Clang" || return 1
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_AR_PATH" \
    "resolved Apple ar" || return 1
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_RANLIB_PATH" \
    "resolved Apple ranlib" || return 1
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_XCODEBUILD_PATH" \
    "resolved xcodebuild" || return 1

  reported_sdk_path="$(
    env -u DEVELOPER_DIR -u SDKROOT xcrun --sdk macosx --show-sdk-path 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve the macOS SDK"
      return 1
    }
  if [[ "$reported_sdk_path" != /* || ! -d "$reported_sdk_path" ]]; then
    keptnear_toolchain_fail "resolved macOS SDK must be an absolute directory"
    return 1
  fi
  KEPTNEAR_ACTIVE_MACOS_SDK_NAME="$(basename "$reported_sdk_path")"
  KEPTNEAR_ACTIVE_MACOS_SDK_PATH="$(cd "$reported_sdk_path" && pwd -P)"

  KEPTNEAR_ACTIVE_APPLE_CLANG_VERSION="$(
    "$KEPTNEAR_ACTIVE_CLANG_PATH" --version | awk 'NR == 1 { print; exit }'
  )"
  KEPTNEAR_ACTIVE_APPLE_CLANG_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_CLANG_PATH"
  )"
  KEPTNEAR_ACTIVE_APPLE_AR_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_AR_PATH"
  )"
  KEPTNEAR_ACTIVE_APPLE_RANLIB_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_RANLIB_PATH"
  )"
  KEPTNEAR_ACTIVE_XCODEBUILD_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_XCODEBUILD_PATH"
  )"
  KEPTNEAR_ACTIVE_MACOS_SDK_VERSION="$(
    env -u DEVELOPER_DIR -u SDKROOT \
      xcrun --sdk macosx --show-sdk-version 2>/dev/null
  )"
  KEPTNEAR_ACTIVE_MACOS_SDK_BUILD_VERSION="$(
    env -u DEVELOPER_DIR -u SDKROOT \
      xcrun --sdk macosx --show-sdk-build-version 2>/dev/null
  )"

  xcode_version_output="$(
    env -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_ACTIVE_XCODEBUILD_PATH" -version
  )"
  KEPTNEAR_ACTIVE_XCODE_VERSION="$(
    printf '%s\n' "$xcode_version_output" |
      awk '$1 == "Xcode" { print $2; exit }'
  )"
  KEPTNEAR_ACTIVE_XCODE_BUILD_VERSION="$(
    printf '%s\n' "$xcode_version_output" |
      awk '$1 == "Build" && $2 == "version" { print $3; exit }'
  )"
}

keptnear_assert_reviewed_distribution_toolchain() {
  local release_target="$1"
  local deployment_target="$2"
  local host_architecture

  if [[ "$release_target" != "$KEPTNEAR_REVIEWED_RELEASE_TARGET" ]]; then
    keptnear_toolchain_fail \
      "release target must be $KEPTNEAR_REVIEWED_RELEASE_TARGET, got $release_target"
    return 1
  fi
  if [[ "$deployment_target" != "$KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET" ]]; then
    keptnear_toolchain_fail \
      "deployment target must be $KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET, got $deployment_target"
    return 1
  fi

  host_architecture="$(uname -m)"
  if [[ "$host_architecture" != "arm64" ]]; then
    keptnear_toolchain_fail "distribution host architecture must be arm64, got $host_architecture"
    return 1
  fi

  keptnear_resolve_active_rust_toolchain || return 1
  keptnear_resolve_active_apple_toolchain || return 1

  if [[ "$KEPTNEAR_ACTIVE_RUSTC_BINARY_SHA256" != "$KEPTNEAR_REVIEWED_RUSTC_BINARY_SHA256" ]]; then
    keptnear_toolchain_fail "rustc binary does not match the reviewed distribution compiler"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_CARGO_BINARY_SHA256" != "$KEPTNEAR_REVIEWED_CARGO_BINARY_SHA256" ]]; then
    keptnear_toolchain_fail "Cargo binary does not match the reviewed distribution tool"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_APPLE_CLANG_VERSION" != "$KEPTNEAR_REVIEWED_APPLE_CLANG_VERSION" ]]; then
    keptnear_toolchain_fail "Apple Clang version does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_APPLE_CLANG_SHA256" != "$KEPTNEAR_REVIEWED_APPLE_CLANG_SHA256" ]]; then
    keptnear_toolchain_fail "Apple Clang binary does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_APPLE_AR_SHA256" != "$KEPTNEAR_REVIEWED_APPLE_AR_SHA256" ]]; then
    keptnear_toolchain_fail "Apple ar binary does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_APPLE_RANLIB_SHA256" != "$KEPTNEAR_REVIEWED_APPLE_RANLIB_SHA256" ]]; then
    keptnear_toolchain_fail "Apple ranlib binary does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_XCODEBUILD_SHA256" != "$KEPTNEAR_REVIEWED_XCODEBUILD_SHA256" ]]; then
    keptnear_toolchain_fail "xcodebuild binary does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_XCODE_VERSION" != "$KEPTNEAR_REVIEWED_XCODE_VERSION" ]]; then
    keptnear_toolchain_fail "Xcode version does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_XCODE_BUILD_VERSION" != "$KEPTNEAR_REVIEWED_XCODE_BUILD_VERSION" ]]; then
    keptnear_toolchain_fail "Xcode build does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_MACOS_SDK_VERSION" != "$KEPTNEAR_REVIEWED_MACOS_SDK_VERSION" ]]; then
    keptnear_toolchain_fail "macOS SDK version does not match the reviewed native toolchain"
    return 1
  fi
  if [[ \
    "$KEPTNEAR_ACTIVE_MACOS_SDK_BUILD_VERSION" != \
    "$KEPTNEAR_REVIEWED_MACOS_SDK_BUILD_VERSION" \
  ]]; then
    keptnear_toolchain_fail "macOS SDK build does not match the reviewed native toolchain"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_MACOS_SDK_NAME" != "$KEPTNEAR_REVIEWED_MACOS_SDK_NAME" ]]; then
    keptnear_toolchain_fail "macOS SDK name does not match the reviewed native toolchain"
    return 1
  fi

  KEPTNEAR_ACTIVE_CFLAGS="-arch arm64 -mmacosx-version-min=$deployment_target -isysroot $KEPTNEAR_ACTIVE_MACOS_SDK_PATH"
}

keptnear_run_current_rust_cargo() {
  if [[ -z "${KEPTNEAR_ACTIVE_RUSTC_PATH:-}" || -z "${KEPTNEAR_ACTIVE_CARGO_PATH:-}" ]]; then
    keptnear_resolve_active_rust_toolchain || return 1
  fi

  env \
    RUSTC="$KEPTNEAR_ACTIVE_RUSTC_PATH" \
    CARGO_BUILD_RUSTC="$KEPTNEAR_ACTIVE_RUSTC_PATH" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    CARGO_BUILD_RUSTC_WRAPPER= \
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER= \
    CARGO_HOME="$KEPTNEAR_ACTIVE_CARGO_HOME" \
    "$KEPTNEAR_ACTIVE_CARGO_PATH" "$@"
}

keptnear_run_reviewed_distribution_cargo() {
  local variable_name
  local -a environment_command

  if [[ \
    -z "${KEPTNEAR_ACTIVE_RUSTC_PATH:-}" || \
    -z "${KEPTNEAR_ACTIVE_CARGO_PATH:-}" || \
    -z "${KEPTNEAR_ACTIVE_CLANG_PATH:-}" || \
    -z "${KEPTNEAR_ACTIVE_MACOS_SDK_PATH:-}" \
  ]]; then
    keptnear_toolchain_fail "reviewed distribution toolchain is not initialized"
    return 1
  fi

  environment_command=(env)
  while IFS= read -r variable_name; do
    environment_command+=(-u "$variable_name")
  done < <(keptnear_distribution_override_names)
  environment_command+=(
    "RUSTC=$KEPTNEAR_ACTIVE_RUSTC_PATH"
    "CARGO_BUILD_RUSTC=$KEPTNEAR_ACTIVE_RUSTC_PATH"
    "RUSTC_WRAPPER="
    "RUSTC_WORKSPACE_WRAPPER="
    "CARGO_BUILD_RUSTC_WRAPPER="
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="
    "RUSTFLAGS="
    "CARGO_ENCODED_RUSTFLAGS="
    "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="
    "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=$KEPTNEAR_ACTIVE_CLANG_PATH"
    "CC=$KEPTNEAR_ACTIVE_CLANG_PATH"
    "CFLAGS=$KEPTNEAR_ACTIVE_CFLAGS"
    "AR=$KEPTNEAR_ACTIVE_AR_PATH"
    "ARFLAGS="
    "RANLIB=$KEPTNEAR_ACTIVE_RANLIB_PATH"
    "RANLIBFLAGS="
    "SDKROOT=$KEPTNEAR_ACTIVE_MACOS_SDK_PATH"
    "DEVELOPER_DIR=$KEPTNEAR_ACTIVE_DEVELOPER_DIR"
    "MACOSX_DEPLOYMENT_TARGET=$KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET"
    "CARGO_HOME=$KEPTNEAR_ACTIVE_CARGO_HOME"
  )

  "${environment_command[@]}" "$KEPTNEAR_ACTIVE_CARGO_PATH" "$@"
}
