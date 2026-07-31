#!/bin/bash

KEPTNEAR_REVIEWED_DISTRIBUTION_HOST="aarch64-apple-darwin"
KEPTNEAR_REVIEWED_RELEASE_TARGET="aarch64-apple-darwin"
KEPTNEAR_REVIEWED_MACOS_DEPLOYMENT_TARGET="13.0"

KEPTNEAR_REVIEWED_RUSTC_BINARY_SHA256="87b02c67012c28083fe485a50b10470a662c828c6e2cd0caf4775e00986cdfc8"
KEPTNEAR_REVIEWED_CARGO_BINARY_SHA256="46c9483604e913070b085dc5acf972bc560395c10dfec1cdb389c4b6bf17cf67"
KEPTNEAR_REVIEWED_CARGO_CLIPPY_BINARY_SHA256="241eb0971b2528d92808a67093453f216fe6b37a7ebbc4831f716160e38b1a10"
KEPTNEAR_REVIEWED_CLIPPY_DRIVER_BINARY_SHA256="4df55b5c3323d628a070bace0069a756c17d9a30afd4943e7a050c63e019fa03"
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
KEPTNEAR_REVIEWED_CRATES_IO_PROTOCOL="sparse"
KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY="index.crates.io-1949cf8c6b5b557f"

KEPTNEAR_SYSTEM_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
KEPTNEAR_RUSTUP_RESOLUTION_PATH="/opt/homebrew/bin:/usr/local/bin:$KEPTNEAR_SYSTEM_PATH"
KEPTNEAR_SYSTEM_ENV="/usr/bin/env"
KEPTNEAR_SYSTEM_AWK="/usr/bin/awk"
KEPTNEAR_SYSTEM_BASENAME="/usr/bin/basename"
KEPTNEAR_SYSTEM_DSCACHEUTIL="/usr/bin/dscacheutil"
KEPTNEAR_SYSTEM_ID="/usr/bin/id"
KEPTNEAR_SYSTEM_MKTEMP="/usr/bin/mktemp"
KEPTNEAR_SYSTEM_PRINTF="/usr/bin/printf"
KEPTNEAR_SYSTEM_SHASUM="/usr/bin/shasum"
KEPTNEAR_SYSTEM_UNAME="/usr/bin/uname"
KEPTNEAR_SYSTEM_XCODE_SELECT="/usr/bin/xcode-select"
KEPTNEAR_SYSTEM_XCRUN="/usr/bin/xcrun"
KEPTNEAR_SYSTEM_CHMOD="/bin/chmod"
KEPTNEAR_SYSTEM_LN="/bin/ln"
KEPTNEAR_SYSTEM_MKDIR="/bin/mkdir"
KEPTNEAR_SYSTEM_REALPATH="/bin/realpath"
KEPTNEAR_SYSTEM_RM="/bin/rm"

keptnear_toolchain_fail() {
  echo "KeptNear distribution toolchain failed: $1" >&2
  return 1
}

keptnear_toolchain_require_regular_executable() {
  local path="$1"
  local description="$2"
  local resolved_path

  if [[ "$path" != /* || ! -f "$path" || ! -x "$path" ]]; then
    keptnear_toolchain_fail "$description must be an absolute regular executable"
    return 1
  fi
  resolved_path="$("$KEPTNEAR_SYSTEM_REALPATH" "$path" 2>/dev/null)" ||
    {
      keptnear_toolchain_fail "$description could not be resolved"
      return 1
    }
  if [[ "$resolved_path" != /* || ! -f "$resolved_path" || -L "$resolved_path" || ! -x "$resolved_path" ]]; then
    keptnear_toolchain_fail "$description must resolve to an absolute regular executable"
    return 1
  fi
}

keptnear_run_clean_shasum() {
  "$KEPTNEAR_SYSTEM_ENV" \
    -i \
    "PATH=$KEPTNEAR_SYSTEM_PATH" \
    LANG=C \
    LC_ALL=C \
    "$KEPTNEAR_SYSTEM_SHASUM" "$@"
}

keptnear_sha256_file() {
  keptnear_run_clean_shasum -a 256 "$1" |
    "$KEPTNEAR_SYSTEM_AWK" '{print $1}'
}

keptnear_toolchain_sha256() {
  keptnear_sha256_file "$1"
}

keptnear_assert_fixed_identity_utilities() {
  local utility_path

  for utility_path in \
    "$KEPTNEAR_SYSTEM_ENV" \
    "$KEPTNEAR_SYSTEM_AWK" \
    "$KEPTNEAR_SYSTEM_BASENAME" \
    "$KEPTNEAR_SYSTEM_DSCACHEUTIL" \
    "$KEPTNEAR_SYSTEM_ID" \
    "$KEPTNEAR_SYSTEM_MKTEMP" \
    "$KEPTNEAR_SYSTEM_PRINTF" \
    "$KEPTNEAR_SYSTEM_SHASUM" \
    "$KEPTNEAR_SYSTEM_UNAME" \
    "$KEPTNEAR_SYSTEM_XCODE_SELECT" \
    "$KEPTNEAR_SYSTEM_XCRUN" \
    "$KEPTNEAR_SYSTEM_CHMOD" \
    "$KEPTNEAR_SYSTEM_LN" \
    "$KEPTNEAR_SYSTEM_MKDIR" \
    "$KEPTNEAR_SYSTEM_REALPATH" \
    "$KEPTNEAR_SYSTEM_RM"; do
    keptnear_toolchain_require_regular_executable \
      "$utility_path" \
      "fixed system utility" || return 1
  done
}

keptnear_resolve_current_user_home() {
  local directory_record
  local user_name

  user_name="$("$KEPTNEAR_SYSTEM_ID" -un 2>/dev/null)" ||
    {
      keptnear_toolchain_fail "could not resolve the current user"
      return 1
    }
  directory_record="$(
    "$KEPTNEAR_SYSTEM_DSCACHEUTIL" \
      -q user \
      -a name "$user_name" 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "could not resolve the current user's home directory"
      return 1
    }
  KEPTNEAR_CURRENT_USER_HOME="$(
    printf '%s\n' "$directory_record" |
      "$KEPTNEAR_SYSTEM_AWK" \
        '$1 == "dir:" { print $2; exit }'
  )"
  if [[ \
    "$KEPTNEAR_CURRENT_USER_HOME" != /* || \
    ! -d "$KEPTNEAR_CURRENT_USER_HOME" || \
    -L "$KEPTNEAR_CURRENT_USER_HOME" \
  ]]; then
    keptnear_toolchain_fail "current user home must be an absolute real directory"
    return 1
  fi
  KEPTNEAR_CURRENT_USER_HOME="$(
    cd "$KEPTNEAR_CURRENT_USER_HOME" && /bin/pwd -P
  )"
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
    RUSTUP_HOME \
    HOME \
    CARGO_HOME \
    CARGO_TARGET_DIR \
    CARGO_BUILD_TARGET \
    CARGO_BUILD_JOBS \
    CARGO_NET_OFFLINE \
    CARGO_NET_GIT_FETCH_WITH_CLI \
    PERL5OPT \
    PERL5LIB \
    PERLLIB \
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
    SQLITE_MAX_COLUMN \
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
    OPENSSL_CONFIG_DIR \
    PKG_CONFIG_PATH \
    PKG_CONFIG_LIBDIR \
    PKG_CONFIG_SYSROOT_DIR \
    PKG_CONFIG_ALLOW_CROSS \
    PKG_CONFIG_ALL_STATIC \
    PKG_CONFIG_ALL_DYNAMIC \
    VCPKGRS_DYNAMIC

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
  local rustup_candidate
  local rustup_path

  keptnear_assert_fixed_identity_utilities || return 1
  keptnear_resolve_current_user_home || return 1
  rustup_path=""
  for rustup_candidate in \
    "$KEPTNEAR_CURRENT_USER_HOME/.asdf/shims/rustup" \
    "$KEPTNEAR_CURRENT_USER_HOME/.cargo/bin/rustup" \
    /opt/homebrew/bin/rustup \
    /usr/local/bin/rustup; do
    if [[ -f "$rustup_candidate" && -x "$rustup_candidate" ]]; then
      rustup_path="$rustup_candidate"
      break
    fi
  done
  if [[ -z "$rustup_path" ]]; then
    keptnear_toolchain_fail "could not resolve rustup from an approved location"
    return 1
  fi
  keptnear_toolchain_require_regular_executable \
    "$rustup_path" \
    "resolved rustup" || return 1

  KEPTNEAR_ACTIVE_RUSTC_PATH="$(
    "$KEPTNEAR_SYSTEM_ENV" \
      -u RUSTUP_TOOLCHAIN \
      -u ASDF_CONFIG_FILE \
      -u ASDF_DATA_DIR \
      "HOME=$KEPTNEAR_CURRENT_USER_HOME" \
      "PATH=$KEPTNEAR_RUSTUP_RESOLUTION_PATH" \
      "$rustup_path" which rustc 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "rustup could not resolve rustc"
      return 1
    }
  KEPTNEAR_ACTIVE_CARGO_PATH="$(
    "$KEPTNEAR_SYSTEM_ENV" \
      -u RUSTUP_TOOLCHAIN \
      -u ASDF_CONFIG_FILE \
      -u ASDF_DATA_DIR \
      "HOME=$KEPTNEAR_CURRENT_USER_HOME" \
      "PATH=$KEPTNEAR_RUSTUP_RESOLUTION_PATH" \
      "$rustup_path" which cargo 2>/dev/null
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
  KEPTNEAR_ACTIVE_CARGO_CLIPPY_PATH="${KEPTNEAR_ACTIVE_CARGO_PATH%/*}/cargo-clippy"
  KEPTNEAR_ACTIVE_CLIPPY_DRIVER_PATH="${KEPTNEAR_ACTIVE_CARGO_PATH%/*}/clippy-driver"
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_CARGO_CLIPPY_PATH" \
    "resolved cargo-clippy" || return 1
  keptnear_toolchain_require_regular_executable \
    "$KEPTNEAR_ACTIVE_CLIPPY_DRIVER_PATH" \
    "resolved clippy-driver" || return 1

  KEPTNEAR_ACTIVE_RUSTC_BINARY_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_RUSTC_PATH"
  )"
  KEPTNEAR_ACTIVE_CARGO_BINARY_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_CARGO_PATH"
  )"
  KEPTNEAR_ACTIVE_CARGO_CLIPPY_BINARY_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_CARGO_CLIPPY_PATH"
  )"
  KEPTNEAR_ACTIVE_CLIPPY_DRIVER_BINARY_SHA256="$(
    keptnear_toolchain_sha256 "$KEPTNEAR_ACTIVE_CLIPPY_DRIVER_PATH"
  )"

  cargo_home_candidate="${KEPTNEAR_ACTIVE_CARGO_PATH%%/toolchains/*}"
  if [[ \
    "$cargo_home_candidate" == "$KEPTNEAR_ACTIVE_CARGO_PATH" || \
    ! -d "$cargo_home_candidate/registry/cache/$KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY" || \
    ! -d "$cargo_home_candidate/registry/index/$KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY" \
  ]]; then
    cargo_home_candidate="$KEPTNEAR_CURRENT_USER_HOME/.cargo"
  fi
  if [[ \
    "$cargo_home_candidate" != /* || \
    ! -d "$cargo_home_candidate" || \
    -L "$cargo_home_candidate" || \
    ! -d "$cargo_home_candidate/registry/cache/$KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY" || \
    ! -d "$cargo_home_candidate/registry/index/$KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY" \
  ]]; then
    keptnear_toolchain_fail "could not resolve the reviewed crates.io Cargo cache"
    return 1
  fi
  KEPTNEAR_ACTIVE_CARGO_CACHE_HOME="$(cd "$cargo_home_candidate" && /bin/pwd -P)"
}

keptnear_resolve_active_apple_toolchain() {
  local reported_sdk_path
  local xcode_version_output

  keptnear_assert_fixed_identity_utilities || return 1

  KEPTNEAR_ACTIVE_DEVELOPER_DIR="$("$KEPTNEAR_SYSTEM_XCODE_SELECT" -p 2>/dev/null)" ||
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
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_SYSTEM_XCRUN" --sdk macosx --find clang 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve Apple Clang"
      return 1
    }
  KEPTNEAR_ACTIVE_AR_PATH="$(
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_SYSTEM_XCRUN" --sdk macosx --find ar 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve Apple ar"
      return 1
    }
  KEPTNEAR_ACTIVE_RANLIB_PATH="$(
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_SYSTEM_XCRUN" --sdk macosx --find ranlib 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve Apple ranlib"
      return 1
    }
  KEPTNEAR_ACTIVE_XCODEBUILD_PATH="$(
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_SYSTEM_XCRUN" --find xcodebuild 2>/dev/null
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
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_SYSTEM_XCRUN" --sdk macosx --show-sdk-path 2>/dev/null
  )" ||
    {
      keptnear_toolchain_fail "xcrun could not resolve the macOS SDK"
      return 1
    }
  if [[ "$reported_sdk_path" != /* || ! -d "$reported_sdk_path" ]]; then
    keptnear_toolchain_fail "resolved macOS SDK must be an absolute directory"
    return 1
  fi
  KEPTNEAR_ACTIVE_MACOS_SDK_NAME="$("$KEPTNEAR_SYSTEM_BASENAME" "$reported_sdk_path")"
  KEPTNEAR_ACTIVE_MACOS_SDK_PATH="$(cd "$reported_sdk_path" && /bin/pwd -P)"

  KEPTNEAR_ACTIVE_APPLE_CLANG_VERSION="$(
    "$KEPTNEAR_ACTIVE_CLANG_PATH" --version |
      "$KEPTNEAR_SYSTEM_AWK" 'NR == 1 { print; exit }'
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
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_SYSTEM_XCRUN" --sdk macosx --show-sdk-version 2>/dev/null
  )"
  KEPTNEAR_ACTIVE_MACOS_SDK_BUILD_VERSION="$(
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_SYSTEM_XCRUN" --sdk macosx --show-sdk-build-version 2>/dev/null
  )"

  xcode_version_output="$(
    "$KEPTNEAR_SYSTEM_ENV" -u DEVELOPER_DIR -u SDKROOT \
      "$KEPTNEAR_ACTIVE_XCODEBUILD_PATH" -version
  )"
  KEPTNEAR_ACTIVE_XCODE_VERSION="$(
    printf '%s\n' "$xcode_version_output" |
      "$KEPTNEAR_SYSTEM_AWK" '$1 == "Xcode" { print $2; exit }'
  )"
  KEPTNEAR_ACTIVE_XCODE_BUILD_VERSION="$(
    printf '%s\n' "$xcode_version_output" |
      "$KEPTNEAR_SYSTEM_AWK" '$1 == "Build" && $2 == "version" { print $3; exit }'
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

  host_architecture="$("$KEPTNEAR_SYSTEM_UNAME" -m)"
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
  if [[ "$KEPTNEAR_ACTIVE_CARGO_CLIPPY_BINARY_SHA256" != "$KEPTNEAR_REVIEWED_CARGO_CLIPPY_BINARY_SHA256" ]]; then
    keptnear_toolchain_fail "cargo-clippy binary does not match the reviewed distribution tool"
    return 1
  fi
  if [[ "$KEPTNEAR_ACTIVE_CLIPPY_DRIVER_BINARY_SHA256" != "$KEPTNEAR_REVIEWED_CLIPPY_DRIVER_BINARY_SHA256" ]]; then
    keptnear_toolchain_fail "clippy-driver binary does not match the reviewed distribution tool"
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

  "$KEPTNEAR_SYSTEM_ENV" \
    RUSTC="$KEPTNEAR_ACTIVE_RUSTC_PATH" \
    CARGO_BUILD_RUSTC="$KEPTNEAR_ACTIVE_RUSTC_PATH" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    CARGO_BUILD_RUSTC_WRAPPER= \
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER= \
    CARGO_HOME="$KEPTNEAR_ACTIVE_CARGO_CACHE_HOME" \
    "$KEPTNEAR_ACTIVE_CARGO_PATH" "$@"
}

keptnear_prepare_isolated_cargo_home() {
  local cargo_registry_entry
  local isolated_cargo_config

  if [[ \
    -z "${KEPTNEAR_ACTIVE_CARGO_CACHE_HOME:-}" || \
    ! -d "$KEPTNEAR_ACTIVE_CARGO_CACHE_HOME/registry" \
  ]]; then
    keptnear_toolchain_fail "reviewed Cargo cache is unavailable"
    return 1
  fi

  KEPTNEAR_ISOLATED_CARGO_ROOT="$(
    "$KEPTNEAR_SYSTEM_MKTEMP" \
      -d /private/tmp/keptnear-distribution-cargo.XXXXXX
  )" ||
    {
      keptnear_toolchain_fail "could not create the isolated Cargo root"
      return 1
    }
  "$KEPTNEAR_SYSTEM_CHMOD" 700 "$KEPTNEAR_ISOLATED_CARGO_ROOT"

  KEPTNEAR_ISOLATED_HOME="$KEPTNEAR_ISOLATED_CARGO_ROOT/home"
  KEPTNEAR_ISOLATED_CARGO_HOME="$KEPTNEAR_ISOLATED_CARGO_ROOT/cargo"
  KEPTNEAR_ISOLATED_BIN="$KEPTNEAR_ISOLATED_CARGO_ROOT/bin"
  KEPTNEAR_ISOLATED_TMPDIR="$KEPTNEAR_ISOLATED_CARGO_ROOT/tmp"
  "$KEPTNEAR_SYSTEM_MKDIR" \
    "$KEPTNEAR_ISOLATED_HOME" \
    "$KEPTNEAR_ISOLATED_CARGO_HOME" \
    "$KEPTNEAR_ISOLATED_CARGO_HOME/registry" \
    "$KEPTNEAR_ISOLATED_CARGO_HOME/registry/cache" \
    "$KEPTNEAR_ISOLATED_CARGO_HOME/registry/index" \
    "$KEPTNEAR_ISOLATED_BIN" \
    "$KEPTNEAR_ISOLATED_TMPDIR"
  "$KEPTNEAR_SYSTEM_CHMOD" \
    700 \
    "$KEPTNEAR_ISOLATED_HOME" \
    "$KEPTNEAR_ISOLATED_CARGO_HOME" \
    "$KEPTNEAR_ISOLATED_BIN" \
    "$KEPTNEAR_ISOLATED_TMPDIR"

  "$KEPTNEAR_SYSTEM_LN" \
    -s \
    "$KEPTNEAR_ACTIVE_CARGO_CLIPPY_PATH" \
    "$KEPTNEAR_ISOLATED_BIN/cargo-clippy"
  "$KEPTNEAR_SYSTEM_LN" \
    -s \
    "$KEPTNEAR_ACTIVE_CLIPPY_DRIVER_PATH" \
    "$KEPTNEAR_ISOLATED_BIN/clippy-driver"

  for cargo_registry_entry in cache index; do
    if [[ ! -d "$KEPTNEAR_ACTIVE_CARGO_CACHE_HOME/registry/$cargo_registry_entry/$KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY" ]]; then
      keptnear_cleanup_isolated_cargo_home
      keptnear_toolchain_fail "reviewed Cargo registry $cargo_registry_entry is unavailable"
      return 1
    fi
    "$KEPTNEAR_SYSTEM_LN" \
      -s \
      "$KEPTNEAR_ACTIVE_CARGO_CACHE_HOME/registry/$cargo_registry_entry/$KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY" \
      "$KEPTNEAR_ISOLATED_CARGO_HOME/registry/$cargo_registry_entry/$KEPTNEAR_REVIEWED_CRATES_IO_CACHE_DIRECTORY"
  done

  isolated_cargo_config="$KEPTNEAR_ISOLATED_CARGO_HOME/config.toml"
  "$KEPTNEAR_SYSTEM_PRINTF" '%s\n' \
    '[registries.crates-io]' \
    "protocol = \"$KEPTNEAR_REVIEWED_CRATES_IO_PROTOCOL\"" \
    '' \
    '[net]' \
    'offline = true' \
    'git-fetch-with-cli = false' \
    >"$isolated_cargo_config"
  "$KEPTNEAR_SYSTEM_CHMOD" 600 "$isolated_cargo_config"
}

keptnear_cleanup_isolated_cargo_home() {
  if [[ \
    -n "${KEPTNEAR_ISOLATED_CARGO_ROOT:-}" && \
    "$KEPTNEAR_ISOLATED_CARGO_ROOT" == \
      /private/tmp/keptnear-distribution-cargo.* \
  ]]; then
    "$KEPTNEAR_SYSTEM_RM" -rf "$KEPTNEAR_ISOLATED_CARGO_ROOT"
  fi
  KEPTNEAR_ISOLATED_CARGO_ROOT=""
  KEPTNEAR_ISOLATED_HOME=""
  KEPTNEAR_ISOLATED_CARGO_HOME=""
  KEPTNEAR_ISOLATED_BIN=""
  KEPTNEAR_ISOLATED_TMPDIR=""
}

keptnear_prepare_distribution_cargo_arguments() {
  local argument
  local cargo_subcommand
  local target_directory
  local -a normalized_arguments

  if [[ $# -eq 0 ]]; then
    keptnear_toolchain_fail "Cargo arguments are required"
    return 1
  fi

  cargo_subcommand="$1"
  shift
  case "$cargo_subcommand" in
    -V|--version)
      if [[ $# -ne 0 ]]; then
        keptnear_toolchain_fail "Cargo version probe does not accept extra arguments"
        return 1
      fi
      KEPTNEAR_DISTRIBUTION_CARGO_ARGUMENTS=("$cargo_subcommand")
      return 0
      ;;
    build|clippy|rustc|test)
      ;;
    *)
      keptnear_toolchain_fail "unsupported distribution Cargo command $cargo_subcommand"
      return 1
      ;;
  esac

  normalized_arguments=()
  while [[ $# -gt 0 ]]; do
    argument="$1"
    shift
    case "$argument" in
      --config|--manifest-path)
        keptnear_toolchain_fail "$argument is controlled by the distribution runner"
        return 1
        ;;
      --config=*|--manifest-path=*|-Zconfig-include*)
        keptnear_toolchain_fail "Cargo configuration injection is not permitted"
        return 1
        ;;
      --target-dir)
        if [[ $# -eq 0 ]]; then
          keptnear_toolchain_fail "--target-dir requires a value"
          return 1
        fi
        target_directory="$1"
        shift
        if [[ "$target_directory" != /* ]]; then
          target_directory="$ROOT_DIR/$target_directory"
        fi
        if [[ \
          "$target_directory" != "$ROOT_DIR/target" && \
          "$target_directory" != "$ROOT_DIR/target/"* \
        ]] || [[ "$target_directory" == *"/../"* || "$target_directory" == */.. ]]; then
          keptnear_toolchain_fail "--target-dir must remain below the repository target directory"
          return 1
        fi
        normalized_arguments+=("--target-dir" "$target_directory")
        ;;
      --target-dir=*)
        target_directory="${argument#--target-dir=}"
        if [[ "$target_directory" != /* ]]; then
          target_directory="$ROOT_DIR/$target_directory"
        fi
        if [[ \
          "$target_directory" != "$ROOT_DIR/target" && \
          "$target_directory" != "$ROOT_DIR/target/"* \
        ]] || [[ "$target_directory" == *"/../"* || "$target_directory" == */.. ]]; then
          keptnear_toolchain_fail "--target-dir must remain below the repository target directory"
          return 1
        fi
        normalized_arguments+=("--target-dir=$target_directory")
        ;;
      *)
        normalized_arguments+=("$argument")
        ;;
    esac
  done

  KEPTNEAR_DISTRIBUTION_CARGO_ARGUMENTS=(
    "$cargo_subcommand"
    --manifest-path
    "$ROOT_DIR/Cargo.toml"
    "${normalized_arguments[@]}"
  )
}

keptnear_run_reviewed_distribution_cargo() {
  local cargo_status
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

  if [[ \
    "${ROOT_DIR:-}" != /* || \
    ! -f "$ROOT_DIR/Cargo.toml" || \
    -e "$ROOT_DIR/.cargo/config" || \
    -e "$ROOT_DIR/.cargo/config.toml" || \
    -e /.cargo/config || \
    -e /.cargo/config.toml \
  ]]; then
    keptnear_toolchain_fail "configuration-free Cargo workspace resolution failed"
    return 1
  fi

  keptnear_prepare_distribution_cargo_arguments "$@" || return 1
  keptnear_prepare_isolated_cargo_home || return 1

  environment_command=("$KEPTNEAR_SYSTEM_ENV" -i)
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
    "PATH=$KEPTNEAR_ISOLATED_BIN:$KEPTNEAR_SYSTEM_PATH"
    "HOME=$KEPTNEAR_ISOLATED_HOME"
    "CARGO_HOME=$KEPTNEAR_ISOLATED_CARGO_HOME"
    "TMPDIR=$KEPTNEAR_ISOLATED_TMPDIR"
    "CARGO_NET_OFFLINE=true"
    "CARGO_NET_GIT_FETCH_WITH_CLI=false"
  )

  if (
    cd /
    "${environment_command[@]}" \
      "$KEPTNEAR_ACTIVE_CARGO_PATH" \
      "${KEPTNEAR_DISTRIBUTION_CARGO_ARGUMENTS[@]}"
  ); then
    cargo_status=0
  else
    cargo_status=$?
  fi
  keptnear_cleanup_isolated_cargo_home
  return "$cargo_status"
}
