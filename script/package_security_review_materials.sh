#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.1.0-alpha}"
PACKAGE_NAME="psw-security-review-materials-$VERSION"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist/security-review"
ARCHIVE_PATH="$DIST_DIR/$PACKAGE_NAME.tar.gz"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
MANIFEST_PATH="$DIST_DIR/$PACKAGE_NAME-manifest.txt"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/psw-security-review-materials.XXXXXX")"
STAGING_ROOT="$TMP_DIR/$PACKAGE_NAME"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

REQUIRED_PATHS=(
  README.md
  Cargo.toml
  Cargo.lock
  crates/psw-core/Cargo.toml
  crates/psw-core/src
  crates/psw-core/tests
  crates/psw-core/examples
  crates/psw-ffi/Cargo.toml
  crates/psw-ffi/src
  crates/psw-cli/Cargo.toml
  crates/psw-cli/src
  apps/macos/Package.swift
  apps/macos/README.md
  apps/macos/Sources
  apps/macos/Tests
  docs
  fixtures
  script
  scripts
)

EXCLUDED_PATHS=(
  .git
  .codex
  .echopath
  target
  dist/releases
  dist/security-review
  apps/macos/.build
)

require_path() {
  local path="$1"
  if [[ ! -e "$ROOT_DIR/$path" ]]; then
    echo "missing required security review material: $path" >&2
    exit 1
  fi
}

copy_path() {
  local path="$1"
  local source="$ROOT_DIR/$path"
  local target="$STAGING_ROOT/$path"
  mkdir -p "$(dirname "$target")"
  cp -R "$source" "$target"
}

require_manifest_text() {
  local pattern="$1"
  if ! grep -F "$pattern" "$MANIFEST_PATH" >/dev/null; then
    echo "manifest missing expected text: $pattern" >&2
    exit 1
  fi
}

for path in "${REQUIRED_PATHS[@]}"; do
  require_path "$path"
done

rm -rf "$STAGING_ROOT"
mkdir -p "$STAGING_ROOT" "$DIST_DIR"

for path in "${REQUIRED_PATHS[@]}"; do
  copy_path "$path"
done

rm -rf "$STAGING_ROOT/dist" \
  "$STAGING_ROOT/target" \
  "$STAGING_ROOT/apps/macos/.build" \
  "$STAGING_ROOT/.git" \
  "$STAGING_ROOT/.codex" \
  "$STAGING_ROOT/.echopath"

BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_REVISION="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || printf 'uncommitted')"

STAGED_MANIFEST="$STAGING_ROOT/SECURITY_REVIEW_MATERIALS_MANIFEST.txt"
cat >"$STAGED_MANIFEST" <<MANIFEST
PSW Security Review Materials
=============================

Package: $PACKAGE_NAME
Version: $VERSION
Build timestamp UTC: $BUILD_TIMESTAMP
Git revision: $GIT_REVISION

Purpose
-------
Reviewer handoff package for external security review preparation.
This package is not evidence that external security review has completed,
does not approve public alpha, and does not recommend production use.

Included material classes
-------------------------
- Rust core, FFI, and CLI source and tests
- macOS app source and tests
- Security-sensitive documentation
- Sanitized fixtures
- Local verification and packaging scripts

Excluded material classes
-------------------------
- .git repository database
- Codex and EchoPath local state
- Rust and Swift build outputs
- release archives and generated review packages
- target directories, caches, credentials, and machine-local state

Required validation after review-driven changes
-----------------------------------------------
- scripts/check.sh
- script/package_macos_alpha.sh
- script/verify_public_alpha_release_ready.sh when release credentials and review evidence exist
MANIFEST

rm -f "$ARCHIVE_PATH" "$CHECKSUM_PATH" "$MANIFEST_PATH"
(
  cd "$TMP_DIR"
  COPYFILE_DISABLE=1 tar -czf "$ARCHIVE_PATH" "$PACKAGE_NAME"
)

ARCHIVE_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$(basename "$ARCHIVE_PATH")" >"$CHECKSUM_PATH"
cp "$STAGED_MANIFEST" "$MANIFEST_PATH"

ARCHIVE_SIZE_BYTES="$(wc -c <"$ARCHIVE_PATH" | tr -d ' ')"

cat >>"$MANIFEST_PATH" <<MANIFEST

Archive
-------
Archive path: ${ARCHIVE_PATH#$ROOT_DIR/}
Checksum path: ${CHECKSUM_PATH#$ROOT_DIR/}
SHA-256: $ARCHIVE_SHA256
Size bytes: $ARCHIVE_SIZE_BYTES
MANIFEST

require_manifest_text "This package is not evidence that external security review has completed"
require_manifest_text "does not approve public alpha"
require_manifest_text "Excluded material classes"

(
  cd "$DIST_DIR"
  shasum -a 256 -c "$(basename "$CHECKSUM_PATH")" >/dev/null
)

echo "Security review materials archive: $ARCHIVE_PATH"
echo "Checksum: $CHECKSUM_PATH"
echo "Manifest: $MANIFEST_PATH"
echo "SHA-256: $ARCHIVE_SHA256"
echo "This package is reviewer handoff material only; it does not approve public alpha."
