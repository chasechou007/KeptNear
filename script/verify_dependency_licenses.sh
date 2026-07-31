#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
METADATA_PATH="$(mktemp "${TMPDIR:-/tmp}/keptnear-cargo-metadata.XXXXXX")"
LICENSE_PATH="$ROOT_DIR/LICENSE"
WORKSPACE_MANIFEST="$ROOT_DIR/Cargo.toml"
SWIFT_MANIFEST="$ROOT_DIR/apps/macos/Package.swift"

cleanup() {
  rm -f "$METADATA_PATH"
}
trap cleanup EXIT

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to verify dependency license metadata" >&2
  exit 1
fi

for required_path in "$LICENSE_PATH" "$WORKSPACE_MANIFEST" "$SWIFT_MANIFEST"; do
  if [[ ! -f "$required_path" ]]; then
    echo "Dependency license verification failed: missing ${required_path#$ROOT_DIR/}" >&2
    exit 1
  fi
done

if ! grep -F -q -- "GNU GENERAL PUBLIC LICENSE" "$LICENSE_PATH" ||
  ! grep -F -q -- "Version 3, 29 June 2007" "$LICENSE_PATH" ||
  ! grep -F -q -- "END OF TERMS AND CONDITIONS" "$LICENSE_PATH"; then
  echo "Dependency license verification failed: LICENSE is not the GPLv3 text" >&2
  exit 1
fi

for required_metadata in \
  'authors = ["Chase Chou <chasechou007@gmail.com>"]' \
  'license = "GPL-3.0-only"' \
  'repository = "https://github.com/chasechou007/KeptNear"'; do
  if ! grep -F -q -- "$required_metadata" "$WORKSPACE_MANIFEST"; then
    echo "Dependency license verification failed: workspace metadata is missing $required_metadata" >&2
    exit 1
  fi
done

for crate_manifest in "$ROOT_DIR"/crates/*/Cargo.toml; do
  for required_metadata in \
    "license.workspace = true" \
    "authors.workspace = true" \
    "repository.workspace = true" \
    "publish = false"; do
    if ! grep -F -q -- "$required_metadata" "$crate_manifest"; then
      echo "Dependency license verification failed: ${crate_manifest#$ROOT_DIR/} is missing $required_metadata" >&2
      exit 1
    fi
  done
done

if grep -E -q -- '\.package[[:space:]]*\(|\.binaryTarget[[:space:]]*\(' "$SWIFT_MANIFEST"; then
  echo "Dependency license verification failed: Swift third-party dependency requires explicit review" >&2
  exit 1
fi

cd "$ROOT_DIR"
cargo metadata --format-version=1 --locked >"$METADATA_PATH"

python3 - "$METADATA_PATH" <<'PY'
import json
from pathlib import Path
import sys

metadata_path = sys.argv[1]
with open(metadata_path, encoding="utf-8") as metadata_file:
    packages = json.load(metadata_file)["packages"]

allowed_registry_expressions = {
    "Apache-2.0",
    "Apache-2.0 AND ISC",
    "MIT",
    "MIT OR Apache-2.0",
    "Apache-2.0 OR MIT",
    "Apache-2.0 OR ISC OR MIT",
    "MIT/Apache-2.0",
    "Unlicense/MIT",
    "Unlicense OR MIT",
    "Apache-2.0 OR BSL-1.0",
    "BSD-3-Clause",
    "ISC",
    "MPL-2.0",
    "Zlib OR Apache-2.0 OR MIT",
    "MIT OR Apache-2.0 OR Zlib",
    "MIT OR Apache-2.0 OR BSD-1-Clause",
    "BSD-2-Clause OR Apache-2.0 OR MIT",
    "(MIT OR Apache-2.0) AND Unicode-3.0",
    "(Apache-2.0 OR MIT) AND Unicode-3.0",
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
}

errors = []
registry_packages = []
for package in packages:
    name = package["name"]
    version = package["version"]
    license_expression = package.get("license")
    source = package.get("source")

    if source is None:
        if license_expression != "GPL-3.0-only":
            errors.append(
                f"workspace package {name} {version} must use GPL-3.0-only, "
                f"found {license_expression or 'missing'}"
            )
        continue

    registry_packages.append((name, version, license_expression))
    if not source.startswith("registry+"):
        errors.append(
            f"dependency {name} {version} uses an unreviewed source: {source}"
        )
    if not license_expression:
        errors.append(f"dependency {name} {version} has no license metadata")
    elif license_expression not in allowed_registry_expressions:
        errors.append(
            f"dependency {name} {version} has an unreviewed license expression: "
            f"{license_expression}"
        )

    if license_expression == "MPL-2.0":
        package_root = Path(package["manifest_path"]).parent
        for candidate in package_root.rglob("*"):
            if not candidate.is_file():
                continue
            try:
                if candidate.stat().st_size > 2_000_000:
                    continue
                if b"Incompatible With Secondary Licenses" in candidate.read_bytes():
                    errors.append(
                        f"dependency {name} {version} opts out of MPL-2.0 "
                        "secondary-license compatibility"
                    )
                    break
            except OSError as error:
                errors.append(
                    f"dependency {name} {version} license notice could not be read: "
                    f"{error.__class__.__name__}"
                )
                break

if errors:
    print("Dependency license verification failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

expressions = sorted({license_expression for _, _, license_expression in registry_packages})
print(f"Dependency license verification passed: {len(registry_packages)} registry packages")
for expression in expressions:
    print(f"- {expression}")
PY

NOTICE_PATH="$ROOT_DIR/THIRD_PARTY_NOTICES.md"
if [[ ! -f "$NOTICE_PATH" ]]; then
  echo "Dependency license verification failed: THIRD_PARTY_NOTICES.md is missing" >&2
  exit 1
fi

for required_notice in \
  "KeptNear enables the \`bundled-sqlcipher\` feature" \
  "Copyright (c) 2008-2020 Zetetic LLC" \
  "Redistribution and use in source and binary forms"; do
  if ! grep -F -q -- "$required_notice" "$NOTICE_PATH"; then
    echo "Dependency license verification failed: SQLCipher notice is incomplete" >&2
    exit 1
  fi
done

echo "Bundled SQLCipher attribution notice is present."
echo "Workspace GPL-3.0-only metadata and dependency source policy are consistent."
echo "Swift package has no external package or binary-target dependency."
