#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
METADATA_PATH="$(mktemp "${TMPDIR:-/tmp}/keptnear-cargo-metadata.XXXXXX")"

cleanup() {
  rm -f "$METADATA_PATH"
}
trap cleanup EXIT

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to verify dependency license metadata" >&2
  exit 1
fi

cd "$ROOT_DIR"
cargo metadata --format-version=1 --locked >"$METADATA_PATH"

python3 - "$METADATA_PATH" <<'PY'
import json
import sys

metadata_path = sys.argv[1]
with open(metadata_path, encoding="utf-8") as metadata_file:
    packages = json.load(metadata_file)["packages"]

allowed_registry_expressions = {
    "MIT",
    "MIT OR Apache-2.0",
    "Apache-2.0 OR MIT",
    "MIT/Apache-2.0",
    "Unlicense/MIT",
    "Unlicense OR MIT",
    "Apache-2.0 OR BSL-1.0",
    "BSD-3-Clause",
    "(MIT OR Apache-2.0) AND Unicode-3.0",
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
    if not license_expression:
        errors.append(f"dependency {name} {version} has no license metadata")
    elif license_expression not in allowed_registry_expressions:
        errors.append(
            f"dependency {name} {version} has an unreviewed license expression: "
            f"{license_expression}"
        )

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
