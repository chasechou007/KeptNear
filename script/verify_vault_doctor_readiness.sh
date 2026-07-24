#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/psw-vault-doctor-readiness.XXXXXX")"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 1
  fi
}

require_file_contains() {
  local path="$1"
  local pattern="$2"
  if ! grep -F "$pattern" "$path" >/dev/null; then
    echo "expected $path to contain: $pattern" >&2
    exit 1
  fi
}

require_file_excludes() {
  local path="$1"
  local pattern="$2"
  if grep -F "$pattern" "$path" >/dev/null; then
    echo "expected $path to omit secret or item content: $pattern" >&2
    exit 1
  fi
}

require_command cargo
require_command python3

SUPPORTED_VAULT="$TMP_DIR/Supported.pswvault"
INCOMPLETE_VAULT="$TMP_DIR/Incomplete.pswvault"
FUTURE_VAULT="$TMP_DIR/Future.pswvault"
TEXT_OUTPUT="$TMP_DIR/doctor-supported.txt"
JSON_OUTPUT="$TMP_DIR/doctor-supported.json"
INCOMPLETE_OUTPUT="$TMP_DIR/doctor-incomplete.txt"
FUTURE_OUTPUT="$TMP_DIR/doctor-future.txt"

cd "$ROOT_DIR"

cargo run --quiet -p psw-core --example create_doctor_fixture -- "$SUPPORTED_VAULT"

cargo run --quiet -p psw-cli -- doctor "$SUPPORTED_VAULT" >"$TEXT_OUTPUT"
require_file_contains "$TEXT_OUTPUT" "Status: usable"
require_file_contains "$TEXT_OUTPUT" "Required structure: yes"
require_file_contains "$TEXT_OUTPUT" "Vault format version: 1"
require_file_contains "$TEXT_OUTPUT" "Record format version: 1"
require_file_contains "$TEXT_OUTPUT" "Encrypted item records: 1"
require_file_contains "$TEXT_OUTPUT" "Attachment files: 1"
require_file_contains "$TEXT_OUTPUT" "Local unlock envelope: yes"

cargo run --quiet -p psw-cli -- doctor --json "$SUPPORTED_VAULT" >"$JSON_OUTPUT"
python3 - "$JSON_OUTPUT" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)

assert report["status"] == "usable"
assert report["required_structure_complete"] is True
assert report["metadata"]["vault_format_version"] == 1
assert report["metadata"]["record_format_version"] == 1
assert report["counts"]["item_record_files"] == 1
assert report["counts"]["attachment_files"] == 1
assert report["counts"]["tombstone_record_files"] == 0
assert report["local_unlock_envelope_present"] is True
PY

for output in "$TEXT_OUTPUT" "$JSON_OUTPUT"; do
  require_file_excludes "$output" "doctor-secret-never-print"
  require_file_excludes "$output" "doctor-user@example.com"
  require_file_excludes "$output" "Doctor Login"
  require_file_excludes "$output" "doctor private note"
done

mkdir -p "$INCOMPLETE_VAULT/items"
cp "$SUPPORTED_VAULT/vault.json" "$INCOMPLETE_VAULT/vault.json"
mkdir -p "$INCOMPLETE_VAULT/keys.enc"

if cargo run --quiet -p psw-cli -- doctor "$INCOMPLETE_VAULT" >"$INCOMPLETE_OUTPUT" 2>&1; then
  echo "expected incomplete vault doctor check to fail" >&2
  exit 1
fi
require_file_contains "$INCOMPLETE_OUTPUT" "Status: unusable"
require_file_contains "$INCOMPLETE_OUTPUT" "Missing or invalid: keys.enc"
require_file_contains "$INCOMPLETE_OUTPUT" "attachments/"
require_file_contains "$INCOMPLETE_OUTPUT" "tombstones/"

cp -R "$SUPPORTED_VAULT" "$FUTURE_VAULT"
python3 - "$FUTURE_VAULT/vault.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    metadata = json.load(handle)
metadata["vault_format_version"] = 999
with open(path, "w", encoding="utf-8") as handle:
    json.dump(metadata, handle, indent=2)
    handle.write("\n")
PY

if cargo run --quiet -p psw-cli -- doctor "$FUTURE_VAULT" >"$FUTURE_OUTPUT" 2>&1; then
  echo "expected future-format vault doctor check to fail" >&2
  exit 1
fi
require_file_contains "$FUTURE_OUTPUT" "Status: unsupported_format"
require_file_contains "$FUTURE_OUTPUT" "vault format is newer than this client supports"

echo "Verified vault doctor readiness evidence."
echo "This is local filesystem readiness only; provider sync status is not checked."
