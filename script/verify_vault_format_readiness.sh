#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_file() {
  local path="$1"
  local description="$2"
  if [[ ! -f "$path" ]]; then
    echo "missing $description: $path" >&2
    exit 1
  fi
}

require_directory() {
  local path="$1"
  local description="$2"
  if [[ ! -d "$path" ]]; then
    echo "missing $description: $path" >&2
    exit 1
  fi
}

require_doc_contains() {
  local path="$1"
  local pattern="$2"
  if ! grep -F "$pattern" "$path" >/dev/null; then
    echo "documentation missing required boundary text in $path: $pattern" >&2
    exit 1
  fi
}

cd "$ROOT_DIR"

require_file "$ROOT_DIR/fixtures/vaults/golden-vault-manifest.json" "golden vault manifest"
require_file "$ROOT_DIR/fixtures/vaults/sync-scenarios.json" "sync scenario fixture"
require_directory "$ROOT_DIR/fixtures/vaults/golden-vault-v1.pswvault" "checked-in golden vault fixture"
require_file "$ROOT_DIR/fixtures/vaults/golden-vault-v1.pswvault/vault.json" "golden fixture metadata"
require_file "$ROOT_DIR/fixtures/vaults/golden-vault-v1.pswvault/keys.enc" "golden fixture key envelope"
require_directory "$ROOT_DIR/fixtures/vaults/golden-vault-v1.pswvault/items" "golden fixture items directory"
require_directory "$ROOT_DIR/fixtures/vaults/golden-vault-v1.pswvault/attachments" "golden fixture attachments directory"
require_directory "$ROOT_DIR/fixtures/vaults/golden-vault-v1.pswvault/tombstones" "golden fixture tombstones directory"
require_file "$ROOT_DIR/crates/psw-core/tests/golden_vectors.rs" "golden vector tests"
require_file "$ROOT_DIR/crates/psw-core/tests/property_hardening.rs" "parser hardening tests"
require_file "$ROOT_DIR/docs/vault-format.md" "vault format documentation"

require_doc_contains "$ROOT_DIR/docs/vault-format.md" "not stable yet"
require_doc_contains "$ROOT_DIR/docs/vault-format.md" "public alpha format freeze"

cargo test -p psw-core --test golden_vectors
cargo test -p psw-core --test property_hardening
cargo test -p psw-core fixture_based_sync_scenarios_match_expected_outcomes

echo "Verified local vault-format readiness evidence."
echo "This does not freeze the experimental format or replace external review."
