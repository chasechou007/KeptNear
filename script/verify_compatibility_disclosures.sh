#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
violations=0

require_literal() {
  local path="$1"
  local literal="$2"

  if ! grep -F -q -- "$literal" "$ROOT_DIR/$path"; then
    printf 'compatibility disclosure violation: %s is missing: %s\n' \
      "$path" "$literal" >&2
    violations=$((violations + 1))
  fi
}

require_literal apps/macos/Sources/PSWMac/Localization.swift \
  "var processCompatibilityDisclosure"
require_literal apps/macos/Sources/PSWMac/Localization.swift \
  "Rotate the credential with its provider"
require_literal apps/macos/Sources/PSWMac/Localization.swift \
  "凭据提供方轮换"
require_literal apps/macos/Sources/PSWMac/Localization.swift \
  "提供元で認証情報をローテーション"
require_literal apps/macos/Sources/PSWMac/UsageProfileSetupView.swift \
  "AppsToolsCompatibilityDisclosure"
require_literal apps/macos/Sources/PSWMac/PendingRequestsView.swift \
  "AppsToolsCompatibilityDisclosure"
require_literal apps/macos/Sources/PSWMac/AppsToolsView.swift \
  "AppsToolsCompatibilityDisclosure"
require_literal crates/psw-cli/src/command.rs \
  "Compatibility delivery:"
require_literal crates/psw-cli/src/command.rs \
  "Revoking access or unpairing stops only future KeptNear delivery."
require_literal crates/psw-cli/src/command.rs \
  "Rotate the credential with its provider to invalidate a delivered copy."
require_literal crates/psw-cli/src/command.rs \
  "Exit status and cancellation:"
require_literal crates/psw-cli/src/command.rs \
  "kills and reaps the direct child"
require_literal crates/psw-cli/src/machine.rs \
  "upstream_rotation_required_for_invalidation"
require_literal docs/product-requirements.md \
  "complete invalidation requires rotating the upstream credential"
require_literal docs/security-model.md \
  "Complete invalidation after delivery requires upstream rotation."
require_literal docs/security-model.md \
  "Native terminal interruption closes that connection"
require_literal \
  openspec/changes/complete-local-password-token-manager/specs/credential-use-interfaces/spec.md \
  "invalidating a delivered copy requires upstream credential rotation"

if [[ "$violations" -ne 0 ]]; then
  printf 'Compatibility disclosure verification failed with %d violation(s).\n' \
    "$violations" >&2
  exit 1
fi

printf 'Compatibility disclosure verification passed.\n'
