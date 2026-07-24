#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/script/swiftpm_local_env.sh"
PACKAGE_PATH="$ROOT_DIR/apps/macos"
TEST_SOURCE="$PACKAGE_PATH/Tests/PSWMacTests/PSWMacWorkflowTests.swift"
TEST_CASE="PSWMacTests.PSWMacWorkflowTests"

require_file() {
  local path="$1"
  local description="$2"
  if [[ ! -f "$path" ]]; then
    echo "missing $description: $path" >&2
    exit 1
  fi
}

require_test_case() {
  local name="$1"
  if ! grep -F "func $name(" "$TEST_SOURCE" >/dev/null; then
    echo "missing macOS security-state test case: $name" >&2
    exit 1
  fi
}

join_by_pipe() {
  local IFS="|"
  echo "$*"
}

run_group() {
  local label="$1"
  shift
  local tests=("$@")
  local filter
  filter="$TEST_CASE/($(join_by_pipe "${tests[@]}"))"

  echo "Running macOS security-state checks: $label"
  swiftpm_test --package-path "$PACKAGE_PATH" --filter "$filter"
}

require_file "$PACKAGE_PATH/Package.swift" "macOS Swift package manifest"
require_file "$TEST_SOURCE" "macOS workflow test source"

clipboard_tests=(
  testClipboardManagerClearsCopiedSecretAfterTimeout
  testClipboardManagerPreservesLaterClipboardContents
  testClipboardManagerClearsManagedSecretOnDemand
  testClipboardManagerClearManagedSecretPreservesLaterClipboardContents
  testClipboardManagerClearManagedSecretInvalidatesPendingTimeout
  testCreateUnlockSearchCopyAndManualLockWorkflow
)

auto_lock_tests=(
  testIdleAutoLockClearsUnlockedState
  testSystemSleepNotificationLocksAndClearsUnlockedState
  testScreenSleepNotificationLocksAndClearsUnlockedState
  testSessionResignActiveNotificationLocksAndClearsUnlockedState
)

app_termination_tests=(
  testAppTerminationLocksAndClearsManagedClipboardSecret
  testAppTerminationPreservesLaterClipboardContents
)

last_window_close_tests=(
  testLastWindowCloseLocksAndPreservesSelectedVaultContext
  testLastWindowClosePreservesLaterClipboardContents
)

vault_switch_tests=(
  testOpeningAnotherVaultClearsPreviousUnlockedSessionState
  testCreatingAnotherVaultClearsPreviousUnlockedSessionStateBeforeNewUnlock
  testClosingUnlockedVaultClearsSelectedVaultStateAndPreservesRecentVault
  testClosingLockedVaultClearsSelectionAndPreservesRecentVaultWithoutLockingCore
)

preference_tests=(
  testSecurityPreferencesPersistAcrossStoreInstances
  testUnsupportedSecurityPreferencesNormalizeToDefaults
)

for test_name in \
  "${clipboard_tests[@]}" \
  "${auto_lock_tests[@]}" \
  "${app_termination_tests[@]}" \
  "${last_window_close_tests[@]}" \
  "${vault_switch_tests[@]}" \
  "${preference_tests[@]}"; do
  require_test_case "$test_name"
done

run_group "clipboard" "${clipboard_tests[@]}"
run_group "auto-lock" "${auto_lock_tests[@]}"
run_group "app-termination" "${app_termination_tests[@]}"
run_group "last-window-close" "${last_window_close_tests[@]}"
run_group "vault-switch-close" "${vault_switch_tests[@]}"
run_group "preferences" "${preference_tests[@]}"

echo "Verified macOS security-state readiness evidence."
echo "This does not replace full macOS tests, signed install verification, notarization, or external review."
