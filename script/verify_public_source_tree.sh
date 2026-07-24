#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANDIDATE_PATHS="$(mktemp "${TMPDIR:-/tmp}/keptnear-public-source.XXXXXX")"

cleanup() {
  rm -f "$CANDIDATE_PATHS"
}
trap cleanup EXIT

cd "$ROOT_DIR"
git ls-files --cached --others --exclude-standard >"$CANDIDATE_PATHS"

violations=0

report_violation() {
  printf 'public source violation: %s\n' "$1" >&2
  violations=$((violations + 1))
}

while IFS= read -r path; do
  [[ -n "$path" ]] || continue

  case "$path" in
    .codex/*|.echopath/*|openspec/*|AGENTS.md|CONTEXT.md|target/*|.build/*|apps/macos/.build/*|dist/*)
      report_violation "forbidden local path is publishable: $path"
      ;;
  esac

  case "$path" in
    fixtures/vaults/golden-vault-v1.pswvault/*)
      ;;
    *.pswvault|*.pswvault/*)
      report_violation "non-fixture vault path is publishable: $path"
      ;;
  esac

  lower_path="$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')"
  case "$lower_path" in
    *.1pux|*.kdbx|*.opvault|*.opvault/*|*.agilekeychain|*.agilekeychain/*|*.pem|*.p12|*.p8|*.key|*.jks|*.keystore|*.mobileprovision|.env|.env.*|*/.env|*/.env.*)
      report_violation "credential or password-manager artifact is publishable: $path"
      ;;
    *.csv)
      case "$path" in
        fixtures/imports/*) ;;
        *) report_violation "CSV outside the synthetic fixture directory is publishable: $path" ;;
      esac
      ;;
    *bitwarden*export*.json|*plaintext*export*.json|*password*export*.json)
      report_violation "likely plaintext password export is publishable: $path"
      ;;
    */logins.json|logins.json|*/passwords.json|passwords.json)
      report_violation "likely browser password export is publishable: $path"
      ;;
  esac

  case "$(basename "$path")" in
    keys.enc)
      if [[ "$path" != "fixtures/vaults/golden-vault-v1.pswvault/keys.enc" ]]; then
        report_violation "vault key envelope outside the approved fixture is publishable: $path"
      fi
      ;;
    local_unlock.enc)
      report_violation "local convenience-unlock envelope is publishable: $path"
      ;;
  esac
done <"$CANDIDATE_PATHS"

secret_patterns=(
  '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'gh[pousr]_[A-Za-z0-9]{20,}'
  'sk-(proj-)?[A-Za-z0-9_-]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
)

while IFS= read -r path; do
  [[ -f "$path" ]] || continue

  for pattern in "${secret_patterns[@]}"; do
    if grep -I -E -q -- "$pattern" "$path"; then
      report_violation "credential-like content found in $path"
      break
    fi
  done

  if [[ -n "${HOME:-}" ]] && grep -I -F -q "$HOME/" "$path"; then
    report_violation "developer home path found in $path"
  fi
done <"$CANDIDATE_PATHS"

if [[ "$violations" -ne 0 ]]; then
  printf 'Public source tree verification failed with %d violation(s).\n' "$violations" >&2
  exit 1
fi

candidate_count="$(wc -l <"$CANDIDATE_PATHS" | tr -d ' ')"
printf 'Public source tree verification passed: %s candidate files checked.\n' "$candidate_count"
