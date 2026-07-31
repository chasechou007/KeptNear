#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANDIDATE_PATHS="$(mktemp "${TMPDIR:-/tmp}/keptnear-secret-candidates.XXXXXX")"
HISTORY_OBJECTS="$(mktemp "${TMPDIR:-/tmp}/keptnear-history-objects.XXXXXX")"
HISTORY_BLOBS="$(mktemp "${TMPDIR:-/tmp}/keptnear-history-blobs.XXXXXX")"
UNIQUE_HISTORY_BLOBS="$(mktemp "${TMPDIR:-/tmp}/keptnear-history-unique-blobs.XXXXXX")"
BLOB_CONTENT="$(mktemp "${TMPDIR:-/tmp}/keptnear-history-content.XXXXXX")"

cleanup() {
  rm -f \
    "$CANDIDATE_PATHS" \
    "$HISTORY_OBJECTS" \
    "$HISTORY_BLOBS" \
    "$UNIQUE_HISTORY_BLOBS" \
    "$BLOB_CONTENT"
}
trap cleanup EXIT

violations=0

report_violation() {
  printf 'repository secret violation: %s\n' "$1" >&2
  violations=$((violations + 1))
}

secret_patterns=(
  '-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----'
  'AGE-SECRET-KEY-1[0-9A-Z]{20,}'
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'gh[pousr]_[A-Za-z0-9]{20,}'
  'glpat-[A-Za-z0-9_-]{20,}'
  'sk-ant-[A-Za-z0-9_-]{20,}'
  'sk-(proj-)?[A-Za-z0-9_-]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  'AIza[0-9A-Za-z_-]{35}'
  '(sk|rk)_live_[0-9A-Za-z]{16,}'
  'npm_[A-Za-z0-9]{30,}'
  'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}'
  'dop_v1_[A-Fa-f0-9]{64}'
)

scan_content() {
  local path="$1"
  local display="$2"
  local pattern

  for pattern in "${secret_patterns[@]}"; do
    if LC_ALL=C grep -I -E -q -- "$pattern" "$path"; then
      report_violation "credential-like content found in $display"
      return
    fi
  done

  if LC_ALL=C grep -I -E 'https?://[^/@[:space:]]+:[^/@[:space:]]+@' "$path" |
    grep -F -v 'https://user:password@api.example.test/v1' >/dev/null; then
    report_violation "credential-bearing URL found in $display"
    return
  fi

  if [[ -n "${HOME:-}" ]] && grep -I -F -q "$HOME/" "$path"; then
    report_violation "developer home path found in $display"
  fi
}

check_sensitive_path() {
  local path="$1"
  local scope="$2"
  local lower_path
  local basename

  lower_path="$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')"
  basename="${lower_path##*/}"

  case "$lower_path" in
    .codex/*|.echopath/*|openspec/*|agents.md|context.md)
      report_violation "$scope contains private development context: $path"
      ;;
  esac

  case "$basename" in
    .env|.npmrc|.pypirc|.netrc|.dockercfg|credentials|credentials.json|service-account.json|id_rsa|id_dsa|id_ecdsa|id_ed25519)
      report_violation "$scope contains a credential-bearing filename: $path"
      ;;
  esac

  case "$lower_path" in
    *.pem|*.p12|*.p8|*.key|*.jks|*.keystore|*.mobileprovision)
      report_violation "$scope contains signing or private-key material: $path"
      ;;
  esac
}

cd "$ROOT_DIR"
git ls-files --cached --others --exclude-standard >"$CANDIDATE_PATHS"

while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  check_sensitive_path "$path" "candidate source tree"

  if [[ -L "$path" ]]; then
    report_violation "candidate source tree contains a symbolic link: $path"
    continue
  fi

  [[ -f "$path" ]] || continue
  scan_content "$path" "candidate source file $path"
done <"$CANDIDATE_PATHS"

git rev-list --objects --all >"$HISTORY_OBJECTS"

while IFS=' ' read -r object_id path; do
  [[ -n "${path:-}" ]] || continue
  check_sensitive_path "$path" "reachable Git history"

  if [[ "$(git cat-file -t "$object_id")" == "blob" ]]; then
    printf '%s\t%s\n' "$object_id" "$path" >>"$HISTORY_BLOBS"
  fi
done <"$HISTORY_OBJECTS"

/usr/bin/awk -F '\t' '!seen[$1]++' "$HISTORY_BLOBS" >"$UNIQUE_HISTORY_BLOBS"

history_blob_count=0
while IFS=$'\t' read -r object_id path; do
  [[ -n "$object_id" ]] || continue
  history_blob_count=$((history_blob_count + 1))
  git cat-file blob "$object_id" >"$BLOB_CONTENT"

  if grep -Iq . "$BLOB_CONTENT"; then
    scan_content "$BLOB_CONTENT" "reachable Git blob $object_id ($path)"
  fi
done <"$UNIQUE_HISTORY_BLOBS"

if [[ "$violations" -ne 0 ]]; then
  printf 'Repository secret verification failed with %d violation(s).\n' "$violations" >&2
  exit 1
fi

candidate_count="$(wc -l <"$CANDIDATE_PATHS" | tr -d ' ')"
printf 'Repository secret verification passed: %s candidate files and %s reachable historical blobs checked.\n' \
  "$candidate_count" \
  "$history_blob_count"
