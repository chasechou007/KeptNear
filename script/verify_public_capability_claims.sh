#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README_PATH="$ROOT_DIR/README.md"
README_ZH_PATH="$ROOT_DIR/README.zh-CN.md"
PRODUCT_OVERVIEW_PATH="$ROOT_DIR/docs/product-overview.md"
PRODUCT_OVERVIEW_ZH_PATH="$ROOT_DIR/docs/product-overview.zh-CN.md"
STATUS_PATH="$ROOT_DIR/docs/capability-status.md"
BRAND_PATH="$ROOT_DIR/docs/brand.md"
MCP_TOOLS_PATH="$ROOT_DIR/crates/keptnear-mcp/src/tools.rs"
PACKAGE_PATH="$ROOT_DIR/script/package_macos_alpha.sh"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "public capability claim violation: missing ${path#$ROOT_DIR/}" >&2
    exit 1
  fi
}

require_literal() {
  local path="$1"
  local expected="$2"
  if ! grep -F "$expected" "$path" >/dev/null; then
    echo "public capability claim violation: ${path#$ROOT_DIR/} is missing: $expected" >&2
    exit 1
  fi
}

reject_literal() {
  local path="$1"
  local forbidden="$2"
  if grep -Fi "$forbidden" "$path" >/dev/null; then
    echo "public capability claim violation: ${path#$ROOT_DIR/} contains forbidden claim: $forbidden" >&2
    exit 1
  fi
}

for path in \
  "$README_PATH" \
  "$README_ZH_PATH" \
  "$PRODUCT_OVERVIEW_PATH" \
  "$PRODUCT_OVERVIEW_ZH_PATH" \
  "$STATUS_PATH" \
  "$BRAND_PATH" \
  "$MCP_TOOLS_PATH" \
  "$PACKAGE_PATH" \
  "$ROOT_DIR/crates/psw-broker/src/main.rs" \
  "$ROOT_DIR/crates/keptnear-mcp/src/main.rs" \
  "$ROOT_DIR/crates/psw-cli/src/keptnear.rs"; do
  require_file "$path"
done

require_literal "$README_PATH" "Local Password &amp; Token Manager"
require_literal "$README_PATH" "## Capability Status"
require_literal "$README_PATH" "### Available In The macOS Source Build"
require_literal "$README_PATH" "### Implemented And Tested In Source"
require_literal "$README_PATH" "### Bundled But Not Activated"
require_literal "$README_PATH" "### Not Shipped"
require_literal "$README_PATH" "An unsigned Apple Silicon DMG is published as an experimental GitHub pre-release"
require_literal "$README_PATH" "does not install or activate a"
require_literal "$README_PATH" "End-user MCP or CLI machine credential access is not a released product"
require_literal "$README_PATH" "Do not use it to store production"

require_literal "$README_ZH_PATH" "## 能力状态"
require_literal "$README_ZH_PATH" "### macOS 源码构建中可用"
require_literal "$README_ZH_PATH" "### 已在源码中实现并测试"
require_literal "$README_ZH_PATH" "### 已打包但尚未激活"
require_literal "$README_ZH_PATH" "### 尚未发布"
require_literal "$README_ZH_PATH" "尚未经过外部安全审计"
require_literal "$README_ZH_PATH" "请勿使用当前版本"
require_literal "$README_ZH_PATH" "不会安装或激活长期运行的"
require_literal "$README_ZH_PATH" "面向最终用户的 MCP 或 CLI 机器凭据访问还不是已发布产品能力"
require_literal "$README_ZH_PATH" "当前没有任何发布配置建议保存生产环境凭据"

require_literal "$PRODUCT_OVERVIEW_PATH" "Current release maturity: experimental pre-alpha"
require_literal "$PRODUCT_OVERVIEW_PATH" "Available in source and the unsigned experimental DMG"
require_literal "$PRODUCT_OVERVIEW_PATH" "Implemented and tested in source"
require_literal "$PRODUCT_OVERVIEW_PATH" "Developer preview; bundled but not activated for end users"
require_literal "$PRODUCT_OVERVIEW_PATH" 'they do not expose a generic `secret.get`'
require_literal "$PRODUCT_OVERVIEW_PATH" "has not completed an external security audit"
require_literal "$PRODUCT_OVERVIEW_PATH" "not recommended for production credentials"
require_literal "$PRODUCT_OVERVIEW_PATH" "### Outside the first-version closure"

require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "当前发布成熟度：实验性 pre-alpha"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "已在源码和未签名实验性 DMG 中提供"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "已在源码中实现并测试"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "开发者预览；已经打包但未面向最终用户激活"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "### 提供明确能力，而不是通用密钥输出"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" '`secret.get`'
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "尚未完成外部安全审计"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "不建议保存生产环境凭据"
require_literal "$PRODUCT_OVERVIEW_ZH_PATH" "### 不在首个完整版本闭环"

for path in \
  "$README_PATH" \
  "$README_ZH_PATH" \
  "$PRODUCT_OVERVIEW_PATH" \
  "$PRODUCT_OVERVIEW_ZH_PATH"; do
  for milestone in \
    v0.2.0-alpha.1 \
    v0.3.0-alpha.1 \
    v0.4.0-beta.1 \
    v0.9.0-rc.1 \
    v1.0.0; do
    require_literal "$path" "$milestone"
  done
done

require_literal "$STATUS_PATH" "Source implementation is not the same as a shipped product capability."
require_literal "$STATUS_PATH" "There is no raw secret retrieval command."
require_literal "$STATUS_PATH" "It does not activate a long-running Broker service"
require_literal "$STATUS_PATH" "No external security review is complete."
require_literal "$STATUS_PATH" "No profile recommends production-secret use."
require_literal "$BRAND_PATH" "**Approved public descriptor:** Local Password & Token Manager"

for capability in \
  credential.search \
  access.request \
  grant.status \
  grant.revoke \
  http.request \
  process.run; do
  require_literal "$MCP_TOOLS_PATH" "\"$capability\""
  require_literal "$STATUS_PATH" "\`$capability\`"
done

require_literal "$PACKAGE_PATH" 'PACKAGED_BROKER="$APP_HELPERS/keptnear-broker"'
require_literal "$PACKAGE_PATH" 'PACKAGED_MCP="$APP_HELPERS/keptnear-mcp"'
require_literal "$PACKAGE_PATH" 'PACKAGED_CLI="$APP_HELPERS/keptnear"'

for path in "$README_PATH" "$PRODUCT_OVERVIEW_PATH" "$STATUS_PATH"; do
  reject_literal "$path" "production-ready password manager"
  reject_literal "$path" "externally audited"
  reject_literal "$path" "automatic cloud sync"
  reject_literal "$path" "end-to-end encrypted cloud service"
  reject_literal "$path" "MCP and CLI are available to end users"
done

for path in "$README_ZH_PATH" "$PRODUCT_OVERVIEW_ZH_PATH"; do
  reject_literal "$path" "生产就绪的密码管理器"
  reject_literal "$path" "已通过外部安全审计"
  reject_literal "$path" "自动云同步"
  reject_literal "$path" "端到端加密云服务"
  reject_literal "$path" "MCP 和 CLI 已面向最终用户发布"
done

echo "Public capability claim verification passed."
