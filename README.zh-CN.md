<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/keptnear-lockup-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/brand/keptnear-lockup.svg">
    <img src="assets/brand/keptnear-lockup.svg" alt="KeptNear" width="460">
  </picture>
</p>

<p align="center"><strong>本地密码与令牌管理器</strong></p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="https://github.com/chasechou007/KeptNear/releases/tag/v0.1.0-prealpha.2">下载</a> ·
  <a href="docs/product-overview.zh-CN.md">产品</a> ·
  <a href="docs/security-model.md">安全</a>
</p>

> 将密码、令牌和密钥保存在本地加密密码库中，并由你决定哪些应用和工具可以使用它们。

KeptNear 是一个开源、本地优先的密码与令牌管理器。数据保存在由用户控制的
加密 `.pswvault` 目录中。密码库放在哪里、是否使用 iCloud Drive、Dropbox、
Syncthing 或 WebDAV 等不受信任的文件服务传输加密文件，都由用户自己决定。

原生 macOS 客户端是人类控制面。KeptNear 也面向需要使用凭据的本地应用、
CLI 工具和 MCP Host：它们应当只能使用经过选择和授权的凭据，而不是得到整个
密码库，也不需要把原始密钥粘贴进普通的 Agent 对话或工具输出。

<p align="center">
  <img src="assets/screenshots/keptnear-vault-overview.png" alt="KeptNear 密码库工作区，使用合成登录数据且敏感字段保持隐藏" width="1100">
</p>
<p align="center"><sub>使用合成测试数据的原生 macOS 密码库工作区。</sub></p>

## 为什么开发 KeptNear

- **密码库始终属于你。** KeptNear 不要求注册账号，也不运营托管密码库或云同步服务。
- **文件同步只是传输层。** 外部服务可以复制加密密码库文件，但不会成为
  KeptNear 的信任边界。
- **人类密码和开发者凭据应当统一管理。** 登录信息、安全备注、信用卡、
  软件许可证、API Token、密钥、证书和自定义字段使用同一个可扩展加密模型。
- **机器访问必须明确授权。** 规划中的最终用户流程会对每个本地使用方进行配对，
  并把权限限制到指定密钥字段和经过批准的操作。
- **日常体验应当原生而现代。** 第一个客户端使用 SwiftUI 构建，底层由可复用的
  Rust 核心提供支持。
- **安全边界可以被检查。** 密码库格式、架构、安全假设、日志策略、打包方式和
  发布门禁都记录在公开文档中。

## 项目状态

> [!WARNING]
> KeptNear 目前是实验性 pre-alpha 软件，尚未经过外部安全审计。请勿使用当前版本
> 保存生产环境密码、令牌、密钥或其他重要凭据。

目前提供适用于 macOS 13 或更高版本、仅支持 Apple Silicon 的实验性 GitHub
预发布 DMG。该安装包没有 Apple Developer ID 签名，也没有经过 Apple 公证，
因此 macOS 无法验证发布者身份，并可能在首次启动时阻止运行。

源码和未签名预览版分别通过维护者有限风险接受记录 `AR-001` 和 `AR-002`
公开。这些记录允许透明地进行实验性评估，但不代表 KeptNear 已通过审计、
达到生产可用状态或适合保存重要凭据。

当前版本：
[v0.1.0-prealpha.2](https://github.com/chasechou007/KeptNear/releases/tag/v0.1.0-prealpha.2)。
已经确定的下一个产品里程碑是 `v0.2.0-alpha.1`。

## 工作方式

```text
用户
  └─ macOS App ────────────────┐
                               ├─ 加密 .pswvault
本地应用或工具                 │
  └─ MCP / CLI ─ Local Broker ┘
                   ├─ 使用方配对
                   ├─ 字段级授权
                   ├─ 用户确认和授权凭证
                   └─ 不含密钥内容的本地审计
```

可移动密码库只保存加密凭据数据。设备信任、应用配对、授权、审批和审计状态
保留在当前设备上，不会跟随密码库同步。MCP 和 CLI 提供经过授权的操作，
而不是通用的原始密钥读取命令。

<p align="center">
  <img src="assets/screenshots/keptnear-apps-tools.png" alt="KeptNear 应用与工具控制面，当前没有已配对的使用方" width="1100">
</p>
<p align="center"><sub>源码构建中的“应用与工具”控制面。面向最终用户的机器访问仍是开发者预览。</sub></p>

完整产品模型请阅读[产品说明](docs/product-overview.zh-CN.md)，实现边界请阅读
[架构文档](docs/architecture.md)。

## 能力状态

KeptNear 会明确区分“已经在源码中实现”“已经打包”和“最终用户已经可以使用”。

### macOS 源码构建中可用

- 创建、打开、解锁、锁定、恢复、备份、还原和文件同步本地加密密码库。
- 创建和管理登录信息、安全备注、信用卡、软件许可证、API Token、API Key、
  SSH Key、证书和自定义凭据。
- 使用搜索、收藏、标签、密码生成、TOTP、密码健康检查、剪贴板自动清理、
  自动锁定、导入导出和显式冲突处理。
- 在原生 macOS 客户端中使用英文、简体中文或日文界面。

### 已在源码中实现并测试

- 设备本地 Broker，包含加密信任状态、使用方身份、字段级授权、审批、授权凭证、
  全局暂停和不含密钥内容的审计。
- 基于认证后的 `keptnear.broker/1.0` 协议实现的六工具 MCP 适配器和类型化
  `keptnear` CLI。
- Broker 代理的 HTTPS 请求和直接子进程兼容操作，避免通过普通机器结果返回
  原始凭据。

这些机器接口仍然需要兼容的 Broker 进程，目前属于源码级开发者预览。

### 已打包但尚未激活

Apple Silicon 安装包包含 App、Broker、MCP 适配器、CLI、FFI 库和封闭协议清单。
将 `KeptNear.app` 拖入“应用程序”只会复制这些组件，不会安装或激活长期运行的
Broker 服务，也没有完成配对、审批、重启、升级和卸载的最终用户生命周期。

### 尚未发布

- 面向最终用户的 MCP 或 CLI 机器凭据访问还不是已发布产品能力。
- 暂无已签名和已公证的安装包。
- KeptNear 不运营托管密码库、KeptNear 账号、遥测上传、自动更新或同步服务。
- 当前没有任何发布配置建议保存生产环境凭据。

每项标签的证据请参阅[能力状态](docs/capability-status.md)。

## 下载当前预览版

当前二进制预览版仅支持 **Apple Silicon (`arm64`)** 和
**macOS 13 或更高版本**。

1. 从
   [v0.1.0-prealpha.2](https://github.com/chasechou007/KeptNear/releases/tag/v0.1.0-prealpha.2)
   下载 DMG 和校验文件。
2. 在下载目录执行：

   ```sh
   shasum -a 256 -c KeptNear-0.1.0-prealpha.2-macos-arm64.dmg.sha256
   ```

3. 打开 DMG，将 `KeptNear.app` 拖入“应用程序”。
4. 首次打开前阅读
   [未签名安装说明](docs/macos-alpha-packaging.md#install-an-unsigned-experimental-dmg)。
   不要为了 KeptNear 全局关闭 Gatekeeper。

已发布 DMG 的 SHA-256：

```text
b926247539f2c3ad8d2ebcf6f5d60f04bbe60db3081b180b45a1d0a149fe35b0
```

## 产品方向

产品方向已经确定，但兼容性和交付成熟度仍处于 1.0 之前。下面是没有承诺日期的
规划顺序：

| 里程碑 | 闭环目标 |
| --- | --- |
| `v0.2.0-alpha.1` | 完善原生 macOS 密码与令牌工作流和公开产品体验。 |
| `v0.3.0-alpha.1` | 提供 KeePassXC 高保真迁移、迁移预览、损失报告和全新本地身份。 |
| `v0.4.0-beta.1` | 激活受支持的最终用户 Broker、MCP、CLI、配对、审批和卸载生命周期。 |
| `v0.9.0-rc.1` | 冻结兼容面，验证升级和恢复，并完成签名与公证发布链路。 |
| `v1.0.0` | 对密码库格式、协议、迁移和核心行为做出稳定兼容承诺。 |

第一个完整产品以 macOS 为先，但产品类别和 Rust 数据模型保持平台中立，未来
增加 Windows 客户端不需要改变产品身份。iOS、浏览器插件、Passkey、团队协作、
共享和 KeptNear 托管服务不在首个完整版本范围内。

## 从源码构建

仓库已经固定经过复核的 Rust 工具链。在仓库根目录运行：

```sh
scripts/check.sh
scripts/build-macos.sh
```

构建并启动本地 macOS App：

```sh
script/build_and_run.sh
```

验证候选公开源码不包含本地 Agent 资料、真实密码库、明文导出、凭据和构建产物：

```sh
script/verify_public_source_tree.sh
script/verify_repository_secrets.sh
```

机器接口目前是开发者预览。使用前请阅读
[本地 CLI 说明](docs/cli-usage.md)和
[本地 MCP Host 配置](docs/mcp-setup.md)。

## 仓库结构

```text
apps/macos/             原生 SwiftUI macOS 客户端
crates/psw-core/        加密密码库模型和工作流
crates/psw-ffi/         macOS App 使用的 C ABI
crates/psw-broker/      设备本地授权边界
crates/keptnear-client/ 共享 Broker 认证客户端
crates/keptnear-mcp/    本地 stdio MCP 适配器
crates/psw-cli/         密码库诊断和 Broker CLI
docs/                   产品、架构、安全和发布文档
fixtures/               脱敏的密码库与导入测试数据
script/, scripts/       构建、打包和验证门禁
```

## 文档

建议首先阅读：

- [产品说明](docs/product-overview.zh-CN.md)
- [Product Overview](docs/product-overview.md)
- [能力状态](docs/capability-status.md)
- [架构](docs/architecture.md)
- [安全模型](docs/security-model.md)
- [密码库格式](docs/vault-format.md)

使用和运维：

- [构建和验证](docs/build.md)
- [macOS Alpha 打包](docs/macos-alpha-packaging.md)
- [macOS 服务激活可行性](docs/macos-service-activation-feasibility.md)
- [加密备份与恢复](docs/backup.md)
- [本地文件同步](docs/sync.md)
- [导入导出格式](docs/import-formats.md)
- [诊断](docs/diagnostics.md)
- [日志策略](docs/logging-policy.md)
- [本地 CLI 说明](docs/cli-usage.md)
- [本地 MCP Host 配置](docs/mcp-setup.md)

信任与发布证据：

- [发布就绪状态](docs/release-readiness.md)
- [安全审查证据](docs/security-review-evidence.md)
- [SQLCipher 分发证据](docs/sqlcipher-distribution-evidence.json)
- [开源就绪状态](docs/open-source-readiness.md)

## Issue 与安全报告

欢迎通过 GitHub Issues 提交可复现的 Bug 和范围明确的功能建议，维护者会尽力处理。
当前暂不接受外部 Pull Request，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

安全问题请按照 [SECURITY.md](SECURITY.md) 私下发送给
`Chase Chou <chasechou007@gmail.com>`。

## 许可证

Copyright (C) 2026 Chase Chou.

KeptNear 使用 GNU General Public License Version 3 only
（`GPL-3.0-only`），详见 [LICENSE](LICENSE)。
