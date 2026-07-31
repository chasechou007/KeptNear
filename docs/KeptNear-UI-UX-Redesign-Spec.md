# KeptNear macOS UI / UX 重构说明

> 文档用途：作为 KeptNear macOS 客户端 UI / UX 重构的设计基线和 Codex 实施说明  
> 适用仓库：`chasechou007/KeptNear`  
> 设计目标版本：macOS public alpha 前的视觉与交互整理  
> 状态：Design Proposal v1.0  
> 配套原型：`keptnear-ui-prototype.html`

## 0. 结论先行

本次重构不应理解为“给现有 SwiftUI 页面换一套颜色”，而应先重建应用的信息架构。

建议将 KeptNear 明确拆成两种界面模式：

1. **进入密码库之前：单页面任务模式**
   - 未选择密码库时显示 Welcome。
   - 已选择但未解锁时显示 Unlock。
   - 不出现空白侧栏、空白条目列表或无效工具栏。
2. **解锁密码库之后：三栏工作模式**
   - 左栏：导航与状态。
   - 中栏：条目搜索、筛选和列表。
   - 右栏：条目查看或编辑。

同时将条目详情从“始终可编辑的表单”改为：

- 默认是安全、清晰的只读详情；
- 用户显式进入编辑状态后才显示表单；
- 编辑状态具有固定的“取消 / 保存”动作；
- 复制、显示密码、打开网址是查看态的一等操作。

这套结构比当前界面更符合 macOS 桌面应用，也更符合密码管理器的核心心智模型：**先定位，再查看，必要时编辑**。

---

## 1. 现状诊断

### 1.1 当前界面的主要问题

| 问题 | 代码层原因 | 用户感知 |
| --- | --- | --- |
| 首次启动出现大面积空白栏 | `ContentView` 始终先创建 `NavigationSplitView`，首次运行仅替换各栏内部内容 | 像一个未完成或加载失败的应用 |
| 首次启动操作重复 | `firstRunSidebarPanel` 和 `firstRunDetailPanel` 同时提供新建、打开、最近打开 | 用户不知道哪一组才是主入口 |
| 工具栏图标过多且权重相同 | `ContentView.body.toolbar` 同时放置新建库、打开、最近、导入、导出、备份、恢复、复制到同步位置、刷新、锁定、关闭和设置 | 图标难以识别，日常操作与低频管理操作混在一起 |
| 左栏职责过载 | `sidebar` 同时承载密码库身份、同步准备度、搜索、五类筛选、安全设置、同步详情、条目列表和底部状态 | 信息密度高但层级弱，小空间内堆积大量控件 |
| 条目默认就是编辑表单 | `loginEditor`、`secureNoteEditor`、`creditCardEditor`、`softwareLicenseEditor` 都直接使用 `Form` | 查看、复制与修改混为一体，容易产生误编辑和保存状态不清 |
| 核心动作藏在表单底部 | 复制密码、复制验证码、打开 URL、收藏、复制、冲突处理、归档和删除都位于多行按钮区 | 高频复制操作离内容太远，危险动作与普通动作视觉接近 |
| 状态表达分散 | `syncReadinessPanel`、`syncStatusPanel`、`securityControls`、`passwordHealthPanel`、`statusBar` 分散在侧栏 | 用户难以区分“正常状态”“需要注意”和“需要立即处理” |
| 单文件承担过多职责 | `ContentView.swift` 约 3000 行，页面、状态、表单、弹窗、动作调度全部集中 | 后续每次 UI 改动都容易牵连业务与安全行为 |

### 1.2 现有实现值得保留的部分

这次重构必须保留 KeptNear 已经建立的产品和安全能力：

- Rust core 与 SwiftUI shell 的边界；
- `.pswvault` 目录格式和本地优先定位；
- `EditorActionGuard` 的未保存更改保护；
- 锁定或切换条目时清理已显示秘密值；
- 密码、TOTP、卡号、验证码、许可证密钥默认隐藏；
- 剪贴板定时清理和锁定时清理；
- 同步冲突、拒绝记录、过期编辑的处理语义；
- Keychain 便捷解锁边界；
- 导入、明文导出、备份与恢复的确认流程；
- 已有菜单命令和快捷键；
- English / 简体中文 / 日本語三种语言。

UI 重构不能以牺牲这些保护为代价。

---

## 2. 设计定位

KeptNear 的视觉气质建议定义为：

> **安静、克制、可信赖的本地数字保管空间。**

它不需要表现成“网络安全控制台”，也不需要模仿浏览器扩展或网页后台。

### 2.1 设计原则

1. **Local first, visually clear**
   - 让用户明确知道密码库位于哪里、当前是否锁定、同步是否就绪。
   - 不把本地文件同步表现成 KeptNear 托管的云服务。
2. **Daily actions first**
   - 新建条目、搜索、复制、显示、打开网址和锁定优先。
   - 导入、导出、备份、恢复、切换密码库属于低频管理操作。
3. **Read before edit**
   - 默认查看，显式编辑。
   - 查看态不渲染可编辑的秘密字段。
4. **Progressive disclosure**
   - 正常状态保持安静。
   - 只有出现冲突、结构缺失、暂停同步或弱密码时，才升级视觉提醒。
5. **Native macOS behavior**
   - 使用原生窗口、菜单、快捷键、Split View、Form、Sheet、Alert 和辅助功能语义。
   - 品牌色负责识别，系统语义色负责成功、警告和错误。
6. **Security behavior must remain observable**
   - 显示、复制、锁定、清理剪贴板等安全行为必须有可理解反馈。
   - 不使用装饰性动画掩盖安全状态。

---

## 3. 新的信息架构

### 3.1 应用状态与界面模式

| 应用状态 | 根视图 | 布局 | 核心动作 |
| --- | --- | --- | --- |
| 没有打开密码库 | `WelcomeView` | 单页面 | 打开密码库、新建密码库、最近使用 |
| 已打开但未解锁 | `UnlockView` | 单页面 | 输入主密码、Keychain 解锁、打开其他密码库 |
| 已解锁且有条目 | `VaultWorkspaceView` | 三栏 | 浏览、搜索、复制、编辑、新建、锁定 |
| 已解锁但为空 | `VaultWorkspaceView` + 空状态 | 左栏 + 中栏 + 右栏空状态 | 新建第一个项目、导入 |
| 搜索无结果 | 中栏空状态，右栏保持稳定 | 三栏 | 清除筛选 |
| 同步或安全问题 | 左栏出现计数和警告目的地 | 三栏 | 打开专属问题页 |

### 3.2 解锁后的三栏职责

#### 左栏：Vault Navigation

只负责“我在哪里”和“去哪里”：

- 当前密码库名称；
- 本地或可能同步的位置提示；
- 所有项目；
- 收藏；
- 类型：登录信息、安全笔记、信用卡、软件许可；
- 密码健康；
- 待解决冲突；
- 归档；
- 底部简短同步状态。

以下内容不再直接展开在左栏：

- 剪贴板超时设置；
- 自动锁定设置；
- 完整同步诊断；
- 拒绝记录文件列表；
- 密码健康的全部问题明细；
- 多个同步恢复按钮。

这些内容进入独立的 Security Center、Sync Center 或 Settings。

#### 中栏：Item List

只负责定位条目：

- 当前集合标题与数量；
- 搜索；
- 类型、标签、排序筛选；
- 条目列表；
- 条目上下文菜单；
- 搜索无结果状态。

推荐条目行显示：

- 类型图标或站点缩略标识；
- 标题；
- 用户名 / 域名 / 类型摘要；
- 收藏、冲突、归档等必要状态。

不要再把普通条目的第二行主要用于显示 `active / archived`。正常状态应保持安静，只有异常或特殊状态才需要强调。

#### 右栏：Item Detail / Editor

负责查看与编辑选中的内容：

- 查看态：内容卡片 + 字段级复制、显示、打开操作；
- 编辑态：明确的表单 + 固定取消/保存；
- 新建态：选择条目类型后填写；
- 冲突态：单独的冲突比较和处理页面；
- 未选中：友好的空状态，而不是空白。

---

## 4. 工具栏重新分级

### 4.1 日常工具栏保留

- 新建项目：主操作，带类型菜单；
- 锁定密码库；
- 更多：上下文和低频操作。

可以保留系统侧栏开关，但不需要自定义一组重复的导航按钮。

### 4.2 移入菜单的操作

建议在 macOS `File` / `Vault` / `Item` 菜单中组织：

**File**

- New Vault
- Open Vault
- Open Recent
- Import
- Export
- Backup
- Restore Backup

**Vault**

- Refresh Sync
- Copy Vault to Sync Location
- Reveal in Finder
- Lock Vault
- Close Vault

**Item**

- New Item
- Edit Item
- Save
- Copy Username / Password / TOTP / 其他秘密字段
- Favorite
- Duplicate
- Archive / Restore
- Delete

低频操作并没有消失，只是不再争夺日常界面的注意力。

---

## 5. 关键页面设计

## 5.1 Welcome

### 目标

首次打开时，只回答两个问题：

1. KeptNear 是什么？
2. 我现在应该做什么？

### 页面内容

- KeptNear 标记；
- 一句清晰主张，例如“你的密码，始终在你身边”；
- 本地优先、文件由用户保管、无需账户的说明；
- 主操作：打开现有密码库；
- 次操作：新建密码库；
- 存在最近密码库时，在操作区下方显示最近列表；
- 不存在最近密码库时，不显示禁用的“打开最近”按钮。

### 交互要求

- Welcome 不创建日常三栏结构；
- `⌘O` 打开密码库；
- 建议为新建密码库提供 `⇧⌘N`，避免与新建条目的 `⌘N` 冲突；
- 新建密码库继续使用系统 `NSSavePanel` 选择位置；
- 页面说明必须避免暗示 KeptNear 提供云同步服务。

## 5.2 Unlock

### 页面内容

- 当前密码库名称；
- 可读的密码库位置；
- 主密码输入；
- 可选的 Keychain 便捷解锁；
- 主操作“解锁密码库”；
- 如果已有便捷解锁，显示独立的 Keychain 解锁主操作；
- “打开其他密码库”位于工具栏或次级链接。

### 交互要求

- 打开页面后自动聚焦主密码；
- 回车执行解锁；
- 解锁失败时在输入区域附近显示错误，不把错误藏在全局状态栏；
- 不回显主密码；
- 解锁成功后清空输入和临时状态。

## 5.3 Main Workspace

### 左栏

- 宽度建议：`200–240 pt`，ideal `220 pt`；
- 可折叠；
- 当前导航项使用 Juniper 的浅色选中背景；
- 只有问题目的地出现橙色或红色计数。

### 中栏

- 宽度建议：`300–380 pt`，ideal `340 pt`；
- 搜索框固定在列表顶部；
- 筛选使用菜单或 active filter chips；
- 条目行高度建议 `56–64 pt`；
- 单击选择，双击可进入编辑或执行可配置默认动作；
- 右键菜单继续使用现有安全动作路径。

### 右栏

- 最小宽度建议：`480 pt`；
- 内容最大宽度建议：`720–780 pt`；
- 标题区显示类型、标题、收藏状态和主操作；
- 高频秘密字段使用字段行；
- 每个字段独立提供 Copy / Reveal；
- URL 提供 Open；
- Delete、Archive、Duplicate、Resolve Conflict 放入更多菜单；
- 默认不显示编辑表单。

## 5.4 Item Edit

### 模式

查看态和编辑态必须在视觉上明显不同。

编辑态建议：

- 右栏顶部出现固定编辑条；
- 左侧显示“编辑 GitHub”；
- 右侧固定“取消”和“保存更改”；
- `⌘S` 保存；
- `Esc` 取消或触发未保存更改确认；
- 导航离开继续走 `EditorActionGuard`；
- 保存成功后回到查看态；
- 保存失败或 stale draft 时停留在编辑态并就近显示原因。

### 密码字段

- 现有保存秘密与新输入秘密的语义必须区分；
- 不要用一个空 `SecureField` 暗示当前密码为空；
- 查看态显示已保存秘密的 redacted row；
- 编辑态可显示“保留当前密码”状态；
- 用户输入新密码后才替换；
- “清除已保存密码”放入明确的危险/次级动作，不与普通文本输入混淆；
- 密码生成器使用 popover 或内联 callout，不占据主表单的大段空间。

## 5.5 Security Center

从左栏“密码健康”进入，作为右侧主内容目的地：

- 顶部显示本次检查的时间和“重新检查”；
- 弱密码与重复密码分组；
- 问题行只显示允许返回的非秘密数据；
- 选择问题后通过现有安全路径定位条目；
- 数据变化后结果失效时，明确显示“需要重新检查”。

## 5.6 Sync Center

从左栏底部状态或问题入口进入：

- 当前密码库位置；
- 最近刷新时间；
- loaded / tombstones / conflicts / rejected counts；
- 自动刷新是否因未保存编辑而暂停；
- 同步结构准备度；
- 诊断、在 Finder 显示、隔离拒绝记录、刷新等恢复操作；
- 冲突进入专门的冲突解决页面。

正常情况下左栏只显示“同步就绪 · 刚刚刷新”，不展开完整诊断。

---

## 6. 视觉规范

## 6.1 色彩

保留现有品牌定义：

| 角色 | Light | 使用 |
| --- | --- | --- |
| Juniper | `#246B5E` | 主按钮、焦点、选中、品牌左叶 |
| Coral | `#D9684A` | 品牌右叶、少量装饰强调 |
| Graphite | `#202724` | 品牌、主要文本 |
| Sidebar neutral | 系统 sidebar material 或约 `#F1F3F0` | 左栏 |
| Detail surface | 系统 window background / white | 详情 |

规则：

- Coral 不作为危险操作颜色；
- 警告、错误、成功继续使用系统 `.orange`、`.red`、`.green`；
- 大面积背景使用系统语义背景，不硬编码为品牌色；
- 深色模式使用现有 `KeptNearBrand` 自适应颜色和系统材料。

## 6.2 字体层级

优先使用系统字体和语义样式：

- 大欢迎标题：`largeTitle` 或定制 34–44 pt；
- 详情标题：`title2`；
- 列表标题：`title3`；
- 导航与列表主文字：`body / callout`；
- 字段标签：`caption`；
- 状态和辅助信息：`caption2`。

不要通过大量粗体制造层级。标题、间距、分组和颜色应共同承担层级。

## 6.3 间距与圆角

- 基础间距：4 / 8 / 12 / 16 / 24 / 32；
- 条目行圆角：8；
- 字段分组卡片：10–12；
- Sheet：遵循系统；
- 按钮优先使用系统 `.bordered` / `.borderedProminent`；
- 不在每个区域都添加阴影，主要依靠系统层级和分隔线。

## 6.4 图标

- 功能图标继续使用 SF Symbols；
- 类型图标保持统一尺寸和容器；
- 品牌 Mark 只用于产品身份和关键空状态；
- 不把 Mark 当作普通状态图标重复使用；
- 同一功能必须固定一个 symbol，特别是同步、备份、恢复和复制到同步位置，避免当前多个动作共用相似循环箭头。

---

## 7. 交互规则

### 7.1 动作层级

每个页面原则上只出现一个 prominent 主操作。

- Welcome：打开密码库；
- Unlock：解锁；
- 空密码库：新建第一个项目；
- 查看条目：复制最主要秘密字段；
- 编辑条目：保存；
- 冲突页面：确认保留或合并方案。

### 7.2 Feedback

- 复制成功：轻量 HUD / toast，例如“密码已复制，将在 30 秒后清除”；
- 保存成功：回到查看态，并短暂显示“已保存”；
- 同步刷新：左栏底部更新最近刷新时间；
- 错误：就近显示，必要时同时在 Sync Center 留下可恢复入口；
- 破坏性操作：继续使用原生 confirmation dialog。

### 7.3 键盘

保留已有：

- `⌘N` 新建项目；
- `⌘S` 保存；
- `⌘F` 搜索；
- `⇧⌘R` 刷新同步；
- `⇧⌘L` 锁定；
- 已有 `⌥⌘` 复制字段快捷键。

建议新增：

- `⌘O` 打开密码库；
- `⇧⌘N` 新建密码库；
- `⌘E` 编辑所选项目；
- `Esc` 退出编辑或关闭临时界面；
- 上下方向键浏览列表。

### 7.4 窗口与响应式行为

- 建议最小窗口：`1040 × 680`；
- 左栏可隐藏；
- 中栏在较窄窗口保持不低于 `300 pt`；
- 右栏内容居中并限制最大宽度；
- 窗口极窄时优先让详情滚动，不压缩秘密字段到不可读；
- 记住用户调整后的栏宽属于可选增强，不作为第一阶段阻塞项。

---

## 8. SwiftUI 结构建议

当前 `ContentView.swift` 约 3000 行。重构应先拆结构，再换视觉，避免大爆炸式改写。

建议目录：

```text
apps/macos/Sources/PSWMac/
  AppShell/
    AppRootView.swift
    VaultWorkspaceView.swift
    VaultToolbar.swift
    WorkspaceDestination.swift
  Onboarding/
    WelcomeView.swift
    UnlockView.swift
    CreateVaultSheet.swift
  Sidebar/
    VaultNavigationSidebar.swift
    VaultIdentityView.swift
    VaultSyncSummaryView.swift
  ItemList/
    ItemListPane.swift
    ItemListRow.swift
    ItemListFiltersView.swift
  ItemDetail/
    ItemDetailPane.swift
    LoginDetailView.swift
    SecureNoteDetailView.swift
    CreditCardDetailView.swift
    SoftwareLicenseDetailView.swift
    SecretFieldRow.swift
  ItemEditor/
    ItemEditorPane.swift
    LoginEditorView.swift
    SecureNoteEditorView.swift
    CreditCardEditorView.swift
    SoftwareLicenseEditorView.swift
    EditorActionBar.swift
  Centers/
    SecurityCenterView.swift
    SyncCenterView.swift
    ConflictResolutionView.swift
  Components/
    EmptyStateView.swift
    InlineStatusBanner.swift
    CopyFeedbackPresenter.swift
```

### 8.1 根状态

建议增加纯 UI 派生状态，不复制核心业务状态：

```swift
enum AppPresentationState: Equatable {
    case welcome
    case locked
    case unlocked
}

enum WorkspaceDestination: Hashable {
    case allItems
    case favorites
    case itemType(ItemType)
    case passwordHealth
    case conflicts
    case archived
    case sync
}

enum ItemPresentationMode: Equatable {
    case empty
    case viewing(itemId: String)
    case editing(itemId: String)
    case creating(kind: ItemEditorKind)
}
```

这些状态用于界面组织，实际数据与动作仍由 `VaultStore` 提供。

### 8.2 安全动作适配

不要让子视图直接绕开现有守卫。

建议把当前 `requestEditorAction` 和 `performEditorAction` 的能力抽成一个可注入协调器或集中 action router：

```swift
struct VaultWorkspaceActions {
    let selectItem: (String?) -> Void
    let beginCreateItem: (ItemEditorKind) -> Void
    let beginEditItem: (String) -> Void
    let cancelEditing: () -> Void
    let saveCurrentEditor: () -> Void
    let lockVault: () -> Void
    let refreshSync: () -> Void
}
```

所有可能丢弃草稿、切换秘密上下文或破坏数据的动作必须继续通过：

- `EditorActionGuard`；
- 对应的 `VaultStore.can...` 能力；
- 现有确认流程；
- `revealedSecrets.clearAll()` 等清理逻辑。

### 8.3 查看态和编辑态

第一阶段可以复用现有 Form 和草稿模型：

1. 新增只读 Detail Views；
2. 选中条目时默认 Detail；
3. 点击 Edit 后再挂载现有 Editor；
4. 保存后回 Detail；
5. 取消或切换时调用现有 discard guard；
6. 等行为稳定后，再逐个重构四类 Editor 的布局。

这样可以降低一次性改动风险。

---

## 9. 实施顺序

## Phase 0：建立保护基线

- 运行现有 Rust、Swift 和脚本检查；
- 确认工作树状态；
- 列出 UI 重构不得改变的安全行为；
- 为 root state、未保存编辑、锁定清理和复制秘密补充必要测试；
- 不修改 Rust core、vault format 或 FFI。

## Phase 1：重构根界面

- 引入 `AppPresentationState`；
- 未打开密码库时直接显示 `WelcomeView`；
- 已打开未解锁时直接显示 `UnlockView`；
- 只有解锁后创建 `VaultWorkspaceView`；
- 移除首次启动侧栏与详情的重复入口；
- 精简首次启动工具栏。

验收重点：解决当前截图中的空白栏、重复按钮和工具栏噪声。

## Phase 2：建立真正的三栏工作区

- 使用三闭包 `NavigationSplitView`：`sidebar / content / detail`；
- 从当前 `sidebar` 中拆出条目列表；
- 导航、列表、详情分别承担单一职责；
- 保留筛选、选择、上下文菜单和草稿保护。

## Phase 3：新增只读详情

- 四类条目分别实现只读详情；
- 字段级 Copy / Reveal / Open；
- 危险和低频操作移入更多菜单；
- 查看态不创建可编辑的秘密输入控件。

## Phase 4：整理编辑体验

- 显式查看 / 编辑模式；
- 顶部固定取消 / 保存；
- 四类编辑表单统一结构；
- 密码生成器改为 popover 或 compact callout；
- stale draft 与冲突提示就近展示。

## Phase 5：Sync / Security 独立页面

- 把当前侧栏内的大段同步、安全和诊断内容移入专属页面；
- 左栏只保留状态摘要和问题计数；
- 保持所有恢复能力可达。

## Phase 6：视觉、深色模式与辅助功能

- 对齐色彩、间距、类型图标和空状态；
- 检查深色模式；
- 检查三种语言；
- 检查 VoiceOver label、键盘焦点和 Dynamic Type 可读性；
- 进行 1040×680、1440×900 和更大窗口测试。

每个 Phase 应独立提交并通过检查，不建议让 Codex 一次完成全部阶段。

---

## 10. 验收标准

### 首次启动

- [ ] 没有密码库时不显示任何空白导航栏或条目栏；
- [ ] 新建和打开入口只出现一套；
- [ ] 没有 recent vault 时不显示无意义的禁用操作；
- [ ] 文案明确本地优先和用户自选同步位置；
- [ ] `⌘O` 能打开密码库。

### 解锁

- [ ] 自动聚焦主密码；
- [ ] 回车可解锁；
- [ ] 解锁错误就近显示；
- [ ] 解锁后清空临时密码；
- [ ] Keychain 便捷解锁语义不变。

### 三栏工作区

- [ ] 左栏只负责导航和摘要；
- [ ] 中栏只负责搜索、筛选和条目；
- [ ] 右栏只负责所选目的地或条目；
- [ ] 工具栏不再平铺所有低频操作；
- [ ] 搜索与所有现有筛选仍可组合；
- [ ] 选择隐藏条目时仍按现有规则保护未保存编辑。

### 条目查看与编辑

- [ ] 默认只读；
- [ ] Secret 默认 redacted；
- [ ] Copy / Reveal / Open 就近可用；
- [ ] 编辑态具有固定 Save / Cancel；
- [ ] `⌘S` 可保存；
- [ ] 离开未保存编辑时出现现有确认；
- [ ] 锁定、切换密码库、切换条目时清理 Reveal 状态；
- [ ] archive、delete、conflict 等能力没有丢失。

### 视觉与可访问性

- [ ] Light / Dark 均可读；
- [ ] 三种语言不会截断关键动作；
- [ ] 所有 icon-only button 有 accessibility label 和 help；
- [ ] 颜色不是状态的唯一表达方式；
- [ ] 最小窗口下没有不可访问的主操作；
- [ ] 键盘可以完成搜索、选择、复制、编辑、保存和锁定。

### 回归

- [ ] `cargo test --workspace` 通过；
- [ ] macOS Swift 测试通过；
- [ ] `scripts/check.sh` 通过或对环境限制有明确记录；
- [ ] 不修改 vault format、cryptography、FFI 和导入导出格式；
- [ ] 不降低现有安全、同步与草稿保护。

---

## 11. 可直接交给 Codex 的执行提示词

下面的提示词用于启动实际改造。第一次只执行 Phase 0 和 Phase 1。

```text
请在当前 KeptNear 仓库中执行 macOS UI / UX 重构的第一阶段。

开始前完整阅读：

1. AGENTS.md 以及仓库内适用的开发约束；
2. docs/product-requirements.md；
3. docs/security-model.md；
4. docs/brand.md；
5. docs/sync.md；
6. deliverables/KeptNear-UI-UX-Redesign-Spec.md；
7. deliverables/keptnear-ui-prototype.html。

本轮范围仅包括：

- Phase 0：确认当前检查基线和不可回归的安全行为；
- Phase 1：重构根界面，分别建立 Welcome、Unlock 和 Unlocked Workspace 三种展示状态。

目标：

- 未打开密码库时只显示单页面 Welcome；
- 已打开但未解锁时只显示单页面 Unlock；
- 只有解锁后才显示工作区；
- 移除首次启动时重复的侧栏入口和详情入口；
- 首次启动与锁定状态不再出现空白栏；
- 精简这两个状态下的工具栏；
- 保持新建、打开、最近打开、主密码解锁和 Keychain 便捷解锁行为不变。

硬约束：

- 不修改 Rust core；
- 不修改 vault format、cryptography、FFI、导入导出格式或同步语义；
- 不绕过 EditorActionGuard；
- 不削弱锁定、切换密码库、切换条目时的秘密状态清理；
- 不删除现有功能或菜单命令；
- 不在本轮实现完整三栏、只读详情或编辑器重构；
- 优先拆分视图文件，不把更多职责继续堆入 ContentView.swift；
- 继续使用原生 SwiftUI 和 macOS 语义控件；
- 保持 English、简体中文和日本語可用；
- 保持现有 KeptNear 品牌 Mark 和调色板。

工作方式：

1. 先检查仓库和当前工作树，给出具体实施计划；
2. 标出本轮会修改和不会修改的文件；
3. 先补足或调整必要测试；
4. 实施 Phase 1；
5. 运行相关 Swift 测试、cargo test --workspace 和可用检查；
6. 对照设计说明进行手工状态检查；
7. 汇报变更、验证证据、剩余风险和下一阶段入口。

如果发现设计说明与现有安全行为冲突，以安全行为为准并暂停说明冲突，不要自行简化。
```

Phase 1 完成并人工确认后，再向 Codex 单独发出 Phase 2 提示，不要把所有阶段合并为一个超大任务。

---

## 12. 原型说明

`keptnear-ui-prototype.html` 是无外部依赖的交互式视觉原型，包含：

- 首次启动；
- 解锁密码库；
- 解锁后的主工作区；
- 条目编辑状态。

原型用于确认布局、层级和交互意图，不是要求 SwiftUI 逐像素模仿网页 CSS。

SwiftUI 实现应优先使用：

- `NavigationSplitView`；
- 系统 sidebar / window background；
- `toolbar` 和 `Commands`；
- 原生 `List`、`Form`、`LabeledContent`、`DisclosureGroup`；
- `ContentUnavailableView`（如果最低系统版本允许，否则使用自定义等价视图）；
- 系统 sheet、alert、confirmation dialog 和 accessibility API。

最终判断标准不是“是否和 HTML 像素相同”，而是：

1. 信息架构是否正确；
2. 高频操作是否更近；
3. 状态是否更容易理解；
4. 安全保护是否完整；
5. 是否具有克制、原生、可信赖的 KeptNear 气质。
