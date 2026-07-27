import Foundation

enum AppLanguage: String, CaseIterable, Identifiable {
    static let storageKey = "appLanguage"

    case english = "en"
    case simplifiedChinese = "zh-Hans"
    case japanese = "ja"

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .english:
            return "English"
        case .simplifiedChinese:
            return "简体中文"
        case .japanese:
            return "日本語"
        }
    }

    static func resolve(_ rawValue: String) -> AppLanguage {
        AppLanguage(rawValue: rawValue) ?? .english
    }
}

struct AppText {
    let selectedLanguage: AppLanguage

    init(_ rawLanguage: String) {
        selectedLanguage = AppLanguage.resolve(rawLanguage)
    }

    var newVault: String { choose("New Vault", "新建密码库", "新規保管庫") }
    var openVault: String { choose("Open Vault", "打开密码库", "保管庫を開く") }
    var openRecentVault: String { choose("Open Recent", "打开最近", "最近使った保管庫を開く") }
    var importItems: String { choose("Import", "导入", "インポート") }
    var exportItems: String { choose("Export", "导出", "エクスポート") }
    var backupVault: String { choose("Backup", "备份", "バックアップ") }
    var restoreBackup: String { choose("Restore", "恢复", "復元") }
    var copyVaultToSyncLocation: String { choose("Copy to Sync", "复制到同步", "同期先へコピー") }
    var syncRefresh: String { choose("Refresh Sync", "刷新同步", "同期を更新") }
    var syncStatus: String { choose("Sync Status", "同步状态", "同期状態") }
    var syncRefreshPaused: String {
        choose("Sync paused for unsaved edits", "同步因未保存编辑而暂停", "未保存の編集があるため同期を一時停止")
    }
    var syncRefreshPausedMessage: String {
        choose(
            "Encrypted file changes are waiting. Save or discard the current edit to refresh from disk.",
            "已有加密文件变更等待处理。保存或放弃当前编辑后将从磁盘刷新。",
            "暗号化ファイルの変更が待機しています。現在の編集を保存または破棄すると、ディスクから更新されます。"
        )
    }
    var syncReadiness: String { choose("Sync Readiness", "同步就绪", "同期準備状況") }
    var lastRefreshed: String { choose("Last refreshed", "上次刷新", "最終更新") }
    var loadedItems: String { choose("Loaded", "已加载", "読み込み済み") }
    var tombstones: String { choose("Tombstones", "删除标记", "削除マーカー") }
    var conflicts: String { choose("Conflicts", "冲突", "競合") }
    var rejectedRecords: String { choose("Rejected", "已拒绝", "拒否済み") }
    var rejectedItems: String { choose("Rejected Items", "拒绝项目", "拒否されたアイテム") }
    var rejectedTombstones: String {
        choose("Rejected Tombstones", "拒绝删除标记", "拒否された削除マーカー")
    }
    var rejectedFiles: String { choose("Rejected Files", "拒绝文件", "拒否されたファイル") }
    var quarantineRejectedRecords: String { choose("Quarantine", "隔离", "隔離") }
    func quarantineResult(_ quarantine: SyncQuarantinePayload) -> String {
        choose(
            "Quarantined \(quarantine.movedRecords) rejected records",
            "已隔离 \(quarantine.movedRecords) 条异常同步记录",
            "拒否された同期レコード \(quarantine.movedRecords) 件を隔離しました"
        )
    }
    func syncReadinessStatus(_ readiness: VaultSyncReadiness) -> String {
        switch readiness.status {
        case .completeLikelySynced:
            return choose(
                "Ready in likely sync folder",
                "已就绪，位于可能同步的位置",
                "同期フォルダと思われる場所で準備完了"
            )
        case .completeLocalOrUnknown:
            return choose(
                "Complete, local or unknown folder",
                "结构完整，本地或未知位置",
                "構成は完全です（ローカルまたは不明なフォルダ）"
            )
        case .incomplete:
            return choose("Incomplete vault structure", "密码库结构不完整", "保管庫の構成が不完全です")
        }
    }

    func requiredVaultStructure(_ complete: Bool) -> String {
        complete
            ? choose("Required structure complete", "必需结构完整", "必須構成は完全です")
            : choose("Required structure incomplete", "必需结构不完整", "必須構成が不完全です")
    }

    func missingRequiredPaths(_ labels: [String]) -> String {
        let value = labels.joined(separator: ", ")
        return choose(
            "Missing or invalid: \(value)",
            "缺失或类型错误：\(value)",
            "不足または無効：\(value)"
        )
    }

    var localUnlockEnvelopePresent: String {
        choose(
            "Local Keychain unlock on this Mac",
            "此 Mac 有本机钥匙串解锁",
            "このMacのローカルキーチェーン解除"
        )
    }

    func syncLocationHint(_ hint: VaultSyncLocationHint) -> String {
        if let provider = hint.provider {
            return choose(
                "Likely synced: \(provider.displayName)",
                "可能同步：\(provider.displayName)",
                "同期の可能性：\(provider.displayName)"
            )
        }
        return choose(
            "Local or unknown sync folder",
            "本地或未知同步位置",
            "ローカルまたは不明な同期フォルダ"
        )
    }
    func rejectedRecordKind(_ kind: String) -> String {
        switch kind {
        case "item":
            return choose("Item", "项目", "アイテム")
        case "tombstone":
            return choose("Tombstone", "删除标记", "削除マーカー")
        default:
            return choose("Record", "记录", "レコード")
        }
    }
    var syncIssueTitle: String { choose("Sync issue detected", "检测到同步问题", "同期の問題を検出") }
    var syncIssueMessage: String {
        choose(
            "Trusted records remain available. Review conflicts, quarantine rejected sync files, or inspect the vault directory.",
            "可信记录仍可使用。请处理冲突、隔离异常同步文件，或检查密码库目录。",
            "信頼済みのレコードは引き続き利用できます。競合を確認し、拒否された同期ファイルを隔離するか、保管庫ディレクトリを調べてください。"
        )
    }
    var showConflicts: String { choose("Show Conflicts", "显示冲突", "競合を表示") }
    var copySyncDiagnostics: String { choose("Copy Sync Diagnostics", "复制同步诊断", "同期診断をコピー") }
    var lock: String { choose("Lock", "锁定", "ロック") }
    var lockVault: String { choose("Lock Vault", "锁定密码库", "保管庫をロック") }
    var closeVault: String { choose("Close Vault", "关闭密码库", "保管庫を閉じる") }
    var forgotMasterPassword: String {
        choose("Forgot master password?", "忘记主密码？", "マスターパスワードを忘れた場合")
    }
    var forgottenPasswordRecoveryTitle: String {
        choose("Master Password Recovery", "主密码恢复", "マスターパスワードの復旧")
    }
    var forgottenPasswordNoRecoveryMessage: String {
        choose(
            "KeptNear cannot recover, reset, or bypass this vault's master password. If Keychain unlock is available, try it before replacing the vault.",
            "KeptNear 无法找回、重置或绕过此密码库的主密码。如果钥匙串解锁可用，请先尝试使用它。",
            "KeptNearでは、この保管庫のマスターパスワードを復旧、リセット、回避できません。キーチェーン解除が利用できる場合は、保管庫を置き換える前にお試しください。"
        )
    }
    var forgottenPasswordLocalCopiesWarning: String {
        choose(
            "Moving this vault to Trash affects only this local copy. Copies in sync providers, other devices, backups, or Trash must be handled separately.",
            "将此密码库移到废纸篓只会影响当前本地副本。同步服务、其他设备、备份或废纸篓中的副本需要另行处理。",
            "この保管庫をゴミ箱へ移動しても、このローカルコピーだけが対象です。同期サービス、他のデバイス、バックアップ、ゴミ箱内のコピーは別途処理が必要です。"
        )
    }
    var selectedVault: String { choose("Selected Vault", "当前密码库", "選択中の保管庫") }
    var closeAndCreateNewVault: String {
        choose("Close and Create New Vault", "关闭并新建密码库", "閉じて新しい保管庫を作成")
    }
    var moveVaultToTrashAndCreateNew: String {
        choose(
            "Move to Trash and Create New Vault",
            "移到废纸篓并新建密码库",
            "ゴミ箱へ移動して新しい保管庫を作成"
        )
    }
    var moveToTrash: String { choose("Move to Trash", "移到废纸篓", "ゴミ箱へ移動") }
    func moveForgottenVaultToTrashTitle(_ vaultName: String) -> String {
        choose(
            "Move “\(vaultName)” to Trash?",
            "将“\(vaultName)”移到废纸篓？",
            "「\(vaultName)」をゴミ箱へ移動しますか？"
        )
    }
    func moveForgottenVaultToTrashMessage(_ vaultName: String) -> String {
        choose(
            "This moves only the local copy of \(vaultName) to macOS Trash and clears its local Keychain unlock material. Synced, backed-up, and other-device copies are not deleted.",
            "此操作只会将 \(vaultName) 的本地副本移到 macOS 废纸篓，并清理其本机钥匙串解锁材料。同步副本、备份和其他设备上的副本不会被删除。",
            "\(vaultName) のローカルコピーだけをmacOSのゴミ箱へ移動し、ローカルのキーチェーン解除情報を消去します。同期済み、バックアップ済み、他のデバイス上のコピーは削除されません。"
        )
    }
    var vaultMenu: String { choose("Vault", "密码库", "保管庫") }
    var itemMenu: String { choose("Item", "项目", "アイテム") }
    var fileMenu: String { choose("File", "文件", "ファイル") }
    var editMenu: String { choose("Edit", "编辑", "編集") }
    var viewMenu: String { choose("View", "显示", "表示") }
    var windowMenu: String { choose("Window", "窗口", "ウインドウ") }
    var helpMenu: String { choose("Help", "帮助", "ヘルプ") }
    var saveItem: String { choose("Save Item", "保存项目", "アイテムを保存") }
    var focusSearch: String { choose("Focus Search", "聚焦搜索", "検索欄にフォーカス") }
    var copyUsername: String { choose("Copy Username", "复制用户名", "ユーザー名をコピー") }
    var copyPassword: String { choose("Copy Password", "复制密码", "パスワードをコピー") }
    var copyTotp: String { choose("Copy TOTP", "复制动态验证码", "TOTPをコピー") }
    var search: String { choose("Search", "搜索", "検索") }
    var localPasswordManager: String {
        choose("Local Password Manager", "本地密码管理器", "ローカルパスワードマネージャー")
    }
    var allItems: String { choose("All Items", "所有项目", "すべての項目") }
    var browse: String { choose("Browse", "浏览", "ブラウズ") }
    var itemTypes: String { choose("Types", "类型", "種類") }
    var securityAndMaintenance: String {
        choose("Security & Maintenance", "安全与维护", "セキュリティと管理")
    }
    var categories: String { choose("Categories", "类别", "カテゴリー") }
    func itemCount(_ count: Int) -> String {
        switch selectedLanguage {
        case .english:
            return count == 1 ? "1 item" : "\(count) items"
        case .simplifiedChinese:
            return "\(count) 个项目"
        case .japanese:
            return "\(count)件"
        }
    }
    var sidebarSyncReady: String { choose("Sync ready", "同步就绪", "同期準備完了") }
    var sidebarSyncNeedsAttention: String {
        choose("Sync needs attention", "同步需要处理", "同期の確認が必要")
    }
    var sidebarSyncWaiting: String {
        choose("Waiting for edits", "等待完成编辑", "編集完了を待機中")
    }
    var notRefreshedYet: String {
        choose("Not refreshed yet", "尚未刷新", "まだ更新されていません")
    }
    var vaultStatus: String { choose("Vault Status", "密码库状态", "保管庫の状態") }
    var vaultStatusUnavailable: String {
        choose(
            "Unlock the vault to view its latest local sync status.",
            "解锁密码库后可查看最新的本地同步状态。",
            "保管庫をロック解除すると、最新のローカル同期状態を確認できます。"
        )
    }
    var unlockToViewItems: String {
        choose(
            "Unlock to view items",
            "解锁后查看项目",
            "項目を表示するにはロックを解除"
        )
    }
    var noItemSelected: String {
        choose("No Item Selected", "未选择项目", "項目が選択されていません")
    }
    var noItemSelectedSubtitle: String {
        choose(
            "Select an item from the list or create a new one.",
            "从列表中选择一个项目，或新建项目。",
            "リストから項目を選択するか、新しい項目を作成してください。"
        )
    }
    var archive: String { choose("Archive", "归档", "アーカイブ") }
    var favoritesFilter: String { choose("Favorites", "收藏", "お気に入り") }
    var conflictsFilter: String { choose("Conflicts", "冲突", "競合") }
    var allTypes: String { choose("All Types", "所有类型", "すべての種類") }
    var allTags: String { choose("All Tags", "所有标签", "すべてのタグ") }
    func navigationTitle(_ destination: VaultNavigationDestination) -> String {
        switch destination {
        case .allItems:
            return allItems
        case .favorites:
            return favoritesFilter
        case .security:
            return security
        case .conflicts:
            return conflictsFilter
        case .archive:
            return archive
        case let .itemType(itemType):
            return itemTypeName(itemType)
        case let .tag(tag):
            return tag
        }
    }
    var clearFilters: String { choose("Clear Filters", "清除过滤", "フィルターをクリア") }
    var noMatchingItemsTitle: String {
        choose("No Matching Items", "没有匹配项目", "一致するアイテムはありません")
    }
    var noMatchingItemsSubtitle: String {
        choose(
            "Search or filters are hiding every item in this vault.",
            "搜索或过滤条件隐藏了此密码库中的所有项目。",
            "検索またはフィルターにより、この保管庫のすべてのアイテムが非表示になっています。"
        )
    }
    var security: String { choose("Security", "安全", "セキュリティ") }
    var passwordHealth: String { choose("Password Health", "密码健康", "パスワードの健全性") }
    var refreshPasswordHealth: String { choose("Check", "检查", "チェック") }
    var checkedLogins: String { choose("Checked", "已检查", "チェック済み") }
    var weakPasswords: String { choose("Weak", "弱密码", "弱い") }
    var reusedPasswords: String { choose("Reused", "重复", "再利用") }
    var passwordHealthNotChecked: String {
        choose(
            "Run a local check for weak and reused login passwords.",
            "本地检查弱密码和重复使用的登录密码。",
            "ログインパスワードの強度と再利用をローカルで確認します。"
        )
    }
    var noPasswordHealthIssues: String {
        choose(
            "No weak or reused login passwords found",
            "未发现弱密码或重复登录密码",
            "弱い、または再利用されているログインパスワードは見つかりませんでした"
        )
    }
    var showItem: String { choose("Show Item", "显示项目", "アイテムを表示") }
    func passwordHealthIssueLabel(_ issue: PasswordHealthIssue) -> String {
        switch issue.kind {
        case .weakPassword:
            return choose("Weak", "弱密码", "弱い")
        case .reusedPassword:
            if let reuseGroupSize = issue.reuseGroupSize {
                return choose(
                    "Reused x\(reuseGroupSize)",
                    "重复 x\(reuseGroupSize)",
                    "再利用 x\(reuseGroupSize)"
                )
            }
            return choose("Reused", "重复", "再利用")
        }
    }
    var trustBoundaryTitle: String { choose("Trust Boundary", "可信边界", "信頼境界") }
    var trustBoundaryLocalVaultTitle: String {
        choose("Local vault files", "本地密码库文件", "ローカル保管庫ファイル")
    }
    var trustBoundaryLocalVaultMessage: String {
        choose(
            "Vaults stay in a .pswvault directory you choose. The app does not use a hosted password service.",
            "密码库保存在你选择的 .pswvault 目录中。应用不使用托管密码服务。",
            "保管庫は選択した .pswvault ディレクトリに保存されます。このアプリはホスト型パスワードサービスを使用しません。"
        )
    }
    var trustBoundarySyncTitle: String { choose("Encrypted file sync", "加密文件同步", "暗号化ファイルの同期") }
    var trustBoundarySyncMessage: String {
        choose(
            "iCloud, Dropbox, Syncthing, and similar tools are untrusted transports for encrypted vault files.",
            "iCloud、Dropbox、Syncthing 等工具只是加密密码库文件的不可信传输层。",
            "iCloud、Dropbox、Syncthingなどは、暗号化された保管庫ファイルを運ぶ信頼されていない転送手段です。"
        )
    }
    var trustBoundaryDiagnosticsTitle: String { choose("Manual diagnostics", "手动诊断", "手動診断") }
    var trustBoundaryDiagnosticsMessage: String {
        choose(
            "Diagnostics are copied only when requested and exclude item content, secrets, full paths, and rejected record file names.",
            "诊断信息只会在你请求时复制，且不包含项目内容、秘密、完整路径或被拒绝记录的文件名。",
            "診断情報は要求した場合にのみコピーされ、アイテム内容、秘密情報、フルパス、拒否されたレコードのファイル名は含まれません。"
        )
    }
    var trustBoundaryFormatTitle: String { choose("Experimental format", "实验性格式", "実験的な形式") }
    var trustBoundaryFormatMessage: String {
        choose(
            "This alpha vault format is not a long-term compatibility contract until format freeze.",
            "在格式冻结之前，此 alpha 密码库格式不是长期兼容性承诺。",
            "形式が固定されるまで、このアルファ版の保管庫形式は長期互換性を保証しません。"
        )
    }
    var clipboard: String { choose("Clipboard", "剪贴板", "クリップボード") }
    var autoLock: String { choose("Auto-lock", "自动锁定", "自動ロック") }
    var disableKeychain: String { choose("Disable Keychain", "停用钥匙串", "キーチェーンを無効化") }
    var welcomeHeadline: String {
        choose(
            "Your passwords, always kept near.",
            "你的密码，始终在你身边。",
            "パスワードを、いつも手元に。"
        )
    }
    var welcomeMessage: String {
        choose(
            "KeptNear stores an encrypted vault in a location you choose. No account, no hosted cloud dependency, and complete offline access.",
            "KeptNear 将加密密码库存储在你选择的位置。无需账户，不依赖托管云服务，离线也能完整使用。",
            "KeptNearは、選択した場所に暗号化保管庫を保存します。アカウントもホスト型クラウドへの依存もなく、オフラインで完全に利用できます。"
        )
    }
    var encryptedVault: String { choose("Encrypted vault", "加密密码库", "暗号化保管庫") }
    var filesStayWithYou: String { choose("Files stay with you", "文件由你保管", "ファイルは自分で管理") }
    var localFirst: String { choose("Local first", "本地优先", "ローカルファースト") }
    var welcomeActionsTitle: String {
        choose("Start using KeptNear", "开始使用 KeptNear", "KeptNearを使い始める")
    }
    var welcomeActionsMessage: String {
        choose(
            "Open an existing .pswvault vault or create a new one on this Mac.",
            "打开已有的 .pswvault 密码库，或在这台 Mac 上创建一个新的密码库。",
            "既存の .pswvault 保管庫を開くか、このMacに新しい保管庫を作成します。"
        )
    }
    var openExistingVault: String {
        choose("Open Existing Vault", "打开现有密码库", "既存の保管庫を開く")
    }
    var welcomeSyncMessage: String {
        choose(
            "KeptNear does not upload your vault. You may place the encrypted directory in iCloud Drive, Dropbox, or another sync folder.",
            "KeptNear 不会上传你的密码库。你可以将加密目录放入 iCloud Drive、Dropbox 或其他同步文件夹。",
            "KeptNearが保管庫をアップロードすることはありません。暗号化ディレクトリはiCloud Drive、Dropbox、その他の同期フォルダに配置できます。"
        )
    }
    var firstRunTitle: String { choose("Start with a local vault", "从本地密码库开始", "ローカル保管庫から始める") }
    var firstRunSubtitle: String {
        choose(
            "Create or open an encrypted .pswvault directory on this Mac.",
            "创建或打开此 Mac 上的加密 .pswvault 目录。",
            "このMacで暗号化された .pswvault ディレクトリを作成または開きます。"
        )
    }
    var lockedVaultTitle: String { choose("Vault Locked", "密码库已锁定", "保管庫はロックされています") }
    var lockedVaultSubtitle: String {
        choose(
            "Unlock with the master password or local Keychain unlock.",
            "使用主密码或本机钥匙串解锁。",
            "マスターパスワードまたはローカルキーチェーンで解除します。"
        )
    }
    var emptyVaultTitle: String { choose("No Items Yet", "还没有项目", "アイテムはまだありません") }
    var emptyVaultSubtitle: String {
        choose(
            "Create a login or secure note, or import existing items to start using this vault.",
            "创建登录项、安全笔记，或导入现有项目即可开始使用此密码库。",
            "ログインまたはセキュアノートを作成するか、既存のアイテムをインポートして、この保管庫を使い始めます。"
        )
    }
    var masterPassword: String { choose("Master Password", "主密码", "マスターパスワード") }
    var confirmMasterPassword: String {
        choose("Confirm Master Password", "确认主密码", "マスターパスワードを確認")
    }
    var currentMasterPassword: String {
        choose("Current Master Password", "当前主密码", "現在のマスターパスワード")
    }
    var newMasterPassword: String { choose("New Master Password", "新主密码", "新しいマスターパスワード") }
    var confirmNewMasterPassword: String {
        choose("Confirm New Master Password", "确认新主密码", "新しいマスターパスワードを確認")
    }
    var changeMasterPassword: String {
        choose("Change Master Password", "更改主密码", "マスターパスワードを変更")
    }
    var masterPasswordRotationHint: String {
        choose(
            "Changes the password that unlocks this vault. Local Keychain unlock is disabled after a successful change.",
            "更改用于解锁此密码库的密码。成功更改后，本机钥匙串解锁会被停用。",
            "この保管庫を解除するパスワードを変更します。変更に成功すると、ローカルキーチェーン解除は無効になります。"
        )
    }
    var masterPasswordStrength: String { choose("Strength", "强度", "強度") }
    func masterPasswordStrengthLabel(_ strength: MasterPasswordStrength) -> String {
        let level: String
        switch strength.level {
        case .empty:
            level = choose("Not evaluated", "未评估", "未評価")
        case .weak:
            level = choose("Weak", "弱", "弱い")
        case .fair:
            level = choose("Fair", "一般", "普通")
        case .strong:
            level = choose("Strong", "强", "強い")
        case .veryStrong:
            level = choose("Very strong", "很强", "非常に強い")
        }
        return choose("Strength: \(level)", "强度：\(level)", "強度：\(level)")
    }
    func masterPasswordStrengthHint(_ strength: MasterPasswordStrength) -> String {
        switch strength.level {
        case .empty:
            return choose("Enter a master password.", "请输入主密码。", "マスターパスワードを入力してください。")
        case .weak:
            if strength.containsCommonWeakTerm {
                return choose(
                    "Avoid common words and predictable sequences.",
                    "避免常见词和可预测序列。",
                    "一般的な単語や予測しやすい並びを避けてください。"
                )
            }
            return choose(
                "Use a longer, less repetitive passphrase.",
                "请使用更长、更少重复的口令。",
                "より長く、繰り返しの少ないパスフレーズを使用してください。"
            )
        case .fair:
            return choose(
                "Usable, but more length or variety is safer.",
                "可以使用，但更长或更多样会更安全。",
                "使用できますが、長さや文字の種類を増やすとより安全です。"
            )
        case .strong:
            return choose(
                "Good local vault password.",
                "适合作为本地密码库主密码。",
                "ローカル保管庫に適したパスワードです。"
            )
        case .veryStrong:
            return choose(
                "Long and varied.",
                "长度和多样性都很好。",
                "十分な長さと多様性があります。"
            )
        }
    }
    var currentMasterPasswordRequired: String {
        choose(
            "Current master password is required",
            "请填写当前主密码",
            "現在のマスターパスワードを入力してください"
        )
    }
    var masterPasswordRequired: String {
        choose("Master password is required", "请填写主密码", "マスターパスワードを入力してください")
    }
    var newMasterPasswordRequired: String {
        choose(
            "New master password is required",
            "请填写新主密码",
            "新しいマスターパスワードを入力してください"
        )
    }
    var createMasterPasswordsDoNotMatch: String {
        choose("Master passwords do not match", "两次输入的主密码不一致", "マスターパスワードが一致しません")
    }
    var masterPasswordsDoNotMatch: String {
        choose(
            "New master passwords do not match",
            "两次输入的新主密码不一致",
            "新しいマスターパスワードが一致しません"
        )
    }
    var masterPasswordChanged: String { choose("Master password changed", "主密码已更改", "マスターパスワードを変更しました") }
    var unlockVaultFirst: String { choose("Unlock a vault first", "请先解锁密码库", "先に保管庫のロックを解除してください") }
    var openVaultFirst: String { choose("Open a vault first", "请先打开密码库", "先に保管庫を開いてください") }
    var enableKeychainUnlock: String {
        choose("Enable Keychain unlock", "启用钥匙串解锁", "キーチェーン解除を有効化")
    }
    var enterMasterPasswordToUnlock: String {
        choose(
            "Enter Master Password",
            "输入主密码解锁",
            "マスターパスワードを入力"
        )
    }
    func unlockVaultNamed(_ vaultName: String) -> String {
        choose(
            "Unlock \(vaultName)",
            "解锁 \(vaultName)",
            "\(vaultName)のロックを解除"
        )
    }
    var unlock: String { choose("Unlock", "解锁", "ロック解除") }
    var unlockWithKeychain: String { choose("Unlock with Keychain", "使用钥匙串解锁", "キーチェーンで解除") }
    var openOtherVault: String {
        choose("Open Another Vault", "打开其他密码库", "別の保管庫を開く")
    }
    var more: String { choose("More", "更多", "その他") }
    var editItem: String { choose("Edit", "编辑", "編集") }
    var title: String { choose("Title", "标题", "タイトル") }
    var itemType: String { choose("Item Type", "项目类型", "アイテムの種類") }
    var login: String { choose("Login", "登录项", "ログイン") }
    var secureNote: String { choose("Secure Note", "安全笔记", "セキュアノート") }
    var creditCard: String { choose("Credit Card", "信用卡", "クレジットカード") }
    var softwareLicense: String { choose("Software License", "软件许可证", "ソフトウェアライセンス") }
    func itemTypeName(_ itemType: String) -> String {
        switch itemType {
        case "login":
            return login
        case "secure note":
            return secureNote
        case "credit card":
            return creditCard
        case "software license":
            return softwareLicense
        default:
            return itemType
        }
    }
    var username: String { choose("Username", "用户名", "ユーザー名") }
    var password: String { choose("Password", "密码", "パスワード") }
    var savedPassword: String { choose("Saved Password", "已保存密码", "保存済みパスワード") }
    var clearSavedPassword: String {
        choose("Clear Saved Password", "清除已保存密码", "保存済みパスワードを消去")
    }
    var keepSavedPassword: String {
        choose("Keep Saved Password", "保留已保存密码", "保存済みパスワードを保持")
    }
    var savedPasswordWillBeCleared: String {
        choose("Password will be cleared", "密码将被清除", "パスワードは消去されます")
    }
    var reveal: String { choose("Reveal", "显示", "表示") }
    var hide: String { choose("Hide", "隐藏", "非表示") }
    var passwordGenerator: String { choose("Password Generator", "密码生成器", "パスワード生成") }
    var generatePassword: String { choose("Generate", "生成", "生成") }
    var selectPasswordCharacterClass: String {
        choose(
            "Select at least one password character class",
            "请至少选择一种密码字符类型",
            "パスワードの文字種を1つ以上選択してください"
        )
    }
    var length: String { choose("Length", "长度", "長さ") }
    var uppercase: String { choose("A-Z", "大写", "大文字") }
    var lowercase: String { choose("a-z", "小写", "小文字") }
    var numbers: String { choose("0-9", "数字", "数字") }
    var symbols: String { choose("Symbols", "符号", "記号") }
    var avoidAmbiguousCharacters: String {
        choose("Avoid ambiguous characters", "避免易混淆字符", "紛らわしい文字を避ける")
    }
    var url: String { choose("URL", "网址", "URL") }
    var urls: String { choose("URLs", "网址", "URL") }
    var copyURL: String { choose("Copy URL", "复制网址", "URLをコピー") }
    var openURL: String { choose("Open URL", "打开网址", "URLを開く") }
    var body: String { choose("Body", "正文", "本文") }
    var copyBody: String { choose("Copy Body", "复制正文", "本文をコピー") }
    var cardholderName: String { choose("Cardholder Name", "持卡人姓名", "カード名義人") }
    var cardNumber: String { choose("Card Number", "卡号", "カード番号") }
    var copyCardNumber: String { choose("Copy Card Number", "复制卡号", "カード番号をコピー") }
    var savedCardNumber: String { choose("Saved Card Number", "已保存卡号", "保存済みカード番号") }
    var clearSavedCardNumber: String {
        choose("Clear Saved Card Number", "清除已保存卡号", "保存済みカード番号を消去")
    }
    var keepSavedCardNumber: String {
        choose("Keep Saved Card Number", "保留已保存卡号", "保存済みカード番号を保持")
    }
    var savedCardNumberWillBeCleared: String {
        choose("Card number will be cleared", "卡号将被清除", "カード番号は消去されます")
    }
    var expiryMonth: String { choose("Expiry Month", "到期月份", "有効期限（月）") }
    var expiryYear: String { choose("Expiry Year", "到期年份", "有効期限（年）") }
    var expiration: String { choose("Expiration", "有效期", "有効期限") }
    var verificationCode: String { choose("Verification Code", "安全码", "セキュリティコード") }
    var copyVerificationCode: String {
        choose("Copy Verification Code", "复制安全码", "セキュリティコードをコピー")
    }
    var savedVerificationCode: String {
        choose("Saved Verification Code", "已保存安全码", "保存済みセキュリティコード")
    }
    var clearSavedVerificationCode: String {
        choose("Clear Saved Verification Code", "清除已保存安全码", "保存済みセキュリティコードを消去")
    }
    var keepSavedVerificationCode: String {
        choose("Keep Saved Verification Code", "保留已保存安全码", "保存済みセキュリティコードを保持")
    }
    var savedVerificationCodeWillBeCleared: String {
        choose("Verification code will be cleared", "安全码将被清除", "セキュリティコードは消去されます")
    }
    var product: String { choose("Product", "产品", "製品") }
    var licenseKey: String { choose("License Key", "许可证密钥", "ライセンスキー") }
    var copyLicenseKey: String { choose("Copy License Key", "复制许可证密钥", "ライセンスキーをコピー") }
    var savedLicenseKey: String { choose("Saved License Key", "已保存许可证密钥", "保存済みライセンスキー") }
    var clearSavedLicenseKey: String {
        choose("Clear Saved License Key", "清除已保存许可证密钥", "保存済みライセンスキーを消去")
    }
    var keepSavedLicenseKey: String {
        choose("Keep Saved License Key", "保留已保存许可证密钥", "保存済みライセンスキーを保持")
    }
    var savedLicenseKeyWillBeCleared: String {
        choose("License key will be cleared", "许可证密钥将被清除", "ライセンスキーは消去されます")
    }
    var licensedTo: String { choose("Licensed To", "授权给", "ライセンス所有者") }
    var tags: String { choose("Tags", "标签", "タグ") }
    var notes: String { choose("Notes", "备注", "メモ") }
    var account: String { choose("Account", "账户", "アカウント") }
    var websites: String { choose("Websites", "网站", "Webサイト") }
    var content: String { choose("Content", "内容", "内容") }
    var cardDetails: String { choose("Card Details", "卡片信息", "カード情報") }
    var protectedFields: String { choose("Protected Fields", "受保护字段", "保護された項目") }
    var licenseDetails: String { choose("License Details", "许可证信息", "ライセンス情報") }
    var otherDetails: String { choose("Other Details", "其他", "その他") }
    var notSet: String { choose("Not set", "未设置", "未設定") }
    var loadingItem: String { choose("Loading item...", "正在加载项目…", "アイテムを読み込み中…") }
    var detailConflictMessage: String {
        choose(
            "Resolve this conflict before copying, revealing, or editing protected fields.",
            "请先解决此冲突，再复制、显示或编辑受保护字段。",
            "保護された項目をコピー、表示、編集する前に競合を解決してください。"
        )
    }
    var detailArchivedMessage: String {
        choose(
            "This item is archived. Restore it from More to return it to the active list.",
            "此项目已归档。可从“更多”中恢复到活跃列表。",
            "このアイテムはアーカイブ済みです。「その他」から有効な一覧へ復元できます。"
        )
    }
    var create: String { choose("Create", "创建", "作成") }
    var save: String { choose("Save", "保存", "保存") }
    var newItem: String { choose("New", "新建", "新規") }
    var confirm: String { choose("Confirm", "确认", "確認") }
    var discardChanges: String { choose("Discard Changes", "放弃修改", "変更を破棄") }
    var unsavedChangesTitle: String { choose("Unsaved Changes", "有未保存修改", "未保存の変更") }
    var unsavedChangesMessage: String {
        choose(
            "Discard unsaved edits and continue?",
            "要放弃未保存的编辑并继续吗？",
            "未保存の編集を破棄して続行しますか？"
        )
    }
    var confirmActionTitle: String { choose("Confirm Action", "确认操作", "操作の確認") }
    var confirmArchiveTitle: String { choose("Archive Item?", "归档项目？", "アイテムをアーカイブしますか？") }
    var confirmArchiveMessage: String {
        choose(
            "Archive this item and hide it from the active list?",
            "要归档此项目并从活跃列表中隐藏吗？",
            "このアイテムをアーカイブして有効な一覧から非表示にしますか？"
        )
    }
    var confirmDeleteTitle: String { choose("Delete Item?", "删除项目？", "アイテムを削除しますか？") }
    var confirmDeleteMessage: String {
        choose(
            "Delete this item by writing a sync tombstone? This cannot be undone in the current app.",
            "要写入同步删除标记来删除此项目吗？当前应用内无法撤销。",
            "同期用の削除マーカーを書き込んでこのアイテムを削除しますか？現在のアプリでは元に戻せません。"
        )
    }
    var resolveConflict: String { choose("Resolve Conflict", "解决冲突", "競合を解決") }
    var loadConflictVersions: String { choose("Load Versions", "加载版本", "バージョンを読み込む") }
    var conflictVersions: String { choose("Conflict Versions", "冲突版本", "競合バージョン") }
    var staleSaveReviewTitle: String {
        choose("Current Sync vs Local Draft", "当前同步版本与本地草稿", "現在の同期版とローカル下書き")
    }
    func staleSaveReviewMessage(_ itemTitle: String) -> String {
        choose(
            "\(itemTitle) changed on disk. Review the preserved draft before saving again.",
            "\(itemTitle) 已在磁盘上变化。再次保存前请复核已保留的本地草稿。",
            "\(itemTitle) はディスク上で変更されています。再度保存する前に、保持された下書きを確認してください。"
        )
    }
    var currentSyncedVersion: String { choose("Current", "当前", "現在") }
    var preservedLocalDraft: String { choose("Draft", "草稿", "下書き") }
    var noVisibleStaleSaveDifferences: String {
        choose("Only hidden fields changed.", "只有隐藏字段发生变化。", "非表示フィールドのみ変更されています。")
    }
    var yes: String { choose("Yes", "是", "はい") }
    var no: String { choose("No", "否", "いいえ") }
    var changedFields: String { choose("Changed", "已更改", "変更あり") }
    var mergeFields: String { choose("Merge Fields", "合并字段", "フィールドをマージ") }
    var mergeBase: String { choose("Merge Base", "合并基底", "マージ基準") }
    var mergeConflict: String { choose("Merge Conflict", "合并冲突", "マージ競合") }
    var keepVersion: String { choose("Keep", "保留", "保持") }
    var revision: String { choose("Revision", "修订", "リビジョン") }
    var redactedValue: String { choose("Hidden", "已隐藏", "非表示") }
    var conflictResolved: String { choose("Conflict resolved", "冲突已解决", "競合を解決しました") }
    var conflictMerged: String { choose("Conflict merged", "冲突已合并", "競合をマージしました") }
    var noSelectedConflict: String {
        choose("No selected conflict", "未选择冲突项目", "競合が選択されていません")
    }
    var conflictResolutionHint: String {
        choose(
            "Keeps the current version and writes a new active revision.",
            "保留当前版本并写入新的活跃修订。",
            "現在のバージョンを保持し、新しい有効リビジョンを書き込みます。"
        )
    }
    var totp: String { choose("TOTP", "动态验证码", "TOTP") }
    var totpSecret: String { choose("TOTP Secret", "动态验证码密钥", "TOTPシークレット") }
    var savedTotpSecret: String {
        choose("Saved TOTP Secret", "已保存动态验证码密钥", "保存済みTOTPシークレット")
    }
    var favorite: String { choose("Favorite", "收藏", "お気に入りに追加") }
    var unfavorite: String { choose("Unfavorite", "取消收藏", "お気に入りから削除") }
    var duplicate: String { choose("Duplicate", "复制", "複製") }
    var restore: String { choose("Restore", "恢复", "復元") }
    var delete: String { choose("Delete", "删除", "削除") }
    var displayName: String { choose("Display Name", "显示名称", "表示名") }
    var cancel: String { choose("Cancel", "取消", "キャンセル") }
    var settings: String { choose("Settings", "设置", "設定") }
    var settingsGeneral: String { choose("General", "通用", "一般") }
    var languageLabel: String { choose("Language", "语言", "言語") }
    var languageHint: String { choose("Changes apply immediately.", "更改会立即生效。", "変更はすぐに反映されます。") }
    var diagnostics: String { choose("Diagnostics", "诊断", "診断") }
    var copyDiagnostics: String { choose("Copy Diagnostics", "复制诊断信息", "診断情報をコピー") }
    var diagnosticsHint: String {
        choose(
            "Copies app, core, vault state, sync counts, and preferences. No item content, secrets, or full paths are included.",
            "复制应用、核心、密码库状态、同步计数和偏好设置。不包含项目内容、秘密或完整路径。",
            "アプリ、コア、保管庫の状態、同期件数、設定をコピーします。アイテム内容、秘密情報、フルパスは含まれません。"
        )
    }
    var diagnosticsCopied: String { choose("Diagnostics copied", "诊断信息已复制", "診断情報をコピーしました") }
    var clipboardPreferenceHint: String {
        choose(
            "Copied secrets are cleared after this delay.",
            "复制的敏感内容会在此时间后清除。",
            "コピーした秘密情報はこの時間が経過すると消去されます。"
        )
    }
    var autoLockPreferenceHint: String {
        choose(
            "Unlocked vaults lock after this idle duration.",
            "密码库会在空闲达到此时间后自动锁定。",
            "ロック解除された保管庫は、操作がない状態がこの時間続くとロックされます。"
        )
    }
    var cleanupLegacyKeychain: String {
        choose("Clean Up Legacy Keychain", "清理旧版钥匙串条目", "古いキーチェーン項目をクリーンアップ")
    }
    var cleanupLegacyKeychainHint: String {
        choose(
            "Removes old alpha Keychain entries for this vault. Current local unlock material is kept.",
            "移除此密码库的旧 alpha 钥匙串条目。当前本机解锁材料会保留。",
            "この保管庫の古いアルファ版キーチェーン項目を削除します。現在のローカル解除情報は保持されます。"
        )
    }
    var legacyKeychainEntriesRemoved: String {
        choose("Legacy Keychain entries removed", "旧版钥匙串条目已移除", "古いキーチェーン項目を削除しました")
    }
    var noLegacyKeychainEntriesFound: String {
        choose(
            "No legacy Keychain entries found",
            "未发现旧版钥匙串条目",
            "古いキーチェーン項目は見つかりませんでした"
        )
    }
    var chooseFile: String { choose("Choose File", "选择文件", "ファイルを選択") }
    var sourceFile: String { choose("Source File", "来源文件", "元ファイル") }
    var exportFile: String { choose("Export File", "导出文件", "エクスポートファイル") }
    var importable: String { choose("Importable", "可导入", "インポート可能") }
    var exported: String { choose("Exported", "已导出", "エクスポート済み") }
    var skipped: String { choose("Skipped", "跳过", "スキップ") }
    var duplicates: String { choose("Duplicates", "重复", "重複") }
    var warnings: String { choose("Warnings", "警告", "警告") }
    var backupDestination: String { choose("Backup Destination", "备份位置", "バックアップ先") }
    var restoredVault: String { choose("Restored Vault", "恢复后的密码库", "復元した保管庫") }
    var syncDestination: String { choose("Sync Destination", "同步位置", "同期先") }
    var itemFiles: String { choose("Item Files", "项目记录", "アイテムファイル") }
    var attachments: String { choose("Attachments", "附件", "添付ファイル") }
    var keepDuplicates: String { choose("Keep duplicates", "保留重复项", "重複を保持") }
    var importNow: String { choose("Import", "导入", "インポート") }
    var revealInFinder: String { choose("Reveal in Finder", "在访达中显示", "Finderで表示") }
    var moveSourceToTrash: String {
        choose("Move Source to Trash", "将来源移到废纸篓", "元ファイルをゴミ箱へ移動")
    }
    var moveExportToTrash: String {
        choose("Move Export to Trash", "将导出文件移到废纸篓", "エクスポートファイルをゴミ箱へ移動")
    }
    var done: String { choose("Done", "完成", "完了") }
    var plaintextImportWarning: String {
        choose(
            "Export files may contain plaintext secrets. Delete or secure the source file after import.",
            "导出文件可能包含明文密码。导入后请删除或妥善保存来源文件。",
            "エクスポートファイルには平文の秘密情報が含まれる場合があります。インポート後に元ファイルを削除するか、安全に保管してください。"
        )
    }
    var exportNow: String { choose("Export", "导出", "エクスポート") }
    var plaintextExportTitle: String {
        choose("Export Plaintext Secrets?", "要导出明文秘密吗？", "秘密情報を平文でエクスポートしますか？")
    }
    var plaintextExportWarning: String {
        choose(
            "The exported file contains plaintext secrets. Delete or secure it after migration.",
            "导出的文件包含明文秘密。迁移完成后请删除或妥善保存。",
            "エクスポートしたファイルには平文の秘密情報が含まれます。移行後に削除するか、安全に保管してください。"
        )
    }
    var titleRequired: String { choose("Title is required", "请填写标题", "タイトルを入力してください") }

    func plaintextExportMessage(_ fileName: String) -> String {
        choose(
            "Write plaintext vault data to \(fileName)? Anyone with this file can read the exported secrets.",
            "要将密码库数据以明文写入 \(fileName) 吗？任何拥有此文件的人都可以读取导出的秘密。",
            "\(fileName) に保管庫データを平文で書き込みますか？このファイルを入手した人は誰でも、エクスポートした秘密情報を読み取れます。"
        )
    }

    func itemStatus(_ status: String) -> String {
        switch status {
        case "active":
            return choose("active", "活跃", "有効")
        case "archived":
            return choose("archived", "已归档", "アーカイブ済み")
        case "deleted":
            return choose("deleted", "已删除", "削除済み")
        case "conflicted":
            return choose("conflicted", "有冲突", "競合あり")
        default:
            return status
        }
    }

    func statusMessage(_ message: String) -> String {
        switch message {
        case let message where message.localizedCaseInsensitiveContains("invalid vault credentials"):
            return choose(
                "Incorrect master password. Try again.",
                "主密码不正确，请重试。",
                "マスターパスワードが正しくありません。もう一度お試しください。"
            )
        case "Rust core connected":
            return choose("Rust core connected", "Rust 核心已连接", "Rustコアに接続しました")
        case "Rust core library not loaded":
            return choose("Rust core library not loaded", "Rust 核心库未加载", "Rustコアライブラリが読み込まれていません")
        case "Vault created":
            return choose("Vault created", "密码库已创建", "保管庫を作成しました")
        case "Vault creation canceled":
            return choose("Vault creation canceled", "已取消创建密码库", "保管庫の作成をキャンセルしました")
        case "Vault creation failed":
            return choose("Vault creation failed", "创建密码库失败", "保管庫の作成に失敗しました")
        case let message where message.contains("target vault directory already exists and is not empty"):
            return choose(
                "Choose an empty location for the new vault",
                "请选择一个空位置创建密码库",
                "新しい保管庫には空の場所を選択してください"
            )
        case "Vault unlocked":
            return choose("Vault unlocked", "密码库已解锁", "保管庫のロックを解除しました")
        case "Vault unlocked with Keychain":
            return choose("Vault unlocked with Keychain", "已使用钥匙串解锁", "キーチェーンで保管庫のロックを解除しました")
        case "Keychain unlock disabled":
            return choose("Keychain unlock disabled", "钥匙串解锁已停用", "キーチェーン解除を無効にしました")
        case "Vault locked":
            return choose("Vault locked", "密码库已锁定", "保管庫をロックしました")
        case "Unlock a vault first":
            return unlockVaultFirst
        case "Open a vault first":
            return openVaultFirst
        case "Unsupported vault file":
            return choose("Unsupported vault file", "不支持的密码库文件", "サポートされていない保管庫ファイル")
        case "Archived":
            return choose("Archived", "已归档", "アーカイブしました")
        case "Restored":
            return choose("Restored", "已恢复", "復元しました")
        case "Only archived items can be restored":
            return choose(
                "Only archived items can be restored",
                "只有已归档项目可以恢复",
                "アーカイブ済みのアイテムのみ復元できます"
            )
        case "Deleted":
            return choose("Deleted", "已删除", "削除しました")
        case "Saved":
            return choose("Saved", "已保存", "保存しました")
        case "Duplicated":
            return choose("Duplicated", "已复制", "複製しました")
        case "Username copied":
            return choose("Username copied", "用户名已复制", "ユーザー名をコピーしました")
        case "login item has no username":
            return choose("login item has no username", "登录项没有用户名", "ログインにユーザー名がありません")
        case "Password copied":
            return choose("Password copied", "密码已复制", "パスワードをコピーしました")
        case "login item has no password":
            return choose("login item has no password", "登录项没有密码", "ログインにパスワードがありません")
        case "URL copied":
            return choose("URL copied", "网址已复制", "URLをコピーしました")
        case "login item has no URL":
            return choose("login item has no URL", "登录项没有网址", "ログインにURLがありません")
        case "Select at least one password character class":
            return selectPasswordCharacterClass
        case "URL opened":
            return choose("URL opened", "网址已打开", "URLを開きました")
        case "login item has no valid URL":
            return choose("login item has no valid URL", "登录项没有可打开的网址", "ログインに有効なURLがありません")
        case "TOTP copied":
            return choose("TOTP copied", "动态验证码已复制", "TOTPをコピーしました")
        case "login item has no TOTP secret":
            return choose(
                "login item has no TOTP secret",
                "登录项没有动态验证码密钥",
                "ログインにTOTPシークレットがありません"
            )
        case "Secure note body copied":
            return choose("Secure note body copied", "安全笔记正文已复制", "セキュアノートの本文をコピーしました")
        case "secure note has no body":
            return choose("secure note has no body", "安全笔记没有正文", "セキュアノートに本文がありません")
        case "Card number copied":
            return choose("Card number copied", "卡号已复制", "カード番号をコピーしました")
        case "credit card has no card number":
            return choose("credit card has no card number", "信用卡没有卡号", "クレジットカードにカード番号がありません")
        case "Verification code copied":
            return choose("Verification code copied", "安全码已复制", "セキュリティコードをコピーしました")
        case "credit card has no verification code":
            return choose(
                "credit card has no verification code",
                "信用卡没有安全码",
                "クレジットカードにセキュリティコードがありません"
            )
        case "License key copied":
            return choose("License key copied", "许可证密钥已复制", "ライセンスキーをコピーしました")
        case "software license has no license key":
            return choose(
                "software license has no license key",
                "软件许可证没有许可证密钥",
                "ソフトウェアライセンスにライセンスキーがありません"
            )
        case "Import preview ready":
            return choose("Import preview ready", "导入预览已就绪", "インポートプレビューの準備ができました")
        case "Import completed":
            return choose("Import completed", "导入已完成", "インポートが完了しました")
        case let message where message.hasPrefix("Export completed:"):
            return exportStatusMessage(message)
        case let message where message.hasPrefix("Backup completed:"):
            return backupStatusMessage(message)
        case let message where message.hasPrefix("Restore completed:"):
            return restoreStatusMessage(message)
        case let message where message.hasPrefix("Vault copied to sync location:"):
            return copyToSyncStatusMessage(message)
        case "Sync refreshed":
            return choose("Sync refreshed", "同步已刷新", "同期を更新しました")
        case "Password health refreshed":
            return choose("Password health refreshed", "密码健康已刷新", "パスワードの健全性を更新しました")
        case "Filters cleared":
            return choose("Filters cleared", "过滤已清除", "フィルターをクリアしました")
        case "Sync refresh paused for unsaved edits":
            return choose(
                "Sync refresh paused for unsaved edits",
                "有未保存修改，已暂停同步刷新",
                "未保存の編集があるため同期の更新を一時停止しました"
            )
        case "Save or discard edits before importing":
            return choose(
                "Save or discard edits before importing",
                "请先保存或放弃修改再导入",
                "インポートする前に編集を保存または破棄してください"
            )
        case "Save or discard edits before sync recovery":
            return choose(
                "Save or discard edits before sync recovery",
                "请先保存或放弃修改再进行同步恢复",
                "同期を復旧する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before exporting":
            return choose(
                "Save or discard edits before exporting",
                "请先保存或放弃修改再导出",
                "エクスポートする前に編集を保存または破棄してください"
            )
        case "Save or discard edits before backing up":
            return choose(
                "Save or discard edits before backing up",
                "请先保存或放弃修改再备份",
                "バックアップする前に編集を保存または破棄してください"
            )
        case "Save or discard edits before restoring backup":
            return choose(
                "Save or discard edits before restoring backup",
                "请先保存或放弃修改再恢复备份",
                "バックアップを復元する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before copying to sync":
            return choose(
                "Save or discard edits before copying to sync",
                "请先保存或放弃修改再复制到同步位置",
                "同期先へコピーする前に編集を保存または破棄してください"
            )
        case "Save or discard edits before changing selection":
            return choose(
                "Save or discard edits before changing selection",
                "请先保存或放弃修改再切换项目",
                "選択を変更する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before archiving":
            return choose(
                "Save or discard edits before archiving",
                "请先保存或放弃修改再归档",
                "アーカイブする前に編集を保存または破棄してください"
            )
        case "Save or discard edits before deleting":
            return choose(
                "Save or discard edits before deleting",
                "请先保存或放弃修改再删除",
                "削除する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before updating favorite":
            return choose(
                "Save or discard edits before updating favorite",
                "请先保存或放弃修改再更新收藏",
                "お気に入りを変更する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before duplicating":
            return choose(
                "Save or discard edits before duplicating",
                "请先保存或放弃修改再复制项目",
                "複製する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before restoring":
            return choose(
                "Save or discard edits before restoring",
                "请先保存或放弃修改再恢复",
                "復元する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before resolving conflict":
            return choose(
                "Save or discard edits before resolving conflict",
                "请先保存或放弃修改再解决冲突",
                "競合を解決する前に編集を保存または破棄してください"
            )
        case "Save or discard edits before switching vaults":
            return choose(
                "Save or discard edits before switching vaults",
                "请先保存或放弃修改再切换密码库",
                "保管庫を切り替える前に編集を保存または破棄してください"
            )
        case "Save or discard edits before closing vault":
            return choose(
                "Save or discard edits before closing vault",
                "请先保存或放弃修改再关闭密码库",
                "保管庫を閉じる前に編集を保存または破棄してください"
            )
        case let message where message.hasPrefix("Quarantined "):
            return quarantineStatusMessage(message)
        case "Conflict resolved":
            return conflictResolved
        case "Conflict merged":
            return conflictMerged
        case "No selected conflict":
            return noSelectedConflict
        case "Resolve conflict before editing":
            return choose("Resolve conflict before editing", "请先解决冲突再编辑", "編集する前に競合を解決してください")
        case "Resolve conflict before copying":
            return choose("Resolve conflict before copying", "请先解决冲突再复制", "コピーする前に競合を解決してください")
        case "Resolve conflict before revealing":
            return choose("Resolve conflict before revealing", "请先解决冲突再显示", "表示する前に競合を解決してください")
        case "Refresh sync before editing this item":
            return choose(
                "Refresh sync before editing this item",
                "请刷新同步后再编辑此项目",
                "このアイテムを編集する前に同期を更新してください"
            )
        case "Local edit kept; current synced item reloaded":
            return choose(
                "Local edit kept; current synced item reloaded",
                "已保留本地编辑，并重新载入当前同步版本",
                "ローカル編集を保持し、現在の同期版を再読み込みしました"
            )
        case let message where message.hasSuffix(" conflict versions"):
            return conflictVersionsStatus(message)
        case let message where itemCountStatus(message) != nil:
            return itemCountStatus(message) ?? message
        case "Title is required":
            return titleRequired
        case "Unsupported item type":
            return choose("Unsupported item type", "暂不支持的项目类型", "サポートされていないアイテムの種類")
        case "Recent vault not found":
            return choose("Recent vault not found", "最近密码库不存在", "最近使った保管庫が見つかりません")
        case "Current master password is required":
            return currentMasterPasswordRequired
        case "Master password is required":
            return masterPasswordRequired
        case "New master password is required":
            return newMasterPasswordRequired
        case "Master passwords do not match":
            return createMasterPasswordsDoNotMatch
        case "New master passwords do not match":
            return masterPasswordsDoNotMatch
        case "Master password changed":
            return masterPasswordChanged
        case "Import source revealed":
            return choose("Import source revealed", "已显示导入来源", "インポート元を表示しました")
        case "Import source moved to Trash":
            return choose("Import source moved to Trash", "导入来源已移到废纸篓", "インポート元をゴミ箱へ移動しました")
        case "Plaintext export revealed":
            return choose("Plaintext export revealed", "已显示明文导出文件", "平文エクスポートを表示しました")
        case "Backup destination revealed":
            return choose("Backup destination revealed", "已显示备份位置", "バックアップ先を表示しました")
        case "Restored vault revealed":
            return choose("Restored vault revealed", "已显示恢复后的密码库", "復元した保管庫を表示しました")
        case "Copied sync vault revealed":
            return choose("Copied sync vault revealed", "已显示同步副本", "同期用の保管庫コピーを表示しました")
        case "Plaintext export moved to Trash":
            return choose(
                "Plaintext export moved to Trash",
                "明文导出文件已移到废纸篓",
                "平文エクスポートをゴミ箱へ移動しました"
            )
        case "Diagnostics copied":
            return diagnosticsCopied
        case "Showing conflicts":
            return choose("Showing conflicts", "正在显示冲突", "競合を表示しています")
        case "Vault revealed in Finder":
            return choose("Vault revealed in Finder", "已在访达中显示密码库", "Finderで保管庫を表示しました")
        case "Vault closed":
            return choose("Vault closed", "密码库已关闭", "保管庫を閉じました")
        case "No vault selected":
            return choose("No vault selected", "未选择密码库", "保管庫が選択されていません")
        case "Lock the vault before moving it to Trash":
            return choose(
                "Lock the vault before moving it to Trash",
                "请先锁定密码库，再将其移到废纸篓",
                "ゴミ箱へ移動する前に保管庫をロックしてください"
            )
        case "Only a local .pswvault directory can be moved to Trash":
            return choose(
                "Only a local .pswvault directory can be moved to Trash",
                "只能将本地 .pswvault 密码库目录移到废纸篓",
                "ローカルの.pswvault保管庫ディレクトリだけをゴミ箱へ移動できます"
            )
        case "Vault could not be moved to Trash":
            return choose(
                "Vault could not be moved to Trash",
                "无法将密码库移到废纸篓",
                "保管庫をゴミ箱へ移動できませんでした"
            )
        case "Vault moved to Trash":
            return choose(
                "Vault moved to Trash",
                "密码库已移到废纸篓",
                "保管庫をゴミ箱へ移動しました"
            )
        case "Vault moved to Trash, but Keychain cleanup failed":
            return choose(
                "Vault moved to Trash, but Keychain cleanup failed",
                "密码库已移到废纸篓，但钥匙串清理失败",
                "保管庫をゴミ箱へ移動しましたが、キーチェーンの消去に失敗しました"
            )
        case "Legacy Keychain entries removed":
            return legacyKeychainEntriesRemoved
        case "No legacy Keychain entries found":
            return noLegacyKeychainEntriesFound
        default:
            return message
        }
    }

    func isErrorStatusMessage(_ message: String) -> Bool {
        if message.localizedCaseInsensitiveContains("invalid vault credentials") {
            return true
        }
        return [
            "No vault selected",
            "Lock the vault before moving it to Trash",
            "Only a local .pswvault directory can be moved to Trash",
            "Vault could not be moved to Trash",
            "Vault moved to Trash, but Keychain cleanup failed"
        ].contains(message)
    }

    private func itemCountStatus(_ message: String) -> String? {
        let parts = message.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 2,
              parts[1] == "items",
              let count = Int(parts[0]),
              count >= 0,
              String(count) == String(parts[0])
        else {
            return nil
        }

        return choose("\(count) items", "\(count) 个项目", "\(count)件のアイテム")
    }

    func durationOption(_ seconds: TimeInterval) -> String {
        let wholeSeconds = Int(seconds)
        if wholeSeconds >= 60, wholeSeconds % 60 == 0 {
            return "\(wholeSeconds / 60)m"
        }
        return "\(wholeSeconds)s"
    }

    private func choose(_ english: String, _ simplifiedChinese: String, _ japanese: String) -> String {
        switch selectedLanguage {
        case .english:
            return english
        case .simplifiedChinese:
            return simplifiedChinese
        case .japanese:
            return japanese
        }
    }

    private func exportStatusMessage(_ message: String) -> String {
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 2 else { return message }
        switch selectedLanguage {
        case .english:
            return message
        case .simplifiedChinese:
            return "导出已完成：\(numbers[0]) 项已导出，\(numbers[1]) 项已跳过"
        case .japanese:
            return "エクスポート完了：\(numbers[0])件をエクスポート、\(numbers[1])件をスキップ"
        }
    }

    private func backupStatusMessage(_ message: String) -> String {
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 3 else { return message }
        switch selectedLanguage {
        case .english:
            return message
        case .simplifiedChinese:
            return "备份已完成：\(numbers[0]) 个项目记录，\(numbers[1]) 个附件，\(numbers[2]) 个删除标记"
        case .japanese:
            return "バックアップ完了：アイテムファイル \(numbers[0])件、添付ファイル \(numbers[1])件、削除マーカー \(numbers[2])件"
        }
    }

    private func restoreStatusMessage(_ message: String) -> String {
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 3 else { return message }
        switch selectedLanguage {
        case .english:
            return message
        case .simplifiedChinese:
            return "恢复已完成：\(numbers[0]) 个项目记录，\(numbers[1]) 个附件，\(numbers[2]) 个删除标记"
        case .japanese:
            return "復元完了：アイテムファイル \(numbers[0])件、添付ファイル \(numbers[1])件、削除マーカー \(numbers[2])件"
        }
    }

    private func copyToSyncStatusMessage(_ message: String) -> String {
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 3 else { return message }
        switch selectedLanguage {
        case .english:
            return message
        case .simplifiedChinese:
            return "已复制到同步位置：\(numbers[0]) 个项目记录，\(numbers[1]) 个附件，\(numbers[2]) 个删除标记"
        case .japanese:
            return "同期先へコピーしました：アイテムファイル \(numbers[0])件、添付ファイル \(numbers[1])件、削除マーカー \(numbers[2])件"
        }
    }

    private func quarantineStatusMessage(_ message: String) -> String {
        let count = message.split { !$0.isNumber }.compactMap { Int($0) }.first ?? 0
        switch selectedLanguage {
        case .english:
            return message
        case .simplifiedChinese:
            return "已隔离 \(count) 条异常同步记录"
        case .japanese:
            return "拒否された同期レコード \(count)件を隔離しました"
        }
    }

    private func conflictVersionsStatus(_ message: String) -> String {
        let count = message.split { !$0.isNumber }.compactMap { Int($0) }.first ?? 0
        switch selectedLanguage {
        case .english:
            return message
        case .simplifiedChinese:
            return "\(count) 个冲突版本"
        case .japanese:
            return "競合バージョン \(count)件"
        }
    }
}
