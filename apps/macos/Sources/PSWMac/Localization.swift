import Foundation

enum AppLanguage: String, CaseIterable, Identifiable {
    static let storageKey = "appLanguage"

    case english = "en"
    case simplifiedChinese = "zh-Hans"

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .english:
            return "English"
        case .simplifiedChinese:
            return "简体中文"
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

    var newVault: String { choose("New Vault", "新建密码库") }
    var openVault: String { choose("Open Vault", "打开密码库") }
    var openRecentVault: String { choose("Open Recent", "打开最近") }
    var importItems: String { choose("Import", "导入") }
    var exportItems: String { choose("Export", "导出") }
    var backupVault: String { choose("Backup", "备份") }
    var restoreBackup: String { choose("Restore", "恢复") }
    var copyVaultToSyncLocation: String { choose("Copy to Sync", "复制到同步") }
    var syncRefresh: String { choose("Refresh Sync", "刷新同步") }
    var syncStatus: String { choose("Sync Status", "同步状态") }
    var syncRefreshPaused: String { choose("Sync paused for unsaved edits", "同步因未保存编辑而暂停") }
    var syncRefreshPausedMessage: String {
        choose(
            "Encrypted file changes are waiting. Save or discard the current edit to refresh from disk.",
            "已有加密文件变更等待处理。保存或放弃当前编辑后将从磁盘刷新。"
        )
    }
    var syncReadiness: String { choose("Sync Readiness", "同步就绪") }
    var lastRefreshed: String { choose("Last refreshed", "上次刷新") }
    var loadedItems: String { choose("Loaded", "已加载") }
    var tombstones: String { choose("Tombstones", "删除标记") }
    var conflicts: String { choose("Conflicts", "冲突") }
    var rejectedRecords: String { choose("Rejected", "已拒绝") }
    var rejectedItems: String { choose("Rejected Items", "拒绝项目") }
    var rejectedTombstones: String { choose("Rejected Tombstones", "拒绝删除标记") }
    var rejectedFiles: String { choose("Rejected Files", "拒绝文件") }
    var quarantineRejectedRecords: String { choose("Quarantine", "隔离") }
    func quarantineResult(_ quarantine: SyncQuarantinePayload) -> String {
        choose(
            "Quarantined \(quarantine.movedRecords) rejected records",
            "已隔离 \(quarantine.movedRecords) 条异常同步记录"
        )
    }
    func syncReadinessStatus(_ readiness: VaultSyncReadiness) -> String {
        switch readiness.status {
        case .completeLikelySynced:
            return choose("Ready in likely sync folder", "已就绪，位于可能同步的位置")
        case .completeLocalOrUnknown:
            return choose("Complete, local or unknown folder", "结构完整，本地或未知位置")
        case .incomplete:
            return choose("Incomplete vault structure", "密码库结构不完整")
        }
    }

    func requiredVaultStructure(_ complete: Bool) -> String {
        complete
            ? choose("Required structure complete", "必需结构完整")
            : choose("Required structure incomplete", "必需结构不完整")
    }

    func missingRequiredPaths(_ labels: [String]) -> String {
        let value = labels.joined(separator: ", ")
        return choose("Missing or invalid: \(value)", "缺失或类型错误：\(value)")
    }

    var localUnlockEnvelopePresent: String {
        choose("Local Keychain unlock on this Mac", "此 Mac 有本机钥匙串解锁")
    }

    func syncLocationHint(_ hint: VaultSyncLocationHint) -> String {
        if let provider = hint.provider {
            return choose(
                "Likely synced: \(provider.displayName)",
                "可能同步：\(provider.displayName)"
            )
        }
        return choose("Local or unknown sync folder", "本地或未知同步位置")
    }
    func rejectedRecordKind(_ kind: String) -> String {
        switch kind {
        case "item":
            return choose("Item", "项目")
        case "tombstone":
            return choose("Tombstone", "删除标记")
        default:
            return choose("Record", "记录")
        }
    }
    var syncIssueTitle: String { choose("Sync issue detected", "检测到同步问题") }
    var syncIssueMessage: String {
        choose(
            "Trusted records remain available. Review conflicts, quarantine rejected sync files, or inspect the vault directory.",
            "可信记录仍可使用。请处理冲突、隔离异常同步文件，或检查密码库目录。"
        )
    }
    var showConflicts: String { choose("Show Conflicts", "显示冲突") }
    var copySyncDiagnostics: String { choose("Copy Sync Diagnostics", "复制同步诊断") }
    var lock: String { choose("Lock", "锁定") }
    var lockVault: String { choose("Lock Vault", "锁定密码库") }
    var closeVault: String { choose("Close Vault", "关闭密码库") }
    var vaultMenu: String { choose("Vault", "密码库") }
    var itemMenu: String { choose("Item", "项目") }
    var saveItem: String { choose("Save Item", "保存项目") }
    var focusSearch: String { choose("Focus Search", "聚焦搜索") }
    var copyUsername: String { choose("Copy Username", "复制用户名") }
    var copyPassword: String { choose("Copy Password", "复制密码") }
    var copyTotp: String { choose("Copy TOTP", "复制动态验证码") }
    var search: String { choose("Search", "搜索") }
    var archive: String { choose("Archive", "归档") }
    var favoritesFilter: String { choose("Favorites", "收藏") }
    var conflictsFilter: String { choose("Conflicts", "冲突") }
    var allTypes: String { choose("All Types", "所有类型") }
    var allTags: String { choose("All Tags", "所有标签") }
    var clearFilters: String { choose("Clear Filters", "清除过滤") }
    var noMatchingItemsTitle: String { choose("No Matching Items", "没有匹配项目") }
    var noMatchingItemsSubtitle: String {
        choose(
            "Search or filters are hiding every item in this vault.",
            "搜索或过滤条件隐藏了此密码库中的所有项目。"
        )
    }
    var security: String { choose("Security", "安全") }
    var passwordHealth: String { choose("Password Health", "密码健康") }
    var refreshPasswordHealth: String { choose("Check", "检查") }
    var checkedLogins: String { choose("Checked", "已检查") }
    var weakPasswords: String { choose("Weak", "弱密码") }
    var reusedPasswords: String { choose("Reused", "重复") }
    var passwordHealthNotChecked: String {
        choose(
            "Run a local check for weak and reused login passwords.",
            "本地检查弱密码和重复使用的登录密码。"
        )
    }
    var noPasswordHealthIssues: String {
        choose("No weak or reused login passwords found", "未发现弱密码或重复登录密码")
    }
    var showItem: String { choose("Show Item", "显示项目") }
    func passwordHealthIssueLabel(_ issue: PasswordHealthIssue) -> String {
        switch issue.kind {
        case .weakPassword:
            return choose("Weak", "弱密码")
        case .reusedPassword:
            if let reuseGroupSize = issue.reuseGroupSize {
                return choose("Reused x\(reuseGroupSize)", "重复 x\(reuseGroupSize)")
            }
            return choose("Reused", "重复")
        }
    }
    var trustBoundaryTitle: String { choose("Trust Boundary", "可信边界") }
    var trustBoundaryLocalVaultTitle: String { choose("Local vault files", "本地密码库文件") }
    var trustBoundaryLocalVaultMessage: String {
        choose(
            "Vaults stay in a .pswvault directory you choose. The app does not use a hosted password service.",
            "密码库保存在你选择的 .pswvault 目录中。应用不使用托管密码服务。"
        )
    }
    var trustBoundarySyncTitle: String { choose("Encrypted file sync", "加密文件同步") }
    var trustBoundarySyncMessage: String {
        choose(
            "iCloud, Dropbox, Syncthing, and similar tools are untrusted transports for encrypted vault files.",
            "iCloud、Dropbox、Syncthing 等工具只是加密密码库文件的不可信传输层。"
        )
    }
    var trustBoundaryDiagnosticsTitle: String { choose("Manual diagnostics", "手动诊断") }
    var trustBoundaryDiagnosticsMessage: String {
        choose(
            "Diagnostics are copied only when requested and exclude item content, secrets, full paths, and rejected record file names.",
            "诊断信息只会在你请求时复制，且不包含项目内容、秘密、完整路径或被拒绝记录的文件名。"
        )
    }
    var trustBoundaryFormatTitle: String { choose("Experimental format", "实验性格式") }
    var trustBoundaryFormatMessage: String {
        choose(
            "This alpha vault format is not a long-term compatibility contract until format freeze.",
            "在格式冻结之前，此 alpha 密码库格式不是长期兼容性承诺。"
        )
    }
    var clipboard: String { choose("Clipboard", "剪贴板") }
    var autoLock: String { choose("Auto-lock", "自动锁定") }
    var disableKeychain: String { choose("Disable Keychain", "停用钥匙串") }
    var firstRunTitle: String { choose("Start with a local vault", "从本地密码库开始") }
    var firstRunSubtitle: String {
        choose(
            "Create or open an encrypted .pswvault directory on this Mac.",
            "创建或打开此 Mac 上的加密 .pswvault 目录。"
        )
    }
    var lockedVaultTitle: String { choose("Vault Locked", "密码库已锁定") }
    var lockedVaultSubtitle: String {
        choose(
            "Unlock with the master password or local Keychain unlock.",
            "使用主密码或本机钥匙串解锁。"
        )
    }
    var emptyVaultTitle: String { choose("No Items Yet", "还没有项目") }
    var emptyVaultSubtitle: String {
        choose(
            "Create a login or secure note, or import existing items to start using this vault.",
            "创建登录项、安全笔记，或导入现有项目即可开始使用此密码库。"
        )
    }
    var masterPassword: String { choose("Master Password", "主密码") }
    var confirmMasterPassword: String { choose("Confirm Master Password", "确认主密码") }
    var currentMasterPassword: String { choose("Current Master Password", "当前主密码") }
    var newMasterPassword: String { choose("New Master Password", "新主密码") }
    var confirmNewMasterPassword: String { choose("Confirm New Master Password", "确认新主密码") }
    var changeMasterPassword: String { choose("Change Master Password", "更改主密码") }
    var masterPasswordRotationHint: String {
        choose(
            "Changes the password that unlocks this vault. Local Keychain unlock is disabled after a successful change.",
            "更改用于解锁此密码库的密码。成功更改后，本机钥匙串解锁会被停用。"
        )
    }
    var masterPasswordStrength: String { choose("Strength", "强度") }
    func masterPasswordStrengthLabel(_ strength: MasterPasswordStrength) -> String {
        let level: String
        switch strength.level {
        case .empty:
            level = choose("Not evaluated", "未评估")
        case .weak:
            level = choose("Weak", "弱")
        case .fair:
            level = choose("Fair", "一般")
        case .strong:
            level = choose("Strong", "强")
        case .veryStrong:
            level = choose("Very strong", "很强")
        }
        return choose("Strength: \(level)", "强度：\(level)")
    }
    func masterPasswordStrengthHint(_ strength: MasterPasswordStrength) -> String {
        switch strength.level {
        case .empty:
            return choose("Enter a master password.", "请输入主密码。")
        case .weak:
            if strength.containsCommonWeakTerm {
                return choose(
                    "Avoid common words and predictable sequences.",
                    "避免常见词和可预测序列。"
                )
            }
            return choose(
                "Use a longer, less repetitive passphrase.",
                "请使用更长、更少重复的口令。"
            )
        case .fair:
            return choose(
                "Usable, but more length or variety is safer.",
                "可以使用，但更长或更多样会更安全。"
            )
        case .strong:
            return choose(
                "Good local vault password.",
                "适合作为本地密码库主密码。"
            )
        case .veryStrong:
            return choose(
                "Long and varied.",
                "长度和多样性都很好。"
            )
        }
    }
    var currentMasterPasswordRequired: String {
        choose("Current master password is required", "请填写当前主密码")
    }
    var masterPasswordRequired: String {
        choose("Master password is required", "请填写主密码")
    }
    var newMasterPasswordRequired: String {
        choose("New master password is required", "请填写新主密码")
    }
    var createMasterPasswordsDoNotMatch: String {
        choose("Master passwords do not match", "两次输入的主密码不一致")
    }
    var masterPasswordsDoNotMatch: String {
        choose("New master passwords do not match", "两次输入的新主密码不一致")
    }
    var masterPasswordChanged: String { choose("Master password changed", "主密码已更改") }
    var unlockVaultFirst: String { choose("Unlock a vault first", "请先解锁密码库") }
    var openVaultFirst: String { choose("Open a vault first", "请先打开密码库") }
    var enableKeychainUnlock: String { choose("Enable Keychain unlock", "启用钥匙串解锁") }
    var unlock: String { choose("Unlock", "解锁") }
    var unlockWithKeychain: String { choose("Unlock with Keychain", "使用钥匙串解锁") }
    var title: String { choose("Title", "标题") }
    var itemType: String { choose("Item Type", "项目类型") }
    var login: String { choose("Login", "登录项") }
    var secureNote: String { choose("Secure Note", "安全笔记") }
    var creditCard: String { choose("Credit Card", "信用卡") }
    var softwareLicense: String { choose("Software License", "软件许可证") }
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
    var username: String { choose("Username", "用户名") }
    var password: String { choose("Password", "密码") }
    var savedPassword: String { choose("Saved Password", "已保存密码") }
    var clearSavedPassword: String { choose("Clear Saved Password", "清除已保存密码") }
    var keepSavedPassword: String { choose("Keep Saved Password", "保留已保存密码") }
    var savedPasswordWillBeCleared: String { choose("Password will be cleared", "密码将被清除") }
    var reveal: String { choose("Reveal", "显示") }
    var hide: String { choose("Hide", "隐藏") }
    var passwordGenerator: String { choose("Password Generator", "密码生成器") }
    var generatePassword: String { choose("Generate", "生成") }
    var selectPasswordCharacterClass: String {
        choose("Select at least one password character class", "请至少选择一种密码字符类型")
    }
    var length: String { choose("Length", "长度") }
    var uppercase: String { choose("A-Z", "大写") }
    var lowercase: String { choose("a-z", "小写") }
    var numbers: String { choose("0-9", "数字") }
    var symbols: String { choose("Symbols", "符号") }
    var avoidAmbiguousCharacters: String { choose("Avoid ambiguous characters", "避免易混淆字符") }
    var url: String { choose("URL", "网址") }
    var urls: String { choose("URLs", "网址") }
    var openURL: String { choose("Open URL", "打开网址") }
    var body: String { choose("Body", "正文") }
    var copyBody: String { choose("Copy Body", "复制正文") }
    var cardholderName: String { choose("Cardholder Name", "持卡人姓名") }
    var cardNumber: String { choose("Card Number", "卡号") }
    var copyCardNumber: String { choose("Copy Card Number", "复制卡号") }
    var savedCardNumber: String { choose("Saved Card Number", "已保存卡号") }
    var clearSavedCardNumber: String { choose("Clear Saved Card Number", "清除已保存卡号") }
    var keepSavedCardNumber: String { choose("Keep Saved Card Number", "保留已保存卡号") }
    var savedCardNumberWillBeCleared: String { choose("Card number will be cleared", "卡号将被清除") }
    var expiryMonth: String { choose("Expiry Month", "到期月份") }
    var expiryYear: String { choose("Expiry Year", "到期年份") }
    var expiration: String { choose("Expiration", "有效期") }
    var verificationCode: String { choose("Verification Code", "安全码") }
    var copyVerificationCode: String { choose("Copy Verification Code", "复制安全码") }
    var savedVerificationCode: String { choose("Saved Verification Code", "已保存安全码") }
    var clearSavedVerificationCode: String { choose("Clear Saved Verification Code", "清除已保存安全码") }
    var keepSavedVerificationCode: String { choose("Keep Saved Verification Code", "保留已保存安全码") }
    var savedVerificationCodeWillBeCleared: String { choose("Verification code will be cleared", "安全码将被清除") }
    var product: String { choose("Product", "产品") }
    var licenseKey: String { choose("License Key", "许可证密钥") }
    var copyLicenseKey: String { choose("Copy License Key", "复制许可证密钥") }
    var savedLicenseKey: String { choose("Saved License Key", "已保存许可证密钥") }
    var clearSavedLicenseKey: String { choose("Clear Saved License Key", "清除已保存许可证密钥") }
    var keepSavedLicenseKey: String { choose("Keep Saved License Key", "保留已保存许可证密钥") }
    var savedLicenseKeyWillBeCleared: String { choose("License key will be cleared", "许可证密钥将被清除") }
    var licensedTo: String { choose("Licensed To", "授权给") }
    var tags: String { choose("Tags", "标签") }
    var notes: String { choose("Notes", "备注") }
    var create: String { choose("Create", "创建") }
    var save: String { choose("Save", "保存") }
    var newItem: String { choose("New", "新建") }
    var confirm: String { choose("Confirm", "确认") }
    var discardChanges: String { choose("Discard Changes", "放弃修改") }
    var unsavedChangesTitle: String { choose("Unsaved Changes", "有未保存修改") }
    var unsavedChangesMessage: String {
        choose(
            "Discard unsaved edits and continue?",
            "要放弃未保存的编辑并继续吗？"
        )
    }
    var confirmActionTitle: String { choose("Confirm Action", "确认操作") }
    var confirmArchiveTitle: String { choose("Archive Item?", "归档项目？") }
    var confirmArchiveMessage: String {
        choose(
            "Archive this item and hide it from the active list?",
            "要归档此项目并从活跃列表中隐藏吗？"
        )
    }
    var confirmDeleteTitle: String { choose("Delete Item?", "删除项目？") }
    var confirmDeleteMessage: String {
        choose(
            "Delete this item by writing a sync tombstone? This cannot be undone in the current app.",
            "要写入同步删除标记来删除此项目吗？当前应用内无法撤销。"
        )
    }
    var resolveConflict: String { choose("Resolve Conflict", "解决冲突") }
    var loadConflictVersions: String { choose("Load Versions", "加载版本") }
    var conflictVersions: String { choose("Conflict Versions", "冲突版本") }
    var staleSaveReviewTitle: String { choose("Current Sync vs Local Draft", "当前同步版本与本地草稿") }
    func staleSaveReviewMessage(_ itemTitle: String) -> String {
        choose(
            "\(itemTitle) changed on disk. Review the preserved draft before saving again.",
            "\(itemTitle) 已在磁盘上变化。再次保存前请复核已保留的本地草稿。"
        )
    }
    var currentSyncedVersion: String { choose("Current", "当前") }
    var preservedLocalDraft: String { choose("Draft", "草稿") }
    var noVisibleStaleSaveDifferences: String {
        choose("Only hidden fields changed.", "只有隐藏字段发生变化。")
    }
    var yes: String { choose("Yes", "是") }
    var no: String { choose("No", "否") }
    var changedFields: String { choose("Changed", "已更改") }
    var mergeFields: String { choose("Merge Fields", "合并字段") }
    var mergeBase: String { choose("Merge Base", "合并基底") }
    var mergeConflict: String { choose("Merge Conflict", "合并冲突") }
    var keepVersion: String { choose("Keep", "保留") }
    var revision: String { choose("Revision", "修订") }
    var redactedValue: String { choose("Hidden", "已隐藏") }
    var conflictResolved: String { choose("Conflict resolved", "冲突已解决") }
    var conflictMerged: String { choose("Conflict merged", "冲突已合并") }
    var noSelectedConflict: String { choose("No selected conflict", "未选择冲突项目") }
    var conflictResolutionHint: String {
        choose(
            "Keeps the current version and writes a new active revision.",
            "保留当前版本并写入新的活跃修订。"
        )
    }
    var totp: String { choose("TOTP", "动态验证码") }
    var totpSecret: String { choose("TOTP Secret", "动态验证码密钥") }
    var savedTotpSecret: String { choose("Saved TOTP Secret", "已保存动态验证码密钥") }
    var favorite: String { choose("Favorite", "收藏") }
    var unfavorite: String { choose("Unfavorite", "取消收藏") }
    var duplicate: String { choose("Duplicate", "复制") }
    var restore: String { choose("Restore", "恢复") }
    var delete: String { choose("Delete", "删除") }
    var displayName: String { choose("Display Name", "显示名称") }
    var cancel: String { choose("Cancel", "取消") }
    var settingsGeneral: String { choose("General", "通用") }
    var languageLabel: String { choose("Language", "语言") }
    var languageHint: String { choose("Changes apply immediately.", "更改会立即生效。") }
    var diagnostics: String { choose("Diagnostics", "诊断") }
    var copyDiagnostics: String { choose("Copy Diagnostics", "复制诊断信息") }
    var diagnosticsHint: String {
        choose(
            "Copies app, core, vault state, sync counts, and preferences. No item content, secrets, or full paths are included.",
            "复制应用、核心、密码库状态、同步计数和偏好设置。不包含项目内容、秘密或完整路径。"
        )
    }
    var diagnosticsCopied: String { choose("Diagnostics copied", "诊断信息已复制") }
    var clipboardPreferenceHint: String {
        choose(
            "Copied secrets are cleared after this delay.",
            "复制的敏感内容会在此时间后清除。"
        )
    }
    var autoLockPreferenceHint: String {
        choose(
            "Unlocked vaults lock after this idle duration.",
            "密码库会在空闲达到此时间后自动锁定。"
        )
    }
    var cleanupLegacyKeychain: String {
        choose("Clean Up Legacy Keychain", "清理旧版钥匙串条目")
    }
    var cleanupLegacyKeychainHint: String {
        choose(
            "Removes old alpha Keychain entries for this vault. Current local unlock material is kept.",
            "移除此密码库的旧 alpha 钥匙串条目。当前本机解锁材料会保留。"
        )
    }
    var legacyKeychainEntriesRemoved: String {
        choose("Legacy Keychain entries removed", "旧版钥匙串条目已移除")
    }
    var noLegacyKeychainEntriesFound: String {
        choose("No legacy Keychain entries found", "未发现旧版钥匙串条目")
    }
    var chooseFile: String { choose("Choose File", "选择文件") }
    var sourceFile: String { choose("Source File", "来源文件") }
    var exportFile: String { choose("Export File", "导出文件") }
    var importable: String { choose("Importable", "可导入") }
    var exported: String { choose("Exported", "已导出") }
    var skipped: String { choose("Skipped", "跳过") }
    var duplicates: String { choose("Duplicates", "重复") }
    var warnings: String { choose("Warnings", "警告") }
    var backupDestination: String { choose("Backup Destination", "备份位置") }
    var restoredVault: String { choose("Restored Vault", "恢复后的密码库") }
    var syncDestination: String { choose("Sync Destination", "同步位置") }
    var itemFiles: String { choose("Item Files", "项目记录") }
    var attachments: String { choose("Attachments", "附件") }
    var keepDuplicates: String { choose("Keep duplicates", "保留重复项") }
    var importNow: String { choose("Import", "导入") }
    var revealInFinder: String { choose("Reveal in Finder", "在访达中显示") }
    var moveSourceToTrash: String { choose("Move Source to Trash", "将来源移到废纸篓") }
    var moveExportToTrash: String { choose("Move Export to Trash", "将导出文件移到废纸篓") }
    var done: String { choose("Done", "完成") }
    var plaintextImportWarning: String {
        choose(
            "Export files may contain plaintext secrets. Delete or secure the source file after import.",
            "导出文件可能包含明文密码。导入后请删除或妥善保存来源文件。"
        )
    }
    var exportNow: String { choose("Export", "导出") }
    var plaintextExportTitle: String { choose("Export Plaintext Secrets?", "要导出明文秘密吗？") }
    var plaintextExportWarning: String {
        choose(
            "The exported file contains plaintext secrets. Delete or secure it after migration.",
            "导出的文件包含明文秘密。迁移完成后请删除或妥善保存。"
        )
    }
    var titleRequired: String { choose("Title is required", "请填写标题") }

    func plaintextExportMessage(_ fileName: String) -> String {
        choose(
            "Write plaintext vault data to \(fileName)? Anyone with this file can read the exported secrets.",
            "要将密码库数据以明文写入 \(fileName) 吗？任何拥有此文件的人都可以读取导出的秘密。"
        )
    }

    func itemStatus(_ status: String) -> String {
        switch status {
        case "active":
            return choose("active", "活跃")
        case "archived":
            return choose("archived", "已归档")
        case "deleted":
            return choose("deleted", "已删除")
        case "conflicted":
            return choose("conflicted", "有冲突")
        default:
            return status
        }
    }

    func statusMessage(_ message: String) -> String {
        switch message {
        case "Rust core connected":
            return choose("Rust core connected", "Rust 核心已连接")
        case "Rust core library not loaded":
            return choose("Rust core library not loaded", "Rust 核心库未加载")
        case "Vault created":
            return choose("Vault created", "密码库已创建")
        case "Vault creation canceled":
            return choose("Vault creation canceled", "已取消创建密码库")
        case "Vault creation failed":
            return choose("Vault creation failed", "创建密码库失败")
        case let message where message.contains("target vault directory already exists and is not empty"):
            return choose(
                "Choose an empty location for the new vault",
                "请选择一个空位置创建密码库"
            )
        case "Vault unlocked":
            return choose("Vault unlocked", "密码库已解锁")
        case "Vault unlocked with Keychain":
            return choose("Vault unlocked with Keychain", "已使用钥匙串解锁")
        case "Keychain unlock disabled":
            return choose("Keychain unlock disabled", "钥匙串解锁已停用")
        case "Vault locked":
            return choose("Vault locked", "密码库已锁定")
        case "Unlock a vault first":
            return unlockVaultFirst
        case "Open a vault first":
            return openVaultFirst
        case "Unsupported vault file":
            return choose("Unsupported vault file", "不支持的密码库文件")
        case "Archived":
            return choose("Archived", "已归档")
        case "Restored":
            return choose("Restored", "已恢复")
        case "Only archived items can be restored":
            return choose("Only archived items can be restored", "只有已归档项目可以恢复")
        case "Deleted":
            return choose("Deleted", "已删除")
        case "Saved":
            return choose("Saved", "已保存")
        case "Duplicated":
            return choose("Duplicated", "已复制")
        case "Username copied":
            return choose("Username copied", "用户名已复制")
        case "login item has no username":
            return choose("login item has no username", "登录项没有用户名")
        case "Password copied":
            return choose("Password copied", "密码已复制")
        case "login item has no password":
            return choose("login item has no password", "登录项没有密码")
        case "Select at least one password character class":
            return selectPasswordCharacterClass
        case "URL opened":
            return choose("URL opened", "网址已打开")
        case "login item has no valid URL":
            return choose("login item has no valid URL", "登录项没有可打开的网址")
        case "TOTP copied":
            return choose("TOTP copied", "动态验证码已复制")
        case "login item has no TOTP secret":
            return choose("login item has no TOTP secret", "登录项没有动态验证码密钥")
        case "Secure note body copied":
            return choose("Secure note body copied", "安全笔记正文已复制")
        case "secure note has no body":
            return choose("secure note has no body", "安全笔记没有正文")
        case "Card number copied":
            return choose("Card number copied", "卡号已复制")
        case "credit card has no card number":
            return choose("credit card has no card number", "信用卡没有卡号")
        case "Verification code copied":
            return choose("Verification code copied", "安全码已复制")
        case "credit card has no verification code":
            return choose("credit card has no verification code", "信用卡没有安全码")
        case "License key copied":
            return choose("License key copied", "许可证密钥已复制")
        case "software license has no license key":
            return choose("software license has no license key", "软件许可证没有许可证密钥")
        case "Import preview ready":
            return choose("Import preview ready", "导入预览已就绪")
        case "Import completed":
            return choose("Import completed", "导入已完成")
        case let message where message.hasPrefix("Export completed:"):
            return exportStatusMessage(message)
        case let message where message.hasPrefix("Backup completed:"):
            return backupStatusMessage(message)
        case let message where message.hasPrefix("Restore completed:"):
            return restoreStatusMessage(message)
        case let message where message.hasPrefix("Vault copied to sync location:"):
            return copyToSyncStatusMessage(message)
        case "Sync refreshed":
            return choose("Sync refreshed", "同步已刷新")
        case "Password health refreshed":
            return choose("Password health refreshed", "密码健康已刷新")
        case "Filters cleared":
            return choose("Filters cleared", "过滤已清除")
        case "Sync refresh paused for unsaved edits":
            return choose("Sync refresh paused for unsaved edits", "有未保存修改，已暂停同步刷新")
        case "Save or discard edits before importing":
            return choose("Save or discard edits before importing", "请先保存或放弃修改再导入")
        case "Save or discard edits before sync recovery":
            return choose("Save or discard edits before sync recovery", "请先保存或放弃修改再进行同步恢复")
        case "Save or discard edits before exporting":
            return choose("Save or discard edits before exporting", "请先保存或放弃修改再导出")
        case "Save or discard edits before backing up":
            return choose("Save or discard edits before backing up", "请先保存或放弃修改再备份")
        case "Save or discard edits before restoring backup":
            return choose("Save or discard edits before restoring backup", "请先保存或放弃修改再恢复备份")
        case "Save or discard edits before copying to sync":
            return choose("Save or discard edits before copying to sync", "请先保存或放弃修改再复制到同步位置")
        case "Save or discard edits before changing selection":
            return choose("Save or discard edits before changing selection", "请先保存或放弃修改再切换项目")
        case "Save or discard edits before archiving":
            return choose("Save or discard edits before archiving", "请先保存或放弃修改再归档")
        case "Save or discard edits before deleting":
            return choose("Save or discard edits before deleting", "请先保存或放弃修改再删除")
        case "Save or discard edits before updating favorite":
            return choose("Save or discard edits before updating favorite", "请先保存或放弃修改再更新收藏")
        case "Save or discard edits before duplicating":
            return choose("Save or discard edits before duplicating", "请先保存或放弃修改再复制项目")
        case "Save or discard edits before restoring":
            return choose("Save or discard edits before restoring", "请先保存或放弃修改再恢复")
        case "Save or discard edits before resolving conflict":
            return choose("Save or discard edits before resolving conflict", "请先保存或放弃修改再解决冲突")
        case "Save or discard edits before switching vaults":
            return choose("Save or discard edits before switching vaults", "请先保存或放弃修改再切换密码库")
        case "Save or discard edits before closing vault":
            return choose("Save or discard edits before closing vault", "请先保存或放弃修改再关闭密码库")
        case let message where message.hasPrefix("Quarantined "):
            return quarantineStatusMessage(message)
        case "Conflict resolved":
            return conflictResolved
        case "Conflict merged":
            return conflictMerged
        case "No selected conflict":
            return noSelectedConflict
        case "Resolve conflict before editing":
            return choose("Resolve conflict before editing", "请先解决冲突再编辑")
        case "Resolve conflict before copying":
            return choose("Resolve conflict before copying", "请先解决冲突再复制")
        case "Resolve conflict before revealing":
            return choose("Resolve conflict before revealing", "请先解决冲突再显示")
        case "Refresh sync before editing this item":
            return choose("Refresh sync before editing this item", "请刷新同步后再编辑此项目")
        case "Local edit kept; current synced item reloaded":
            return choose(
                "Local edit kept; current synced item reloaded",
                "已保留本地编辑，并重新载入当前同步版本"
            )
        case let message where message.hasSuffix(" conflict versions"):
            return conflictVersionsStatus(message)
        case let message where itemCountStatus(message) != nil:
            return itemCountStatus(message) ?? message
        case "Title is required":
            return titleRequired
        case "Unsupported item type":
            return choose("Unsupported item type", "暂不支持的项目类型")
        case "Recent vault not found":
            return choose("Recent vault not found", "最近密码库不存在")
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
            return choose("Import source revealed", "已显示导入来源")
        case "Import source moved to Trash":
            return choose("Import source moved to Trash", "导入来源已移到废纸篓")
        case "Plaintext export revealed":
            return choose("Plaintext export revealed", "已显示明文导出文件")
        case "Backup destination revealed":
            return choose("Backup destination revealed", "已显示备份位置")
        case "Restored vault revealed":
            return choose("Restored vault revealed", "已显示恢复后的密码库")
        case "Copied sync vault revealed":
            return choose("Copied sync vault revealed", "已显示同步副本")
        case "Plaintext export moved to Trash":
            return choose("Plaintext export moved to Trash", "明文导出文件已移到废纸篓")
        case "Diagnostics copied":
            return diagnosticsCopied
        case "Showing conflicts":
            return choose("Showing conflicts", "正在显示冲突")
        case "Vault revealed in Finder":
            return choose("Vault revealed in Finder", "已在访达中显示密码库")
        case "Vault closed":
            return choose("Vault closed", "密码库已关闭")
        case "Legacy Keychain entries removed":
            return legacyKeychainEntriesRemoved
        case "No legacy Keychain entries found":
            return noLegacyKeychainEntriesFound
        default:
            return message
        }
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

        return choose("\(count) items", "\(count) 个项目")
    }

    func durationOption(_ seconds: TimeInterval) -> String {
        let wholeSeconds = Int(seconds)
        if wholeSeconds >= 60, wholeSeconds % 60 == 0 {
            return "\(wholeSeconds / 60)m"
        }
        return "\(wholeSeconds)s"
    }

    private func choose(_ english: String, _ simplifiedChinese: String) -> String {
        switch selectedLanguage {
        case .english:
            return english
        case .simplifiedChinese:
            return simplifiedChinese
        }
    }

    private func exportStatusMessage(_ message: String) -> String {
        guard selectedLanguage == .simplifiedChinese else { return message }
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 2 else { return message }
        return "导出已完成：\(numbers[0]) 项已导出，\(numbers[1]) 项已跳过"
    }

    private func backupStatusMessage(_ message: String) -> String {
        guard selectedLanguage == .simplifiedChinese else { return message }
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 3 else { return message }
        return "备份已完成：\(numbers[0]) 个项目记录，\(numbers[1]) 个附件，\(numbers[2]) 个删除标记"
    }

    private func restoreStatusMessage(_ message: String) -> String {
        guard selectedLanguage == .simplifiedChinese else { return message }
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 3 else { return message }
        return "恢复已完成：\(numbers[0]) 个项目记录，\(numbers[1]) 个附件，\(numbers[2]) 个删除标记"
    }

    private func copyToSyncStatusMessage(_ message: String) -> String {
        guard selectedLanguage == .simplifiedChinese else { return message }
        let numbers = message
            .split { !$0.isNumber }
            .compactMap { Int($0) }
        guard numbers.count >= 3 else { return message }
        return "已复制到同步位置：\(numbers[0]) 个项目记录，\(numbers[1]) 个附件，\(numbers[2]) 个删除标记"
    }

    private func quarantineStatusMessage(_ message: String) -> String {
        guard selectedLanguage == .simplifiedChinese else { return message }
        let count = message.split { !$0.isNumber }.compactMap { Int($0) }.first ?? 0
        return "已隔离 \(count) 条异常同步记录"
    }

    private func conflictVersionsStatus(_ message: String) -> String {
        guard selectedLanguage == .simplifiedChinese else { return message }
        let count = message.split { !$0.isNumber }.compactMap { Int($0) }.first ?? 0
        return "\(count) 个冲突版本"
    }
}
