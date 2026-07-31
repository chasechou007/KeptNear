import AppKit
import XCTest
@testable import PSWMac

@MainActor
final class PSWMacWorkflowTests: XCTestCase {
    private func makeIsolatedDefaults() -> UserDefaults {
        let defaultsName = "PSWMacWorkflowTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsName)!
        addTeardownBlock {
            defaults.removePersistentDomain(forName: defaultsName)
        }
        return defaults
    }

    private func resetSelectionForNewItem(_ store: VaultStore) {
        store.selectedItemId = nil
        store.selectedDetail = nil
        store.selectedSecureNoteDetail = nil
        store.selectedCreditCardDetail = nil
        store.selectedSoftwareLicenseDetail = nil
        store.selectedCredentialDetail = nil
    }

    private func makeUnlockedSeededLoginStore(path: String) -> (store: VaultStore, service: FakeCoreService) {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: path))
        store.unlock(password: "correct horse")
        return (store, service)
    }

    private func configureNextRefreshAsConflictedLogin(_ service: FakeCoreService) {
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )
    }

    private func seedPasswordHealth(_ store: VaultStore) {
        store.passwordHealth = PasswordHealthPayload(
            checkedLoginPasswords: 1,
            weakPasswords: 1,
            reusedPasswords: 0,
            issues: [
                PasswordHealthIssue(
                    itemId: "item_1",
                    title: "Email",
                    kind: .weakPassword
                )
            ]
        )
    }

    func testReleaseFFICandidatesAreRestrictedToTheApplicationBundle() {
        let candidates = RustCoreBridge.libraryCandidates(
            privateFrameworksPath: "/Applications/KeptNear.app/Contents/Frameworks",
            bundlePath: "/Applications/KeptNear.app",
            environment: ["PSW_FFI_LIBRARY": "/tmp/untrusted/libpsw_ffi.dylib"],
            currentDirectoryPath: "/tmp/untrusted",
            includeDevelopmentOverrides: false
        )

        XCTAssertEqual(candidates, [
            "/Applications/KeptNear.app/Contents/Frameworks/libpsw_ffi.dylib"
        ])
        XCTAssertFalse(candidates.contains { $0.hasPrefix("/tmp/untrusted") })
    }

    func testDevelopmentFFICandidatesRetainExplicitLocalOverrides() {
        let candidates = RustCoreBridge.libraryCandidates(
            privateFrameworksPath: nil,
            bundlePath: "/workspace/.build/debug",
            environment: ["PSW_FFI_LIBRARY": "/workspace/target/debug/custom.dylib"],
            currentDirectoryPath: "/workspace",
            includeDevelopmentOverrides: true
        )

        XCTAssertEqual(candidates.first, "/workspace/target/debug/custom.dylib")
        XCTAssertTrue(candidates.contains("/workspace/target/debug/libpsw_ffi.dylib"))
    }

    private func sampleLoginConflictCandidates() -> [ConflictCandidateView] {
        [
            ConflictCandidateView(
                itemId: "item_1",
                revision: "rev_left",
                title: "Email Left",
                itemType: "login",
                status: "active",
                favorite: false,
                tags: ["personal"],
                comparisonFields: [
                    ConflictCandidateField(label: "title", value: "Email Left", redacted: false),
                    ConflictCandidateField(label: "username", value: "me@example.com", redacted: false),
                    ConflictCandidateField(label: "password", value: nil, redacted: true)
                ],
                changedFields: ["title", "username", "password"],
                preview: "username: me@example.com"
            ),
            ConflictCandidateView(
                itemId: "item_1",
                revision: "rev_right",
                title: "Email Right",
                itemType: "login",
                status: "active",
                favorite: true,
                tags: ["work"],
                comparisonFields: [
                    ConflictCandidateField(label: "title", value: "Email Right", redacted: false),
                    ConflictCandidateField(label: "username", value: "work@example.com", redacted: false),
                    ConflictCandidateField(label: "password", value: nil, redacted: true)
                ],
                changedFields: ["title", "username", "password"],
                preview: "username: work@example.com"
            )
        ]
    }

    private func createRequiredVaultStructure(at vaultURL: URL) throws {
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("items", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("attachments", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("tombstones", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data("{\"format_name\":\"psw-vault\"}".utf8)
            .write(to: vaultURL.appendingPathComponent("vault.json"))
        try Data("{\"envelope\":\"test\"}".utf8)
            .write(to: vaultURL.appendingPathComponent("keys.enc"))
    }

    func testAppPresentationStateUsesVaultSelectionAndUnlockState() {
        XCTAssertEqual(
            AppPresentationState(hasSelectedVault: false, isUnlocked: false),
            .welcome
        )
        XCTAssertEqual(
            AppPresentationState(hasSelectedVault: false, isUnlocked: true),
            .welcome
        )
        XCTAssertEqual(
            AppPresentationState(hasSelectedVault: true, isUnlocked: false),
            .locked
        )
        XCTAssertEqual(
            AppPresentationState(hasSelectedVault: true, isUnlocked: true),
            .unlocked
        )
    }

    func testLanguageTextSupportsEnglishAndSimplifiedChinese() {
        let english = AppText(AppLanguage.english.rawValue)
        let chinese = AppText(AppLanguage.simplifiedChinese.rawValue)

        XCTAssertEqual(english.welcomeHeadline, "Your passwords, always kept near.")
        XCTAssertEqual(chinese.welcomeHeadline, "你的密码，始终在你身边。")
        XCTAssertEqual(english.localPasswordManager, "Local Password & Token Manager")
        XCTAssertEqual(chinese.localPasswordManager, "本地密码与令牌管理器")
        XCTAssertEqual(english.openExistingVault, "Open Existing Vault")
        XCTAssertEqual(chinese.openExistingVault, "打开现有密码库")
        XCTAssertEqual(english.unlockVaultNamed("Personal"), "Unlock Personal")
        XCTAssertEqual(chinese.unlockVaultNamed("Personal"), "解锁 Personal")
        XCTAssertEqual(english.newVault, "New Vault")
        XCTAssertEqual(chinese.newVault, "新建密码库")
        XCTAssertEqual(english.exportItems, "Export")
        XCTAssertEqual(chinese.exportItems, "导出")
        XCTAssertEqual(chinese.exported, "已导出")
        XCTAssertEqual(chinese.plaintextExportTitle, "要导出明文秘密吗？")
        XCTAssertEqual(
            chinese.exportOmission(reason: "unsupported-template", count: 2),
            "已省略 2 个模板不受支持的凭据"
        )
        XCTAssertEqual(
            english.exportOmission(reason: "conflicted-credential", count: 1),
            "1 conflicted credential(s) omitted"
        )
        XCTAssertEqual(english.unlockWithKeychain, "Unlock with Keychain")
        XCTAssertEqual(chinese.unlockWithKeychain, "使用钥匙串解锁")
        XCTAssertEqual(english.enterMasterPasswordToUnlock, "Enter Master Password")
        XCTAssertEqual(chinese.enterMasterPasswordToUnlock, "输入主密码解锁")
        XCTAssertEqual(
            english.statusMessage("invalid vault credentials"),
            "Incorrect master password. Try again."
        )
        XCTAssertEqual(chinese.statusMessage("invalid vault credentials"), "主密码不正确，请重试。")
        XCTAssertTrue(chinese.isErrorStatusMessage("invalid vault credentials"))
        XCTAssertFalse(chinese.isErrorStatusMessage("Vault locked"))
        XCTAssertEqual(
            chinese.statusMessage(VaultStore.appsToolsVaultPathConflictStatus),
            "检测到密码库副本冲突；“应用与工具”访问已停用"
        )
        XCTAssertTrue(
            chinese.isErrorStatusMessage(VaultStore.appsToolsVaultPathConflictStatus)
        )
        XCTAssertEqual(english.closeVault, "Close Vault")
        XCTAssertEqual(chinese.closeVault, "关闭密码库")
        XCTAssertEqual(chinese.statusMessage("Vault closed"), "密码库已关闭")
        XCTAssertEqual(english.forgotMasterPassword, "Forgot master password?")
        XCTAssertEqual(chinese.forgotMasterPassword, "忘记主密码？")
        XCTAssertEqual(english.closeAndCreateNewVault, "Close and Create New Vault")
        XCTAssertEqual(chinese.closeAndCreateNewVault, "关闭并新建密码库")
        XCTAssertEqual(
            chinese.statusMessage("Vault moved to Trash"),
            "密码库已移到废纸篓"
        )
        XCTAssertEqual(
            chinese.statusMessage("Vault moved to Trash, but Keychain cleanup failed"),
            "密码库已移到废纸篓，但钥匙串清理失败"
        )
        XCTAssertTrue(
            chinese.isErrorStatusMessage("Vault moved to Trash, but Keychain cleanup failed")
        )
        XCTAssertEqual(english.firstRunTitle, "Start with a local vault")
        XCTAssertEqual(chinese.firstRunTitle, "从本地密码库开始")
        XCTAssertEqual(english.lockedVaultTitle, "Vault Locked")
        XCTAssertEqual(chinese.lockedVaultTitle, "密码库已锁定")
        XCTAssertEqual(english.emptyVaultTitle, "No Items Yet")
        XCTAssertEqual(chinese.emptyVaultTitle, "还没有项目")
        XCTAssertEqual(english.browse, "Browse")
        XCTAssertEqual(chinese.browse, "浏览")
        XCTAssertEqual(english.itemTypes, "Types")
        XCTAssertEqual(chinese.itemTypes, "类型")
        XCTAssertEqual(english.securityAndMaintenance, "Security & Maintenance")
        XCTAssertEqual(chinese.securityAndMaintenance, "安全与维护")
        XCTAssertEqual(english.itemCount(1), "1 item")
        XCTAssertEqual(english.itemCount(2), "2 items")
        XCTAssertEqual(chinese.itemCount(2), "2 个项目")
        XCTAssertEqual(english.sidebarSyncReady, "Sync ready")
        XCTAssertEqual(chinese.sidebarSyncReady, "同步就绪")
        XCTAssertEqual(chinese.sidebarSyncNeedsAttention, "同步需要处理")
        XCTAssertEqual(chinese.sidebarSyncWaiting, "等待完成编辑")
        XCTAssertEqual(chinese.notRefreshedYet, "尚未刷新")
        XCTAssertEqual(english.login, "Login")
        XCTAssertEqual(chinese.login, "登录项")
        XCTAssertEqual(english.secureNote, "Secure Note")
        XCTAssertEqual(chinese.secureNote, "安全笔记")
        XCTAssertEqual(chinese.body, "正文")
        XCTAssertEqual(chinese.titleRequired, "请填写标题")
        XCTAssertEqual(chinese.moveSourceToTrash, "将来源移到废纸篓")
        XCTAssertEqual(chinese.exportFile, "导出文件")
        XCTAssertEqual(chinese.moveExportToTrash, "将导出文件移到废纸篓")
        XCTAssertEqual(english.diagnostics, "Diagnostics")
        XCTAssertEqual(chinese.diagnostics, "诊断")
        XCTAssertEqual(english.diagnosticsCopied, "Diagnostics copied")
        XCTAssertEqual(chinese.statusMessage("Diagnostics copied"), "诊断信息已复制")
        XCTAssertEqual(english.syncIssueTitle, "Sync issue detected")
        XCTAssertEqual(chinese.syncIssueTitle, "检测到同步问题")
        XCTAssertEqual(english.syncRefreshPaused, "Sync paused for unsaved edits")
        XCTAssertEqual(chinese.syncRefreshPaused, "同步因未保存编辑而暂停")
        XCTAssertEqual(
            english.syncRefreshPausedMessage,
            "Encrypted file changes are waiting. Save or discard the current edit to refresh from disk."
        )
        XCTAssertEqual(
            chinese.syncRefreshPausedMessage,
            "已有加密文件变更等待处理。保存或放弃当前编辑后将从磁盘刷新。"
        )
        XCTAssertEqual(english.quarantineRejectedRecords, "Quarantine")
        XCTAssertEqual(chinese.quarantineRejectedRecords, "隔离")
        XCTAssertEqual(english.syncReadiness, "Sync Readiness")
        XCTAssertEqual(chinese.syncReadiness, "同步就绪")
        XCTAssertEqual(
            english.syncReadinessStatus(VaultSyncReadiness(
                locationHint: VaultSyncLocationHint(provider: .dropbox),
                requiredPaths: [],
                localUnlockEnvelopePresent: false
            )),
            "Ready in likely sync folder"
        )
        XCTAssertEqual(
            chinese.syncReadinessStatus(VaultSyncReadiness(
                locationHint: VaultSyncLocationHint(provider: nil),
                requiredPaths: [],
                localUnlockEnvelopePresent: false
            )),
            "结构完整，本地或未知位置"
        )
        XCTAssertEqual(english.requiredVaultStructure(true), "Required structure complete")
        XCTAssertEqual(chinese.requiredVaultStructure(false), "必需结构不完整")
        XCTAssertEqual(english.missingRequiredPaths(["keys.enc"]), "Missing or invalid: keys.enc")
        XCTAssertEqual(chinese.localUnlockEnvelopePresent, "此 Mac 有本机钥匙串解锁")
        XCTAssertEqual(english.copySyncDiagnostics, "Copy Sync Diagnostics")
        XCTAssertEqual(chinese.copySyncDiagnostics, "复制同步诊断")
        XCTAssertEqual(english.rejectedFiles, "Rejected Files")
        XCTAssertEqual(chinese.rejectedFiles, "拒绝文件")
        XCTAssertEqual(english.rejectedRecordKind("item"), "Item")
        XCTAssertEqual(chinese.rejectedRecordKind("tombstone"), "删除标记")
        XCTAssertEqual(english.rejectedRecordKind("unknown"), "Record")
        XCTAssertEqual(english.lastRefreshed, "Last refreshed")
        XCTAssertEqual(chinese.lastRefreshed, "上次刷新")
        XCTAssertEqual(
            english.syncLocationHint(VaultSyncLocationHint(provider: .iCloudDrive)),
            "Likely synced: iCloud Drive"
        )
        XCTAssertEqual(
            chinese.syncLocationHint(VaultSyncLocationHint(provider: .iCloudDrive)),
            "可能同步：iCloud Drive"
        )
        XCTAssertEqual(
            english.syncLocationHint(VaultSyncLocationHint(provider: nil)),
            "Local or unknown sync folder"
        )
        XCTAssertEqual(
            chinese.syncLocationHint(VaultSyncLocationHint(provider: nil)),
            "本地或未知同步位置"
        )
        XCTAssertEqual(english.vaultMenu, "Vault")
        XCTAssertEqual(chinese.vaultMenu, "密码库")
        XCTAssertEqual(english.itemMenu, "Item")
        XCTAssertEqual(chinese.itemMenu, "项目")
        XCTAssertEqual(english.fileMenu, "File")
        XCTAssertEqual(chinese.fileMenu, "文件")
        XCTAssertEqual(english.editMenu, "Edit")
        XCTAssertEqual(chinese.editMenu, "编辑")
        XCTAssertEqual(english.viewMenu, "View")
        XCTAssertEqual(chinese.viewMenu, "显示")
        XCTAssertEqual(english.windowMenu, "Window")
        XCTAssertEqual(chinese.windowMenu, "窗口")
        XCTAssertEqual(english.helpMenu, "Help")
        XCTAssertEqual(chinese.helpMenu, "帮助")
        XCTAssertEqual(english.settings, "Settings")
        XCTAssertEqual(chinese.settings, "设置")
        XCTAssertEqual(english.saveItem, "Save Item")
        XCTAssertEqual(chinese.saveItem, "保存项目")
        XCTAssertEqual(english.focusSearch, "Focus Search")
        XCTAssertEqual(chinese.focusSearch, "聚焦搜索")
        XCTAssertEqual(english.copyUsername, "Copy Username")
        XCTAssertEqual(chinese.copyUsername, "复制用户名")
        XCTAssertEqual(english.copyPassword, "Copy Password")
        XCTAssertEqual(chinese.copyPassword, "复制密码")
        XCTAssertEqual(english.copyTotp, "Copy TOTP")
        XCTAssertEqual(chinese.copyTotp, "复制动态验证码")
        XCTAssertEqual(english.copyCardNumber, "Copy Card Number")
        XCTAssertEqual(chinese.copyCardNumber, "复制卡号")
        XCTAssertEqual(english.copyVerificationCode, "Copy Verification Code")
        XCTAssertEqual(chinese.copyVerificationCode, "复制安全码")
        XCTAssertEqual(english.copyLicenseKey, "Copy License Key")
        XCTAssertEqual(chinese.copyLicenseKey, "复制许可证密钥")
        XCTAssertEqual(english.showItem, "Show Item")
        XCTAssertEqual(chinese.showItem, "显示项目")
        XCTAssertEqual(english.conflictsFilter, "Conflicts")
        XCTAssertEqual(chinese.conflictsFilter, "冲突")
        XCTAssertEqual(english.allTypes, "All Types")
        XCTAssertEqual(chinese.allTypes, "所有类型")
        XCTAssertEqual(english.itemTypeName("login"), "Login")
        XCTAssertEqual(chinese.itemTypeName("login"), "登录项")
        XCTAssertEqual(english.itemTypeName("secure note"), "Secure Note")
        XCTAssertEqual(chinese.itemTypeName("secure note"), "安全笔记")
        XCTAssertEqual(english.itemTypeName("credit card"), "Credit Card")
        XCTAssertEqual(chinese.itemTypeName("credit card"), "信用卡")
        XCTAssertEqual(english.itemTypeName("software license"), "Software License")
        XCTAssertEqual(chinese.itemTypeName("software license"), "软件许可证")
        XCTAssertEqual(english.itemTypeName("passkey"), "passkey")
        XCTAssertEqual(chinese.itemTypeName("passkey"), "passkey")
        XCTAssertEqual(english.allTags, "All Tags")
        XCTAssertEqual(chinese.allTags, "所有标签")
        XCTAssertEqual(english.clearFilters, "Clear Filters")
        XCTAssertEqual(chinese.clearFilters, "清除过滤")
        XCTAssertEqual(english.urls, "URLs")
        XCTAssertEqual(chinese.urls, "网址")
        XCTAssertEqual(english.noMatchingItemsTitle, "No Matching Items")
        XCTAssertEqual(chinese.noMatchingItemsTitle, "没有匹配项目")
        XCTAssertTrue(english.noMatchingItemsSubtitle.contains("filters are hiding"))
        XCTAssertTrue(chinese.noMatchingItemsSubtitle.contains("过滤条件"))
        XCTAssertEqual(english.showConflicts, "Show Conflicts")
        XCTAssertEqual(chinese.showConflicts, "显示冲突")
        XCTAssertEqual(english.trustBoundaryTitle, "Trust Boundary")
        XCTAssertEqual(chinese.trustBoundaryTitle, "可信边界")
        XCTAssertEqual(english.trustBoundaryLocalVaultTitle, "Local vault files")
        XCTAssertEqual(chinese.trustBoundaryLocalVaultTitle, "本地密码库文件")
        XCTAssertTrue(english.trustBoundaryLocalVaultMessage.contains("does not use a hosted password service"))
        XCTAssertEqual(english.trustBoundarySyncTitle, "Encrypted file sync")
        XCTAssertEqual(chinese.trustBoundarySyncTitle, "加密文件同步")
        XCTAssertTrue(english.trustBoundarySyncMessage.contains("untrusted transports"))
        XCTAssertEqual(english.trustBoundaryDiagnosticsTitle, "Manual diagnostics")
        XCTAssertEqual(chinese.trustBoundaryDiagnosticsTitle, "手动诊断")
        XCTAssertTrue(english.trustBoundaryDiagnosticsMessage.contains("copied only when requested"))
        XCTAssertTrue(english.trustBoundaryDiagnosticsMessage.contains("exclude item content"))
        XCTAssertTrue(english.trustBoundaryDiagnosticsMessage.contains("rejected record file names"))
        XCTAssertEqual(english.trustBoundaryFormatTitle, "Experimental format")
        XCTAssertEqual(chinese.trustBoundaryFormatTitle, "实验性格式")
        XCTAssertTrue(chinese.trustBoundaryFormatMessage.contains("格式冻结"))
        XCTAssertEqual(chinese.statusMessage("Vault revealed in Finder"), "已在访达中显示密码库")
        XCTAssertEqual(english.changeMasterPassword, "Change Master Password")
        XCTAssertEqual(chinese.changeMasterPassword, "更改主密码")
        XCTAssertEqual(english.confirmMasterPassword, "Confirm Master Password")
        XCTAssertEqual(chinese.confirmMasterPassword, "确认主密码")
        XCTAssertEqual(
            english.plaintextExportMessage("backup.json"),
            "Enter your current master password to write plaintext vault data to backup.json. Anyone with this file can read the exported secrets."
        )
        XCTAssertEqual(
            chinese.plaintextExportMessage("backup.json"),
            "请输入当前主密码，将密码库数据以明文写入 backup.json。任何拥有此文件的人都可以读取导出的秘密。"
        )
        let weakStrength = MasterPasswordStrength.evaluate("password12345")
        let strongStrength = MasterPasswordStrength.evaluate("LocalVaults-2026")
        XCTAssertEqual(english.masterPasswordStrengthLabel(weakStrength), "Strength: Weak")
        XCTAssertEqual(chinese.masterPasswordStrengthLabel(weakStrength), "强度：弱")
        XCTAssertEqual(english.masterPasswordStrengthLabel(strongStrength), "Strength: Strong")
        XCTAssertEqual(chinese.masterPasswordStrengthLabel(strongStrength), "强度：强")
        XCTAssertEqual(
            english.masterPasswordStrengthHint(weakStrength),
            "Avoid common words and predictable sequences."
        )
        XCTAssertEqual(
            chinese.masterPasswordStrengthHint(MasterPasswordStrength.evaluate("short")),
            "请使用更长、更少重复的口令。"
        )
        XCTAssertEqual(chinese.statusMessage("Master password is required"), "请填写主密码")
        XCTAssertEqual(chinese.statusMessage("Master passwords do not match"), "两次输入的主密码不一致")
        XCTAssertEqual(chinese.statusMessage("Master password changed"), "主密码已更改")
        XCTAssertEqual(chinese.statusMessage("New master passwords do not match"), "两次输入的新主密码不一致")
        XCTAssertEqual(english.statusMessage("Recent vault not found"), "Recent vault not found")
        XCTAssertEqual(chinese.statusMessage("Recent vault not found"), "最近密码库不存在")
        XCTAssertEqual(english.backupVault, "Backup")
        XCTAssertEqual(chinese.backupVault, "备份")
        XCTAssertEqual(english.restoreBackup, "Restore")
        XCTAssertEqual(chinese.restoreBackup, "恢复")
        XCTAssertEqual(english.copyVaultToSyncLocation, "Copy to Sync")
        XCTAssertEqual(chinese.copyVaultToSyncLocation, "复制到同步")
        XCTAssertEqual(english.backupDestination, "Backup Destination")
        XCTAssertEqual(chinese.backupDestination, "备份位置")
        XCTAssertEqual(english.restoredVault, "Restored Vault")
        XCTAssertEqual(chinese.restoredVault, "恢复后的密码库")
        XCTAssertEqual(english.syncDestination, "Sync Destination")
        XCTAssertEqual(chinese.syncDestination, "同步位置")
        XCTAssertEqual(english.itemFiles, "Item Files")
        XCTAssertEqual(chinese.itemFiles, "项目记录")
        XCTAssertEqual(english.attachments, "Attachments")
        XCTAssertEqual(chinese.attachments, "附件")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before backing up"), "请先保存或放弃修改再备份")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before restoring backup"), "请先保存或放弃修改再恢复备份")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before copying to sync"), "请先保存或放弃修改再复制到同步位置")
        XCTAssertEqual(
            chinese.statusMessage("Backup completed: 3 items, 1 attachments, 2 tombstones"),
            "备份已完成：3 个项目记录，1 个附件，2 个删除标记"
        )
        XCTAssertEqual(
            chinese.statusMessage("Restore completed: 3 items, 1 attachments, 2 tombstones"),
            "恢复已完成：3 个项目记录，1 个附件，2 个删除标记"
        )
        XCTAssertEqual(chinese.statusMessage("Backup destination revealed"), "已显示备份位置")
        XCTAssertEqual(chinese.statusMessage("Restored vault revealed"), "已显示恢复后的密码库")
        XCTAssertEqual(chinese.statusMessage("Copied sync vault revealed"), "已显示同步副本")
        XCTAssertEqual(
            chinese.statusMessage("Vault copied to sync location: 3 items, 1 attachments, 2 tombstones"),
            "已复制到同步位置：3 个项目记录，1 个附件，2 个删除标记"
        )
        XCTAssertEqual(english.resolveConflict, "Resolve Conflict")
        XCTAssertEqual(chinese.resolveConflict, "解决冲突")
        XCTAssertEqual(english.loadConflictVersions, "Load Versions")
        XCTAssertEqual(chinese.loadConflictVersions, "加载版本")
        XCTAssertEqual(chinese.statusMessage("Only archived items can be restored"), "只有已归档项目可以恢复")
        XCTAssertEqual(english.mergeFields, "Merge Fields")
        XCTAssertEqual(chinese.mergeFields, "合并字段")
        XCTAssertEqual(english.mergeBase, "Merge Base")
        XCTAssertEqual(chinese.mergeBase, "合并基底")
        XCTAssertEqual(english.expiration, "Expiration")
        XCTAssertEqual(chinese.expiration, "有效期")
        XCTAssertEqual(english.totpSecret, "TOTP Secret")
        XCTAssertEqual(chinese.totpSecret, "动态验证码密钥")
        XCTAssertEqual(english.savedPassword, "Saved Password")
        XCTAssertEqual(chinese.savedPassword, "已保存密码")
        XCTAssertEqual(english.savedTotpSecret, "Saved TOTP Secret")
        XCTAssertEqual(chinese.savedTotpSecret, "已保存动态验证码密钥")
        XCTAssertEqual(english.savedCardNumber, "Saved Card Number")
        XCTAssertEqual(chinese.savedCardNumber, "已保存卡号")
        XCTAssertEqual(english.clearSavedCardNumber, "Clear Saved Card Number")
        XCTAssertEqual(chinese.clearSavedCardNumber, "清除已保存卡号")
        XCTAssertEqual(english.keepSavedCardNumber, "Keep Saved Card Number")
        XCTAssertEqual(chinese.keepSavedCardNumber, "保留已保存卡号")
        XCTAssertEqual(english.savedCardNumberWillBeCleared, "Card number will be cleared")
        XCTAssertEqual(chinese.savedCardNumberWillBeCleared, "卡号将被清除")
        XCTAssertEqual(english.savedVerificationCode, "Saved Verification Code")
        XCTAssertEqual(chinese.savedVerificationCode, "已保存安全码")
        XCTAssertEqual(english.clearSavedVerificationCode, "Clear Saved Verification Code")
        XCTAssertEqual(chinese.clearSavedVerificationCode, "清除已保存安全码")
        XCTAssertEqual(english.keepSavedVerificationCode, "Keep Saved Verification Code")
        XCTAssertEqual(chinese.keepSavedVerificationCode, "保留已保存安全码")
        XCTAssertEqual(english.savedVerificationCodeWillBeCleared, "Verification code will be cleared")
        XCTAssertEqual(chinese.savedVerificationCodeWillBeCleared, "安全码将被清除")
        XCTAssertEqual(english.savedLicenseKey, "Saved License Key")
        XCTAssertEqual(chinese.savedLicenseKey, "已保存许可证密钥")
        XCTAssertEqual(english.clearSavedLicenseKey, "Clear Saved License Key")
        XCTAssertEqual(chinese.clearSavedLicenseKey, "清除已保存许可证密钥")
        XCTAssertEqual(english.keepSavedLicenseKey, "Keep Saved License Key")
        XCTAssertEqual(chinese.keepSavedLicenseKey, "保留已保存许可证密钥")
        XCTAssertEqual(english.savedLicenseKeyWillBeCleared, "License key will be cleared")
        XCTAssertEqual(chinese.savedLicenseKeyWillBeCleared, "许可证密钥将被清除")
        XCTAssertEqual(english.reveal, "Reveal")
        XCTAssertEqual(chinese.reveal, "显示")
        XCTAssertEqual(english.hide, "Hide")
        XCTAssertEqual(chinese.hide, "隐藏")
        XCTAssertEqual(english.creditCard, "Credit Card")
        XCTAssertEqual(chinese.creditCard, "信用卡")
        XCTAssertEqual(english.softwareLicense, "Software License")
        XCTAssertEqual(chinese.softwareLicense, "软件许可证")
        XCTAssertEqual(english.clearSavedPassword, "Clear Saved Password")
        XCTAssertEqual(chinese.clearSavedPassword, "清除已保存密码")
        XCTAssertEqual(english.keepSavedPassword, "Keep Saved Password")
        XCTAssertEqual(chinese.keepSavedPassword, "保留已保存密码")
        XCTAssertEqual(english.savedPasswordWillBeCleared, "Password will be cleared")
        XCTAssertEqual(chinese.savedPasswordWillBeCleared, "密码将被清除")
        XCTAssertEqual(english.restore, "Restore")
        XCTAssertEqual(chinese.restore, "恢复")
        XCTAssertEqual(english.duplicate, "Duplicate")
        XCTAssertEqual(chinese.duplicate, "复制")
        XCTAssertEqual(chinese.statusMessage("Duplicated"), "已复制")
        XCTAssertEqual(chinese.statusMessage("2 conflict versions"), "2 个冲突版本")
        XCTAssertEqual(chinese.statusMessage("Conflict resolved"), "冲突已解决")
        XCTAssertEqual(chinese.statusMessage("Conflict merged"), "冲突已合并")
        XCTAssertEqual(chinese.statusMessage("Quarantined 2 rejected records"), "已隔离 2 条异常同步记录")
        let quarantine = SyncQuarantinePayload(
            movedRecords: 2,
            movedItemRecords: 1,
            movedTombstoneRecords: 1
        )
        XCTAssertEqual(english.quarantineResult(quarantine), "Quarantined 2 rejected records")
        XCTAssertEqual(chinese.quarantineResult(quarantine), "已隔离 2 条异常同步记录")
        XCTAssertEqual(chinese.statusMessage("Restored"), "已恢复")
        XCTAssertEqual(chinese.clipboardPreferenceHint, "复制的敏感内容会在此时间后清除。")
        XCTAssertEqual(english.cleanupLegacyKeychain, "Clean Up Legacy Keychain")
        XCTAssertEqual(chinese.cleanupLegacyKeychain, "清理旧版钥匙串条目")
        XCTAssertEqual(chinese.statusMessage("Legacy Keychain entries removed"), "旧版钥匙串条目已移除")
        XCTAssertEqual(chinese.statusMessage("No legacy Keychain entries found"), "未发现旧版钥匙串条目")
        XCTAssertEqual(english.durationOption(300), "5m")
        XCTAssertEqual(chinese.itemStatus("archived"), "已归档")
        XCTAssertEqual(chinese.statusMessage("Vault created"), "密码库已创建")
        XCTAssertEqual(chinese.statusMessage("Vault creation canceled"), "已取消创建密码库")
        XCTAssertEqual(chinese.statusMessage("Vault creation failed"), "创建密码库失败")
        XCTAssertEqual(
            chinese.statusMessage("invalid vault: target vault directory already exists and is not empty"),
            "请选择一个空位置创建密码库"
        )
        XCTAssertEqual(chinese.statusMessage("Vault unlocked"), "密码库已解锁")
        XCTAssertEqual(chinese.statusMessage("Vault unlocked with Keychain"), "已使用钥匙串解锁")
        XCTAssertEqual(chinese.statusMessage("Keychain unlock disabled"), "钥匙串解锁已停用")
        XCTAssertEqual(chinese.statusMessage("Vault locked"), "密码库已锁定")
        XCTAssertEqual(chinese.statusMessage("Archived"), "已归档")
        XCTAssertEqual(chinese.statusMessage("Deleted"), "已删除")
        XCTAssertEqual(chinese.statusMessage("Saved"), "已保存")
        XCTAssertEqual(english.statusMessage("12 items"), "12 items")
        XCTAssertEqual(chinese.statusMessage("0 items"), "0 个项目")
        XCTAssertEqual(chinese.statusMessage("1 items"), "1 个项目")
        XCTAssertEqual(chinese.statusMessage("12 items"), "12 个项目")
        XCTAssertEqual(chinese.statusMessage("01 items"), "01 items")
        XCTAssertEqual(chinese.statusMessage("login item has no username"), "登录项没有用户名")
        XCTAssertEqual(chinese.statusMessage("login item has no password"), "登录项没有密码")
        XCTAssertEqual(
            chinese.statusMessage("Select at least one password character class"),
            "请至少选择一种密码字符类型"
        )
        XCTAssertEqual(english.avoidAmbiguousCharacters, "Avoid ambiguous characters")
        XCTAssertEqual(chinese.avoidAmbiguousCharacters, "避免易混淆字符")
        XCTAssertEqual(english.openURL, "Open URL")
        XCTAssertEqual(chinese.openURL, "打开网址")
        XCTAssertEqual(chinese.statusMessage("URL opened"), "网址已打开")
        XCTAssertEqual(chinese.statusMessage("login item has no valid URL"), "登录项没有可打开的网址")
        XCTAssertEqual(english.copyBody, "Copy Body")
        XCTAssertEqual(chinese.copyBody, "复制正文")
        XCTAssertEqual(chinese.statusMessage("login item has no TOTP secret"), "登录项没有动态验证码密钥")
        XCTAssertEqual(chinese.statusMessage("Secure note body copied"), "安全笔记正文已复制")
        XCTAssertEqual(chinese.statusMessage("secure note has no body"), "安全笔记没有正文")
        XCTAssertEqual(chinese.statusMessage("credit card has no card number"), "信用卡没有卡号")
        XCTAssertEqual(chinese.statusMessage("credit card has no verification code"), "信用卡没有安全码")
        XCTAssertEqual(chinese.statusMessage("software license has no license key"), "软件许可证没有许可证密钥")
        XCTAssertEqual(chinese.statusMessage("Sync refresh paused for unsaved edits"), "有未保存修改，已暂停同步刷新")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before importing"), "请先保存或放弃修改再导入")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before sync recovery"), "请先保存或放弃修改再进行同步恢复")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before exporting"), "请先保存或放弃修改再导出")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before changing selection"), "请先保存或放弃修改再切换项目")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before archiving"), "请先保存或放弃修改再归档")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before deleting"), "请先保存或放弃修改再删除")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before updating favorite"), "请先保存或放弃修改再更新收藏")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before duplicating"), "请先保存或放弃修改再复制项目")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before restoring"), "请先保存或放弃修改再恢复")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before resolving conflict"), "请先保存或放弃修改再解决冲突")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before switching vaults"), "请先保存或放弃修改再切换密码库")
        XCTAssertEqual(chinese.statusMessage("Save or discard edits before closing vault"), "请先保存或放弃修改再关闭密码库")
        XCTAssertEqual(chinese.statusMessage("Filters cleared"), "过滤已清除")
        XCTAssertEqual(chinese.statusMessage("Plaintext export revealed"), "已显示明文导出文件")
        XCTAssertEqual(chinese.statusMessage("Plaintext export moved to Trash"), "明文导出文件已移到废纸篓")
        XCTAssertEqual(chinese.statusMessage("Showing conflicts"), "正在显示冲突")
        XCTAssertEqual(chinese.statusMessage("Unsupported item type"), "暂不支持的项目类型")
        XCTAssertEqual(chinese.statusMessage("Resolve conflict before copying"), "请先解决冲突再复制")
        XCTAssertEqual(chinese.statusMessage("Resolve conflict before revealing"), "请先解决冲突再显示")
        XCTAssertEqual(chinese.statusMessage("Refresh sync before editing this item"), "请刷新同步后再编辑此项目")
        XCTAssertEqual(
            chinese.statusMessage("Local edit kept; current synced item reloaded"),
            "已保留本地编辑，并重新载入当前同步版本"
        )
        XCTAssertEqual(
            chinese.statusMessage("Export completed: 2 exported, 1 skipped"),
            "导出已完成：2 项已导出，1 项已跳过"
        )
        XCTAssertEqual(AppLanguage.resolve("unknown"), .english)
    }

    func testMenuBarLocalizationMapsStandardTitlesAcrossLanguages() {
        let english = AppText(AppLanguage.english.rawValue)
        let chinese = AppText(AppLanguage.simplifiedChinese.rawValue)
        let japanese = AppText(AppLanguage.japanese.rawValue)

        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "File"), .file)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "文件"), .file)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "ファイル"), .file)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "Edit"), .edit)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "编辑"), .edit)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "View"), .view)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "显示"), .view)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "Window"), .window)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "Help"), .help)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "Item"), .item)
        XCTAssertEqual(MenuBarLocalization.kind(forTitle: "密码库"), .vault)
        XCTAssertNil(MenuBarLocalization.kind(forTitle: "KeptNear"))

        XCTAssertEqual(MenuBarLocalization.localizedTitle(for: .file, text: chinese), "文件")
        XCTAssertEqual(MenuBarLocalization.localizedTitle(for: .edit, text: chinese), "编辑")
        XCTAssertEqual(MenuBarLocalization.localizedTitle(for: .view, text: japanese), "表示")
        XCTAssertEqual(MenuBarLocalization.localizedTitle(for: .window, text: english), "Window")
        XCTAssertEqual(MenuBarLocalization.localizedTitle(for: .help, text: chinese), "帮助")
        XCTAssertEqual(MenuBarLocalization.localizedTitle(for: .item, text: chinese), "项目")
        XCTAssertEqual(MenuBarLocalization.localizedTitle(for: .vault, text: japanese), "保管庫")
    }

    func testLanguageTextSupportsJapanese() {
        let japanese = AppText(AppLanguage.japanese.rawValue)

        XCTAssertEqual(
            AppLanguage.allCases,
            [.english, .simplifiedChinese, .japanese]
        )
        XCTAssertEqual(AppLanguage.japanese.rawValue, "ja")
        XCTAssertEqual(AppLanguage.japanese.displayName, "日本語")
        XCTAssertEqual(AppLanguage.resolve("ja"), .japanese)
        XCTAssertEqual(AppLanguage.resolve("unknown"), .english)

        XCTAssertEqual(japanese.welcomeHeadline, "パスワードを、いつも手元に。")
        XCTAssertEqual(
            japanese.localPasswordManager,
            "ローカルパスワード・トークンマネージャー"
        )
        XCTAssertEqual(japanese.openExistingVault, "既存の保管庫を開く")
        XCTAssertEqual(japanese.unlockVaultNamed("Personal"), "Personalのロックを解除")
        XCTAssertEqual(japanese.newVault, "新規保管庫")
        XCTAssertEqual(japanese.openRecentVault, "最近使った保管庫を開く")
        XCTAssertEqual(japanese.languageLabel, "言語")
        XCTAssertEqual(japanese.languageHint, "変更はすぐに反映されます。")
        XCTAssertEqual(japanese.fileMenu, "ファイル")
        XCTAssertEqual(japanese.editMenu, "編集")
        XCTAssertEqual(japanese.viewMenu, "表示")
        XCTAssertEqual(japanese.windowMenu, "ウインドウ")
        XCTAssertEqual(japanese.helpMenu, "ヘルプ")
        XCTAssertEqual(japanese.itemMenu, "アイテム")
        XCTAssertEqual(japanese.vaultMenu, "保管庫")
        XCTAssertEqual(japanese.settings, "設定")
        XCTAssertEqual(japanese.login, "ログイン")
        XCTAssertEqual(japanese.secureNote, "セキュアノート")
        XCTAssertEqual(japanese.browse, "ブラウズ")
        XCTAssertEqual(japanese.itemTypes, "種類")
        XCTAssertEqual(japanese.securityAndMaintenance, "セキュリティと管理")
        XCTAssertEqual(japanese.itemCount(2), "2件")
        XCTAssertEqual(japanese.sidebarSyncReady, "同期準備完了")
        XCTAssertEqual(japanese.notRefreshedYet, "まだ更新されていません")
        XCTAssertEqual(japanese.masterPassword, "マスターパスワード")
        XCTAssertEqual(japanese.enterMasterPasswordToUnlock, "マスターパスワードを入力")
        XCTAssertEqual(japanese.forgotMasterPassword, "マスターパスワードを忘れた場合")
        XCTAssertEqual(
            japanese.closeAndCreateNewVault,
            "閉じて新しい保管庫を作成"
        )
        XCTAssertEqual(
            japanese.statusMessage("invalid vault credentials"),
            "マスターパスワードが正しくありません。もう一度お試しください。"
        )
        XCTAssertEqual(
            japanese.statusMessage(VaultStore.appsToolsVaultPathConflictStatus),
            "保管庫のコピー競合を検出しました。アプリとツールからのアクセスは利用できません。"
        )
        XCTAssertEqual(
            japanese.statusMessage("Vault moved to Trash"),
            "保管庫をゴミ箱へ移動しました"
        )
        XCTAssertEqual(japanese.diagnostics, "診断")
        XCTAssertEqual(japanese.syncReadiness, "同期準備状況")
        XCTAssertEqual(japanese.trustBoundaryTitle, "信頼境界")
        XCTAssertEqual(
            japanese.syncRefreshPausedMessage,
            "暗号化ファイルの変更が待機しています。現在の編集を保存または破棄すると、ディスクから更新されます。"
        )
        XCTAssertEqual(
            japanese.masterPasswordStrengthLabel(
                MasterPasswordStrength.evaluate("LocalVaults-2026")
            ),
            "強度：強い"
        )
        XCTAssertEqual(
            japanese.syncLocationHint(VaultSyncLocationHint(provider: .iCloudDrive)),
            "同期の可能性：iCloud Drive"
        )
        XCTAssertEqual(
            japanese.staleSaveReviewMessage("Personal Email"),
            "Personal Email はディスク上で変更されています。再度保存する前に、保持された下書きを確認してください。"
        )
        XCTAssertEqual(
            japanese.plaintextExportMessage("backup.json"),
            "現在のマスターパスワードを入力して、backup.json に保管庫データを平文で書き込みます。このファイルを入手した人は誰でも、エクスポートした秘密情報を読み取れます。"
        )

        XCTAssertEqual(japanese.statusMessage("Vault created"), "保管庫を作成しました")
        XCTAssertEqual(japanese.statusMessage("Vault unlocked"), "保管庫のロックを解除しました")
        XCTAssertEqual(japanese.statusMessage("12 items"), "12件のアイテム")
        XCTAssertEqual(
            japanese.statusMessage("Export completed: 2 exported, 1 skipped"),
            "エクスポート完了：2件をエクスポート、1件をスキップ"
        )
        XCTAssertEqual(
            japanese.statusMessage("Backup completed: 3 items, 1 attachments, 2 tombstones"),
            "バックアップ完了：アイテムファイル 3件、添付ファイル 1件、削除マーカー 2件"
        )
        XCTAssertEqual(
            japanese.statusMessage("Restore completed: 3 items, 1 attachments, 2 tombstones"),
            "復元完了：アイテムファイル 3件、添付ファイル 1件、削除マーカー 2件"
        )
        XCTAssertEqual(
            japanese.statusMessage("Vault copied to sync location: 3 items, 1 attachments, 2 tombstones"),
            "同期先へコピーしました：アイテムファイル 3件、添付ファイル 1件、削除マーカー 2件"
        )
        XCTAssertEqual(
            japanese.statusMessage("Quarantined 2 rejected records"),
            "拒否された同期レコード 2件を隔離しました"
        )
        XCTAssertEqual(
            japanese.statusMessage("2 conflict versions"),
            "競合バージョン 2件"
        )
        XCTAssertEqual(
            japanese.statusMessage("Save or discard edits before switching vaults"),
            "保管庫を切り替える前に編集を保存または破棄してください"
        )
        XCTAssertEqual(
            japanese.statusMessage("opaque core error"),
            "opaque core error"
        )
    }

    func testCredentialTemplateCatalogContainsRequiredProviderNeutralTypes() {
        XCTAssertEqual(
            CredentialTemplateKind.requiredTemplates.map(\.rawValue),
            [
                "login",
                "api-token",
                "api-key",
                "ssh-key",
                "certificate",
                "secure-note",
                "custom"
            ]
        )
        XCTAssertEqual(
            Set(CredentialTemplateKind.requiredTemplates.map(\.rawValue)).count,
            CredentialTemplateKind.requiredTemplates.count
        )
        XCTAssertEqual(
            CredentialTemplateKind.credentialTemplates.filter(\.usesTemplateCredentialForm),
            [.apiToken, .apiKey, .sshKey, .certificate, .custom]
        )
        XCTAssertEqual(CredentialTemplateKind.apiToken.primarySecretKind, "api-token")
        XCTAssertEqual(CredentialTemplateKind.apiKey.primarySecretKind, "api-key")
        XCTAssertEqual(CredentialTemplateKind.sshKey.primarySecretKind, "private-key")
        XCTAssertEqual(CredentialTemplateKind.certificate.primarySecretKind, "certificate")
        XCTAssertEqual(CredentialTemplateKind.custom.primarySecretKind, "generic-secret")
        XCTAssertTrue(CredentialTemplateKind.apiToken.supportsExpiry)
        XCTAssertTrue(CredentialTemplateKind.apiKey.supportsExpiry)
        XCTAssertTrue(CredentialTemplateKind.certificate.supportsExpiry)
        XCTAssertFalse(CredentialTemplateKind.sshKey.supportsExpiry)
        XCTAssertFalse(CredentialTemplateKind.custom.supportsExpiry)
    }

    func testSimpleAPITokenTemplateRequiresOnlyTitleAndSecret() {
        var form = TemplateCredentialForm(template: .apiToken)
        XCTAssertFalse(form.isValidForSave)

        form.title = "Git hosting token"
        XCTAssertFalse(form.isValidForSave)

        form.secret = "token-marker"
        XCTAssertTrue(form.isValidForSave)
        XCTAssertTrue(form.expiry.isEmpty)
        XCTAssertTrue(form.notes.isEmpty)
        XCTAssertTrue(form.tags.isEmpty)
    }

    func testCredentialTemplateLabelsCoverEnglishChineseAndJapanese() {
        let expectedAPITokenLabels: [AppLanguage: String] = [
            .english: "API Token",
            .simplifiedChinese: "API 令牌",
            .japanese: "APIトークン"
        ]
        for language in AppLanguage.allCases {
            let text = AppText(language.rawValue)
            XCTAssertEqual(
                text.credentialTemplateName(.apiToken),
                expectedAPITokenLabels[language]
            )
            for template in CredentialTemplateKind.requiredTemplates {
                XCTAssertFalse(
                    text.credentialTemplateName(template)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                        .isEmpty
                )
            }
        }
    }

    func testMacCommandAvailabilityTracksUnlockedAndSaveGuardState() {
        let locked = PSWMacCommandAvailability(
            isUnlocked: false,
            canSaveCurrentEditor: true,
            canCopyUsername: true,
            canCopyPassword: true,
            canCopyTotp: true,
            canCopySecureNoteBody: true,
            canCopyCardNumber: true,
            canCopyCardVerificationCode: true,
            canCopyLicenseKey: true
        )

        XCTAssertTrue(locked.isEnabled(.newVault))
        XCTAssertTrue(locked.isEnabled(.openVault))
        for command in PSWMacCommand.allCases where ![.newVault, .openVault].contains(command) {
            XCTAssertFalse(locked.isEnabled(command))
        }

        let unlocked = PSWMacCommandAvailability(
            isUnlocked: true,
            canSaveCurrentEditor: true,
            canEditItem: true,
            hasRecentVault: true,
            canCopyUsername: true,
            canCopyPassword: true,
            canCopyTotp: true,
            canCopySecureNoteBody: true,
            canCopyCardNumber: true,
            canCopyCardVerificationCode: true,
            canCopyLicenseKey: true
        )

        for command in PSWMacCommand.allCases {
            XCTAssertTrue(unlocked.isEnabled(command))
        }

        let ineligibleLoginSelection = PSWMacCommandAvailability(
            isUnlocked: true,
            canSaveCurrentEditor: false,
            hasRecentVault: true,
            canCopyUsername: false,
            canCopyPassword: false,
            canCopyTotp: false,
            canCopySecureNoteBody: false,
            canCopyCardNumber: false,
            canCopyCardVerificationCode: false,
            canCopyLicenseKey: false
        )

        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.newVault))
        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.openVault))
        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.openRecentVault))
        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.newItem))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.editItem))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.saveCurrentEditor))
        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.focusSearch))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.copyUsername))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.copyPassword))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.copyTotp))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.copySecureNoteBody))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.copyCardNumber))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.copyCardVerificationCode))
        XCTAssertFalse(ineligibleLoginSelection.isEnabled(.copyLicenseKey))
        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.refreshSync))
        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.lockVault))
    }

    func testMacCommandHandlerOnlyPerformsEnabledCommands() {
        var performedCommands: [PSWMacCommand] = []

        let lockedHandler = PSWMacCommandHandler(
            availability: PSWMacCommandAvailability(isUnlocked: false, canSaveCurrentEditor: true),
            createNewVault: { performedCommands.append(.newVault) },
            openVault: { performedCommands.append(.openVault) },
            openRecentVault: { performedCommands.append(.openRecentVault) },
            createNewItem: { performedCommands.append(.newItem) },
            saveCurrentEditor: { performedCommands.append(.saveCurrentEditor) },
            focusSearch: { performedCommands.append(.focusSearch) },
            copyUsername: { performedCommands.append(.copyUsername) },
            copyPassword: { performedCommands.append(.copyPassword) },
            copyTotp: { performedCommands.append(.copyTotp) },
            copySecureNoteBody: { performedCommands.append(.copySecureNoteBody) },
            copyCardNumber: { performedCommands.append(.copyCardNumber) },
            copyCardVerificationCode: { performedCommands.append(.copyCardVerificationCode) },
            copyLicenseKey: { performedCommands.append(.copyLicenseKey) },
            refreshSync: { performedCommands.append(.refreshSync) },
            lockVault: { performedCommands.append(.lockVault) }
        )

        for command in PSWMacCommand.allCases {
            lockedHandler.perform(command)
        }

        XCTAssertEqual(performedCommands, [.newVault, .openVault])
        performedCommands.removeAll()

        let guardedHandler = PSWMacCommandHandler(
            availability: PSWMacCommandAvailability(
                isUnlocked: true,
                canSaveCurrentEditor: false,
                canEditItem: true,
                hasRecentVault: true,
                canCopyUsername: true,
                canCopyPassword: true,
                canCopyTotp: false,
                canCopySecureNoteBody: true,
                canCopyCardNumber: true,
                canCopyCardVerificationCode: false,
                canCopyLicenseKey: true
            ),
            createNewVault: { performedCommands.append(.newVault) },
            openVault: { performedCommands.append(.openVault) },
            openRecentVault: { performedCommands.append(.openRecentVault) },
            createNewItem: { performedCommands.append(.newItem) },
            saveCurrentEditor: { performedCommands.append(.saveCurrentEditor) },
            focusSearch: { performedCommands.append(.focusSearch) },
            copyUsername: { performedCommands.append(.copyUsername) },
            copyPassword: { performedCommands.append(.copyPassword) },
            copyTotp: { performedCommands.append(.copyTotp) },
            copySecureNoteBody: { performedCommands.append(.copySecureNoteBody) },
            copyCardNumber: { performedCommands.append(.copyCardNumber) },
            copyCardVerificationCode: { performedCommands.append(.copyCardVerificationCode) },
            copyLicenseKey: { performedCommands.append(.copyLicenseKey) },
            refreshSync: { performedCommands.append(.refreshSync) },
            lockVault: { performedCommands.append(.lockVault) },
            editCurrentItem: { performedCommands.append(.editItem) }
        )

        for command in PSWMacCommand.allCases {
            guardedHandler.perform(command)
        }

        XCTAssertEqual(performedCommands, [
            .newVault,
            .openVault,
            .openRecentVault,
            .newItem,
            .editItem,
            .focusSearch,
            .copyUsername,
            .copyPassword,
            .copySecureNoteBody,
            .copyCardNumber,
            .copyLicenseKey,
            .refreshSync,
            .lockVault
        ])
    }

    func testItemListRowActionsUseNonSecretRowMetadata() {
        let login = VaultItemView(
            id: "login",
            title: "Email",
            itemType: "login",
            status: "active",
            favorite: false,
            tags: ["personal"]
        )
        let favoriteCard = VaultItemView(
            id: "card",
            title: "Travel Card",
            itemType: "credit card",
            status: "active",
            favorite: true,
            tags: ["travel"]
        )
        let conflicted = VaultItemView(
            id: "conflict",
            title: "Conflict",
            itemType: "login",
            status: "conflicted",
            conflictId: "conflict_login",
            favorite: false,
            tags: []
        )
        let archived = VaultItemView(
            id: "archived",
            title: "Old",
            itemType: "secure note",
            status: "archived",
            favorite: false,
            tags: []
        )

        XCTAssertEqual(
            ItemListRowAction.actions(for: login),
            [.copyUsername, .copyPassword, .copyTotp, .openURL, .favorite, .duplicate, .archive, .delete]
        )
        XCTAssertEqual(
            ItemListRowAction.actions(for: favoriteCard),
            [.copyCardNumber, .copyVerificationCode, .favorite, .duplicate, .archive, .delete]
        )
        XCTAssertEqual(ItemListRowAction.actions(for: conflicted), [.resolveConflict])
        XCTAssertEqual(
            ItemListRowAction.actions(for: archived),
            [.copyBody, .favorite, .duplicate, .restoreArchive, .delete]
        )
        XCTAssertEqual(ItemListRowAction.favorite.title(text: AppText("en"), item: favoriteCard), "Unfavorite")
        XCTAssertEqual(ItemListRowAction.favorite.title(text: AppText("zh-Hans"), item: login), "收藏")
        XCTAssertTrue(ItemListRowAction.archive.isDestructive)
        XCTAssertTrue(ItemListRowAction.delete.isDestructive)
        XCTAssertEqual(ItemListRowAction.archive.destructiveAction, .archive)
        XCTAssertEqual(ItemListRowAction.delete.destructiveAction, .delete)
        XCTAssertNil(ItemListRowAction.copyPassword.destructiveAction)
    }

    func testVaultItemSummarySubtitleKeepsNormalRowsQuietAndHighlightsSpecialStatus() {
        let active = VaultItemView(
            id: "active",
            title: "Email",
            itemType: "login",
            status: "active",
            favorite: false,
            tags: ["personal", "mail", "ignored"]
        )
        let archived = VaultItemView(
            id: "archived",
            title: "Old Note",
            itemType: "secure note",
            status: "archived",
            favorite: false,
            tags: ["old"]
        )

        XCTAssertEqual(
            VaultItemSummaryRow.subtitle(for: active, text: AppText("en")),
            "Login · personal · mail"
        )
        XCTAssertEqual(
            VaultItemSummaryRow.subtitle(for: archived, text: AppText("zh-Hans")),
            "安全笔记 · 已归档"
        )
    }

    func testVaultWorkspaceLayoutPreservesThreeUsableColumnsAtMinimumWindowWidth() {
        XCTAssertEqual(VaultWorkspaceLayout.sidebarIdeal, 220)
        XCTAssertEqual(VaultWorkspaceLayout.itemListIdeal, 340)
        XCTAssertGreaterThanOrEqual(VaultWorkspaceLayout.detailMinimum, 480)
        XCTAssertLessThanOrEqual(
            VaultWorkspaceLayout.sidebarMinimum
                + VaultWorkspaceLayout.itemListMinimum
                + VaultWorkspaceLayout.detailMinimum,
            1_040
        )
    }

    func testVaultDetailModeDefaultsSelectedItemsToReadOnly() {
        XCTAssertEqual(
            VaultDetailMode(hasSelection: false, isEditing: false, isCreating: false),
            .empty
        )
        XCTAssertEqual(
            VaultDetailMode(hasSelection: true, isEditing: false, isCreating: false),
            .readOnly
        )
        XCTAssertEqual(
            VaultDetailMode(hasSelection: true, isEditing: true, isCreating: false),
            .editing
        )
        XCTAssertEqual(
            VaultDetailMode(hasSelection: false, isEditing: false, isCreating: true),
            .creating
        )
        XCTAssertEqual(
            VaultDetailMode(hasSelection: true, isEditing: true, isCreating: true),
            .creating
        )
    }

    func testVaultItemDetailModelKeepsProtectedValuesOutOfReadOnlyPresentation() throws {
        let item = VaultItemView(
            id: "login_1",
            title: "Email",
            itemType: "login",
            status: "active",
            favorite: true,
            tags: ["personal"]
        )
        let detail = LoginDetail(
            id: "login_1",
            revision: "rev_1",
            title: "Email",
            username: "me@example.com",
            url: "https://mail.example.com",
            notes: "Primary inbox",
            totpSecret: "JBSWY3DPEHPK3PXP",
            favorite: true,
            tags: ["personal"],
            status: "active"
        )

        let model = try XCTUnwrap(VaultItemDetailModel(
            item: item,
            login: detail,
            credential: nil,
            secureNote: nil,
            creditCard: nil,
            softwareLicense: nil
        ))
        guard case let .login(login) = model.content else {
            return XCTFail("Expected login read-only content")
        }

        XCTAssertEqual(login.username, "me@example.com")
        XCTAssertEqual(login.urls, ["https://mail.example.com"])
        XCTAssertEqual(login.notes, "Primary inbox")
        XCTAssertTrue(login.hasTotpSecret)
        XCTAssertFalse(String(reflecting: model).contains("JBSWY3DPEHPK3PXP"))
    }

    func testCredentialSummaryAndDetailDecodeStableSecretFieldIdentityWithoutValue() throws {
        let itemData = Data(
            """
            {
              "id": "credential_1",
              "revision": "revision_1",
              "title": "Build API",
              "item_type": "api token",
              "template_id": "api-token",
              "secret_kinds": ["api-token"],
              "status": "active",
              "conflict_id": null,
              "favorite": true,
              "tags": ["automation"]
            }
            """.utf8
        )
        let item = try JSONDecoder().decode(VaultItemView.self, from: itemData)
        XCTAssertEqual(item.credentialTemplateKind, .apiToken)
        XCTAssertTrue(item.isTemplateCredential)
        XCTAssertEqual(item.secretKinds, ["api-token"])

        let detailData = Data(
            """
            {
              "id": "credential_1",
              "revision": "revision_1",
              "title": "Build API",
              "template_id": "api-token",
              "fields": [
                {
                  "value_type": "secret",
                  "role": "token",
                  "label": null,
                  "secret_field_id": "field_01J_STABLE",
                  "secret_kind": "api-token",
                  "has_value": true
                },
                {
                  "value_type": "text",
                  "role": "expiry",
                  "label": null,
                  "text": "2027-12-31"
                }
              ],
              "favorite": true,
              "tags": ["automation"],
              "status": "active"
            }
            """.utf8
        )
        let detail = try JSONDecoder().decode(CredentialDetail.self, from: detailData)
        XCTAssertEqual(detail.secretFields.map(\.secretFieldId), ["field_01J_STABLE"])
        XCTAssertEqual(detail.secretFields.map(\.secretKind), ["api-token"])
        XCTAssertEqual(detail.textFields.map(\.text), ["2027-12-31"])

        let model = try XCTUnwrap(VaultItemDetailModel(
            item: item,
            login: nil,
            credential: detail,
            secureNote: nil,
            creditCard: nil,
            softwareLicense: nil
        ))
        guard case let .credential(credential) = model.content else {
            return XCTFail("Expected generic credential read-only content")
        }
        XCTAssertEqual(credential.secretFields.map(\.secretFieldId), ["field_01J_STABLE"])
        XCTAssertFalse(String(reflecting: model).contains("token-marker"))
    }

    func testTypedConflictCandidateDecodesRedactedSecretAndDeletionState() throws {
        let data = Data(
            """
            {
              "item_id": "credential_1",
              "revision": "revision_deleted",
              "title": "Deployment token",
              "item_type": "api token",
              "template_id": "api-token",
              "status": "deleted",
              "favorite": false,
              "tags": ["automation"],
              "comparison_fields": [],
              "changed_fields": ["fields"],
              "credential_fields": [
                {
                  "value_type": "secret",
                  "index": 0,
                  "role": "token",
                  "label": "Deploy token",
                  "secret_field_id": "secret_field_01J_STABLE",
                  "secret_kind": "api-token",
                  "has_value": true,
                  "changed": true
                },
                {
                  "value_type": "text",
                  "index": 1,
                  "role": "notes",
                  "label": null,
                  "text": "Production deploy",
                  "changed": false
                }
              ],
              "field_shape_changed": true,
              "supports_safe_field_merge": false
            }
            """.utf8
        )

        let candidate = try JSONDecoder().decode(ConflictCandidateView.self, from: data)

        XCTAssertEqual(candidate.status, "deleted")
        XCTAssertEqual(candidate.templateId, "api-token")
        XCTAssertTrue(candidate.fieldShapeChanged)
        XCTAssertFalse(candidate.supportsSafeFieldMerge)
        XCTAssertEqual(candidate.credentialFields.count, 2)
        guard case let .secret(secret) = candidate.credentialFields[0] else {
            return XCTFail("Expected redacted typed secret field")
        }
        XCTAssertEqual(secret.secretFieldId, "secret_field_01J_STABLE")
        XCTAssertEqual(secret.secretKind, "api-token")
        XCTAssertTrue(secret.hasValue)
        XCTAssertTrue(secret.changed)
        guard case let .text(textField) = candidate.credentialFields[1] else {
            return XCTFail("Expected typed text field")
        }
        XCTAssertEqual(textField.text, "Production deploy")
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("private-token-marker"))
    }

    func testUnlockedPayloadDecodesPathFreeAppsToolsConflictWithLegacyDefault() throws {
        let currentData = Data(
            """
            {
              "type": "unlocked",
              "session_id": 7,
              "items": [],
              "apps_tools_vault_path_conflict": true
            }
            """.utf8
        )
        guard case let .unlocked(current) = try JSONDecoder().decode(
            CorePayload.self,
            from: currentData
        ) else {
            return XCTFail("Expected unlocked payload")
        }
        XCTAssertTrue(current.appsToolsVaultPathConflict)

        let legacyData = Data(
            """
            {
              "type": "unlocked",
              "session_id": 8,
              "items": []
            }
            """.utf8
        )
        guard case let .unlocked(legacy) = try JSONDecoder().decode(
            CorePayload.self,
            from: legacyData
        ) else {
            return XCTFail("Expected legacy unlocked payload")
        }
        XCTAssertFalse(legacy.appsToolsVaultPathConflict)
        XCTAssertFalse(String(decoding: currentData, as: UTF8.self).contains("/Users/"))
    }

    func testAuthorizedCredentialIdsPayloadDecodesStableIdentitiesOnly() throws {
        let data = Data(
            """
            {
              "type": "authorizedCredentialIds",
              "credential_ids": [
                "credential_01J_AUTHORIZED",
                "credential_01J_SECOND"
              ]
            }
            """.utf8
        )

        guard case let .authorizedCredentialIds(payload) = try JSONDecoder().decode(
            CorePayload.self,
            from: data
        ) else {
            return XCTFail("Expected authorized credential identity payload")
        }
        XCTAssertEqual(
            payload.credentialIds,
            ["credential_01J_AUTHORIZED", "credential_01J_SECOND"]
        )
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("secret-marker"))
    }

    func testAppsToolsConsumerDetailPayloadDecodesOnlyManagementMetadata() throws {
        let data = Data(
            """
            {
              "type": "appsToolsConsumerDetail",
              "detail": {
                "consumer": {
                  "consumer_id": "consumer_01",
                  "label": "Local adapter",
                  "identity": {
                    "executable_name": "adapter",
                    "bundle_identifier": "com.example.adapter",
                    "team_identifier": "EXAMPLE",
                    "code_signing_evidence": "verified-with-team-identifier",
                    "code_signature_fingerprint": "0102-0304-0506-0708"
                  },
                  "access_rule_count": 1,
                  "usage_profile_count": 1,
                  "created_at_ms": 100
                },
                "field_grants": [{
                  "access_rule_id": "access_rule_01",
                  "field": {
                    "vault_id": "vault_01",
                    "credential_id": "credential_01",
                    "secret_field_id": "secret_field_01",
                    "current_vault": true,
                    "credential_title": "Deploy Token",
                    "field_label": "Token",
                    "secret_kind": "api-token"
                  },
                  "capability": "process.run",
                  "capability_version": 1,
                  "confirmation_policy": "every-use",
                  "lifetime": "persistent",
                  "expires_at_ms": null,
                  "created_at_ms": 110,
                  "active": true
                }],
                "usage_profiles": [{
                  "usage_profile_id": "usage_profile_01",
                  "label": "Child environment",
                  "capability": "process.run",
                  "capability_version": 1,
                  "placement": {
                    "kind": "process-environment",
                    "variable_name": "SERVICE_TOKEN",
                    "append_newline": null,
                    "reference_variable_name": null,
                    "render_dev_fd_path": null,
                    "header_name": null
                  },
                  "created_at_ms": 120
                }],
                "recent_audit_events": [{
                  "audit_event_id": "audit_event_01",
                  "occurred_at_ms": 130,
                  "kind": "credential-use",
                  "field": null,
                  "capability": "process.run",
                  "capability_version": 1,
                  "decision": "allowed",
                  "confirmation_method": "user-approval"
                }]
              }
            }
            """.utf8
        )

        guard case let .appsToolsConsumerDetail(payload) = try JSONDecoder().decode(
            CorePayload.self,
            from: data
        ) else {
            return XCTFail("Expected Apps & Tools Consumer detail payload")
        }
        XCTAssertEqual(payload.detail.consumer.identity.executableName, "adapter")
        XCTAssertEqual(payload.detail.fieldGrants.first?.confirmationPolicy, "every-use")
        XCTAssertEqual(
            payload.detail.usageProfiles.first?.placement.variableName,
            "SERVICE_TOKEN"
        )
        XCTAssertEqual(payload.detail.recentAuditEvents.first?.decision, "allowed")
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("seeded-secret-marker"))
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("/Users/"))
    }

    func testAppsToolsUsageProfilePayloadsDecodeTemplatesRecommendationsAndReceipts() throws {
        let setupData = Data(
            """
            {
              "type": "appsToolsUsageProfileSetup",
              "setup": {
                "consumer_id": "consumer_01",
                "templates": [{
                  "template_id": "http-bearer-authorization",
                  "capability": "http.request",
                  "capability_version": 1,
                  "technical_field": "none",
                  "suggested_value": null
                }, {
                  "template_id": "http-api-key-header",
                  "capability": "http.request",
                  "capability_version": 1,
                  "technical_field": "http-header-name",
                  "suggested_value": "X-API-Key"
                }, {
                  "template_id": "cli-environment-variable",
                  "capability": "process.run",
                  "capability_version": 1,
                  "technical_field": "environment-variable-name",
                  "suggested_value": null
                }],
                "recommendation": {
                  "recommendation_id": "github-cli",
                  "template_id": "cli-environment-variable",
                  "technical_name": "GH_TOKEN"
                }
              }
            }
            """.utf8
        )
        guard case let .appsToolsUsageProfileSetup(setupPayload) =
            try JSONDecoder().decode(CorePayload.self, from: setupData)
        else {
            return XCTFail("Expected Usage Profile setup payload")
        }
        XCTAssertEqual(setupPayload.setup.consumerId, "consumer_01")
        XCTAssertEqual(
            setupPayload.setup.templates.map(\.templateId),
            [
                "http-bearer-authorization",
                "http-api-key-header",
                "cli-environment-variable",
            ]
        )
        XCTAssertEqual(setupPayload.setup.recommendation?.recommendationId, "github-cli")
        XCTAssertEqual(setupPayload.setup.recommendation?.technicalName, "GH_TOKEN")

        let createdData = Data(
            """
            {
              "type": "appsToolsUsageProfileCreated",
              "consumer_id": "consumer_01",
              "profile": {
                "usage_profile_id": "usage_profile_01",
                "label": "GitHub CLI",
                "capability": "process.run",
                "capability_version": 1,
                "placement": {
                  "kind": "process-environment",
                  "variable_name": "GH_TOKEN",
                  "append_newline": null,
                  "reference_variable_name": null,
                  "render_dev_fd_path": null,
                  "header_name": null
                },
                "created_at_ms": 120
              }
            }
            """.utf8
        )
        guard case let .appsToolsUsageProfileCreated(createdPayload) =
            try JSONDecoder().decode(CorePayload.self, from: createdData)
        else {
            return XCTFail("Expected Usage Profile creation receipt")
        }
        XCTAssertEqual(createdPayload.consumerId, "consumer_01")
        XCTAssertEqual(createdPayload.profile.usageProfileId, "usage_profile_01")
        XCTAssertEqual(createdPayload.profile.placement.variableName, "GH_TOKEN")

        let removedData = Data(
            """
            {
              "type": "appsToolsUsageProfileRemoved",
              "consumer_id": "consumer_01",
              "usage_profile_id": "usage_profile_01",
              "removed": true
            }
            """.utf8
        )
        guard case let .appsToolsUsageProfileRemoved(removedPayload) =
            try JSONDecoder().decode(CorePayload.self, from: removedData)
        else {
            return XCTFail("Expected Usage Profile removal receipt")
        }
        XCTAssertEqual(removedPayload.consumerId, "consumer_01")
        XCTAssertEqual(removedPayload.usageProfileId, "usage_profile_01")
        XCTAssertTrue(removedPayload.removed)

        for data in [setupData, createdData, removedData] {
            let serialized = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(serialized.contains("seeded-secret-marker"))
            XCTAssertFalse(serialized.contains("/Users/"))
            XCTAssertFalse(serialized.contains("\"script\""))
            XCTAssertFalse(serialized.contains("\"command\""))
        }
    }

    func testAppsToolsPendingRequestQueuePayloadDecodesWithoutSecretOrPathMaterial() throws {
        let data = Data(
            """
            {
              "type": "appsToolsPendingRequests",
              "queue": {
                "pending_count": 1,
                "requests": [{
                  "request_source": "pairing",
                  "request_id": "pairing_request_01",
                  "kind": "pairing",
                  "consumer_id": null,
                  "consumer_label": null,
                  "identity": {
                    "executable_name": "local-adapter",
                    "bundle_identifier": "com.example.adapter",
                    "team_identifier": null,
                    "code_signing_evidence": "verified-without-team-identifier",
                    "code_signature_fingerprint": "0102-0304-0506-0708"
                  },
                  "pairing_comparison_code": "0123456789",
                  "pairing_key_fingerprint": "1112-1314-1516-1718",
                  "vault_id": null,
                  "credential_id": null,
                  "secret_field_id": null,
                  "capability": null,
                  "capability_version": null,
                  "request_description": null,
                  "created_at_ms": null,
                  "expires_at_ms": null,
                  "remaining_ms": 300000
                }]
              }
            }
            """.utf8
        )

        guard case let .appsToolsPendingRequests(payload) = try JSONDecoder().decode(
            CorePayload.self,
            from: data
        ) else {
            return XCTFail("Expected Apps & Tools pending request payload")
        }
        XCTAssertEqual(payload.queue.pendingCount, 1)
        XCTAssertEqual(payload.queue.requests.first?.id, "pairing:pairing_request_01")
        XCTAssertEqual(payload.queue.requests.first?.pairingComparisonCode, "0123456789")
        XCTAssertEqual(payload.queue.requests.first?.identity?.executableName, "local-adapter")
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("seeded-secret-marker"))
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("/Users/"))
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("pairing_public_key"))
    }

    func testAppsToolsDecisionAndCredentialReviewPayloadsDecodeWithoutSecretMaterial() throws {
        let decisionData = Data(
            """
            {
              "type": "appsToolsPendingRequestDecision",
              "decision": {
                "action": "configure-long-term-access",
                "status": "approved",
                "use_grant_id": null,
                "access_rule_id": "access_rule_01"
              }
            }
            """.utf8
        )
        guard case let .appsToolsPendingRequestDecision(payload) = try JSONDecoder().decode(
            CorePayload.self,
            from: decisionData
        ) else {
            return XCTFail("Expected Apps & Tools decision payload")
        }
        XCTAssertEqual(payload.decision.action, "configure-long-term-access")
        XCTAssertEqual(payload.decision.accessRuleId, "access_rule_01")
        XCTAssertNil(payload.decision.useGrantId)

        let reviewData = Data(
            """
            {
              "type": "appsToolsCredentialReview",
              "review": {
                "request_id": "approval_request_01",
                "request_description": "release credential",
                "capability": "process.run",
                "capability_version": 1,
                "truncated": false,
                "candidates": [{
                  "credential_id": "credential_01",
                  "title": "Release Token",
                  "template_id": "api-token",
                  "tags": ["release"],
                  "favorite": true,
                  "secret_fields": [{
                    "secret_field_id": "secret_field_01",
                    "role": "token",
                    "label": "Production",
                    "kind": "api-token"
                  }]
                }]
              }
            }
            """.utf8
        )
        guard case let .appsToolsCredentialReview(reviewPayload) = try JSONDecoder().decode(
            CorePayload.self,
            from: reviewData
        ) else {
            return XCTFail("Expected Apps & Tools credential review payload")
        }
        XCTAssertEqual(reviewPayload.review.candidates.first?.title, "Release Token")
        XCTAssertEqual(
            reviewPayload.review.candidates.first?.secretFields.first?.kind,
            "api-token"
        )
        let serialized = String(decoding: reviewData, as: UTF8.self)
        XCTAssertFalse(serialized.contains("seeded-secret-marker"))
        XCTAssertFalse(serialized.contains("/Users/"))
    }

    func testVaultItemDetailCapabilitiesMapFieldCopyActions() {
        let capabilities = VaultItemDetailCapabilities(
            canEdit: true,
            canCopyLoginFields: true,
            canCopyTotp: false,
            canOpenURL: true,
            canCopySecureNoteBody: false,
            canCopyCreditCardFields: true,
            canCopySoftwareLicenseFields: false,
            canCopyCredentialFields: false,
            canRevealSecrets: true,
            canToggleFavorite: true,
            canDuplicate: true,
            canResolveConflict: false,
            canRestoreArchive: false,
            canArchive: true,
            canDelete: true
        )

        XCTAssertTrue(capabilities.canCopy(.username))
        XCTAssertTrue(capabilities.canCopy(.password))
        XCTAssertTrue(capabilities.canCopy(.url("https://example.com")))
        XCTAssertFalse(capabilities.canCopy(.totp))
        XCTAssertFalse(capabilities.canCopy(.secureNoteBody))
        XCTAssertTrue(capabilities.canCopy(.cardNumber))
        XCTAssertTrue(capabilities.canCopy(.cardVerificationCode))
        XCTAssertFalse(capabilities.canCopy(.licenseKey))
    }

    func testSecretCopyCommandsUseExistingClipboardWorkflows() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                totpSecret: "JBSWY3DPEHPK3PXP"
            )
        ])
        let clipboard = FakeClipboard()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SecretCopyCommands.pswvault"))
        store.unlock(password: "correct horse")
        func makeHandler() -> PSWMacCommandHandler {
            PSWMacCommandHandler(
                availability: PSWMacCommandAvailability(
                    isUnlocked: store.isUnlocked,
                    canSaveCurrentEditor: store.canSaveCurrentEditor,
                    canCopyUsername: store.canCopyLoginFields,
                    canCopyPassword: store.canCopyLoginFields,
                    canCopyTotp: store.canCopyTotpCode,
                    canCopySecureNoteBody: store.canCopySecureNoteBody,
                    canCopyCardNumber: store.canCopyCreditCardFields,
                    canCopyCardVerificationCode: store.canCopyCreditCardFields,
                    canCopyLicenseKey: store.canCopySoftwareLicenseFields
                ),
                createNewVault: {},
                openVault: {},
                openRecentVault: {},
                createNewItem: {},
                saveCurrentEditor: {},
                focusSearch: {},
                copyUsername: { store.copyUsername() },
                copyPassword: { store.copyPassword() },
                copyTotp: { store.copyTotp() },
                copySecureNoteBody: { store.copySecureNoteBody() },
                copyCardNumber: { store.copyCardNumber() },
                copyCardVerificationCode: { store.copyCardVerificationCode() },
                copyLicenseKey: { store.copyLicenseKey() },
                refreshSync: {},
                lockVault: {}
            )
        }

        var handler = makeHandler()
        handler.perform(.copyUsername)
        handler.perform(.copyPassword)
        handler.perform(.copyTotp)

        store.select(itemId: nil)
        var note = SecureNoteForm()
        note.title = "Recovery"
        note.body = "offline backup codes"
        store.saveSecureNote(form: note)
        handler = makeHandler()
        handler.perform(.copySecureNoteBody)

        store.select(itemId: nil)
        var card = CreditCardForm()
        card.title = "Travel Card"
        card.cardholderName = "Alice Example"
        card.number = "4111111111111111"
        card.verificationCode = "123"
        store.saveCreditCard(form: card)
        handler = makeHandler()
        handler.perform(.copyCardNumber)
        handler.perform(.copyCardVerificationCode)

        store.select(itemId: nil)
        var license = SoftwareLicenseForm()
        license.title = "Editor License"
        license.product = "TextPro"
        license.licenseKey = "AAAA-BBBB-CCCC"
        store.saveSoftwareLicense(form: license)
        handler = makeHandler()
        handler.perform(.copyLicenseKey)

        XCTAssertEqual(clipboard.copied.map(\.value), [
            "me@example.com",
            "email-password",
            "123456",
            "offline backup codes",
            "4111111111111111",
            "123",
            "AAAA-BBBB-CCCC"
        ])
        XCTAssertEqual(clipboard.copied.map(\.timeout), Array(repeating: 45, count: 7))
        XCTAssertEqual(service.loginFieldRequests, ["username", "password"])
        XCTAssertEqual(service.creditCardFieldRequests, ["number", "verification_code"])
        XCTAssertEqual(service.softwareLicenseFieldRequests, ["license_key"])
        XCTAssertEqual(service.totpCodeCallCount, 1)
        XCTAssertEqual(store.statusMessage, "License key copied")
    }

    func testSyncRefreshPayloadDecodesRejectedRecordFilesWithBackwardCompatibility() throws {
        let payload = try JSONDecoder().decode(SyncRefreshPayload.self, from: Data("""
        {
          "loaded_items": 1,
          "applied_tombstones": 0,
          "detected_conflicts": 0,
          "rejected_records": 2,
          "rejected_item_records": 1,
          "rejected_tombstone_records": 1,
          "rejected_record_files": [
            { "kind": "item", "file_name": "bad_item.enc" },
            { "kind": "tombstone", "file_name": "bad_tombstone.enc" }
          ],
          "items": []
        }
        """.utf8))

        XCTAssertEqual(payload.rejectedRecordFiles, [
            SyncRejectedRecordFile(kind: "item", fileName: "bad_item.enc"),
            SyncRejectedRecordFile(kind: "tombstone", fileName: "bad_tombstone.enc")
        ])

        let legacyPayload = try JSONDecoder().decode(SyncRefreshPayload.self, from: Data("""
        {
          "loaded_items": 1,
          "applied_tombstones": 0,
          "detected_conflicts": 0,
          "rejected_records": 1,
          "rejected_item_records": 1,
          "rejected_tombstone_records": 0,
          "items": []
        }
        """.utf8))

        XCTAssertEqual(legacyPayload.rejectedRecordFiles, [])
    }

    func testVaultSyncLocationHintDetectsCommonProviderFolders() {
        XCTAssertEqual(
            VaultSyncLocationHint.classify(url: URL(fileURLWithPath: "/Users/alice/Library/Mobile Documents/com~apple~CloudDocs/Passwords/Main.pswvault")).provider,
            .iCloudDrive
        )
        XCTAssertEqual(
            VaultSyncLocationHint.classify(url: URL(fileURLWithPath: "/Users/alice/Dropbox/Passwords/Main.pswvault")).provider,
            .dropbox
        )
        XCTAssertEqual(
            VaultSyncLocationHint.classify(url: URL(fileURLWithPath: "/Users/alice/Library/CloudStorage/OneDrive-Personal/Passwords/Main.pswvault")).provider,
            .oneDrive
        )
        XCTAssertEqual(
            VaultSyncLocationHint.classify(url: URL(fileURLWithPath: "/Users/alice/Library/CloudStorage/GoogleDrive-alice/My Drive/Passwords/Main.pswvault")).provider,
            .googleDrive
        )
        XCTAssertEqual(
            VaultSyncLocationHint.classify(url: URL(fileURLWithPath: "/Users/alice/Syncthing/Passwords/Main.pswvault")).provider,
            .syncthing
        )
    }

    func testVaultSyncLocationHintFallsBackToLocalOrUnknown() {
        let hint = VaultSyncLocationHint.classify(url: URL(fileURLWithPath: "/Users/alice/Documents/Passwords/Main.pswvault"))

        XCTAssertNil(hint.provider)
        XCTAssertFalse(hint.isLikelySynced)
    }

    func testVaultSyncReadinessReportsCompleteRecognizedPlacementAndLocalUnlockEnvelope() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot
            .appendingPathComponent("Dropbox", isDirectory: true)
            .appendingPathComponent("Passwords", isDirectory: true)
            .appendingPathComponent("Main.pswvault", isDirectory: true)
        try createRequiredVaultStructure(at: vaultURL)
        try Data("local".utf8).write(to: vaultURL.appendingPathComponent("local_unlock.enc"))
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let readiness = try XCTUnwrap(VaultSyncReadiness.inspect(url: vaultURL))

        XCTAssertEqual(readiness.status, .completeLikelySynced)
        XCTAssertEqual(readiness.locationHint.provider, .dropbox)
        XCTAssertTrue(readiness.requiredStructureComplete)
        XCTAssertTrue(readiness.missingOrInvalidRequiredPathLabels.isEmpty)
        XCTAssertTrue(readiness.localUnlockEnvelopePresent)
    }

    func testVaultSyncReadinessReportsCompleteLocalOrUnknownPlacement() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot
            .appendingPathComponent("Local", isDirectory: true)
            .appendingPathComponent("Main.pswvault", isDirectory: true)
        try createRequiredVaultStructure(at: vaultURL)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let readiness = try XCTUnwrap(VaultSyncReadiness.inspect(url: vaultURL))

        XCTAssertEqual(readiness.status, .completeLocalOrUnknown)
        XCTAssertNil(readiness.locationHint.provider)
        XCTAssertTrue(readiness.requiredStructureComplete)
        XCTAssertFalse(readiness.localUnlockEnvelopePresent)
    }

    func testVaultSyncReadinessReportsIncompleteStructureWithoutFullPaths() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("Broken.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
        try Data("metadata".utf8).write(to: vaultURL.appendingPathComponent("vault.json"))
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("keys.enc", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("items", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let readiness = try XCTUnwrap(VaultSyncReadiness.inspect(url: vaultURL))

        XCTAssertEqual(readiness.status, .incomplete)
        XCTAssertFalse(readiness.requiredStructureComplete)
        XCTAssertEqual(
            readiness.missingOrInvalidRequiredPathLabels,
            ["keys.enc", "attachments/", "tombstones/"]
        )
        XCTAssertFalse(readiness.missingOrInvalidRequiredPathLabels.contains(vaultURL.path))
    }

    func testSavedSecretRevealCacheRevealsHidesAndClearsTransientValues() {
        let loginPassword = SavedSecretRevealKey(itemId: "login_1", field: .loginPassword)
        let loginTotp = SavedSecretRevealKey(itemId: "login_1", field: .loginTotpSecret)
        let licenseKey = SavedSecretRevealKey(itemId: "license_1", field: .softwareLicenseKey)
        var cache = SavedSecretRevealCache()

        XCTAssertFalse(cache.isRevealed(loginPassword))

        cache.reveal("email-password", for: loginPassword)
        cache.reveal("JBSWY3DPEHPK3PXP", for: loginTotp)
        cache.reveal("AAAA-BBBB-CCCC", for: licenseKey)

        XCTAssertEqual(cache.value(for: loginPassword), "email-password")
        XCTAssertTrue(cache.isRevealed(loginTotp))

        cache.hide(loginPassword)

        XCTAssertNil(cache.value(for: loginPassword))
        XCTAssertEqual(cache.value(for: loginTotp), "JBSWY3DPEHPK3PXP")

        cache.clear(itemId: "login_1")

        XCTAssertNil(cache.value(for: loginTotp))
        XCTAssertEqual(cache.value(for: licenseKey), "AAAA-BBBB-CCCC")

        cache.clearAll()

        XCTAssertFalse(cache.isRevealed(licenseKey))
    }

    func testMasterPasswordRotationFormClearsSensitiveFields() {
        var form = MasterPasswordRotationForm(
            currentPassword: "old-master-password",
            newPassword: "new-master-password",
            confirmation: "new-master-password"
        )

        XCTAssertFalse(form.isEmpty)

        form.clear()

        XCTAssertTrue(form.isEmpty)
        XCTAssertEqual(form.currentPassword, "")
        XCTAssertEqual(form.newPassword, "")
        XCTAssertEqual(form.confirmation, "")
    }

    func testMasterPasswordStrengthClassifiesCommonInputs() {
        XCTAssertEqual(MasterPasswordStrength.evaluate("").level, .empty)
        XCTAssertEqual(MasterPasswordStrength.evaluate("short1!").level, .weak)

        let repeated = MasterPasswordStrength.evaluate("aaaaaaaaaaaa")
        XCTAssertEqual(repeated.level, .weak)
        XCTAssertEqual(repeated.characterClassCount, 1)

        let common = MasterPasswordStrength.evaluate("password12345")
        XCTAssertEqual(common.level, .weak)
        XCTAssertTrue(common.containsCommonWeakTerm)

        XCTAssertEqual(MasterPasswordStrength.evaluate("correct horse").level, .fair)
        XCTAssertEqual(MasterPasswordStrength.evaluate("LocalVaults-2026").level, .strong)
        XCTAssertEqual(MasterPasswordStrength.evaluate("BetterLocalVault2026!Long").level, .veryStrong)
    }

    func testPasswordGeneratorUsesSelectedCharacterClasses() throws {
        var byte: UInt8 = 0
        let generator = PasswordGenerator {
            defer { byte = byte &+ 1 }
            return byte
        }
        let password = try generator.generate(options: PasswordGeneratorOptions(
            length: 12,
            includeUppercase: false,
            includeLowercase: false,
            includeNumbers: true,
            includeSymbols: false
        ))

        XCTAssertEqual(password.count, 12)
        XCTAssertTrue(password.allSatisfy { "23456789".contains($0) })
    }

    func testPasswordGeneratorIncludesEveryEnabledCharacterClass() throws {
        var byte: UInt8 = 0
        let generator = PasswordGenerator {
            defer { byte = byte &+ 1 }
            return byte
        }
        let password = try generator.generate(options: PasswordGeneratorOptions(
            length: 16,
            includeUppercase: true,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: true
        ))

        XCTAssertEqual(password.count, 16)
        XCTAssertTrue(password.contains { "ABCDEFGHJKLMNPQRSTUVWXYZ".contains($0) })
        XCTAssertTrue(password.contains { "abcdefghijkmnopqrstuvwxyz".contains($0) })
        XCTAssertTrue(password.contains { "23456789".contains($0) })
        XCTAssertTrue(password.contains { "!@#$%^&*-_=+?".contains($0) })
    }

    func testPasswordGeneratorAvoidsAmbiguousCharactersByDefault() {
        let options = PasswordGeneratorOptions(
            length: 20,
            includeUppercase: true,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: false
        )
        let alphabet = PasswordGenerator.alphabet(for: options)

        XCTAssertFalse(alphabet.contains("I"))
        XCTAssertFalse(alphabet.contains("O"))
        XCTAssertFalse(alphabet.contains("l"))
        XCTAssertFalse(alphabet.contains("0"))
        XCTAssertFalse(alphabet.contains("1"))
        XCTAssertTrue(alphabet.contains("A"))
        XCTAssertTrue(alphabet.contains("m"))
        XCTAssertTrue(alphabet.contains("2"))
    }

    func testPasswordGeneratorCanUseFullAlphabetsWhenAmbiguousAllowed() {
        let options = PasswordGeneratorOptions(
            length: 20,
            includeUppercase: true,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: false,
            avoidAmbiguousCharacters: false
        )
        let alphabet = PasswordGenerator.alphabet(for: options)

        XCTAssertTrue(alphabet.contains("I"))
        XCTAssertTrue(alphabet.contains("O"))
        XCTAssertTrue(alphabet.contains("l"))
        XCTAssertTrue(alphabet.contains("0"))
        XCTAssertTrue(alphabet.contains("1"))
    }

    func testPasswordGeneratorExcludesDisabledCharacterClasses() throws {
        var byte: UInt8 = 0
        let generator = PasswordGenerator {
            defer { byte = byte &+ 1 }
            return byte
        }
        let password = try generator.generate(options: PasswordGeneratorOptions(
            length: 16,
            includeUppercase: false,
            includeLowercase: true,
            includeNumbers: true,
            includeSymbols: false
        ))

        XCTAssertEqual(password.count, 16)
        XCTAssertTrue(password.contains { "abcdefghijkmnopqrstuvwxyz".contains($0) })
        XCTAssertTrue(password.contains { "23456789".contains($0) })
        XCTAssertTrue(password.allSatisfy { "abcdefghijkmnopqrstuvwxyz23456789".contains($0) })
    }

    func testPasswordGeneratorRejectsNoSelectedCharacterClasses() {
        let options = PasswordGeneratorOptions(
            length: 20,
            includeUppercase: false,
            includeLowercase: false,
            includeNumbers: false,
            includeSymbols: false
        )
        let generator = PasswordGenerator { 0 }

        XCTAssertFalse(options.hasSelectedCharacterClass)
        XCTAssertTrue(PasswordGenerator.alphabet(for: options).isEmpty)
        XCTAssertThrowsError(try generator.generate(options: options)) { error in
            XCTAssertEqual(error.localizedDescription, "Select at least one password character class")
        }
    }

    func testPasswordGeneratorPreferencesPersistOptionsWithoutGeneratedSecrets() throws {
        let suiteName = "PSWMacTests.PasswordGeneratorPreferences.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let preferences = PasswordGeneratorPreferences(defaults: defaults)
        let generatedPassword = "Generated-Password-Value-2026"
        let options = PasswordGeneratorOptions(
            length: 72,
            includeUppercase: false,
            includeLowercase: true,
            includeNumbers: false,
            includeSymbols: true,
            avoidAmbiguousCharacters: false
        )

        preferences.saveOptions(options)
        let loaded = preferences.loadOptions()

        XCTAssertEqual(loaded.length, 64)
        XCTAssertFalse(loaded.includeUppercase)
        XCTAssertTrue(loaded.includeLowercase)
        XCTAssertFalse(loaded.includeNumbers)
        XCTAssertTrue(loaded.includeSymbols)
        XCTAssertFalse(loaded.avoidAmbiguousCharacters)

        let persistedValues = defaults.dictionaryWithValues(forKeys: PasswordGeneratorPreferences.allKeys)
        XCTAssertEqual(Set(persistedValues.keys), Set(PasswordGeneratorPreferences.allKeys))
        XCTAssertFalse(persistedValues.values.contains { value in
            String(describing: value).contains(generatedPassword)
        })
    }

    func testEditorDraftStateDetectsUnsavedChangesForAllItemTypes() {
        let cleanDrafts = EditorDraftState()
        for kind in ItemEditorKind.allCases {
            XCTAssertFalse(cleanDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: kind))
        }

        var loginDrafts = EditorDraftState()
        loginDrafts.login.title = "Email"
        XCTAssertTrue(loginDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .login))
        XCTAssertFalse(loginDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .secureNote))

        var templateCredentialDrafts = EditorDraftState()
        templateCredentialDrafts.templateCredential.title = "Build API"
        XCTAssertTrue(
            templateCredentialDrafts.hasUnsavedChanges(
                isUnlocked: true,
                activeKind: .templateCredential
            )
        )
        XCTAssertFalse(
            templateCredentialDrafts.hasUnsavedChanges(
                isUnlocked: true,
                activeKind: .login
            )
        )

        var credentialDrafts = EditorDraftState()
        credentialDrafts.credential.title = "Build API"
        XCTAssertTrue(
            credentialDrafts.hasUnsavedChanges(
                isUnlocked: true,
                activeKind: .credential
            )
        )
        XCTAssertFalse(
            credentialDrafts.hasUnsavedChanges(
                isUnlocked: true,
                activeKind: .templateCredential
            )
        )

        var secureNoteDrafts = EditorDraftState()
        secureNoteDrafts.secureNote.body = "offline backup codes"
        XCTAssertTrue(secureNoteDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .secureNote))
        XCTAssertFalse(secureNoteDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .creditCard))

        var cardDrafts = EditorDraftState()
        cardDrafts.creditCard.cardholderName = "Alice Example"
        XCTAssertTrue(cardDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .creditCard))
        XCTAssertFalse(cardDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .softwareLicense))

        var licenseDrafts = EditorDraftState()
        licenseDrafts.softwareLicense.product = "TextPro"
        XCTAssertTrue(licenseDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .softwareLicense))
        XCTAssertFalse(licenseDrafts.hasUnsavedChanges(isUnlocked: true, activeKind: .login))

        for kind in ItemEditorKind.allCases {
            XCTAssertFalse(loginDrafts.hasUnsavedChanges(isUnlocked: false, activeKind: kind))
            XCTAssertFalse(templateCredentialDrafts.hasUnsavedChanges(isUnlocked: false, activeKind: kind))
            XCTAssertFalse(credentialDrafts.hasUnsavedChanges(isUnlocked: false, activeKind: kind))
            XCTAssertFalse(secureNoteDrafts.hasUnsavedChanges(isUnlocked: false, activeKind: kind))
            XCTAssertFalse(cardDrafts.hasUnsavedChanges(isUnlocked: false, activeKind: kind))
            XCTAssertFalse(licenseDrafts.hasUnsavedChanges(isUnlocked: false, activeKind: kind))
        }
    }

    func testEditorActionGuardProtectsDestructiveMutationsWithUnsavedDrafts() {
        let cleanDrafts = EditorDraftState()
        for guardedAction in [
            EditorGuardedAction.editorNavigation,
            .createVault,
            .manualSyncRefresh,
            .importCommit,
            .backupVault,
            .restoreBackup,
            .copyVaultToSyncLocation,
            .syncRecovery,
            .destructiveItemMutation
        ] {
            for kind in ItemEditorKind.allCases {
                XCTAssertFalse(EditorActionGuard.shouldConfirmDiscard(
                    before: guardedAction,
                    drafts: cleanDrafts,
                    isUnlocked: true,
                    activeKind: kind
                ))
            }
        }

        var loginDrafts = EditorDraftState()
        loginDrafts.login.title = "Email"
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .editorNavigation,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .createVault,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .destructiveItemMutation,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .manualSyncRefresh,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .importCommit,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .backupVault,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .restoreBackup,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .copyVaultToSyncLocation,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .syncRecovery,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .login
        ))
        XCTAssertFalse(EditorActionGuard.shouldConfirmDiscard(
            before: .destructiveItemMutation,
            drafts: loginDrafts,
            isUnlocked: true,
            activeKind: .secureNote
        ))

        var secureNoteDrafts = EditorDraftState()
        secureNoteDrafts.secureNote.body = "offline backup codes"
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .destructiveItemMutation,
            drafts: secureNoteDrafts,
            isUnlocked: true,
            activeKind: .secureNote
        ))

        var cardDrafts = EditorDraftState()
        cardDrafts.creditCard.cardholderName = "Alice Example"
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .destructiveItemMutation,
            drafts: cardDrafts,
            isUnlocked: true,
            activeKind: .creditCard
        ))

        var licenseDrafts = EditorDraftState()
        licenseDrafts.softwareLicense.product = "TextPro"
        XCTAssertTrue(EditorActionGuard.shouldConfirmDiscard(
            before: .destructiveItemMutation,
            drafts: licenseDrafts,
            isUnlocked: true,
            activeKind: .softwareLicense
        ))

        for kind in ItemEditorKind.allCases {
            for guardedAction in [
                EditorGuardedAction.editorNavigation,
                .createVault,
                .manualSyncRefresh,
                .importCommit,
                .backupVault,
                .restoreBackup,
                .copyVaultToSyncLocation,
                .syncRecovery,
                .destructiveItemMutation
            ] {
                XCTAssertFalse(EditorActionGuard.shouldConfirmDiscard(
                    before: guardedAction,
                    drafts: loginDrafts,
                    isUnlocked: false,
                    activeKind: kind
                ))
            }
        }
    }

    func testClipboardManagerClearsCopiedSecretAfterTimeout() {
        let pasteboard = FakePasteboard()
        pasteboard.clearContents()
        let manager = ClipboardManager(pasteboard: pasteboard)

        manager.copy("temporary-secret", clearAfter: 0.05)
        XCTAssertEqual(pasteboard.string(forType: .string), "temporary-secret")

        let cleared = expectation(description: "clipboard cleared")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            XCTAssertNil(pasteboard.string(forType: .string))
            cleared.fulfill()
        }
        wait(for: [cleared], timeout: 1.0)
    }

    func testClipboardManagerPreservesLaterClipboardContents() {
        let pasteboard = FakePasteboard()
        pasteboard.clearContents()
        let manager = ClipboardManager(pasteboard: pasteboard)

        manager.copy("temporary-secret", clearAfter: 0.1)
        pasteboard.clearContents()
        pasteboard.setString("user-copied-later", forType: .string)

        let preserved = expectation(description: "later clipboard preserved")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
            XCTAssertEqual(pasteboard.string(forType: .string), "user-copied-later")
            pasteboard.clearContents()
            preserved.fulfill()
        }
        wait(for: [preserved], timeout: 1.0)
    }

    func testClipboardManagerClearsManagedSecretOnDemand() {
        let pasteboard = FakePasteboard()
        pasteboard.clearContents()
        let manager = ClipboardManager(pasteboard: pasteboard)

        manager.copy("temporary-secret", clearAfter: 60)
        XCTAssertEqual(pasteboard.string(forType: .string), "temporary-secret")

        manager.clearManagedSecret()

        XCTAssertNil(pasteboard.string(forType: .string))
    }

    func testClipboardManagerClearManagedSecretPreservesLaterClipboardContents() {
        let pasteboard = FakePasteboard()
        pasteboard.clearContents()
        let manager = ClipboardManager(pasteboard: pasteboard)

        manager.copy("temporary-secret", clearAfter: 0.05)
        pasteboard.clearContents()
        pasteboard.setString("user-copied-later", forType: .string)

        manager.clearManagedSecret()
        XCTAssertEqual(pasteboard.string(forType: .string), "user-copied-later")

        let preserved = expectation(description: "later clipboard preserved after clear")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            XCTAssertEqual(pasteboard.string(forType: .string), "user-copied-later")
            pasteboard.clearContents()
            preserved.fulfill()
        }
        wait(for: [preserved], timeout: 1.0)
    }

    func testClipboardManagerClearManagedSecretInvalidatesPendingTimeout() {
        let pasteboard = FakePasteboard()
        pasteboard.clearContents()
        let manager = ClipboardManager(pasteboard: pasteboard)

        manager.copy("temporary-secret", clearAfter: 0.05)
        manager.clearManagedSecret()
        pasteboard.setString("temporary-secret", forType: .string)

        let preserved = expectation(description: "matching later clipboard preserved after clear")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            XCTAssertEqual(pasteboard.string(forType: .string), "temporary-secret")
            pasteboard.clearContents()
            preserved.fulfill()
        }
        wait(for: [preserved], timeout: 1.0)
    }

    func testRecentVaultPersistsAcrossStoreInstances() throws {
        let defaultsName = "PSWMacWorkflowTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsName)!
        defer { defaults.removePersistentDomain(forName: defaultsName) }

        let firstService = FakeCoreService()
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("PSWMacWorkflowTests.\(UUID().uuidString)", isDirectory: true)
        let vaultURL = parentURL.appendingPathComponent("Recent.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parentURL) }
        let firstStore = VaultStore(
            service: firstService,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )
        firstStore.openVault(url: vaultURL)

        XCTAssertEqual(firstStore.recentVaultURL?.path, vaultURL.path)

        let secondService = FakeCoreService()
        let secondStore = VaultStore(
            service: secondService,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )
        secondStore.openRecentVault()

        XCTAssertEqual(secondStore.recentVaultURL?.path, vaultURL.path)
        XCTAssertEqual(secondService.openedPath, vaultURL.path)
        XCTAssertFalse(secondStore.isUnlocked)
    }

    func testOpeningMissingRecentVaultClearsShortcutWithoutCoreOpen() throws {
        let defaults = makeIsolatedDefaults()
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("PSWMacWorkflowTests.\(UUID().uuidString)", isDirectory: true)
        let vaultURL = parentURL.appendingPathComponent("MissingRecent.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: parentURL)
        }

        let firstService = FakeCoreService()
        let firstStore = VaultStore(
            service: firstService,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )
        firstStore.openVault(url: vaultURL)
        XCTAssertEqual(firstService.openedPath, vaultURL.path)
        XCTAssertEqual(firstStore.recentVaultURL?.path, vaultURL.path)

        try FileManager.default.removeItem(at: vaultURL)
        let secondService = FakeCoreService()
        let secondStore = VaultStore(
            service: secondService,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )

        let opened = secondStore.openRecentVault()

        XCTAssertFalse(opened)
        XCTAssertNil(secondService.openedPath)
        XCTAssertNil(secondStore.recentVaultURL)
        XCTAssertEqual(secondStore.statusMessage, "Recent vault not found")
        XCTAssertNil(defaults.string(forKey: "recentVaultPath"))
    }

    func testOpeningAnotherVaultClearsPreviousUnlockedSessionState() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/Old.pswvault")
        let newVaultURL = URL(fileURLWithPath: "/tmp/New.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        markVaultSwitchStateDirty(store, clipboard: clipboard)

        store.openVault(url: newVaultURL)

        XCTAssertEqual(service.openedPath, newVaultURL.path)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertFalse(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, newVaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, newVaultURL.path)
        XCTAssertNil(clipboard.currentValue)
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 1)
        assertVaultSwitchStateCleared(store)
        XCTAssertEqual(store.statusMessage, "New.pswvault")
    }

    func testOpeningAnotherVaultIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/DirtyOpenOld.pswvault")
        let newVaultURL = URL(fileURLWithPath: "/tmp/DirtyOpenNew.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        let opened = store.openVault(url: newVaultURL)

        XCTAssertFalse(opened)
        XCTAssertEqual(service.openedPath, oldVaultURL.path)
        XCTAssertTrue(service.lockedSessionIds.isEmpty)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, oldVaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, oldVaultURL.path)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before switching vaults")
        XCTAssertFalse(store.canExport)
    }

    func testSystemOpenVaultPathUsesOpenVaultWorkflowAndLeavesVaultLocked() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/SystemOpen.pswvault")

        let opened = SystemVaultOpenHandler.openFirstVault(from: [
            URL(fileURLWithPath: "/tmp/notes.txt"),
            vaultURL
        ], store: store)

        XCTAssertTrue(opened)
        XCTAssertEqual(service.openedPath, vaultURL.path)
        XCTAssertEqual(store.vaultURL?.path, vaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, vaultURL.path)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertEqual(store.statusMessage, "SystemOpen.pswvault")
    }

    func testSystemOpenUnsupportedPathRejectsBeforeCoreOpen() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        let opened = SystemVaultOpenHandler.openFirstVault(from: [
            URL(fileURLWithPath: "/tmp/plaintext.json"),
            URL(fileURLWithPath: "/tmp/readme.txt")
        ], store: store)

        XCTAssertFalse(opened)
        XCTAssertNil(service.openedPath)
        XCTAssertNil(store.vaultURL)
        XCTAssertEqual(store.statusMessage, "Unsupported vault file")
        XCTAssertEqual(
            AppText(AppLanguage.simplifiedChinese.rawValue).statusMessage("Unsupported vault file"),
            "不支持的密码库文件"
        )
    }

    func testSystemOpenVaultPathIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/SystemOpenDirtyOld.pswvault")
        let newVaultURL = URL(fileURLWithPath: "/tmp/SystemOpenDirtyNew.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        let opened = SystemVaultOpenHandler.openFirstVault(from: [newVaultURL], store: store)

        XCTAssertFalse(opened)
        XCTAssertEqual(service.openedPath, oldVaultURL.path)
        XCTAssertTrue(service.lockedSessionIds.isEmpty)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, oldVaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, oldVaultURL.path)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before switching vaults")
    }

    func testConfirmedOpenVaultCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/DirtyOpenConfirmedOld.pswvault")
        let newVaultURL = URL(fileURLWithPath: "/tmp/DirtyOpenConfirmedNew.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        let opened = store.openVault(url: newVaultURL, discardingUnsavedEdits: true)

        XCTAssertTrue(opened)
        XCTAssertEqual(service.openedPath, newVaultURL.path)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertFalse(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, newVaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, newVaultURL.path)
        assertVaultSwitchStateCleared(store)
        XCTAssertEqual(store.statusMessage, "DirtyOpenConfirmedNew.pswvault")
    }

    func testOpeningRecentVaultIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/DirtyRecentOld.pswvault")
        let recentVaultURL = URL(fileURLWithPath: "/tmp/DirtyRecentNew.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.recentVaultURL = recentVaultURL
        store.setEditorHasUnsavedChanges(true)

        let opened = store.openRecentVault()

        XCTAssertFalse(opened)
        XCTAssertEqual(service.openedPath, oldVaultURL.path)
        XCTAssertTrue(service.lockedSessionIds.isEmpty)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, oldVaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, recentVaultURL.path)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before switching vaults")
    }

    func testCreatingAnotherVaultClearsPreviousUnlockedSessionStateBeforeNewUnlock() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/OldCreate.pswvault")
        let newVaultURL = URL(fileURLWithPath: "/tmp/NewCreate.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        markVaultSwitchStateDirty(store, clipboard: clipboard)

        XCTAssertTrue(store.createVault(
            url: newVaultURL,
            displayName: "NewCreate",
            password: "correct horse",
            confirmation: "correct horse"
        ))

        XCTAssertEqual(service.createdPath, newVaultURL.path)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.sessionId, 7)
        XCTAssertEqual(store.vaultURL?.path, newVaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, newVaultURL.path)
        XCTAssertNil(clipboard.currentValue)
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 1)
        assertVaultSwitchStateCleared(store)
        XCTAssertEqual(store.statusMessage, "Vault created")
    }

    func testCreatingAnotherVaultIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/DirtyCreateOld.pswvault")
        let newVaultURL = URL(fileURLWithPath: "/tmp/DirtyCreateNew.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        let created = store.createVault(
            url: newVaultURL,
            displayName: "DirtyCreateNew",
            password: "correct horse",
            confirmation: "correct horse"
        )

        XCTAssertFalse(created)
        XCTAssertNil(service.createdPath)
        XCTAssertTrue(service.lockedSessionIds.isEmpty)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, oldVaultURL.path)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before switching vaults")
    }

    func testConfirmedCreateVaultCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let oldVaultURL = URL(fileURLWithPath: "/tmp/DirtyCreateConfirmedOld.pswvault")
        let newVaultURL = URL(fileURLWithPath: "/tmp/DirtyCreateConfirmedNew.pswvault")
        store.openVault(url: oldVaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        let created = store.createVault(
            url: newVaultURL,
            displayName: "DirtyCreateNew",
            password: "correct horse",
            confirmation: "correct horse",
            discardingUnsavedEdits: true
        )

        XCTAssertTrue(created)
        XCTAssertEqual(service.createdPath, newVaultURL.path)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, newVaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, newVaultURL.path)
        XCTAssertEqual(store.statusMessage, "Vault created")
        XCTAssertTrue(store.canExport)
    }

    func testClosingUnlockedVaultClearsSelectedVaultStateAndPreservesRecentVault() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/CloseUnlocked.pswvault")
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        markVaultSwitchStateDirty(store, clipboard: clipboard)

        store.closeVault()

        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertFalse(store.isUnlocked)
        XCTAssertNil(store.vaultURL)
        XCTAssertEqual(store.recentVaultURL?.path, vaultURL.path)
        XCTAssertFalse(store.convenienceUnlockAvailable)
        XCTAssertNil(clipboard.currentValue)
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 1)
        assertVaultSwitchStateCleared(store)
        XCTAssertEqual(store.statusMessage, "Vault closed")
    }

    func testClosingVaultIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/DirtyClose.pswvault")
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        let closed = store.closeVault()

        XCTAssertFalse(closed)
        XCTAssertTrue(service.lockedSessionIds.isEmpty)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.vaultURL?.path, vaultURL.path)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before closing vault")
    }

    func testConfirmedCloseVaultCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/DirtyCloseConfirmed.pswvault")
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        let closed = store.closeVault(discardingUnsavedEdits: true)

        XCTAssertTrue(closed)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertFalse(store.isUnlocked)
        XCTAssertNil(store.vaultURL)
        assertVaultSwitchStateCleared(store)
        XCTAssertEqual(store.statusMessage, "Vault closed")
    }

    func testClosingLockedVaultClearsSelectionAndPreservesRecentVaultWithoutLockingCore() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: convenienceUnlockStore,
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/CloseLocked.pswvault")
        try? convenienceUnlockStore.saveMaterial("local-material", for: vaultURL)
        store.openVault(url: vaultURL)

        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.convenienceUnlockAvailable)

        store.closeVault()

        XCTAssertTrue(service.lockedSessionIds.isEmpty)
        XCTAssertNil(store.vaultURL)
        XCTAssertEqual(store.recentVaultURL?.path, vaultURL.path)
        XCTAssertFalse(store.convenienceUnlockAvailable)
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 0)
        assertVaultSwitchStateCleared(store)
        XCTAssertEqual(store.statusMessage, "Vault closed")
    }

    func testMovingForgottenVaultToTrashClearsLocalStateAndKeychainMaterial() throws {
        let defaults = makeIsolatedDefaults()
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("PSWMacWorkflowTests.\(UUID().uuidString)", isDirectory: true)
        let vaultURL = parentURL.appendingPathComponent("Forgotten.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: parentURL)
        }

        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let importSourceHandler = FakeImportSourceHandler()
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        try convenienceUnlockStore.saveMaterial("local-material", for: vaultURL)
        convenienceUnlockStore.saveLegacyPasswordMaterial("legacy-password", for: vaultURL)
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: convenienceUnlockStore,
            importSourceHandler: importSourceHandler,
            userDefaults: defaults
        )
        store.openVault(url: vaultURL)

        let moved = store.moveForgottenVaultToTrash()

        XCTAssertEqual(moved, .moved)
        XCTAssertEqual(importSourceHandler.trashedURLs, [vaultURL.standardizedFileURL])
        XCTAssertNil(store.vaultURL)
        XCTAssertNil(store.recentVaultURL)
        XCTAssertFalse(store.convenienceUnlockAvailable)
        XCTAssertNil(convenienceUnlockStore.material(for: vaultURL))
        XCTAssertEqual(convenienceUnlockStore.legacyPasswordMaterialCount(for: vaultURL), 0)
        XCTAssertNil(defaults.string(forKey: "recentVaultPath"))
        XCTAssertTrue(service.lockedSessionIds.isEmpty)
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 0)
        assertVaultSwitchStateCleared(store)
        XCTAssertEqual(store.statusMessage, "Vault moved to Trash")
    }

    func testMovingForgottenVaultToTrashRejectsUnlockedAndUnsupportedTargets() throws {
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("PSWMacWorkflowTests.\(UUID().uuidString)", isDirectory: true)
        let unlockedVaultURL = parentURL.appendingPathComponent("Unlocked.pswvault", isDirectory: true)
        let regularFileURL = parentURL.appendingPathComponent("Regular.pswvault")
        let wrongExtensionURL = parentURL.appendingPathComponent("WrongExtension", isDirectory: true)
        let symlinkTargetURL = parentURL.appendingPathComponent("Target.pswvault", isDirectory: true)
        let symlinkURL = parentURL.appendingPathComponent("Link.pswvault", isDirectory: true)
        let missingURL = parentURL.appendingPathComponent("Missing.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: unlockedVaultURL, withIntermediateDirectories: true)
        try Data().write(to: regularFileURL)
        try FileManager.default.createDirectory(at: wrongExtensionURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: symlinkTargetURL, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: symlinkTargetURL)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: parentURL)
        }

        let importSourceHandler = FakeImportSourceHandler()
        let unlockedStore = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        unlockedStore.openVault(url: unlockedVaultURL)
        unlockedStore.unlock(password: "correct horse")

        XCTAssertEqual(unlockedStore.moveForgottenVaultToTrash(), .failed)
        XCTAssertEqual(unlockedStore.statusMessage, "Lock the vault before moving it to Trash")
        XCTAssertEqual(unlockedStore.vaultURL?.path, unlockedVaultURL.path)

        for unsupportedURL in [
            regularFileURL,
            wrongExtensionURL,
            symlinkURL,
            missingURL,
            URL(string: "https://example.invalid/Remote.pswvault")!
        ] {
            let store = VaultStore(
                service: FakeCoreService(),
                clipboard: FakeClipboard(),
                convenienceUnlockStore: FakeConvenienceUnlockStore(),
                importSourceHandler: importSourceHandler,
                userDefaults: makeIsolatedDefaults()
            )
            store.openVault(url: unsupportedURL)

            XCTAssertEqual(
                store.moveForgottenVaultToTrash(),
                .failed,
                unsupportedURL.absoluteString
            )
            XCTAssertEqual(
                store.statusMessage,
                "Only a local .pswvault directory can be moved to Trash"
            )
            XCTAssertEqual(store.vaultURL, unsupportedURL)
            XCTAssertEqual(store.recentVaultURL?.standardizedFileURL.path, unsupportedURL.standardizedFileURL.path)
        }
        XCTAssertTrue(importSourceHandler.trashedURLs.isEmpty)
    }

    func testForgottenVaultTrashFailurePreservesSelectionRecentAndKeychain() throws {
        let defaults = makeIsolatedDefaults()
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("PSWMacWorkflowTests.\(UUID().uuidString)", isDirectory: true)
        let vaultURL = parentURL.appendingPathComponent("TrashFailure.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: parentURL)
        }

        let importSourceHandler = FakeImportSourceHandler()
        importSourceHandler.trashError = NSError(domain: "trash-test", code: 1)
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        try convenienceUnlockStore.saveMaterial("local-material", for: vaultURL)
        let store = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: convenienceUnlockStore,
            importSourceHandler: importSourceHandler,
            userDefaults: defaults
        )
        store.openVault(url: vaultURL)

        let moved = store.moveForgottenVaultToTrash()

        XCTAssertEqual(moved, .failed)
        XCTAssertEqual(importSourceHandler.trashedURLs, [vaultURL.standardizedFileURL])
        XCTAssertEqual(store.vaultURL?.path, vaultURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, vaultURL.path)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material")
        XCTAssertEqual(defaults.string(forKey: "recentVaultPath"), vaultURL.standardizedFileURL.path)
        XCTAssertEqual(store.statusMessage, "Vault could not be moved to Trash")
    }

    func testForgottenVaultKeychainCleanupFailureClosesMovedVaultWithWarning() throws {
        let defaults = makeIsolatedDefaults()
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("PSWMacWorkflowTests.\(UUID().uuidString)", isDirectory: true)
        let vaultURL = parentURL.appendingPathComponent("KeychainFailure.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: parentURL)
        }

        let importSourceHandler = FakeImportSourceHandler()
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        try convenienceUnlockStore.saveMaterial("local-material", for: vaultURL)
        convenienceUnlockStore.saveLegacyPasswordMaterial("legacy-password", for: vaultURL)
        convenienceUnlockStore.resetDeleteCallHistory()
        convenienceUnlockStore.deleteMaterialError = NSError(domain: "keychain-test", code: 1)
        let store = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: convenienceUnlockStore,
            importSourceHandler: importSourceHandler,
            userDefaults: defaults
        )
        store.openVault(url: vaultURL)

        let moved = store.moveForgottenVaultToTrash()

        XCTAssertEqual(moved, .movedWithKeychainCleanupFailure)
        XCTAssertEqual(importSourceHandler.trashedURLs, [vaultURL.standardizedFileURL])
        XCTAssertNil(store.vaultURL)
        XCTAssertNil(store.recentVaultURL)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material")
        XCTAssertEqual(convenienceUnlockStore.legacyPasswordMaterialCount(for: vaultURL), 0)
        XCTAssertEqual(convenienceUnlockStore.deleteMaterialURLs, [vaultURL.standardizedFileURL])
        XCTAssertEqual(convenienceUnlockStore.deleteLegacyMaterialURLs, [vaultURL.standardizedFileURL])
        XCTAssertEqual(
            store.statusMessage,
            "Vault moved to Trash, but Keychain cleanup failed"
        )
    }

    func testSecurityPreferencesPersistAcrossStoreInstances() {
        let defaultsName = "PSWMacWorkflowTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsName)!
        defer { defaults.removePersistentDomain(forName: defaultsName) }

        let firstStore = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )
        firstStore.clipboardTimeout = 15
        firstStore.autoLockSeconds = 900

        let secondStore = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )

        XCTAssertEqual(secondStore.clipboardTimeout, 15)
        XCTAssertEqual(secondStore.autoLockSeconds, 900)
        XCTAssertEqual(defaults.double(forKey: VaultStore.clipboardTimeoutKey), 15)
        XCTAssertEqual(defaults.double(forKey: VaultStore.autoLockSecondsKey), 900)
    }

    func testUnsupportedSecurityPreferencesNormalizeToDefaults() {
        let defaultsName = "PSWMacWorkflowTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsName)!
        defer { defaults.removePersistentDomain(forName: defaultsName) }
        defaults.set(-1.0, forKey: VaultStore.clipboardTimeoutKey)
        defaults.set(42.0, forKey: VaultStore.autoLockSecondsKey)

        let store = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )

        XCTAssertEqual(store.clipboardTimeout, VaultStore.defaultClipboardTimeout)
        XCTAssertEqual(store.autoLockSeconds, VaultStore.defaultAutoLockSeconds)
        XCTAssertEqual(defaults.double(forKey: VaultStore.clipboardTimeoutKey), VaultStore.defaultClipboardTimeout)
        XCTAssertEqual(defaults.double(forKey: VaultStore.autoLockSecondsKey), VaultStore.defaultAutoLockSeconds)
    }

    func testPasswordHealthRefreshStoresDisplayData() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        service.nextPasswordHealthPayload = PasswordHealthPayload(
            checkedLoginPasswords: 3,
            weakPasswords: 1,
            reusedPasswords: 2,
            issues: [
                PasswordHealthIssue(
                    itemId: "item_1",
                    title: "Email",
                    kind: .weakPassword
                ),
                PasswordHealthIssue(
                    itemId: "item_2",
                    title: "Forum",
                    kind: .reusedPassword,
                    reuseGroupSize: 2
                )
            ]
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/PasswordHealth.pswvault"))
        store.unlock(password: "correct horse")
        store.refreshPasswordHealth()

        XCTAssertEqual(service.passwordHealthCallCount, 1)
        XCTAssertEqual(store.passwordHealth?.checkedLoginPasswords, 3)
        XCTAssertEqual(store.passwordHealth?.weakPasswords, 1)
        XCTAssertEqual(store.passwordHealth?.reusedPasswords, 2)
        XCTAssertEqual(store.passwordHealth?.issues.map(\.title), ["Email", "Forum"])
        XCTAssertEqual(store.passwordHealth?.issues.last?.reuseGroupSize, 2)
        XCTAssertEqual(store.statusMessage, "Password health refreshed")
    }

    func testPasswordHealthIssueNavigationSelectsAffectedItem() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Forum",
                username: "me@example.com",
                password: "reused-password",
                url: "https://forum.example.com",
                notes: "Community account",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/PasswordHealthNavigate.pswvault"))
        store.unlock(password: "correct horse")

        let issue = PasswordHealthIssue(
            itemId: "item_2",
            title: "Forum",
            kind: .reusedPassword,
            reuseGroupSize: 2
        )

        XCTAssertTrue(store.showPasswordHealthIssue(issue))

        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertEqual(store.selectedDetail?.title, "Forum")
        XCTAssertEqual(store.selectedDetail?.username, "me@example.com")
    }

    func testPasswordHealthIssueNavigationClearsHidingFilters() throws {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "me@example.com",
                password: "weak-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"],
                favorite: false
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/PasswordHealthFilterNavigate.pswvault"))
        store.unlock(password: "correct horse")
        store.items = try service.archiveItem(sessionId: store.sessionId ?? 0, itemId: "item_2", expectedRevision: nil)
        store.searchText = "Email"
        store.showFavoritesOnly = true
        store.showConflictsOnly = true
        store.includeArchived = false

        let issue = PasswordHealthIssue(
            itemId: "item_2",
            title: "Bank",
            kind: .weakPassword
        )

        XCTAssertTrue(store.showPasswordHealthIssue(issue))

        XCTAssertEqual(store.searchText, "")
        XCTAssertFalse(store.showFavoritesOnly)
        XCTAssertFalse(store.showConflictsOnly)
        XCTAssertTrue(store.includeArchived)
        XCTAssertEqual(store.items.map(\.title), ["Email", "Bank"])
        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertEqual(store.selectedDetail?.title, "Bank")
    }

    func testPasswordHealthIssueNavigationRejectsDirtyEditorWithoutDiscard() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Forum",
                username: "me@example.com",
                password: "reused-password",
                url: "https://forum.example.com",
                notes: "Community account",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/PasswordHealthDirtyNavigate.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "Email"
        store.setEditorHasUnsavedChanges(true)

        let issue = PasswordHealthIssue(
            itemId: "item_2",
            title: "Forum",
            kind: .reusedPassword,
            reuseGroupSize: 2
        )

        XCTAssertFalse(store.showPasswordHealthIssue(issue))

        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.searchText, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")
    }

    func testPasswordHealthClearsWhenVaultLocksOrSwitches() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        service.nextPasswordHealthPayload = PasswordHealthPayload(
            checkedLoginPasswords: 1,
            weakPasswords: 1,
            reusedPasswords: 0,
            issues: [
                PasswordHealthIssue(
                    itemId: "item_1",
                    title: "Email",
                    kind: .weakPassword
                )
            ]
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/PasswordHealthLock.pswvault"))
        store.unlock(password: "correct horse")
        store.refreshPasswordHealth()
        XCTAssertNotNil(store.passwordHealth)

        store.lock()

        XCTAssertNil(store.passwordHealth)

        store.openVault(url: URL(fileURLWithPath: "/tmp/PasswordHealthSwitch.pswvault"))
        store.unlock(password: "correct horse")
        store.refreshPasswordHealth()
        XCTAssertNotNil(store.passwordHealth)

        store.openVault(url: URL(fileURLWithPath: "/tmp/PasswordHealthOther.pswvault"))

        XCTAssertNil(store.passwordHealth)
    }

    func testPasswordHealthIssueLabelsAreLocalized() {
        let english = AppText(AppLanguage.english.rawValue)
        let chinese = AppText(AppLanguage.simplifiedChinese.rawValue)
        let weak = PasswordHealthIssue(
            itemId: "item_1",
            title: "Email",
            kind: .weakPassword
        )
        let reused = PasswordHealthIssue(
            itemId: "item_2",
            title: "Forum",
            kind: .reusedPassword,
            reuseGroupSize: 2
        )

        XCTAssertEqual(english.passwordHealthIssueLabel(weak), "Weak")
        XCTAssertEqual(english.passwordHealthIssueLabel(reused), "Reused x2")
        XCTAssertEqual(chinese.passwordHealthIssueLabel(weak), "弱密码")
        XCTAssertEqual(chinese.passwordHealthIssueLabel(reused), "重复 x2")
    }

    func testPasswordHealthClearsAfterSaveImportAndSyncRefresh() {
        let context = makeUnlockedSeededLoginStore(path: "/tmp/PasswordHealthInvalidation.pswvault")
        let store = context.store
        let service = context.service

        seedPasswordHealth(store)
        var form = LoginForm(detail: store.selectedDetail!)
        form.notes = "Updated inbox"

        XCTAssertEqual(store.saveLogin(form: form), .saved)
        XCTAssertNil(store.passwordHealth)

        seedPasswordHealth(store)
        store.previewImport(url: URL(fileURLWithPath: "/tmp/password-health-import.json"))
        XCTAssertTrue(store.commitImport(keepDuplicates: true))
        XCTAssertNil(store.passwordHealth)

        seedPasswordHealth(store)
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: store.items.count,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: store.items
        )
        store.refreshFromDisk()
        XCTAssertNil(store.passwordHealth)
    }

    func testPasswordHealthClearsAfterConflictAndLifecycleMutations() {
        let context = makeUnlockedSeededLoginStore(path: "/tmp/PasswordHealthLifecycle.pswvault")
        let store = context.store
        let service = context.service

        seedPasswordHealth(store)
        XCTAssertTrue(store.duplicateSelectedItem())
        XCTAssertNil(store.passwordHealth)

        seedPasswordHealth(store)
        XCTAssertTrue(store.toggleFavoriteSelected())
        XCTAssertNil(store.passwordHealth)

        seedPasswordHealth(store)
        XCTAssertTrue(store.archiveSelected())
        XCTAssertNil(store.passwordHealth)

        store.includeArchived = true
        store.search()
        store.select(itemId: "item_2")
        seedPasswordHealth(store)
        XCTAssertTrue(store.restoreSelectedArchive())
        XCTAssertNil(store.passwordHealth)

        store.select(itemId: "item_2")
        seedPasswordHealth(store)
        XCTAssertTrue(store.deleteSelected())
        XCTAssertNil(store.passwordHealth)

        configureNextRefreshAsConflictedLogin(service)
        store.refreshFromDisk()
        seedPasswordHealth(store)
        XCTAssertTrue(store.resolveSelectedConflict())
        XCTAssertNil(store.passwordHealth)
    }

    func testResolveSelectedConflictUsesConflictIdAndRefreshesSyncStatus() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/Conflict.pswvault"))
        store.unlock(password: "correct horse")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )

        store.refreshFromDisk()
        XCTAssertTrue(store.canResolveSelectedConflict)

        XCTAssertTrue(store.resolveSelectedConflict())

        XCTAssertEqual(service.resolvedConflictIds, ["conflict_item_1"])
        XCTAssertEqual(store.items.first?.status, "active")
        XCTAssertNil(store.items.first?.conflictId)
        XCTAssertEqual(store.syncReport?.detectedConflicts, 0)
        XCTAssertEqual(store.statusMessage, "Conflict resolved")
        XCTAssertTrue(store.isUnlocked)
    }

    func testConflictCandidatesCanResolveSelectedRevision() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        service.nextConflictCandidates = [
            ConflictCandidateView(
                itemId: "item_1",
                revision: "rev_left",
                title: "Email Left",
                itemType: "login",
                status: "active",
                favorite: false,
                tags: ["personal"],
                comparisonFields: [
                    ConflictCandidateField(label: "username", value: "me@example.com", redacted: false),
                    ConflictCandidateField(label: "password", value: nil, redacted: true)
                ],
                changedFields: ["username"],
                preview: "username: me@example.com"
            ),
            ConflictCandidateView(
                itemId: "item_1",
                revision: "rev_right",
                title: "Email Right",
                itemType: "login",
                status: "active",
                favorite: true,
                tags: ["work"],
                comparisonFields: [
                    ConflictCandidateField(label: "username", value: "work@example.com", redacted: false),
                    ConflictCandidateField(label: "password", value: nil, redacted: true)
                ],
                changedFields: ["username", "password"],
                preview: "username: work@example.com"
            )
        ]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/ConflictCandidates.pswvault"))
        store.unlock(password: "correct horse")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )
        store.refreshFromDisk()

        store.loadSelectedConflictCandidates()

        XCTAssertEqual(service.loadedConflictIds, ["conflict_item_1"])
        XCTAssertEqual(store.conflictCandidates.map(\.revision), ["rev_left", "rev_right"])
        XCTAssertEqual(store.conflictCandidates[0].comparisonFields[0].value, "me@example.com")
        XCTAssertEqual(store.conflictCandidates[0].comparisonFields[1].label, "password")
        XCTAssertTrue(store.conflictCandidates[0].comparisonFields[1].redacted)
        XCTAssertNil(store.conflictCandidates[0].comparisonFields[1].value)
        XCTAssertEqual(store.conflictCandidates[1].changedFields, ["username", "password"])
        XCTAssertEqual(store.statusMessage, "2 conflict versions")

        XCTAssertTrue(store.resolveSelectedConflictCandidate(revision: "rev_right"))

        XCTAssertEqual(service.resolvedConflictCandidateRevisions, ["rev_right"])
        XCTAssertTrue(store.conflictCandidates.isEmpty)
        XCTAssertEqual(store.syncReport?.detectedConflicts, 0)
        XCTAssertEqual(store.statusMessage, "Conflict resolved")
    }

    func testConflictCandidatesCanMergeSafeFieldsByRevision() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        service.nextConflictCandidates = [
            ConflictCandidateView(
                itemId: "item_1",
                revision: "rev_left",
                title: "Email Left",
                itemType: "login",
                status: "active",
                favorite: false,
                tags: ["personal"],
                comparisonFields: [
                    ConflictCandidateField(label: "title", value: "Email Left", redacted: false),
                    ConflictCandidateField(label: "username", value: "me@example.com", redacted: false),
                    ConflictCandidateField(label: "password", value: nil, redacted: true)
                ],
                changedFields: ["title", "username", "password"],
                preview: "username: me@example.com"
            ),
            ConflictCandidateView(
                itemId: "item_1",
                revision: "rev_right",
                title: "Email Right",
                itemType: "login",
                status: "active",
                favorite: true,
                tags: ["work"],
                comparisonFields: [
                    ConflictCandidateField(label: "title", value: "Email Right", redacted: false),
                    ConflictCandidateField(label: "username", value: "work@example.com", redacted: false),
                    ConflictCandidateField(label: "password", value: nil, redacted: true)
                ],
                changedFields: ["title", "username", "password"],
                preview: "username: work@example.com"
            )
        ]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/ConflictMerge.pswvault"))
        store.unlock(password: "correct horse")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )
        store.refreshFromDisk()
        store.loadSelectedConflictCandidates()

        XCTAssertTrue(store.resolveSelectedConflictMerge(
            baseRevision: "rev_left",
            fieldSelections: [
                ConflictMergeFieldSelection(fieldLabel: "title", revision: "rev_right"),
                ConflictMergeFieldSelection(fieldLabel: "username", revision: "rev_right")
            ]
        ))

        XCTAssertEqual(service.resolvedConflictMergeRequests.count, 1)
        XCTAssertEqual(service.resolvedConflictMergeRequests[0].conflictId, "conflict_item_1")
        XCTAssertEqual(service.resolvedConflictMergeRequests[0].baseRevision, "rev_left")
        XCTAssertEqual(service.resolvedConflictMergeRequests[0].fieldSelections, [
            ConflictMergeFieldSelection(fieldLabel: "title", revision: "rev_right"),
            ConflictMergeFieldSelection(fieldLabel: "username", revision: "rev_right")
        ])
        XCTAssertTrue(store.conflictCandidates.isEmpty)
        XCTAssertEqual(store.syncReport?.detectedConflicts, 0)
        XCTAssertEqual(store.statusMessage, "Conflict merged")
    }

    func testResolveSelectedConflictCandidateRejectsAndConfirmsDirtyEditorDiscard() {
        let rejected = makeUnlockedSeededLoginStore(path: "/tmp/DirtyConflictCandidate.pswvault")
        rejected.service.nextConflictCandidates = sampleLoginConflictCandidates()
        configureNextRefreshAsConflictedLogin(rejected.service)
        rejected.store.refreshFromDisk()
        rejected.store.loadSelectedConflictCandidates()
        rejected.store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(rejected.store.resolveSelectedConflictCandidate(revision: "rev_right"))

        XCTAssertTrue(rejected.service.resolvedConflictCandidateRevisions.isEmpty)
        XCTAssertEqual(rejected.store.conflictCandidates.map(\.revision), ["rev_left", "rev_right"])
        XCTAssertEqual(rejected.store.selectedItemId, "item_1")
        XCTAssertTrue(rejected.store.selectedItem?.isConflicted == true)
        XCTAssertEqual(rejected.store.statusMessage, "Save or discard edits before resolving conflict")
        XCTAssertFalse(rejected.store.canExport)

        let confirmed = makeUnlockedSeededLoginStore(path: "/tmp/DirtyConflictCandidateConfirmed.pswvault")
        confirmed.service.nextConflictCandidates = sampleLoginConflictCandidates()
        configureNextRefreshAsConflictedLogin(confirmed.service)
        confirmed.store.refreshFromDisk()
        confirmed.store.loadSelectedConflictCandidates()
        confirmed.store.setEditorHasUnsavedChanges(true)

        XCTAssertTrue(confirmed.store.resolveSelectedConflictCandidate(
            revision: "rev_right",
            discardingUnsavedEdits: true
        ))

        XCTAssertEqual(confirmed.service.resolvedConflictCandidateRevisions, ["rev_right"])
        XCTAssertTrue(confirmed.store.conflictCandidates.isEmpty)
        XCTAssertEqual(confirmed.store.syncReport?.detectedConflicts, 0)
        XCTAssertEqual(confirmed.store.statusMessage, "Conflict resolved")
        XCTAssertTrue(confirmed.store.canExport)
    }

    func testResolveSelectedConflictMergeRejectsAndConfirmsDirtyEditorDiscard() {
        let fieldSelections = [
            ConflictMergeFieldSelection(fieldLabel: "title", revision: "rev_right"),
            ConflictMergeFieldSelection(fieldLabel: "username", revision: "rev_right")
        ]
        let rejected = makeUnlockedSeededLoginStore(path: "/tmp/DirtyConflictMerge.pswvault")
        rejected.service.nextConflictCandidates = sampleLoginConflictCandidates()
        configureNextRefreshAsConflictedLogin(rejected.service)
        rejected.store.refreshFromDisk()
        rejected.store.loadSelectedConflictCandidates()
        rejected.store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(rejected.store.resolveSelectedConflictMerge(
            baseRevision: "rev_left",
            fieldSelections: fieldSelections
        ))

        XCTAssertTrue(rejected.service.resolvedConflictMergeRequests.isEmpty)
        XCTAssertEqual(rejected.store.conflictCandidates.map(\.revision), ["rev_left", "rev_right"])
        XCTAssertEqual(rejected.store.selectedItemId, "item_1")
        XCTAssertTrue(rejected.store.selectedItem?.isConflicted == true)
        XCTAssertEqual(rejected.store.statusMessage, "Save or discard edits before resolving conflict")
        XCTAssertFalse(rejected.store.canExport)

        let confirmed = makeUnlockedSeededLoginStore(path: "/tmp/DirtyConflictMergeConfirmed.pswvault")
        confirmed.service.nextConflictCandidates = sampleLoginConflictCandidates()
        configureNextRefreshAsConflictedLogin(confirmed.service)
        confirmed.store.refreshFromDisk()
        confirmed.store.loadSelectedConflictCandidates()
        confirmed.store.setEditorHasUnsavedChanges(true)

        XCTAssertTrue(confirmed.store.resolveSelectedConflictMerge(
            baseRevision: "rev_left",
            fieldSelections: fieldSelections,
            discardingUnsavedEdits: true
        ))

        XCTAssertEqual(confirmed.service.resolvedConflictMergeRequests.count, 1)
        XCTAssertEqual(confirmed.service.resolvedConflictMergeRequests[0].baseRevision, "rev_left")
        XCTAssertEqual(confirmed.service.resolvedConflictMergeRequests[0].fieldSelections, fieldSelections)
        XCTAssertTrue(confirmed.store.conflictCandidates.isEmpty)
        XCTAssertEqual(confirmed.store.syncReport?.detectedConflicts, 0)
        XCTAssertEqual(confirmed.store.statusMessage, "Conflict merged")
        XCTAssertTrue(confirmed.store.canExport)
    }

    func testResolveSelectedConflictRequiresConflictedSelection() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/NoConflict.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertFalse(store.canResolveSelectedConflict)
        XCTAssertFalse(store.resolveSelectedConflict())

        XCTAssertTrue(service.resolvedConflictIds.isEmpty)
        XCTAssertEqual(store.statusMessage, "No selected conflict")
    }

    func testConflictedSelectionBlocksOrdinaryMutationsButAllowsResolution() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/ConflictGuard.pswvault"))
        store.unlock(password: "correct horse")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )

        store.refreshFromDisk()

        XCTAssertFalse(store.canSaveCurrentEditor)
        XCTAssertFalse(store.canMutateSelectedItem)
        XCTAssertTrue(store.canResolveSelectedConflict)

        var form = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        form.title = "Edited Email"
        store.saveLogin(form: form)
        store.toggleFavoriteSelected()
        store.archiveSelected()
        store.deleteSelected()

        XCTAssertEqual(service.updateLoginCallCount, 0)
        XCTAssertEqual(service.setFavoriteCallCount, 0)
        XCTAssertEqual(service.archiveItemCallCount, 0)
        XCTAssertEqual(service.deleteItemCallCount, 0)
        XCTAssertEqual(store.statusMessage, "Resolve conflict before editing")

        XCTAssertTrue(store.resolveSelectedConflict())
        XCTAssertEqual(service.resolvedConflictIds, ["conflict_item_1"])
        XCTAssertTrue(store.canSaveCurrentEditor)
        XCTAssertTrue(store.canMutateSelectedItem)
    }

    func testConflictedLoginSelectionBlocksSecretCopyBeforeCoreFieldReads() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                totpSecret: "JBSWY3DPEHPK3PXP"
            )
        ])
        let clipboard = FakeClipboard()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/ConflictCopy.pswvault"))
        store.unlock(password: "correct horse")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )

        store.refreshFromDisk()

        XCTAssertFalse(store.canCopyLoginFields)
        XCTAssertFalse(store.canCopyTotpCode)
        XCTAssertTrue(store.canResolveSelectedConflict)

        store.copyUsername()
        store.copyPassword()
        store.copyTotp()

        XCTAssertTrue(service.loginFieldRequests.isEmpty)
        XCTAssertEqual(service.totpCodeCallCount, 0)
        XCTAssertTrue(clipboard.copied.isEmpty)
        XCTAssertNil(clipboard.currentValue)
        XCTAssertEqual(store.statusMessage, "Resolve conflict before copying")
    }

    func testConflictedStructuredSelectionsBlockSecretCopyBeforeCoreFieldReads() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/StructuredConflictCopy.pswvault"),
            displayName: "Structured",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var note = SecureNoteForm()
        note.title = "Recovery"
        note.body = "offline backup codes"
        store.saveSecureNote(form: note)

        var card = CreditCardForm()
        card.title = "Travel Card"
        card.cardholderName = "Alice"
        card.number = "4111111111111111"
        card.verificationCode = "123"
        store.saveCreditCard(form: card)

        var license = SoftwareLicenseForm()
        license.title = "App"
        license.product = "Desk"
        license.licenseKey = "AAAA-BBBB-CCCC"
        store.saveSoftwareLicense(form: license)

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 3,
            appliedTombstones: 0,
            detectedConflicts: 3,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Recovery",
                    itemType: "secure note",
                    status: "conflicted",
                    conflictId: "conflict_note",
                    favorite: false,
                    tags: []
                ),
                VaultItemView(
                    id: "item_2",
                    title: "Travel Card",
                    itemType: "credit card",
                    status: "conflicted",
                    conflictId: "conflict_card",
                    favorite: false,
                    tags: []
                ),
                VaultItemView(
                    id: "item_3",
                    title: "App",
                    itemType: "software license",
                    status: "conflicted",
                    conflictId: "conflict_license",
                    favorite: false,
                    tags: []
                )
            ]
        )

        store.refreshFromDisk()

        store.select(itemId: "item_1")
        XCTAssertFalse(store.canCopySecureNoteBody)
        store.copySecureNoteBody()

        store.select(itemId: "item_2")
        XCTAssertFalse(store.canCopyCreditCardFields)
        store.copyCardNumber()
        store.copyCardVerificationCode()

        store.select(itemId: "item_3")
        XCTAssertFalse(store.canCopySoftwareLicenseFields)
        store.copyLicenseKey()

        XCTAssertTrue(service.creditCardFieldRequests.isEmpty)
        XCTAssertTrue(service.softwareLicenseFieldRequests.isEmpty)
        XCTAssertTrue(clipboard.copied.isEmpty)
        XCTAssertNil(clipboard.currentValue)
        XCTAssertEqual(store.statusMessage, "Resolve conflict before copying")
    }

    func testRevealSavedLoginSecretsUsesExistingFieldReadsWithoutCopying() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                totpSecret: "JBSWY3DPEHPK3PXP"
            )
        ])
        let clipboard = FakeClipboard()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RevealLogin.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertEqual(store.revealSelectedLoginPassword(), "email-password")
        XCTAssertEqual(store.revealSelectedLoginTotpSecret(), "JBSWY3DPEHPK3PXP")

        XCTAssertEqual(service.loginFieldRequests, ["password"])
        XCTAssertTrue(clipboard.copied.isEmpty)
        XCTAssertNil(clipboard.currentValue)
    }

    func testRevealStructuredSecretsUsesExistingFieldReadsWithoutCopying() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/RevealStructured.pswvault"),
            displayName: "Structured",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var card = CreditCardForm()
        card.title = "Travel Card"
        card.cardholderName = "Alice"
        card.number = "4111111111111111"
        card.verificationCode = "123"
        store.saveCreditCard(form: card)

        XCTAssertEqual(store.revealSelectedCardNumber(), "4111111111111111")
        XCTAssertEqual(store.revealSelectedCardVerificationCode(), "123")

        resetSelectionForNewItem(store)
        var license = SoftwareLicenseForm()
        license.title = "TextPro"
        license.product = "TextPro"
        license.licenseKey = "AAAA-BBBB-CCCC"
        license.licensedTo = "Alice"
        store.saveSoftwareLicense(form: license)

        XCTAssertEqual(store.revealSelectedLicenseKey(), "AAAA-BBBB-CCCC")

        XCTAssertEqual(service.creditCardFieldRequests, ["number", "verification_code"])
        XCTAssertEqual(service.softwareLicenseFieldRequests, ["license_key"])
        XCTAssertTrue(clipboard.copied.isEmpty)
        XCTAssertNil(clipboard.currentValue)
    }

    func testRevealSavedSecretsRejectsConflictedSelectionBeforeFieldReads() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                totpSecret: "JBSWY3DPEHPK3PXP"
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RevealConflict.pswvault"))
        store.unlock(password: "correct horse")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )

        store.refreshFromDisk()

        XCTAssertNil(store.revealSelectedLoginPassword())
        XCTAssertNil(store.revealSelectedLoginTotpSecret())
        XCTAssertTrue(service.loginFieldRequests.isEmpty)
        XCTAssertEqual(store.statusMessage, "Resolve conflict before revealing")
    }

    func testRevealSavedSecretsReturnsNilAndReportsEmptyFields() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RevealEmpty.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertNil(store.revealSelectedLoginPassword())
        XCTAssertEqual(service.loginFieldRequests, ["password"])
        XCTAssertEqual(store.statusMessage, "login item has no password")

        XCTAssertNil(store.revealSelectedLoginTotpSecret())
        XCTAssertEqual(store.statusMessage, "login item has no TOTP secret")
    }

    func testLoginTotpSecretCanBeSavedCopiedAndCleared() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/Totp.pswvault"),
            displayName: "TOTP",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var form = LoginForm()
        form.title = "Email"
        form.username = "alice"
        form.password = "secret"
        form.url = "https://example.com"
        form.totpSecret = "otpauth://totp/Example:alice?secret=GEZD%20GNBV-GY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example"
        store.saveLogin(form: form)

        XCTAssertEqual(store.selectedDetail?.totpSecret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        XCTAssertTrue(store.canCopyTotpCode)

        store.copyTotp()

        XCTAssertEqual(clipboard.copied.map(\.value), ["123456"])
        XCTAssertEqual(store.statusMessage, "TOTP copied")

        var edited = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        XCTAssertEqual(edited.totpSecret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        edited.totpSecret = ""
        store.saveLogin(form: edited)

        XCTAssertNil(store.selectedDetail?.totpSecret)
        XCTAssertFalse(store.canCopyTotpCode)
        XCTAssertEqual(service.totpCodeCallCount, 1)

        store.copyTotp()

        XCTAssertEqual(clipboard.copied.map(\.value), ["123456"])
        XCTAssertEqual(service.totpCodeCallCount, 1)
        XCTAssertEqual(store.statusMessage, "login item has no TOTP secret")
    }

    func testChangeMasterPasswordValidationDoesNotCallCore() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        XCTAssertFalse(store.changeMasterPassword(
            currentPassword: "correct horse",
            newPassword: "new correct horse",
            confirmation: "new correct horse"
        ))
        XCTAssertEqual(store.statusMessage, "Unlock a vault first")

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/RotateValidation.pswvault"),
            displayName: "Rotate",
            password: "correct horse",
            confirmation: "correct horse"
        )

        XCTAssertFalse(store.changeMasterPassword(
            currentPassword: "",
            newPassword: "new correct horse",
            confirmation: "new correct horse"
        ))
        XCTAssertEqual(store.statusMessage, "Current master password is required")

        XCTAssertFalse(store.changeMasterPassword(
            currentPassword: "correct horse",
            newPassword: "",
            confirmation: ""
        ))
        XCTAssertEqual(store.statusMessage, "New master password is required")

        XCTAssertFalse(store.changeMasterPassword(
            currentPassword: "correct horse",
            newPassword: "new correct horse",
            confirmation: "different"
        ))
        XCTAssertEqual(store.statusMessage, "New master passwords do not match")
        XCTAssertTrue(service.masterPasswordChanges.isEmpty)
    }

    func testCreateVaultRequiresConfirmedMasterPassword() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/CreateValidation.pswvault")

        XCTAssertFalse(store.createVault(
            url: vaultURL,
            displayName: "Create",
            password: "",
            confirmation: ""
        ))
        XCTAssertNil(service.createdPath)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertEqual(store.statusMessage, "Master password is required")

        XCTAssertFalse(store.createVault(
            url: vaultURL,
            displayName: "Create",
            password: "correct horse",
            confirmation: "different"
        ))
        XCTAssertNil(service.createdPath)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertEqual(store.statusMessage, "Master passwords do not match")

        XCTAssertTrue(store.createVault(
            url: vaultURL,
            displayName: "Create",
            password: "short",
            confirmation: "short"
        ))
        XCTAssertEqual(service.createdPath, vaultURL.path)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.statusMessage, "Vault created")
    }

    func testSelectingAnotherItemIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Work",
                username: "me@work.example",
                password: "work-password",
                url: "https://work.example.com",
                notes: "Work inbox",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtySelection.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertEqual(store.selectedItemId, "item_1")
        store.setEditorHasUnsavedChanges(true)

        let selected = store.select(itemId: "item_2")

        XCTAssertFalse(selected)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")
        XCTAssertFalse(store.canExport)
    }

    func testItemListRowActionTargetsRequestedItem() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Work",
                username: "me@work.example",
                password: "work-password",
                url: "https://work.example.com",
                notes: "Work inbox",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ItemListActionTarget.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertTrue(store.prepareItemListAction(itemId: "item_2"))

        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertEqual(store.selectedDetail?.title, "Work")
    }

    func testItemListRowActionRejectsDirtyEditorWithoutDiscard() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Work",
                username: "me@work.example",
                password: "work-password",
                url: "https://work.example.com",
                notes: "Work inbox",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ItemListActionDirty.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(store.prepareItemListAction(itemId: "item_2"))

        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")
    }

    func testConfirmedSelectionCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Work",
                username: "me@work.example",
                password: "work-password",
                url: "https://work.example.com",
                notes: "Work inbox",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtySelectionConfirmed.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertEqual(store.selectedItemId, "item_1")
        store.setEditorHasUnsavedChanges(true)

        let selected = store.select(itemId: "item_2", discardingUnsavedEdits: true)

        XCTAssertTrue(selected)
        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertEqual(store.selectedDetail?.title, "Work")
        XCTAssertEqual(store.selectedDetail?.username, "me@work.example")
        XCTAssertTrue(store.canExport)
    }

    func testArchiveSelectedIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyArchive.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)

        let archived = store.archiveSelected()

        XCTAssertFalse(archived)
        XCTAssertEqual(service.archiveItemCallCount, 0)
        XCTAssertEqual(store.items.map(\.title), ["Email"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before archiving")
        XCTAssertFalse(store.canExport)
    }

    func testConfirmedArchiveSelectedCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyArchiveConfirmed.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)

        let archived = store.archiveSelected(discardingUnsavedEdits: true)

        XCTAssertTrue(archived)
        XCTAssertEqual(service.archiveItemCallCount, 1)
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertNil(store.selectedItemId)
        XCTAssertNil(store.selectedDetail)
        XCTAssertEqual(store.statusMessage, "Archived")
        XCTAssertTrue(store.canExport)
    }

    func testDeleteSelectedIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyDelete.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)

        let deleted = store.deleteSelected()

        XCTAssertFalse(deleted)
        XCTAssertEqual(service.deleteItemCallCount, 0)
        XCTAssertEqual(store.items.map(\.title), ["Email"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before deleting")
        XCTAssertFalse(store.canExport)
    }

    func testConfirmedDeleteSelectedCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyDeleteConfirmed.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)

        let deleted = store.deleteSelected(discardingUnsavedEdits: true)

        XCTAssertTrue(deleted)
        XCTAssertEqual(service.deleteItemCallCount, 1)
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertNil(store.selectedItemId)
        XCTAssertNil(store.selectedDetail)
        XCTAssertEqual(store.statusMessage, "Deleted")
        XCTAssertTrue(store.canExport)
    }

    func testToggleFavoriteSelectedRejectsAndConfirmsDirtyEditorDiscard() {
        let rejected = makeUnlockedSeededLoginStore(path: "/tmp/DirtyFavorite.pswvault")
        rejected.store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(rejected.store.toggleFavoriteSelected())

        XCTAssertEqual(rejected.service.setFavoriteCallCount, 0)
        XCTAssertEqual(rejected.store.selectedItemId, "item_1")
        XCTAssertEqual(rejected.store.selectedDetail?.favorite, false)
        XCTAssertEqual(rejected.store.statusMessage, "Save or discard edits before updating favorite")
        XCTAssertFalse(rejected.store.canExport)

        let confirmed = makeUnlockedSeededLoginStore(path: "/tmp/DirtyFavoriteConfirmed.pswvault")
        confirmed.store.setEditorHasUnsavedChanges(true)

        XCTAssertTrue(confirmed.store.toggleFavoriteSelected(discardingUnsavedEdits: true))

        XCTAssertEqual(confirmed.service.setFavoriteCallCount, 1)
        XCTAssertEqual(confirmed.store.selectedItemId, "item_1")
        XCTAssertEqual(confirmed.store.selectedDetail?.favorite, true)
        XCTAssertTrue(confirmed.store.canExport)
    }

    func testDuplicateSelectedItemRejectsAndConfirmsDirtyEditorDiscard() {
        let rejected = makeUnlockedSeededLoginStore(path: "/tmp/DirtyDuplicate.pswvault")
        rejected.store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(rejected.store.duplicateSelectedItem())

        XCTAssertEqual(rejected.service.createLoginCallCount, 0)
        XCTAssertEqual(rejected.store.items.map(\.title), ["Email"])
        XCTAssertEqual(rejected.store.selectedItemId, "item_1")
        XCTAssertEqual(rejected.store.selectedDetail?.title, "Email")
        XCTAssertEqual(rejected.store.statusMessage, "Save or discard edits before duplicating")
        XCTAssertFalse(rejected.store.canExport)

        let confirmed = makeUnlockedSeededLoginStore(path: "/tmp/DirtyDuplicateConfirmed.pswvault")
        confirmed.store.setEditorHasUnsavedChanges(true)

        XCTAssertTrue(confirmed.store.duplicateSelectedItem(discardingUnsavedEdits: true))

        XCTAssertEqual(confirmed.service.createLoginCallCount, 1)
        XCTAssertEqual(confirmed.store.items.map(\.title), ["Email", "Email Copy"])
        XCTAssertNotEqual(confirmed.store.selectedItemId, "item_1")
        XCTAssertEqual(confirmed.store.selectedDetail?.title, "Email Copy")
        XCTAssertTrue(confirmed.store.canExport)
    }

    func testRestoreSelectedArchiveRejectsAndConfirmsDirtyEditorDiscard() {
        let rejected = makeUnlockedSeededLoginStore(path: "/tmp/DirtyRestore.pswvault")
        XCTAssertTrue(rejected.store.archiveSelected())
        rejected.store.includeArchived = true
        rejected.store.search()
        XCTAssertTrue(rejected.store.select(itemId: "item_1"))
        rejected.store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(rejected.store.restoreSelectedArchive())

        XCTAssertEqual(rejected.service.restoreItemCallCount, 0)
        XCTAssertEqual(rejected.store.items.map(\.status), ["archived"])
        XCTAssertEqual(rejected.store.selectedItemId, "item_1")
        XCTAssertEqual(rejected.store.selectedDetail?.status, "archived")
        XCTAssertEqual(rejected.store.statusMessage, "Save or discard edits before restoring")
        XCTAssertFalse(rejected.store.canExport)

        let confirmed = makeUnlockedSeededLoginStore(path: "/tmp/DirtyRestoreConfirmed.pswvault")
        XCTAssertTrue(confirmed.store.archiveSelected())
        confirmed.store.includeArchived = true
        confirmed.store.search()
        XCTAssertTrue(confirmed.store.select(itemId: "item_1"))
        confirmed.store.setEditorHasUnsavedChanges(true)

        XCTAssertTrue(confirmed.store.restoreSelectedArchive(discardingUnsavedEdits: true))

        XCTAssertEqual(confirmed.service.restoreItemCallCount, 1)
        XCTAssertEqual(confirmed.store.items.map(\.status), ["active"])
        XCTAssertEqual(confirmed.store.selectedItemId, "item_1")
        XCTAssertEqual(confirmed.store.selectedDetail?.status, "active")
        XCTAssertTrue(confirmed.store.canExport)
    }

    func testResolveSelectedConflictRejectsAndConfirmsDirtyEditorDiscard() {
        let rejected = makeUnlockedSeededLoginStore(path: "/tmp/DirtyResolveConflict.pswvault")
        rejected.service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )
        rejected.store.refreshFromDisk()
        rejected.store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(rejected.store.resolveSelectedConflict())

        XCTAssertTrue(rejected.service.resolvedConflictIds.isEmpty)
        XCTAssertEqual(rejected.store.selectedItemId, "item_1")
        XCTAssertTrue(rejected.store.selectedItem?.isConflicted == true)
        XCTAssertEqual(rejected.store.statusMessage, "Save or discard edits before resolving conflict")
        XCTAssertFalse(rejected.store.canExport)

        let confirmed = makeUnlockedSeededLoginStore(path: "/tmp/DirtyResolveConflictConfirmed.pswvault")
        confirmed.service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    title: "Email",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_item_1",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )
        confirmed.store.refreshFromDisk()
        confirmed.store.setEditorHasUnsavedChanges(true)

        XCTAssertTrue(confirmed.store.resolveSelectedConflict(discardingUnsavedEdits: true))

        XCTAssertEqual(confirmed.service.resolvedConflictIds, ["conflict_item_1"])
        XCTAssertEqual(confirmed.store.selectedItemId, "item_1")
        XCTAssertFalse(confirmed.store.selectedItem?.isConflicted == true)
        XCTAssertEqual(confirmed.store.statusMessage, "Conflict resolved")
        XCTAssertTrue(confirmed.store.canExport)
    }

    func testChangeMasterPasswordClearsConvenienceUnlockMaterial() {
        let service = FakeCoreService()
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        let vaultURL = URL(fileURLWithPath: "/tmp/Rotate.pswvault")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: convenienceUnlockStore,
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: vaultURL,
            displayName: "Rotate",
            password: "correct horse",
            confirmation: "correct horse",
            rememberForConvenience: true
        )

        XCTAssertTrue(store.isUnlocked)
        XCTAssertTrue(store.convenienceUnlockAvailable)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material-7")

        XCTAssertTrue(store.changeMasterPassword(
            currentPassword: "correct horse",
            newPassword: "short",
            confirmation: "short"
        ))

        XCTAssertEqual(service.masterPasswordChanges.count, 1)
        XCTAssertEqual(service.masterPasswordChanges.first?.sessionId, 7)
        XCTAssertEqual(service.masterPasswordChanges.first?.currentPassword, "correct horse")
        XCTAssertEqual(service.masterPasswordChanges.first?.newPassword, "short")
        XCTAssertTrue(store.isUnlocked)
        XCTAssertFalse(store.convenienceUnlockAvailable)
        XCTAssertNil(convenienceUnlockStore.material(for: vaultURL))
        XCTAssertEqual(store.statusMessage, "Master password changed")
    }

    func testFailedConvenienceUnlockDiscardsStaleLocalMaterialAndCanBeReenabled() {
        let service = FakeCoreService()
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        let vaultURL = URL(fileURLWithPath: "/tmp/StaleConvenience.pswvault")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: convenienceUnlockStore,
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: vaultURL,
            displayName: "Stale",
            password: "correct horse",
            confirmation: "correct horse",
            rememberForConvenience: true
        )
        store.lock()

        XCTAssertTrue(store.convenienceUnlockAvailable)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material-7")

        service.localMaterialUnlockError = CoreBridgeError.commandFailed("Local unlock material rejected")
        store.unlockWithConvenience()

        XCTAssertFalse(store.isUnlocked)
        XCTAssertFalse(store.convenienceUnlockAvailable)
        XCTAssertNil(convenienceUnlockStore.material(for: vaultURL))
        XCTAssertEqual(service.localMaterialUnlockPath, vaultURL.path)
        XCTAssertEqual(service.localMaterialUsed, "local-material-7")
        XCTAssertEqual(store.statusMessage, "Local unlock material rejected")

        service.localMaterialUnlockError = nil
        store.unlock(password: "correct horse", rememberForConvenience: true)

        XCTAssertTrue(store.isUnlocked)
        XCTAssertTrue(store.convenienceUnlockAvailable)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material-7")
        XCTAssertEqual(service.localUnlockMaterialRequests, [7, 7])
    }

    func testLegacyKeychainCleanupPreservesCurrentConvenienceUnlockMaterial() {
        let service = FakeCoreService()
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        let vaultURL = URL(fileURLWithPath: "/tmp/Legacy.pswvault")
        let otherVaultURL = URL(fileURLWithPath: "/tmp/Other.pswvault")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: convenienceUnlockStore,
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: vaultURL,
            displayName: "Legacy",
            password: "correct horse",
            confirmation: "correct horse",
            rememberForConvenience: true
        )
        convenienceUnlockStore.saveLegacyPasswordMaterial(
            "correct horse",
            service: "psw-local-vault.master-password.v1",
            for: vaultURL
        )
        convenienceUnlockStore.saveLegacyPasswordMaterial(
            "correct horse",
            service: "psw-local-vault.convenience-unlock.v1",
            for: vaultURL
        )
        convenienceUnlockStore.saveLegacyPasswordMaterial("other secret", for: otherVaultURL)

        XCTAssertTrue(store.convenienceUnlockAvailable)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material-7")
        XCTAssertEqual(convenienceUnlockStore.legacyPasswordMaterialCount(for: vaultURL), 2)
        XCTAssertEqual(convenienceUnlockStore.legacyPasswordMaterialCount(for: otherVaultURL), 1)

        store.cleanupLegacyKeychainPasswords()

        XCTAssertEqual(convenienceUnlockStore.legacyPasswordMaterialCount(for: vaultURL), 0)
        XCTAssertEqual(convenienceUnlockStore.legacyPasswordMaterialCount(for: otherVaultURL), 1)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material-7")
        XCTAssertTrue(store.convenienceUnlockAvailable)
        XCTAssertEqual(store.statusMessage, "Legacy Keychain entries removed")

        store.lock()
        store.unlockWithConvenience()

        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(service.localMaterialUsed, "local-material-7")

        store.cleanupLegacyKeychainPasswords()
        XCTAssertEqual(store.statusMessage, "No legacy Keychain entries found")
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material-7")
        XCTAssertTrue(store.convenienceUnlockAvailable)
    }

    func testDiagnosticsReportIncludesSupportContextAndExcludesSecrets() {
        let defaultsName = "PSWMacWorkflowTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: defaultsName)!
        defer { defaults.removePersistentDomain(forName: defaultsName) }
        let rawSecretMarker = "KN_SECRET_63_C8B1"
        let titleMarker = "KN_TITLE_63_28D4"
        let urlMarker = "https://kn-url-63.invalid/9e71"
        let requestBodyMarker = "KN_REQ_BODY_63_20AF"
        let commandArgumentsMarker = "KN_ARGS_63_674C"
        let executablePathMarker = "/Applications/KN_EXEC_PATH_63_447A/agent"
        let standardOutputMarker = "KN_STDOUT_63_18E2"
        let standardErrorMarker = "KN_STDERR_63_B039"
        let responseBodyMarker = "KN_RESP_BODY_63_0D55"
        let usernameMarker = "KN_USERNAME_63_5A91"
        let notesMarker = "KN_NOTES_63_9FF0"
        let tagMarker = "KN_TAG_63_407B"
        let forbiddenMarkers = [
            rawSecretMarker,
            titleMarker,
            urlMarker,
            requestBodyMarker,
            commandArgumentsMarker,
            executablePathMarker,
            standardOutputMarker,
            standardErrorMarker,
            responseBodyMarker,
            usernameMarker,
            notesMarker,
            tagMarker
        ]
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: titleMarker,
                username: usernameMarker,
                password: rawSecretMarker,
                url: urlMarker,
                notes: "\(notesMarker) \(requestBodyMarker) \(responseBodyMarker)",
                tags: [tagMarker, commandArgumentsMarker, standardOutputMarker, standardErrorMarker]
            )
        ])
        service.status = forbiddenMarkers.joined(separator: " | ")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: defaults
        )
        let vaultURL = URL(fileURLWithPath: "/Users/tester/Library/Mobile Documents/com~apple~CloudDocs/Private/Synced.pswvault")

        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.clipboardTimeout = 120
        store.autoLockSeconds = 600
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 2,
            appliedTombstones: 1,
            detectedConflicts: 1,
            rejectedRecords: 3,
            rejectedItemRecords: 2,
            rejectedTombstoneRecords: 1,
            rejectedRecordFiles: [
                SyncRejectedRecordFile(kind: "item", fileName: "bad_bank.enc"),
                SyncRejectedRecordFile(kind: "tombstone", fileName: "bad_delete.enc")
            ],
            items: [
                VaultItemView(
                    id: "sync_item",
                    title: titleMarker,
                    itemType: "login",
                    status: "active",
                    favorite: false,
                    tags: ["finance"]
                )
            ]
        )
        store.refreshFromDisk()
        let importURL = URL(fileURLWithPath: "/Users/tester/Downloads/bitwarden-export.json")
        store.previewImport(url: importURL)
        let exportURL = URL(fileURLWithPath: "/Users/tester/Desktop/psw-plaintext-export.json")
        store.plaintextExportURL = exportURL

        let report = store.diagnosticsReport(languageRaw: AppLanguage.simplifiedChinese.rawValue)

        XCTAssertTrue(report.contains("KeptNear Diagnostics"))
        XCTAssertTrue(report.contains("Core available: yes"))
        XCTAssertTrue(report.contains("Core status: connected"))
        XCTAssertTrue(report.contains("Vault selected: yes"))
        XCTAssertTrue(report.contains("Vault name: Synced.pswvault"))
        XCTAssertTrue(report.contains("Vault unlocked: yes"))
        XCTAssertTrue(report.contains("Item count: 1"))
        XCTAssertTrue(report.contains("Plaintext import cleanup pending: yes"))
        XCTAssertTrue(report.contains("Plaintext export cleanup pending: yes"))
        XCTAssertTrue(report.contains("Convenience unlock available: no"))
        XCTAssertTrue(report.contains("Clipboard clear seconds: 120"))
        XCTAssertTrue(report.contains("Auto-lock seconds: 600"))
        XCTAssertTrue(report.contains("Language: zh-Hans"))
        XCTAssertTrue(report.contains("Sync loaded items: 2"))
        XCTAssertTrue(report.contains("Sync applied tombstones: 1"))
        XCTAssertTrue(report.contains("Sync detected conflicts: 1"))
        XCTAssertTrue(report.contains("Sync rejected records: 3"))
        XCTAssertTrue(report.contains("Sync rejected item records: 2"))
        XCTAssertTrue(report.contains("Sync rejected tombstone records: 1"))
        XCTAssertTrue(report.contains("Sync refresh deferred by unsaved edits: no"))
        XCTAssertTrue(report.contains("Secret fields included: no"))

        XCTAssertFalse(report.contains(vaultURL.path))
        XCTAssertFalse(report.contains("/Users/tester"))
        XCTAssertFalse(report.contains("CloudDocs"))
        XCTAssertFalse(report.contains("correct horse"))
        XCTAssertFalse(report.contains("Strength"))
        XCTAssertFalse(report.contains("Weak"))
        XCTAssertFalse(report.contains("Very strong"))
        XCTAssertFalse(report.contains("bitwarden-export.json"))
        XCTAssertFalse(report.contains(importURL.path))
        XCTAssertFalse(report.contains("psw-plaintext-export.json"))
        XCTAssertFalse(report.contains(exportURL.path))
        XCTAssertFalse(report.contains("bad_bank.enc"))
        XCTAssertFalse(report.contains("bad_delete.enc"))
        for marker in forbiddenMarkers {
            XCTAssertFalse(report.contains(marker), "diagnostics leaked \(marker)")
        }

        store.copyDiagnostics(languageRaw: AppLanguage.english.rawValue)
        XCTAssertEqual(store.statusMessage, "Diagnostics copied")
    }

    func testDiagnosticsSnapshotUsesOnlyApprovedSupportFields() {
        let store = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        let snapshot = store.diagnosticsSnapshot(languageRaw: AppLanguage.english.rawValue)
        let labels = Set(Mirror(reflecting: snapshot).children.compactMap { $0.label })

        XCTAssertEqual(labels, Set([
            "appName",
            "appVersion",
            "appBuild",
            "coreAvailable",
            "coreStatus",
            "vaultSelected",
            "vaultName",
            "unlocked",
            "itemCount",
            "plaintextImportCleanupPending",
            "plaintextExportCleanupPending",
            "convenienceUnlockAvailable",
            "syncReadiness",
            "sync",
            "syncRefreshDeferredByUnsavedEdits",
            "clipboardTimeoutSeconds",
            "autoLockSeconds",
            "language"
        ]))
    }

    func testDiagnosticsReportIncludesConvenienceUnlockAvailabilityWithoutMaterial() {
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        let store = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: convenienceUnlockStore,
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/Users/tester/Secrets/Convenience.pswvault")
        try? convenienceUnlockStore.saveMaterial("local-unlock-material-secret", for: vaultURL)

        store.openVault(url: vaultURL)
        let report = store.diagnosticsReport(languageRaw: AppLanguage.english.rawValue)

        XCTAssertTrue(store.convenienceUnlockAvailable)
        XCTAssertTrue(report.contains("Convenience unlock available: yes"))
        XCTAssertFalse(report.contains("local-unlock-material-secret"))
        XCTAssertFalse(report.contains(vaultURL.path))
        XCTAssertFalse(report.contains("/Users/tester"))
    }

    func testImportPreviewAndCommitRefreshItems() {
        let service = FakeCoreService()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/Import.pswvault")
        let importURL = URL(fileURLWithPath: "/tmp/export.json")

        store.createVault(
            url: vaultURL,
            displayName: "Import",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.previewImport(url: importURL)

        XCTAssertEqual(store.importSourceURL?.path, importURL.path)
        XCTAssertEqual(store.importPreview?.importableRecords, 1)
        XCTAssertEqual(service.previewedImportPath, importURL.path)
        XCTAssertEqual(service.previewedImportFormat, "bitwarden-json")

        store.commitImport(keepDuplicates: true)

        XCTAssertEqual(service.committedImportPath, importURL.path)
        XCTAssertEqual(service.committedImportFormat, "bitwarden-json")
        XCTAssertEqual(service.committedKeepDuplicates, true)
        XCTAssertEqual(store.items.map(\.title), ["Imported"])
        XCTAssertEqual(store.items.first?.tags, ["imported"])
        XCTAssertTrue(store.importCompleted)
        XCTAssertEqual(store.importSourceURL?.path, importURL.path)
        XCTAssertEqual(store.statusMessage, "Import completed")

        store.revealImportSource()
        XCTAssertEqual(importSourceHandler.revealedURLs.map(\.path), [importURL.path])
        XCTAssertEqual(store.statusMessage, "Import source revealed")

        store.moveImportSourceToTrash()
        XCTAssertEqual(importSourceHandler.trashedURLs.map(\.path), [importURL.path])
        XCTAssertNil(store.importSourceURL)
        XCTAssertFalse(store.importCompleted)
        XCTAssertEqual(store.statusMessage, "Import source moved to Trash")
    }

    func testCsvImportPreviewAndCommitUseGenericLoginCsvFormat() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/ImportCsv.pswvault")
        let importURL = URL(fileURLWithPath: "/tmp/logins.CSV")

        store.createVault(
            url: vaultURL,
            displayName: "Import CSV",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.previewImport(url: importURL)

        XCTAssertEqual(store.importSourceURL?.path, importURL.path)
        XCTAssertEqual(service.previewedImportPath, importURL.path)
        XCTAssertEqual(service.previewedImportFormat, "generic-login-csv")

        store.commitImport(keepDuplicates: false)

        XCTAssertEqual(service.committedImportPath, importURL.path)
        XCTAssertEqual(service.committedImportFormat, "generic-login-csv")
        XCTAssertEqual(service.committedKeepDuplicates, false)
        XCTAssertTrue(store.importCompleted)
        XCTAssertEqual(store.statusMessage, "Import completed")
    }

    func testImportCommitIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let importURL = URL(fileURLWithPath: "/tmp/dirty-import.json")

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/DirtyImport.pswvault"),
            displayName: "Dirty Import",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.select(itemId: "item_1")
        store.previewImport(url: importURL)
        store.setEditorHasUnsavedChanges(true)

        let imported = store.commitImport(keepDuplicates: false)

        XCTAssertFalse(imported)
        XCTAssertNil(service.committedImportPath)
        XCTAssertFalse(store.importCompleted)
        XCTAssertEqual(store.importSourceURL?.path, importURL.path)
        XCTAssertEqual(store.importPreview?.importableRecords, 1)
        XCTAssertEqual(store.items.map(\.title), ["Email"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before importing")
        XCTAssertFalse(store.canExport)
    }

    func testConfirmedImportCommitCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let importURL = URL(fileURLWithPath: "/tmp/dirty-import-confirmed.json")

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/DirtyImportConfirmed.pswvault"),
            displayName: "Dirty Import",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.select(itemId: "item_1")
        store.previewImport(url: importURL)
        store.setEditorHasUnsavedChanges(true)

        let imported = store.commitImport(keepDuplicates: false, discardingUnsavedEdits: true)

        XCTAssertTrue(imported)
        XCTAssertEqual(service.committedImportPath, importURL.path)
        XCTAssertEqual(service.committedKeepDuplicates, false)
        XCTAssertTrue(store.importCompleted)
        XCTAssertEqual(store.items.map(\.title), ["Imported"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Imported")
        XCTAssertEqual(store.statusMessage, "Import completed")
        XCTAssertTrue(store.canExport)
    }

    func testExportRequiresUnlockedVaultAndRecordsResult() {
        let service = FakeCoreService()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        let exportURL = URL(fileURLWithPath: "/tmp/export.json")

        XCTAssertFalse(store.canExport)
        XCTAssertFalse(
            store.exportItems(
                destinationURL: exportURL,
                currentMasterPassword: "correct horse"
            )
        )
        XCTAssertNil(service.exportedPath)

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/Export.pswvault"),
            displayName: "Export",
            password: "correct horse",
            confirmation: "correct horse"
        )
        service.nextExportResult = ExportResultPayload(
            exportedRecords: 2,
            skippedRecords: 1,
            warnings: ["Export file contains plaintext secrets."],
            omissions: [
                ExportOmissionPayload(reason: "conflicted-credential", count: 1)
            ]
        )

        XCTAssertTrue(store.canExport)
        XCTAssertFalse(
            store.exportItems(
                destinationURL: exportURL,
                currentMasterPassword: ""
            )
        )
        XCTAssertEqual(store.statusMessage, "Current master password is required")
        XCTAssertNil(service.exportedPath)
        XCTAssertNil(service.exportedCurrentPassword)
        XCTAssertTrue(
            store.exportItems(
                destinationURL: exportURL,
                currentMasterPassword: "correct horse"
            )
        )

        XCTAssertEqual(service.exportedPath, exportURL.path)
        XCTAssertEqual(service.exportedFormat, "keptnear-json")
        XCTAssertEqual(service.exportedCurrentPassword, "correct horse")
        XCTAssertEqual(store.exportResult?.exportedRecords, 2)
        XCTAssertEqual(store.exportResult?.skippedRecords, 1)
        XCTAssertEqual(
            store.exportResult?.omissions,
            [ExportOmissionPayload(reason: "conflicted-credential", count: 1)]
        )
        XCTAssertEqual(store.exportResult?.warnings, ["Export file contains plaintext secrets."])
        XCTAssertEqual(store.plaintextExportURL?.path, exportURL.path)
        XCTAssertEqual(store.statusMessage, "Export completed: 2 exported, 1 skipped")

        store.revealPlaintextExport()
        XCTAssertEqual(importSourceHandler.revealedURLs.map(\.path), [exportURL.path])
        XCTAssertEqual(store.statusMessage, "Plaintext export revealed")
        XCTAssertEqual(store.plaintextExportURL?.path, exportURL.path)

        store.movePlaintextExportToTrash()
        XCTAssertEqual(importSourceHandler.trashedURLs.map(\.path), [exportURL.path])
        XCTAssertNil(store.plaintextExportURL)
        XCTAssertEqual(store.statusMessage, "Plaintext export moved to Trash")
    }

    func testExportIsUnavailableWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let exportURL = URL(fileURLWithPath: "/tmp/dirty-export.json")

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/DirtyExport.pswvault"),
            displayName: "Dirty Export",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var form = LoginForm()
        form.title = "Email"
        form.username = "me@example.com"
        form.password = "email-password"
        store.saveLogin(form: form)
        store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(store.canExport)
        XCTAssertFalse(
            store.exportItems(
                destinationURL: exportURL,
                currentMasterPassword: "correct horse"
            )
        )
        XCTAssertNil(service.exportedPath)
        XCTAssertNil(store.exportResult)
        XCTAssertNil(store.plaintextExportURL)
        XCTAssertEqual(store.statusMessage, "Save or discard edits before exporting")

        store.setEditorHasUnsavedChanges(false)
        XCTAssertTrue(store.canExport)
    }

    func testEncryptedBackupRequiresUnlockedVaultAndRecordsResult() {
        let service = FakeCoreService()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        let backupURL = URL(fileURLWithPath: "/tmp/Backup.pswvault")

        XCTAssertFalse(store.canBackup)
        XCTAssertFalse(store.backupVault(destinationURL: backupURL))
        XCTAssertNil(service.backupDestinationPath)
        XCTAssertNil(store.backupDestinationURL)

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/BackupSource.pswvault"),
            displayName: "Backup Source",
            password: "correct horse",
            confirmation: "correct horse"
        )
        service.nextBackupResult = BackupResultPayload(
            copiedItemFiles: 3,
            copiedAttachmentFiles: 1,
            copiedTombstoneFiles: 2
        )

        XCTAssertTrue(store.canBackup)
        XCTAssertTrue(store.backupVault(destinationURL: backupURL))

        XCTAssertEqual(service.backupCallCount, 1)
        XCTAssertEqual(service.backupDestinationPath, backupURL.path)
        XCTAssertEqual(store.backupResult?.copiedItemFiles, 3)
        XCTAssertEqual(store.backupResult?.copiedAttachmentFiles, 1)
        XCTAssertEqual(store.backupResult?.copiedTombstoneFiles, 2)
        XCTAssertEqual(store.backupDestinationURL?.path, backupURL.path)
        XCTAssertEqual(store.statusMessage, "Backup completed: 3 items, 1 attachments, 2 tombstones")

        store.revealBackupDestination()

        XCTAssertEqual(importSourceHandler.revealedURLs.map(\.path), [backupURL.path])
        XCTAssertEqual(store.statusMessage, "Backup destination revealed")
    }

    func testEncryptedBackupRejectsAndConfirmsDirtyEditorDiscard() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let backupURL = URL(fileURLWithPath: "/tmp/DirtyBackup.pswvault")

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyBackupSource.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(store.backupVault(destinationURL: backupURL))
        XCTAssertEqual(service.backupCallCount, 0)
        XCTAssertNil(store.backupResult)
        XCTAssertNil(store.backupDestinationURL)
        XCTAssertEqual(store.statusMessage, "Save or discard edits before backing up")

        service.nextBackupResult = BackupResultPayload(
            copiedItemFiles: 1,
            copiedAttachmentFiles: 0,
            copiedTombstoneFiles: 0
        )

        XCTAssertTrue(store.backupVault(destinationURL: backupURL, discardingUnsavedEdits: true))
        XCTAssertEqual(service.backupCallCount, 1)
        XCTAssertEqual(service.backupDestinationPath, backupURL.path)
        XCTAssertEqual(store.backupResult?.copiedItemFiles, 1)
        XCTAssertEqual(store.backupDestinationURL?.path, backupURL.path)
        XCTAssertEqual(store.statusMessage, "Backup completed: 1 items, 0 attachments, 0 tombstones")
    }

    func testRestoreEncryptedBackupSelectsRestoredVaultLockedAndRecordsResult() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let clipboard = FakeClipboard()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        let currentURL = URL(fileURLWithPath: "/tmp/CurrentRestoreSource.pswvault")
        let sourceURL = URL(fileURLWithPath: "/tmp/BackupToRestore.pswvault")
        let destinationURL = URL(fileURLWithPath: "/tmp/RestoredBackup.pswvault")

        store.openVault(url: currentURL)
        store.unlock(password: "correct horse")
        XCTAssertTrue(store.isUnlocked)
        XCTAssertFalse(store.items.isEmpty)

        service.nextRestoreBackupResult = RestoreBackupResultPayload(
            copiedItemFiles: 4,
            copiedAttachmentFiles: 2,
            copiedTombstoneFiles: 1
        )

        XCTAssertTrue(store.restoreVaultBackup(sourceURL: sourceURL, destinationURL: destinationURL))

        XCTAssertEqual(service.restoreBackupCallCount, 1)
        XCTAssertEqual(service.restoreSourcePath, sourceURL.path)
        XCTAssertEqual(service.restoreDestinationPath, destinationURL.path)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 1)
        XCTAssertEqual(store.vaultURL?.path, destinationURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, destinationURL.path)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertNil(store.selectedItemId)
        XCTAssertNil(store.syncReport)
        XCTAssertEqual(store.restoreBackupResult?.copiedItemFiles, 4)
        XCTAssertEqual(store.restoreBackupResult?.copiedAttachmentFiles, 2)
        XCTAssertEqual(store.restoreBackupResult?.copiedTombstoneFiles, 1)
        XCTAssertEqual(store.restoredBackupURL?.path, destinationURL.path)
        XCTAssertEqual(store.statusMessage, "Restore completed: 4 items, 2 attachments, 1 tombstones")

        store.revealRestoredBackup()

        XCTAssertEqual(importSourceHandler.revealedURLs.map(\.path), [destinationURL.path])
        XCTAssertEqual(store.statusMessage, "Restored vault revealed")
    }

    func testRestoreEncryptedBackupRejectsAndConfirmsDirtyEditorDiscard() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let currentURL = URL(fileURLWithPath: "/tmp/DirtyRestoreCurrent.pswvault")
        let sourceURL = URL(fileURLWithPath: "/tmp/DirtyRestoreBackup.pswvault")
        let destinationURL = URL(fileURLWithPath: "/tmp/DirtyRestoredBackup.pswvault")

        store.openVault(url: currentURL)
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(store.restoreVaultBackup(sourceURL: sourceURL, destinationURL: destinationURL))
        XCTAssertEqual(service.restoreBackupCallCount, 0)
        XCTAssertEqual(store.vaultURL?.path, currentURL.path)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertNil(store.restoreBackupResult)
        XCTAssertNil(store.restoredBackupURL)
        XCTAssertEqual(store.statusMessage, "Save or discard edits before restoring backup")

        service.nextRestoreBackupResult = RestoreBackupResultPayload(
            copiedItemFiles: 1,
            copiedAttachmentFiles: 0,
            copiedTombstoneFiles: 0
        )

        XCTAssertTrue(store.restoreVaultBackup(
            sourceURL: sourceURL,
            destinationURL: destinationURL,
            discardingUnsavedEdits: true
        ))
        XCTAssertEqual(service.restoreBackupCallCount, 1)
        XCTAssertEqual(store.restoredBackupURL?.path, destinationURL.path)
        XCTAssertEqual(store.vaultURL?.path, destinationURL.path)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertEqual(store.statusMessage, "Restore completed: 1 items, 0 attachments, 0 tombstones")
    }

    func testCopyVaultToSyncLocationSelectsCopiedVaultLockedAndPreservesSource() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let sourceURL = tempRoot.appendingPathComponent("Local.pswvault", isDirectory: true)
        let destinationURL = tempRoot
            .appendingPathComponent("Dropbox", isDirectory: true)
            .appendingPathComponent("Synced.pswvault", isDirectory: true)
        try createRequiredVaultStructure(at: sourceURL)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let clipboard = FakeClipboard()
        let importSourceHandler = FakeImportSourceHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: sourceURL)
        store.unlock(password: "correct horse")
        XCTAssertTrue(store.canCopyVaultToSyncLocation)
        XCTAssertFalse(store.items.isEmpty)

        service.nextRestoreBackupResult = RestoreBackupResultPayload(
            copiedItemFiles: 5,
            copiedAttachmentFiles: 2,
            copiedTombstoneFiles: 1
        )

        XCTAssertTrue(store.copyVaultToSyncLocation(destinationURL: destinationURL))

        XCTAssertEqual(service.restoreBackupCallCount, 1)
        XCTAssertEqual(service.restoreSourcePath, sourceURL.path)
        XCTAssertEqual(service.restoreDestinationPath, destinationURL.path)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: sourceURL.path))
        XCTAssertEqual(store.vaultURL?.path, destinationURL.path)
        XCTAssertEqual(store.recentVaultURL?.path, destinationURL.path)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertNil(store.selectedItemId)
        XCTAssertEqual(store.copyVaultToSyncResult?.copiedItemFiles, 5)
        XCTAssertEqual(store.copyVaultToSyncResult?.copiedAttachmentFiles, 2)
        XCTAssertEqual(store.copyVaultToSyncResult?.copiedTombstoneFiles, 1)
        XCTAssertEqual(store.copiedSyncVaultURL?.path, destinationURL.path)
        XCTAssertEqual(store.statusMessage, "Vault copied to sync location: 5 items, 2 attachments, 1 tombstones")

        store.revealCopiedSyncVault()

        XCTAssertEqual(importSourceHandler.revealedURLs.map(\.path), [destinationURL.path])
        XCTAssertEqual(store.statusMessage, "Copied sync vault revealed")
    }

    func testCopyVaultToSyncLocationRequiresSelectedVaultAndCleanEditor() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let destinationURL = URL(fileURLWithPath: "/tmp/SyncedCopy.pswvault")

        XCTAssertFalse(store.canCopyVaultToSyncLocation)
        XCTAssertFalse(store.copyVaultToSyncLocation(destinationURL: destinationURL))
        XCTAssertEqual(service.restoreBackupCallCount, 0)
        XCTAssertNil(store.copyVaultToSyncResult)
        XCTAssertNil(store.copiedSyncVaultURL)

        store.openVault(url: URL(fileURLWithPath: "/tmp/LocalCopySource.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)

        XCTAssertTrue(store.canCopyVaultToSyncLocation)
        XCTAssertFalse(store.copyVaultToSyncLocation(destinationURL: destinationURL))
        XCTAssertEqual(service.restoreBackupCallCount, 0)
        XCTAssertEqual(store.vaultURL?.path, "/tmp/LocalCopySource.pswvault")
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertNil(store.copyVaultToSyncResult)
        XCTAssertNil(store.copiedSyncVaultURL)
        XCTAssertEqual(store.statusMessage, "Save or discard edits before copying to sync")

        service.nextRestoreBackupResult = RestoreBackupResultPayload(
            copiedItemFiles: 1,
            copiedAttachmentFiles: 0,
            copiedTombstoneFiles: 0
        )

        XCTAssertTrue(store.copyVaultToSyncLocation(
            destinationURL: destinationURL,
            discardingUnsavedEdits: true
        ))
        XCTAssertEqual(service.restoreBackupCallCount, 1)
        XCTAssertEqual(service.restoreSourcePath, "/tmp/LocalCopySource.pswvault")
        XCTAssertEqual(service.restoreDestinationPath, destinationURL.path)
        XCTAssertEqual(store.vaultURL?.path, destinationURL.path)
        XCTAssertEqual(store.copiedSyncVaultURL?.path, destinationURL.path)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertEqual(store.statusMessage, "Vault copied to sync location: 1 items, 0 attachments, 0 tombstones")
    }

    func testPlaintextExportTrashFailurePreservesDestinationForRetry() {
        let service = FakeCoreService()
        let importSourceHandler = FakeImportSourceHandler()
        importSourceHandler.trashError = CoreBridgeError.commandFailed("Trash unavailable")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        let exportURL = URL(fileURLWithPath: "/tmp/export-retry.json")

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/ExportTrashFailure.pswvault"),
            displayName: "Export",
            password: "correct horse",
            confirmation: "correct horse"
        )
        XCTAssertTrue(
            store.exportItems(
                destinationURL: exportURL,
                currentMasterPassword: "correct horse"
            )
        )

        store.movePlaintextExportToTrash()

        XCTAssertEqual(importSourceHandler.trashedURLs.map(\.path), [exportURL.path])
        XCTAssertEqual(store.plaintextExportURL?.path, exportURL.path)
        XCTAssertEqual(store.statusMessage, "Trash unavailable")
    }

    func testInvalidLoginTitleDoesNotCallCoreSave() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/InvalidTitle.pswvault"),
            displayName: "Invalid",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var form = LoginForm()
        form.title = "   "
        form.username = "alice"
        form.password = "secret"

        store.saveLogin(form: form)

        XCTAssertEqual(store.statusMessage, "Title is required")
        XCTAssertEqual(service.createLoginCallCount, 0)
        XCTAssertEqual(service.updateLoginCallCount, 0)
        XCTAssertTrue(store.items.isEmpty)
    }

    func testEmptyUsernameDoesNotModifyClipboard() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/EmptyUsername.pswvault"),
            displayName: "Empty Username",
            password: "correct horse",
            confirmation: "correct horse"
        )
        clipboard.copy("existing-value", clearAfter: 45)

        var form = LoginForm()
        form.title = "Username Optional"
        form.password = "secret"
        store.saveLogin(form: form)

        store.copyUsername()

        XCTAssertEqual(clipboard.copied.map(\.value), ["existing-value"])
        XCTAssertEqual(clipboard.currentValue, "existing-value")
        XCTAssertEqual(store.statusMessage, "login item has no username")
    }

    func testInvalidStructuredItemTitlesDoNotCallCoreSave() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/InvalidStructuredTitles.pswvault"),
            displayName: "Invalid Structured",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var noteForm = SecureNoteForm()
        noteForm.title = "   "
        noteForm.body = "offline backup codes"

        store.saveSecureNote(form: noteForm)

        XCTAssertEqual(store.statusMessage, "Title is required")
        XCTAssertEqual(service.createSecureNoteCallCount, 0)
        XCTAssertEqual(service.updateSecureNoteCallCount, 0)
        XCTAssertTrue(store.items.isEmpty)

        var cardForm = CreditCardForm()
        cardForm.title = "\n\t"
        cardForm.cardholderName = "Alice Example"

        store.saveCreditCard(form: cardForm)

        XCTAssertEqual(store.statusMessage, "Title is required")
        XCTAssertEqual(service.createCreditCardCallCount, 0)
        XCTAssertEqual(service.updateCreditCardCallCount, 0)
        XCTAssertTrue(store.items.isEmpty)

        var licenseForm = SoftwareLicenseForm()
        licenseForm.title = ""
        licenseForm.product = "TextPro"

        store.saveSoftwareLicense(form: licenseForm)

        XCTAssertEqual(store.statusMessage, "Title is required")
        XCTAssertEqual(service.createSoftwareLicenseCallCount, 0)
        XCTAssertEqual(service.updateSoftwareLicenseCallCount, 0)
        XCTAssertTrue(store.items.isEmpty)
    }

    func testSecureNoteCreateSelectUpdateWorkflow() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/SecureNote.pswvault"),
            displayName: "Notes",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var form = SecureNoteForm()
        form.title = "Recovery Notes"
        form.body = "offline backup codes"
        form.tagsText = "recovery, personal, recovery"
        form.favorite = true

        store.saveSecureNote(form: form)

        XCTAssertEqual(service.createSecureNoteCallCount, 1)
        XCTAssertEqual(store.items.first?.itemType, "secure note")
        XCTAssertEqual(store.items.first?.title, "Recovery Notes")
        XCTAssertEqual(store.selectedSecureNoteDetail?.body, "offline backup codes")
        XCTAssertEqual(store.selectedSecureNoteDetail?.tags, ["recovery", "personal"])
        XCTAssertNil(store.selectedDetail)
        XCTAssertFalse(store.canCopyLoginFields)
        XCTAssertTrue(store.canCopySecureNoteBody)

        store.copyUsername()
        store.copyPassword()
        store.copyTotp()
        XCTAssertTrue(clipboard.copied.isEmpty)

        let itemId = store.items[0].id
        store.select(itemId: itemId)
        XCTAssertEqual(store.selectedSecureNoteDetail?.title, "Recovery Notes")

        var edited = SecureNoteForm(detail: try! XCTUnwrap(store.selectedSecureNoteDetail))
        edited.title = "Recovery Notes Edited"
        edited.body = "rotated backup codes"
        edited.tagsText = "recovery"
        edited.favorite = false
        store.saveSecureNote(form: edited)

        XCTAssertEqual(service.updateSecureNoteCallCount, 1)
        XCTAssertEqual(store.items.first?.title, "Recovery Notes Edited")
        XCTAssertEqual(store.selectedSecureNoteDetail?.body, "rotated backup codes")
        XCTAssertEqual(store.selectedSecureNoteDetail?.favorite, false)
        XCTAssertEqual(store.selectedSecureNoteDetail?.tags, ["recovery"])
        XCTAssertEqual(store.statusMessage, "Saved")

        store.copySecureNoteBody()

        XCTAssertEqual(clipboard.copied.map(\.value), ["rotated backup codes"])
        XCTAssertEqual(clipboard.copied.map(\.timeout), [45])
        XCTAssertEqual(store.statusMessage, "Secure note body copied")

        edited = SecureNoteForm(detail: try! XCTUnwrap(store.selectedSecureNoteDetail))
        edited.body = "   "
        store.saveSecureNote(form: edited)
        store.copySecureNoteBody()

        XCTAssertEqual(clipboard.copied.map(\.value), ["rotated backup codes"])
        XCTAssertEqual(store.statusMessage, "secure note has no body")
    }

    func testCreditCardCreateEditCopyAndRestoreWorkflow() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/Card.pswvault"),
            displayName: "Cards",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var form = CreditCardForm()
        form.title = "Travel Card"
        form.cardholderName = "Alice Example"
        form.number = "4111111111111111"
        form.expiryMonth = "04"
        form.expiryYear = "2030"
        form.verificationCode = "123"
        form.notes = "Travel rewards card"
        form.tagsText = "finance, travel"
        form.favorite = true
        store.saveCreditCard(form: form)

        XCTAssertEqual(service.createCreditCardCallCount, 1)
        XCTAssertEqual(store.selectedItem?.itemType, "credit card")
        XCTAssertEqual(store.selectedCreditCardDetail?.title, "Travel Card")
        XCTAssertEqual(store.selectedCreditCardDetail?.cardholderName, "Alice Example")
        XCTAssertEqual(store.selectedCreditCardDetail?.expiryMonth, 4)
        XCTAssertEqual(store.selectedCreditCardDetail?.expiryYear, 2030)
        XCTAssertNil(store.selectedDetail)
        let cardId = try! XCTUnwrap(store.selectedItemId)

        store.copyCardNumber()
        store.copyCardVerificationCode()

        XCTAssertEqual(clipboard.copied.map(\.value), ["4111111111111111", "123"])
        XCTAssertEqual(store.statusMessage, "Verification code copied")

        var edited = CreditCardForm(detail: try! XCTUnwrap(store.selectedCreditCardDetail))
        XCTAssertTrue(edited.number.isEmpty)
        XCTAssertTrue(edited.verificationCode.isEmpty)
        edited.title = "Travel Card Edited"
        edited.cardholderName = "Alice B. Example"
        edited.expiryYear = "2031"
        edited.favorite = false
        store.saveCreditCard(form: edited)

        XCTAssertEqual(service.updateCreditCardCallCount, 1)
        XCTAssertEqual(store.selectedCreditCardDetail?.title, "Travel Card Edited")
        XCTAssertEqual(service.cardNumber(for: cardId), "4111111111111111")
        XCTAssertEqual(service.cardVerificationCode(for: cardId), "123")

        var clearForm = CreditCardForm(detail: try! XCTUnwrap(store.selectedCreditCardDetail))
        clearForm.clearNumberOnSave = true
        clearForm.clearVerificationCodeOnSave = true
        store.saveCreditCard(form: clearForm)

        XCTAssertEqual(service.updateCreditCardCallCount, 2)
        XCTAssertNil(service.cardNumber(for: cardId))
        XCTAssertNil(service.cardVerificationCode(for: cardId))

        store.copyCardNumber()
        store.copyCardVerificationCode()

        XCTAssertEqual(clipboard.copied.map(\.value), ["4111111111111111", "123"])
        XCTAssertEqual(store.statusMessage, "credit card has no verification code")

        var replaceForm = CreditCardForm(detail: try! XCTUnwrap(store.selectedCreditCardDetail))
        replaceForm.clearNumberOnSave = true
        replaceForm.clearVerificationCodeOnSave = true
        replaceForm.number = "5555555555554444"
        replaceForm.verificationCode = "987"
        store.saveCreditCard(form: replaceForm)

        XCTAssertEqual(service.updateCreditCardCallCount, 3)
        XCTAssertEqual(service.cardNumber(for: cardId), "5555555555554444")
        XCTAssertEqual(service.cardVerificationCode(for: cardId), "987")

        store.copyCardNumber()
        store.copyCardVerificationCode()

        XCTAssertEqual(clipboard.copied.map(\.value), [
            "4111111111111111",
            "123",
            "5555555555554444",
            "987"
        ])
        XCTAssertEqual(store.statusMessage, "Verification code copied")

        store.archiveSelected()
        XCTAssertNil(store.selectedItemId)
        store.includeArchived = true
        store.search()
        XCTAssertEqual(store.items.first?.status, "archived")
        store.select(itemId: cardId)
        XCTAssertTrue(store.canRestoreSelectedArchive)

        store.restoreSelectedArchive()

        XCTAssertEqual(store.selectedItemId, cardId)
        XCTAssertEqual(store.selectedCreditCardDetail?.status, "active")
        XCTAssertEqual(store.selectedCreditCardDetail?.title, "Travel Card Edited")
    }

    func testSoftwareLicenseCreateEditCopyAndExportWorkflow() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/License.pswvault"),
            displayName: "Licenses",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var form = SoftwareLicenseForm()
        form.title = "Editor License"
        form.product = "TextPro"
        form.licenseKey = "AAAA-BBBB-CCCC"
        form.licensedTo = "alice@example.com"
        form.notes = "Renewal due Q4"
        form.tagsText = "software, tools"
        form.favorite = true
        store.saveSoftwareLicense(form: form)

        XCTAssertEqual(service.createSoftwareLicenseCallCount, 1)
        XCTAssertEqual(store.selectedItem?.itemType, "software license")
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.product, "TextPro")
        let licenseId = try! XCTUnwrap(store.selectedItemId)

        store.copyLicenseKey()

        XCTAssertEqual(clipboard.copied.map(\.value), ["AAAA-BBBB-CCCC"])
        XCTAssertEqual(store.statusMessage, "License key copied")

        var edited = SoftwareLicenseForm(detail: try! XCTUnwrap(store.selectedSoftwareLicenseDetail))
        XCTAssertTrue(edited.licenseKey.isEmpty)
        edited.title = "Editor License Edited"
        edited.notes = "Updated renewal note"
        edited.favorite = false
        store.saveSoftwareLicense(form: edited)

        XCTAssertEqual(service.updateSoftwareLicenseCallCount, 1)
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.title, "Editor License Edited")
        XCTAssertEqual(service.licenseKey(for: licenseId), "AAAA-BBBB-CCCC")

        var clearForm = SoftwareLicenseForm(detail: try! XCTUnwrap(store.selectedSoftwareLicenseDetail))
        clearForm.clearLicenseKeyOnSave = true
        store.saveSoftwareLicense(form: clearForm)

        XCTAssertEqual(service.updateSoftwareLicenseCallCount, 2)
        XCTAssertNil(service.licenseKey(for: licenseId))

        store.copyLicenseKey()

        XCTAssertEqual(clipboard.copied.map(\.value), ["AAAA-BBBB-CCCC"])
        XCTAssertEqual(store.statusMessage, "software license has no license key")

        var replaceForm = SoftwareLicenseForm(detail: try! XCTUnwrap(store.selectedSoftwareLicenseDetail))
        replaceForm.clearLicenseKeyOnSave = true
        replaceForm.licenseKey = "DDDD-EEEE-FFFF"
        store.saveSoftwareLicense(form: replaceForm)

        XCTAssertEqual(service.updateSoftwareLicenseCallCount, 3)
        XCTAssertEqual(service.licenseKey(for: licenseId), "DDDD-EEEE-FFFF")

        store.copyLicenseKey()

        XCTAssertEqual(clipboard.copied.map(\.value), ["AAAA-BBBB-CCCC", "DDDD-EEEE-FFFF"])
        XCTAssertEqual(store.statusMessage, "License key copied")

        service.nextExportResult = ExportResultPayload(
            exportedRecords: 2,
            skippedRecords: 0,
            warnings: ["Software license items were exported as secure notes."]
        )
        XCTAssertTrue(
            store.exportItems(
                destinationURL: URL(fileURLWithPath: "/tmp/structured-export.json"),
                currentMasterPassword: "correct horse",
                exportFormat: "bitwarden-json"
            )
        )
        XCTAssertEqual(service.exportedFormat, "bitwarden-json")
        XCTAssertEqual(store.exportResult?.exportedRecords, 2)
        XCTAssertEqual(store.statusMessage, "Export completed: 2 exported, 0 skipped")
    }

    func testDuplicateSelectedSupportedItemsCreatesActiveCopiesAndPreservesSecrets() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/Duplicate.pswvault"),
            displayName: "Duplicate",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var login = LoginForm()
        login.title = "Example"
        login.username = "alice"
        login.password = "login-secret"
        login.url = "https://example.com"
        login.notes = "Primary account"
        login.totpSecret = "JBSWY3DPEHPK3PXP"
        login.tagsText = "work, primary"
        login.favorite = true
        store.saveLogin(form: login)
        let originalLoginId = try! XCTUnwrap(store.selectedItemId)

        XCTAssertTrue(store.canDuplicateSelectedItem)
        XCTAssertTrue(store.duplicateSelectedItem())

        let loginCopyId = try! XCTUnwrap(store.selectedItemId)
        XCTAssertNotEqual(loginCopyId, originalLoginId)
        XCTAssertEqual(service.createLoginCallCount, 2)
        XCTAssertEqual(store.selectedDetail?.title, "Example Copy")
        XCTAssertEqual(store.selectedDetail?.username, "alice")
        XCTAssertEqual(store.selectedDetail?.url, "https://example.com")
        XCTAssertEqual(store.selectedDetail?.notes, "Primary account")
        XCTAssertEqual(store.selectedDetail?.totpSecret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(store.selectedDetail?.tags, ["work", "primary"])
        XCTAssertEqual(store.selectedDetail?.favorite, true)
        XCTAssertEqual(service.password(for: loginCopyId), "login-secret")
        XCTAssertEqual(store.statusMessage, "Duplicated")

        resetSelectionForNewItem(store)
        var note = SecureNoteForm()
        note.title = "Recovery"
        note.body = "backup codes"
        note.tagsText = "personal"
        note.favorite = true
        store.saveSecureNote(form: note)
        let originalNoteId = try! XCTUnwrap(store.selectedItemId)

        XCTAssertTrue(store.duplicateSelectedItem())

        let noteCopyId = try! XCTUnwrap(store.selectedItemId)
        XCTAssertNotEqual(noteCopyId, originalNoteId)
        XCTAssertEqual(service.createSecureNoteCallCount, 2)
        XCTAssertEqual(store.selectedSecureNoteDetail?.title, "Recovery Copy")
        XCTAssertEqual(store.selectedSecureNoteDetail?.body, "backup codes")
        XCTAssertEqual(store.selectedSecureNoteDetail?.tags, ["personal"])
        XCTAssertEqual(store.selectedSecureNoteDetail?.favorite, true)

        resetSelectionForNewItem(store)
        var card = CreditCardForm()
        card.title = "Travel Card"
        card.cardholderName = "Alice Example"
        card.number = "4111111111111111"
        card.expiryMonth = "04"
        card.expiryYear = "2030"
        card.verificationCode = "123"
        card.notes = "Travel rewards"
        card.tagsText = "finance, travel"
        card.favorite = true
        store.saveCreditCard(form: card)
        let originalCardId = try! XCTUnwrap(store.selectedItemId)

        XCTAssertTrue(store.duplicateSelectedItem())

        let cardCopyId = try! XCTUnwrap(store.selectedItemId)
        XCTAssertNotEqual(cardCopyId, originalCardId)
        XCTAssertEqual(service.createCreditCardCallCount, 2)
        XCTAssertEqual(store.selectedCreditCardDetail?.title, "Travel Card Copy")
        XCTAssertEqual(store.selectedCreditCardDetail?.cardholderName, "Alice Example")
        XCTAssertEqual(store.selectedCreditCardDetail?.expiryMonth, 4)
        XCTAssertEqual(store.selectedCreditCardDetail?.expiryYear, 2030)
        XCTAssertEqual(store.selectedCreditCardDetail?.notes, "Travel rewards")
        XCTAssertEqual(store.selectedCreditCardDetail?.tags, ["finance", "travel"])
        XCTAssertEqual(store.selectedCreditCardDetail?.favorite, true)
        XCTAssertEqual(service.cardNumber(for: cardCopyId), "4111111111111111")
        XCTAssertEqual(service.cardVerificationCode(for: cardCopyId), "123")

        resetSelectionForNewItem(store)
        var license = SoftwareLicenseForm()
        license.title = "Editor License"
        license.product = "TextPro"
        license.licenseKey = "AAAA-BBBB-CCCC"
        license.licensedTo = "alice@example.com"
        license.notes = "Renewal due Q4"
        license.tagsText = "software, tools"
        license.favorite = true
        store.saveSoftwareLicense(form: license)
        let originalLicenseId = try! XCTUnwrap(store.selectedItemId)

        XCTAssertTrue(store.duplicateSelectedItem())

        let licenseCopyId = try! XCTUnwrap(store.selectedItemId)
        XCTAssertNotEqual(licenseCopyId, originalLicenseId)
        XCTAssertEqual(service.createSoftwareLicenseCallCount, 2)
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.title, "Editor License Copy")
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.product, "TextPro")
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.licensedTo, "alice@example.com")
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.notes, "Renewal due Q4")
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.tags, ["software", "tools"])
        XCTAssertEqual(store.selectedSoftwareLicenseDetail?.favorite, true)
        XCTAssertEqual(service.licenseKey(for: licenseCopyId), "AAAA-BBBB-CCCC")
    }

    func testDuplicateSelectedItemIsUnavailableForConflictedSelection() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/DuplicateConflict.pswvault"),
            displayName: "Duplicate",
            password: "correct horse",
            confirmation: "correct horse"
        )
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "conflicted",
                    revision: "rev_conflict",
                    title: "Conflicted",
                    itemType: "login",
                    status: "conflicted",
                    conflictId: "conflict_1",
                    favorite: false,
                    tags: []
                )
            ]
        )
        store.refreshFromDisk()

        XCTAssertFalse(store.canDuplicateSelectedItem)
        XCTAssertFalse(store.duplicateSelectedItem())
        XCTAssertEqual(service.createLoginCallCount, 0)
        XCTAssertEqual(store.statusMessage, "Resolve conflict before editing")
    }

    func testEmptyStructuredSecretsDoNotModifyClipboard() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/EmptyStructuredSecrets.pswvault"),
            displayName: "Empty Structured",
            password: "correct horse",
            confirmation: "correct horse"
        )
        clipboard.copy("existing-secret", clearAfter: 45)

        var cardForm = CreditCardForm()
        cardForm.title = "Empty Card"
        cardForm.cardholderName = "Alice Example"
        store.saveCreditCard(form: cardForm)

        store.copyCardNumber()
        XCTAssertEqual(clipboard.copied.map(\.value), ["existing-secret"])
        XCTAssertEqual(store.statusMessage, "credit card has no card number")

        store.copyCardVerificationCode()
        XCTAssertEqual(clipboard.copied.map(\.value), ["existing-secret"])
        XCTAssertEqual(store.statusMessage, "credit card has no verification code")

        store.selectedItemId = nil
        store.selectedCreditCardDetail = nil

        var licenseForm = SoftwareLicenseForm()
        licenseForm.title = "Empty License"
        licenseForm.product = "TextPro"
        store.saveSoftwareLicense(form: licenseForm)

        store.copyLicenseKey()
        XCTAssertEqual(clipboard.copied.map(\.value), ["existing-secret"])
        XCTAssertEqual(store.statusMessage, "software license has no license key")
        XCTAssertEqual(clipboard.currentValue, "existing-secret")
    }

    func testImportedSecureNoteLoadsSecureNoteDetail() {
        let service = FakeCoreService()
        service.importSecureNoteOnCommit = true
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/ImportSecureNote.pswvault"),
            displayName: "Import Note",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.previewImport(url: URL(fileURLWithPath: "/tmp/export.json"))
        store.commitImport(keepDuplicates: false)

        XCTAssertEqual(store.items.first?.itemType, "secure note")
        XCTAssertEqual(store.items.first?.tags, ["imported"])
        XCTAssertEqual(store.selectedSecureNoteDetail?.title, "Imported Note")
        XCTAssertEqual(store.selectedSecureNoteDetail?.body, "Imported secure note")
        XCTAssertEqual(store.selectedSecureNoteDetail?.tags, ["imported"])
        XCTAssertNil(store.selectedDetail)
        XCTAssertEqual(store.statusMessage, "Import completed")
    }

    func testImportedCreditCardLoadsCreditCardDetail() {
        let service = FakeCoreService()
        service.importCreditCardOnCommit = true
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/ImportCard.pswvault"),
            displayName: "Import Card",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.previewImport(url: URL(fileURLWithPath: "/tmp/cards.json"))
        store.commitImport(keepDuplicates: false)

        XCTAssertEqual(store.items.first?.itemType, "credit card")
        XCTAssertEqual(store.items.first?.tags, ["imported"])
        XCTAssertEqual(store.selectedCreditCardDetail?.title, "Imported Card")
        XCTAssertEqual(store.selectedCreditCardDetail?.cardholderName, "Alice Imported")
        XCTAssertEqual(store.selectedCreditCardDetail?.expiryMonth, 4)
        XCTAssertEqual(store.selectedCreditCardDetail?.expiryYear, 2030)
        XCTAssertEqual(store.selectedCreditCardDetail?.tags, ["imported"])
        XCTAssertNil(store.selectedDetail)
        XCTAssertNil(store.selectedSecureNoteDetail)
        XCTAssertEqual(store.statusMessage, "Import completed")
    }

    func testManualSyncRefreshUpdatesItemsAndReport() {
        let service = FakeCoreService()
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_001)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/SyncManual.pswvault"),
            displayName: "Sync",
            password: "correct horse",
            confirmation: "correct horse"
        )
        XCTAssertNil(store.lastSyncRefreshAt)
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 3,
            appliedTombstones: 1,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "conflicted", favorite: false, tags: ["sync"])
            ]
        )

        store.refreshFromDisk()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.syncReport?.loadedItems, 3)
        XCTAssertEqual(store.syncReport?.detectedConflicts, 1)
        XCTAssertEqual(store.syncReport?.rejectedItemRecords, 0)
        XCTAssertEqual(store.syncReport?.rejectedTombstoneRecords, 0)
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.items.map(\.title), ["Synced"])
        XCTAssertEqual(store.statusMessage, "Sync refreshed")

        store.lock()
        XCTAssertNil(store.syncReport)
        XCTAssertNil(store.lastSyncRefreshAt)
    }

    func testManualSyncRefreshPreservesSearchFilter() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_002)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SyncSearch.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "mail"
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Mail"])

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 2,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "item_1", title: "Mail", itemType: "login", status: "active", favorite: false, tags: ["personal"]),
                VaultItemView(id: "item_2", title: "Bank", itemType: "login", status: "active", favorite: false, tags: ["finance"])
            ]
        )

        store.refreshFromDisk()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.searchText, "mail")
        XCTAssertEqual(store.items.map(\.title), ["Mail"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
    }

    func testManualSyncRefreshPreservesFavoriteFilter() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_003)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SyncFavorite.pswvault"))
        store.unlock(password: "correct horse")
        store.showFavoritesOnly = true
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Mail"])

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 3,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "item_1", title: "Mail", itemType: "login", status: "active", favorite: true, tags: ["personal"]),
                VaultItemView(id: "item_2", title: "Bank", itemType: "login", status: "active", favorite: false, tags: ["finance"]),
                VaultItemView(id: "item_3", title: "Deploy", itemType: "login", status: "active", favorite: true, tags: ["work"])
            ]
        )

        store.refreshFromDisk()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertTrue(store.showFavoritesOnly)
        XCTAssertEqual(store.items.map(\.title), ["Mail", "Deploy"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
    }

    func testManualSyncRefreshPreservesTagFilter() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_004)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SyncTagFilter.pswvault"))
        store.unlock(password: "correct horse")
        store.selectedTagFilter = "finance"
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Bank"])

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 3,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "item_1", title: "Mail", itemType: "login", status: "active", favorite: false, tags: ["personal"]),
                VaultItemView(id: "item_2", title: "Bank", itemType: "login", status: "active", favorite: false, tags: ["finance"]),
                VaultItemView(id: "item_3", title: "Budget", itemType: "login", status: "active", favorite: false, tags: ["finance", "planning"])
            ]
        )

        store.refreshFromDisk()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.selectedTagFilter, "finance")
        XCTAssertEqual(store.items.map(\.title), ["Bank", "Budget"])
        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertTrue(store.availableTags.contains("finance"))
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
    }

    func testManualSyncRefreshPreservesItemTypeFilter() {
        let service = FakeCoreService()
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_005)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/SyncItemTypeFilter.pswvault"),
            displayName: "Sync",
            password: "correct horse",
            confirmation: "correct horse"
        )
        var card = CreditCardForm()
        card.title = "Travel Card"
        card.cardholderName = "Alice Example"
        card.number = "4111111111111111"
        card.expiryMonth = "04"
        card.expiryYear = "2030"
        card.verificationCode = "123"
        card.tagsText = "finance"
        store.saveCreditCard(form: card)
        store.selectedItemTypeFilter = "credit card"
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Travel Card"])

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 2,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "item_1", title: "Travel Card Updated", itemType: "credit card", status: "active", favorite: false, tags: ["finance"]),
                VaultItemView(id: "item_2", title: "Mail", itemType: "login", status: "active", favorite: false, tags: ["personal"])
            ]
        )

        store.refreshFromDisk()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.selectedItemTypeFilter, "credit card")
        XCTAssertEqual(store.items.map(\.title), ["Travel Card Updated"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.availableItemTypes, ["login", "credit card"])
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
    }

    func testManualSyncRefreshPreservesConflictFilter() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank Conflict",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        service.markConflicted(itemId: "item_2", conflictId: "conflict_bank")
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_006)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SyncConflictFilter.pswvault"))
        store.unlock(password: "correct horse")
        store.showConflictsOnly = true
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Bank Conflict"])

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 3,
            appliedTombstones: 0,
            detectedConflicts: 2,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "item_1", title: "Mail", itemType: "login", status: "active", favorite: false, tags: ["personal"]),
                VaultItemView(id: "item_2", title: "Bank Conflict", itemType: "login", status: "conflicted", conflictId: "conflict_bank", favorite: false, tags: ["finance"]),
                VaultItemView(id: "item_3", title: "Deploy Conflict", itemType: "login", status: "conflicted", conflictId: "conflict_deploy", favorite: false, tags: ["work"])
            ]
        )

        store.refreshFromDisk()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertTrue(store.showConflictsOnly)
        XCTAssertEqual(store.items.map(\.title), ["Bank Conflict", "Deploy Conflict"])
        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
    }

    func testManualSyncRefreshIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SyncDirtyManual.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "external_item", title: "External", itemType: "login", status: "active", favorite: false, tags: [])
            ]
        )

        store.refreshFromDisk()

        XCTAssertEqual(service.refreshCallCount, 0)
        XCTAssertNil(store.syncReport)
        XCTAssertNil(store.lastSyncRefreshAt)
        XCTAssertEqual(store.items.map(\.title), ["Email"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.statusMessage, "Sync refresh paused for unsaved edits")
    }

    func testConfirmedManualSyncRefreshCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_070)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SyncDirtyConfirmed.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "external_item", title: "External", itemType: "login", status: "active", favorite: false, tags: [])
            ]
        )

        store.refreshFromDisk(discardingUnsavedEdits: true)

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.syncReport?.loadedItems, 1)
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.items.map(\.title), ["External"])
        XCTAssertEqual(store.selectedItemId, "external_item")
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
    }

    func testFailedSyncRefreshClearsStaleSyncStatusAndDiagnostics() {
        let service = FakeCoreService()
        var refreshTimes = [
            Date(timeIntervalSince1970: 1_800_000_050)
        ]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTimes.removeFirst() },
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/SyncFailure.pswvault"),
            displayName: "Sync",
            password: "correct horse",
            confirmation: "correct horse"
        )
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 4,
            appliedTombstones: 1,
            detectedConflicts: 1,
            rejectedRecords: 2,
            rejectedItemRecords: 1,
            rejectedTombstoneRecords: 1,
            items: [
                VaultItemView(id: "sync_item", title: "Trusted", itemType: "login", status: "active", favorite: false, tags: [])
            ]
        )
        store.refreshFromDisk()
        XCTAssertEqual(store.syncReport?.loadedItems, 4)
        XCTAssertEqual(store.lastSyncRefreshAt, Date(timeIntervalSince1970: 1_800_000_050))

        service.refreshError = CoreBridgeError.commandFailed("missing required sync directory")
        store.refreshFromDisk()

        XCTAssertNil(store.syncReport)
        XCTAssertNil(store.lastSyncRefreshAt)
        XCTAssertEqual(store.statusMessage, "missing required sync directory")

        let report = store.diagnosticsReport(languageRaw: AppLanguage.english.rawValue)
        XCTAssertTrue(report.contains("Sync report: none"))
        XCTAssertTrue(report.contains("Sync refresh deferred by unsaved edits: no"))
        XCTAssertFalse(report.contains("Sync loaded items: 4"))
        XCTAssertFalse(report.contains("Sync rejected records: 2"))
    }

    func testSyncIssueRecoveryActionsCopyDiagnosticsAndRevealVault() {
        let service = FakeCoreService()
        let importSourceHandler = FakeImportSourceHandler()
        let diagnosticsPasteboard = FakePasteboard()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            diagnosticsPasteboard: diagnosticsPasteboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/SyncIssues.pswvault")

        store.createVault(
            url: vaultURL,
            displayName: "Sync",
            password: "correct horse",
            confirmation: "correct horse"
        )
        XCTAssertFalse(store.hasSyncIssues)
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 2,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 2,
            rejectedItemRecords: 1,
            rejectedTombstoneRecords: 1,
            rejectedRecordFiles: [
                SyncRejectedRecordFile(kind: "item", fileName: "bad_item.enc"),
                SyncRejectedRecordFile(kind: "tombstone", fileName: "bad_tombstone.enc")
            ],
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "conflicted", favorite: false, tags: ["sync"])
            ]
        )

        store.refreshFromDisk()
        XCTAssertTrue(store.hasSyncIssues)

        store.copySyncIssueDiagnostics(languageRaw: AppLanguage.english.rawValue)
        XCTAssertEqual(store.statusMessage, "Diagnostics copied")
        let copiedDiagnostics = diagnosticsPasteboard.string(forType: .string) ?? ""
        XCTAssertTrue(copiedDiagnostics.contains("Sync detected conflicts: 1"))
        XCTAssertTrue(copiedDiagnostics.contains("Sync rejected records: 2"))
        XCTAssertTrue(copiedDiagnostics.contains("Sync rejected item records: 1"))
        XCTAssertTrue(copiedDiagnostics.contains("Sync rejected tombstone records: 1"))
        XCTAssertFalse(copiedDiagnostics.contains(vaultURL.path))
        XCTAssertFalse(copiedDiagnostics.contains("bad_item.enc"))
        XCTAssertFalse(copiedDiagnostics.contains("bad_tombstone.enc"))

        store.revealVaultInFinder()
        XCTAssertEqual(importSourceHandler.revealedURLs, [vaultURL])
        XCTAssertEqual(store.statusMessage, "Vault revealed in Finder")
    }

    func testSyncReadinessDiagnosticsIncludeNonSecretStatusAndOmitFullPath() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot
            .appendingPathComponent("Dropbox", isDirectory: true)
            .appendingPathComponent("Passwords", isDirectory: true)
            .appendingPathComponent("Ready.pswvault", isDirectory: true)
        try createRequiredVaultStructure(at: vaultURL)
        try Data("local".utf8).write(to: vaultURL.appendingPathComponent("local_unlock.enc"))
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)

        let report = store.diagnosticsReport(languageRaw: AppLanguage.english.rawValue)

        XCTAssertTrue(report.contains("Sync readiness: completeLikelySynced"))
        XCTAssertTrue(report.contains("Sync required structure complete: yes"))
        XCTAssertTrue(report.contains("Sync likely provider: Dropbox"))
        XCTAssertTrue(report.contains("Sync local unlock envelope present: yes"))
        XCTAssertTrue(report.contains("Sync missing required paths: none"))
        XCTAssertFalse(report.contains(tempRoot.path))
        XCTAssertFalse(report.contains(vaultURL.path))
    }

    func testSyncReadinessRecoveryActionsCopyDiagnosticsAndRevealVault() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("Broken.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultURL, withIntermediateDirectories: true)
        try Data("metadata".utf8).write(to: vaultURL.appendingPathComponent("vault.json"))
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("items", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let importSourceHandler = FakeImportSourceHandler()
        let diagnosticsPasteboard = FakePasteboard()
        let store = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            diagnosticsPasteboard: diagnosticsPasteboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            importSourceHandler: importSourceHandler,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)
        XCTAssertEqual(store.syncReadiness?.status, .incomplete)

        store.copySyncReadinessDiagnostics(languageRaw: AppLanguage.english.rawValue)

        XCTAssertEqual(store.statusMessage, "Diagnostics copied")
        let copiedDiagnostics = diagnosticsPasteboard.string(forType: .string) ?? ""
        XCTAssertTrue(copiedDiagnostics.contains("Sync readiness: incomplete"))
        XCTAssertTrue(copiedDiagnostics.contains("Sync required structure complete: no"))
        XCTAssertTrue(copiedDiagnostics.contains("Sync missing required paths: keys.enc, attachments/, tombstones/"))
        XCTAssertFalse(copiedDiagnostics.contains(tempRoot.path))
        XCTAssertFalse(copiedDiagnostics.contains(vaultURL.path))

        store.revealVaultInFinder()

        XCTAssertEqual(importSourceHandler.revealedURLs, [vaultURL])
        XCTAssertEqual(store.statusMessage, "Vault revealed in Finder")
    }

    func testQuarantineRejectedSyncRecordsRefreshesSyncStatus() {
        let service = FakeCoreService()
        var refreshTimes = [
            Date(timeIntervalSince1970: 1_800_000_010),
            Date(timeIntervalSince1970: 1_800_000_020),
            Date(timeIntervalSince1970: 1_800_000_030)
        ]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTimes.removeFirst() },
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/SyncQuarantine.pswvault"),
            displayName: "Sync",
            password: "correct horse",
            confirmation: "correct horse"
        )
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 2,
            rejectedItemRecords: 1,
            rejectedTombstoneRecords: 1,
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "active", favorite: false, tags: ["sync"])
            ]
        )
        store.refreshFromDisk()
        XCTAssertTrue(store.canQuarantineRejectedRecords)
        XCTAssertEqual(store.lastSyncRefreshAt, Date(timeIntervalSince1970: 1_800_000_010))
        XCTAssertNil(store.lastSyncQuarantine)

        service.nextQuarantinePayload = SyncQuarantinePayload(
            movedRecords: 2,
            movedItemRecords: 1,
            movedTombstoneRecords: 1
        )
        service.nextRefreshPayloadAfterQuarantine = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            rejectedItemRecords: 0,
            rejectedTombstoneRecords: 0,
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "active", favorite: false, tags: ["sync"])
            ]
        )

        store.quarantineRejectedRecords()

        XCTAssertEqual(service.quarantineRejectedCallCount, 1)
        XCTAssertEqual(service.refreshCallCount, 2)
        XCTAssertEqual(store.syncReport?.rejectedRecords, 0)
        XCTAssertEqual(store.lastSyncRefreshAt, Date(timeIntervalSince1970: 1_800_000_020))
        XCTAssertEqual(store.lastSyncQuarantine, SyncQuarantinePayload(
            movedRecords: 2,
            movedItemRecords: 1,
            movedTombstoneRecords: 1
        ))
        XCTAssertFalse(store.canQuarantineRejectedRecords)
        XCTAssertEqual(store.statusMessage, "Quarantined 2 rejected records")
        XCTAssertEqual(store.items.map(\.title), ["Synced"])

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            rejectedItemRecords: 0,
            rejectedTombstoneRecords: 0,
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "active", favorite: false, tags: ["sync"])
            ]
        )
        store.refreshFromDisk()

        XCTAssertEqual(store.lastSyncRefreshAt, Date(timeIntervalSince1970: 1_800_000_030))
        XCTAssertNil(store.lastSyncQuarantine)
    }

    func testQuarantineRejectedRecordsIsRejectedWhileEditorHasUnsavedChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { Date(timeIntervalSince1970: 1_800_000_030) },
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/DirtyQuarantine.pswvault"),
            displayName: "Sync",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.select(itemId: "item_1")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 2,
            rejectedItemRecords: 1,
            rejectedTombstoneRecords: 1,
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "active", favorite: false, tags: ["sync"])
            ]
        )
        store.refreshFromDisk()
        store.select(itemId: "sync_item")
        store.setEditorHasUnsavedChanges(true)

        let quarantined = store.quarantineRejectedRecords()

        XCTAssertFalse(quarantined)
        XCTAssertEqual(service.quarantineRejectedCallCount, 0)
        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.syncReport?.rejectedRecords, 2)
        XCTAssertNil(store.lastSyncQuarantine)
        XCTAssertEqual(store.items.map(\.title), ["Synced"])
        XCTAssertEqual(store.selectedItemId, "sync_item")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before sync recovery")
        XCTAssertFalse(store.canExport)
    }

    func testConfirmedQuarantineRejectedRecordsCanDiscardUnsavedEditorChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        var refreshTimes = [
            Date(timeIntervalSince1970: 1_800_000_040),
            Date(timeIntervalSince1970: 1_800_000_050)
        ]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTimes.removeFirst() },
            userDefaults: makeIsolatedDefaults()
        )

        store.createVault(
            url: URL(fileURLWithPath: "/tmp/DirtyQuarantineConfirmed.pswvault"),
            displayName: "Sync",
            password: "correct horse",
            confirmation: "correct horse"
        )
        store.select(itemId: "item_1")
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 2,
            rejectedItemRecords: 1,
            rejectedTombstoneRecords: 1,
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "active", favorite: false, tags: ["sync"])
            ]
        )
        store.refreshFromDisk()
        store.select(itemId: "sync_item")
        store.setEditorHasUnsavedChanges(true)
        service.nextQuarantinePayload = SyncQuarantinePayload(
            movedRecords: 2,
            movedItemRecords: 1,
            movedTombstoneRecords: 1
        )
        service.nextRefreshPayloadAfterQuarantine = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            rejectedItemRecords: 0,
            rejectedTombstoneRecords: 0,
            items: [
                VaultItemView(id: "sync_item", title: "Synced", itemType: "login", status: "active", favorite: false, tags: ["sync"])
            ]
        )

        let quarantined = store.quarantineRejectedRecords(discardingUnsavedEdits: true)

        XCTAssertTrue(quarantined)
        XCTAssertEqual(service.quarantineRejectedCallCount, 1)
        XCTAssertEqual(service.refreshCallCount, 2)
        XCTAssertEqual(store.syncReport?.rejectedRecords, 0)
        XCTAssertEqual(store.lastSyncRefreshAt, Date(timeIntervalSince1970: 1_800_000_050))
        XCTAssertEqual(store.lastSyncQuarantine, SyncQuarantinePayload(
            movedRecords: 2,
            movedItemRecords: 1,
            movedTombstoneRecords: 1
        ))
        XCTAssertEqual(store.items.map(\.title), ["Synced"])
        XCTAssertEqual(store.selectedItemId, "sync_item")
        XCTAssertEqual(store.statusMessage, "Quarantined 2 rejected records")
        XCTAssertTrue(store.canExport)

        store.lock()

        XCTAssertNil(store.lastSyncQuarantine)
    }

    func testVaultDirectoryChangeTriggersSyncRefreshWhenUnlocked() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("Watched.pswvault", isDirectory: true)
        try createRequiredVaultStructure(at: vaultURL)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService()
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_030)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.checkForVaultFileChanges()
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "external_item", title: "External", itemType: "login", status: "active", favorite: false, tags: [])
            ]
        )

        let itemURL = vaultURL
            .appendingPathComponent("items", isDirectory: true)
            .appendingPathComponent("item_external.enc")
        try Data("changed".utf8).write(to: itemURL)
        store.checkForVaultFileChanges()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.items.map(\.title), ["External"])
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)

        store.lock()
        try Data("changed again".utf8).write(to: itemURL)
        store.checkForVaultFileChanges()
        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertNil(store.lastSyncRefreshAt)
    }

    func testVaultStructureRemovalTriggersAutomaticRefreshFailureForEmptyVault() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("WatchedStructureMissing.pswvault", isDirectory: true)
        try createRequiredVaultStructure(at: vaultURL)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.checkForVaultFileChanges()

        service.refreshError = CoreBridgeError.commandFailed("missing required path keys.enc")
        try FileManager.default.removeItem(at: vaultURL.appendingPathComponent("keys.enc"))
        store.checkForVaultFileChanges()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertNil(store.syncReport)
        XCTAssertNil(store.lastSyncRefreshAt)
        XCTAssertEqual(store.statusMessage, "missing required path keys.enc")
    }

    func testVaultMetadataReplacementTriggersAutomaticRefreshForEmptyVault() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("WatchedMetadata.pswvault", isDirectory: true)
        try createRequiredVaultStructure(at: vaultURL)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService()
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_060)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.checkForVaultFileChanges()
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 0,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: []
        )

        try Data("{\"format_name\":\"psw-vault\",\"display_name\":\"Renamed\"}".utf8)
            .write(to: vaultURL.appendingPathComponent("vault.json"))
        store.checkForVaultFileChanges()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.syncReport?.loadedItems, 0)
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
    }

    func testAutomaticSyncRefreshDefersWhileEditorHasUnsavedChanges() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("WatchedDirty.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("items", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("tombstones", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Local Draft",
                username: "me@example.com",
                password: "local-password",
                url: "https://mail.example.com",
                notes: "local",
                tags: []
            )
        ])
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_050)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.checkForVaultFileChanges()
        store.setEditorHasUnsavedChanges(true)
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "external_item", title: "External", itemType: "login", status: "active", favorite: false, tags: [])
            ]
        )

        let itemURL = vaultURL
            .appendingPathComponent("items", isDirectory: true)
            .appendingPathComponent("item_external.enc")
        try Data("changed".utf8).write(to: itemURL)
        store.checkForVaultFileChanges()

        XCTAssertEqual(service.refreshCallCount, 0)
        XCTAssertEqual(store.items.map(\.title), ["Local Draft"])
        XCTAssertTrue(store.syncRefreshDeferredByUnsavedEdits)
        XCTAssertNil(store.lastSyncRefreshAt)
        XCTAssertEqual(store.statusMessage, "Sync refresh paused for unsaved edits")

        let pausedReport = store.diagnosticsReport(languageRaw: AppLanguage.english.rawValue)
        XCTAssertTrue(pausedReport.contains("Sync refresh deferred by unsaved edits: yes"))
        XCTAssertFalse(pausedReport.contains(tempRoot.path))
        XCTAssertFalse(pausedReport.contains(vaultURL.path))

        store.setEditorHasUnsavedChanges(false)

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertFalse(store.syncRefreshDeferredByUnsavedEdits)
        XCTAssertEqual(store.items.map(\.title), ["External"])
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.statusMessage, "Sync refreshed")
        XCTAssertTrue(
            store.diagnosticsReport(languageRaw: AppLanguage.english.rawValue)
                .contains("Sync refresh deferred by unsaved edits: no")
        )
    }

    func testManualSyncRefreshClearsDeferredAutomaticRefresh() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("WatchedManualResume.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("items", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("tombstones", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Local Draft",
                username: "me@example.com",
                password: "local-password",
                url: "https://mail.example.com",
                notes: "local",
                tags: []
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.checkForVaultFileChanges()
        store.setEditorHasUnsavedChanges(true)
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "external_item", title: "External", itemType: "login", status: "active", favorite: false, tags: [])
            ]
        )

        let itemURL = vaultURL
            .appendingPathComponent("items", isDirectory: true)
            .appendingPathComponent("item_external.enc")
        try Data("changed".utf8).write(to: itemURL)
        store.checkForVaultFileChanges()
        XCTAssertTrue(store.syncRefreshDeferredByUnsavedEdits)

        store.refreshFromDisk()
        store.setEditorHasUnsavedChanges(false)

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertFalse(store.syncRefreshDeferredByUnsavedEdits)
        XCTAssertEqual(store.items.map(\.title), ["External"])
    }

    func testAutomaticSyncRefreshPreservesArchivedFilter() throws {
        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PSWMacWorkflowTests-\(UUID().uuidString)", isDirectory: true)
        let vaultURL = tempRoot.appendingPathComponent("WatchedArchived.pswvault", isDirectory: true)
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("items", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: vaultURL.appendingPathComponent("tombstones", isDirectory: true),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_040)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.archiveSelected()
        store.includeArchived = true
        store.search()
        XCTAssertEqual(store.items.map(\.status), ["archived"])
        store.checkForVaultFileChanges()

        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(id: "item_1", title: "Mail", itemType: "login", status: "archived", favorite: false, tags: ["personal"])
            ]
        )

        let itemURL = vaultURL
            .appendingPathComponent("items", isDirectory: true)
            .appendingPathComponent("item_archived.enc")
        try Data("changed".utf8).write(to: itemURL)
        store.checkForVaultFileChanges()

        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertTrue(store.includeArchived)
        XCTAssertEqual(store.items.map(\.title), ["Mail"])
        XCTAssertEqual(store.items.map(\.status), ["archived"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
    }

    private func assertLockedAndCleared(
        _ store: VaultStore,
        service: FakeCoreService,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertFalse(store.isUnlocked, file: file, line: line)
        XCTAssertNil(store.sessionId, file: file, line: line)
        XCTAssertEqual(service.lockedSessionIds, [7], file: file, line: line)
        XCTAssertTrue(store.items.isEmpty, file: file, line: line)
        XCTAssertNil(store.selectedItemId, file: file, line: line)
        XCTAssertNil(store.selectedDetail, file: file, line: line)
        XCTAssertNil(store.selectedSecureNoteDetail, file: file, line: line)
        XCTAssertNil(store.selectedCreditCardDetail, file: file, line: line)
        XCTAssertNil(store.selectedSoftwareLicenseDetail, file: file, line: line)
        XCTAssertTrue(store.conflictCandidates.isEmpty, file: file, line: line)
        XCTAssertEqual(store.searchText, "", file: file, line: line)
        XCTAssertFalse(store.showFavoritesOnly, file: file, line: line)
        XCTAssertFalse(store.showConflictsOnly, file: file, line: line)
        XCTAssertNil(store.selectedItemTypeFilter, file: file, line: line)
        XCTAssertTrue(store.availableItemTypes.isEmpty, file: file, line: line)
        XCTAssertNil(store.selectedTagFilter, file: file, line: line)
        XCTAssertTrue(store.availableTags.isEmpty, file: file, line: line)
        XCTAssertNil(store.importSourceURL, file: file, line: line)
        XCTAssertNil(store.importPreview, file: file, line: line)
        XCTAssertFalse(store.importCompleted, file: file, line: line)
        XCTAssertNil(store.exportResult, file: file, line: line)
        XCTAssertNil(store.plaintextExportURL, file: file, line: line)
        XCTAssertNil(store.backupResult, file: file, line: line)
        XCTAssertNil(store.backupDestinationURL, file: file, line: line)
        XCTAssertNil(store.restoreBackupResult, file: file, line: line)
        XCTAssertNil(store.restoredBackupURL, file: file, line: line)
        XCTAssertNil(store.copyVaultToSyncResult, file: file, line: line)
        XCTAssertNil(store.copiedSyncVaultURL, file: file, line: line)
        XCTAssertNil(store.passwordHealth, file: file, line: line)
        XCTAssertNil(store.syncReport, file: file, line: line)
        XCTAssertNil(store.lastSyncRefreshAt, file: file, line: line)
        XCTAssertEqual(store.statusMessage, "Vault locked", file: file, line: line)
    }

    private func markVaultSwitchStateDirty(_ store: VaultStore, clipboard: FakeClipboard) {
        store.searchText = "old vault query"
        store.showFavoritesOnly = true
        store.showConflictsOnly = true
        store.importSourceURL = URL(fileURLWithPath: "/tmp/old-import.json")
        store.importPreview = ImportPreviewPayload(
            importableRecords: 1,
            skippedRecords: 0,
            duplicateRecords: 0,
            warnings: []
        )
        store.importCompleted = true
        store.exportResult = ExportResultPayload(exportedRecords: 1, skippedRecords: 0, warnings: [])
        store.plaintextExportURL = URL(fileURLWithPath: "/tmp/old-export.json")
        store.backupResult = BackupResultPayload(copiedItemFiles: 1, copiedAttachmentFiles: 0, copiedTombstoneFiles: 0)
        store.backupDestinationURL = URL(fileURLWithPath: "/tmp/old-backup.pswvault")
        store.restoreBackupResult = RestoreBackupResultPayload(copiedItemFiles: 1, copiedAttachmentFiles: 0, copiedTombstoneFiles: 0)
        store.restoredBackupURL = URL(fileURLWithPath: "/tmp/old-restored.pswvault")
        store.copyVaultToSyncResult = RestoreBackupResultPayload(copiedItemFiles: 1, copiedAttachmentFiles: 0, copiedTombstoneFiles: 0)
        store.copiedSyncVaultURL = URL(fileURLWithPath: "/tmp/old-synced.pswvault")
        store.syncReport = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: store.items
        )
        store.lastSyncRefreshAt = Date(timeIntervalSince1970: 1_800_000_060)
        store.passwordHealth = PasswordHealthPayload(
            checkedLoginPasswords: 1,
            weakPasswords: 1,
            reusedPasswords: 0,
            issues: [
                PasswordHealthIssue(
                    itemId: "item_1",
                    title: "Old Vault",
                    kind: .weakPassword
                )
            ]
        )
        clipboard.copy("old-vault-secret", clearAfter: 60)
    }

    private func assertVaultSwitchStateCleared(
        _ store: VaultStore,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertTrue(store.items.isEmpty, file: file, line: line)
        XCTAssertNil(store.selectedItemId, file: file, line: line)
        XCTAssertNil(store.selectedDetail, file: file, line: line)
        XCTAssertNil(store.selectedSecureNoteDetail, file: file, line: line)
        XCTAssertNil(store.selectedCreditCardDetail, file: file, line: line)
        XCTAssertNil(store.selectedSoftwareLicenseDetail, file: file, line: line)
        XCTAssertTrue(store.conflictCandidates.isEmpty, file: file, line: line)
        XCTAssertEqual(store.searchText, "", file: file, line: line)
        XCTAssertFalse(store.showFavoritesOnly, file: file, line: line)
        XCTAssertFalse(store.showConflictsOnly, file: file, line: line)
        XCTAssertNil(store.importSourceURL, file: file, line: line)
        XCTAssertNil(store.importPreview, file: file, line: line)
        XCTAssertFalse(store.importCompleted, file: file, line: line)
        XCTAssertNil(store.exportResult, file: file, line: line)
        XCTAssertNil(store.plaintextExportURL, file: file, line: line)
        XCTAssertNil(store.backupResult, file: file, line: line)
        XCTAssertNil(store.backupDestinationURL, file: file, line: line)
        XCTAssertNil(store.restoreBackupResult, file: file, line: line)
        XCTAssertNil(store.restoredBackupURL, file: file, line: line)
        XCTAssertNil(store.copyVaultToSyncResult, file: file, line: line)
        XCTAssertNil(store.copiedSyncVaultURL, file: file, line: line)
        XCTAssertNil(store.passwordHealth, file: file, line: line)
        XCTAssertNil(store.syncReport, file: file, line: line)
        XCTAssertNil(store.lastSyncRefreshAt, file: file, line: line)
    }

    func testIdleAutoLockClearsUnlockedState() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/AutoLock.pswvault")

        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.searchText = "mail"
        store.conflictCandidates = [
            ConflictCandidateView(
                itemId: "item_1",
                revision: "rev_conflict",
                title: "Email",
                itemType: "login",
                status: "active",
                favorite: false,
                tags: ["personal"],
                comparisonFields: [],
                changedFields: ["username"],
                preview: "username: me@example.com"
            )
        ]
        store.importSourceURL = URL(fileURLWithPath: "/tmp/import.json")
        store.importPreview = ImportPreviewPayload(importableRecords: 1, skippedRecords: 0, duplicateRecords: 0, warnings: [])
        store.importCompleted = true
        store.exportResult = ExportResultPayload(exportedRecords: 1, skippedRecords: 0, warnings: [])
        store.syncReport = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: store.items
        )
        XCTAssertTrue(store.isUnlocked)
        XCTAssertNotNil(store.selectedDetail)

        store.autoLockSeconds = VaultStore.supportedAutoLockDurations[0]
        store.lockIfIdle(now: Date().addingTimeInterval(VaultStore.supportedAutoLockDurations[0] + 1))

        assertLockedAndCleared(store, service: service)
    }

    func testSystemSleepNotificationLocksAndClearsUnlockedState() {
        assertWorkspaceNotificationLocksAndClears(
            NSWorkspace.willSleepNotification,
            description: "system sleep locks vault"
        )
    }

    func testScreenSleepNotificationLocksAndClearsUnlockedState() {
        assertWorkspaceNotificationLocksAndClears(
            NSWorkspace.screensDidSleepNotification,
            description: "screen sleep locks vault"
        )
    }

    func testSessionResignActiveNotificationLocksAndClearsUnlockedState() {
        assertWorkspaceNotificationLocksAndClears(
            NSWorkspace.sessionDidResignActiveNotification,
            description: "session resign active locks vault"
        )
    }

    func testAppTerminationLocksAndClearsManagedClipboardSecret() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let pasteboard = FakePasteboard()
        let store = VaultStore(
            service: service,
            clipboard: ClipboardManager(pasteboard: pasteboard),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/Termination.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "mail"
        store.syncReport = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: store.items
        )
        store.copyPassword()
        XCTAssertEqual(pasteboard.string(forType: .string), "email-password")

        let appDelegate = AppDelegate()
        appDelegate.installTerminationHandler {
            store.lock()
        }
        appDelegate.applicationWillTerminate(Notification(name: NSApplication.willTerminateNotification))

        assertLockedAndCleared(store, service: service)
        XCTAssertNil(pasteboard.string(forType: .string))
    }

    func testAppTerminationPreservesLaterClipboardContents() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let pasteboard = FakePasteboard()
        let store = VaultStore(
            service: service,
            clipboard: ClipboardManager(pasteboard: pasteboard),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/TerminationClipboard.pswvault"))
        store.unlock(password: "correct horse")
        store.copyPassword()
        pasteboard.clearContents()
        pasteboard.setString("user-copied-later", forType: .string)

        let appDelegate = AppDelegate()
        appDelegate.installTerminationHandler {
            store.lock()
        }
        appDelegate.applicationWillTerminate(Notification(name: NSApplication.willTerminateNotification))

        assertLockedAndCleared(store, service: service)
        XCTAssertEqual(pasteboard.string(forType: .string), "user-copied-later")
        pasteboard.clearContents()
    }

    func testLastWindowCloseLocksAndPreservesSelectedVaultContext() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let pasteboard = FakePasteboard()
        let store = VaultStore(
            service: service,
            clipboard: ClipboardManager(pasteboard: pasteboard),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/LastWindow.pswvault")
        store.openVault(url: vaultURL)
        store.unlock(password: "correct horse")
        store.searchText = "mail"
        store.syncReport = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: store.items
        )
        store.copyPassword()
        XCTAssertEqual(pasteboard.string(forType: .string), "email-password")

        let appDelegate = AppDelegate()
        appDelegate.installLastWindowCloseHandler {
            store.lock()
        }
        let shouldTerminate = appDelegate.applicationShouldTerminateAfterLastWindowClosed(NSApplication.shared)

        XCTAssertFalse(shouldTerminate)
        assertLockedAndCleared(store, service: service)
        XCTAssertEqual(store.vaultURL, vaultURL)
        XCTAssertEqual(store.recentVaultURL, vaultURL)
        XCTAssertNil(pasteboard.string(forType: .string))
    }

    func testLastWindowClosePreservesLaterClipboardContents() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let pasteboard = FakePasteboard()
        let store = VaultStore(
            service: service,
            clipboard: ClipboardManager(pasteboard: pasteboard),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/LastWindowClipboard.pswvault"))
        store.unlock(password: "correct horse")
        store.copyPassword()
        pasteboard.clearContents()
        pasteboard.setString("user-copied-later", forType: .string)

        let appDelegate = AppDelegate()
        appDelegate.installLastWindowCloseHandler {
            store.lock()
        }
        let shouldTerminate = appDelegate.applicationShouldTerminateAfterLastWindowClosed(NSApplication.shared)

        XCTAssertFalse(shouldTerminate)
        assertLockedAndCleared(store, service: service)
        XCTAssertEqual(pasteboard.string(forType: .string), "user-copied-later")
        pasteboard.clearContents()
    }

    private func assertWorkspaceNotificationLocksAndClears(
        _ notificationName: Notification.Name,
        description: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SystemLock.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "mail"
        store.syncReport = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: store.items
        )
        XCTAssertTrue(store.isUnlocked)

        NSWorkspace.shared.notificationCenter.post(
            name: notificationName,
            object: NSWorkspace.shared
        )

        let locked = expectation(description: description)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            self.assertLockedAndCleared(store, service: service, file: file, line: line)
            locked.fulfill()
        }
        wait(for: [locked], timeout: 1.0)
    }

    func testVaultPathConflictKeepsHumanVaultUnlockedAndFailsAppsToolsClosed() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "",
                tags: []
            )
        ])
        service.appsToolsVaultPathConflict = true
        service.nextAuthorizedCredentialIds = ["item_1"]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let selectedPath = "/tmp/private-copy-marker/Personal.pswvault"

        store.openVault(url: URL(fileURLWithPath: selectedPath))
        store.unlock(password: "correct horse")

        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.items.map(\.title), ["Email"])
        XCTAssertTrue(store.appsToolsVaultPathConflict)
        XCTAssertFalse(store.appsToolsAuthorizationInventoryAvailable)
        XCTAssertTrue(store.authorizedCredentialIds.isEmpty)
        XCTAssertEqual(store.appsToolsSnapshot, .empty)
        XCTAssertEqual(service.authorizedCredentialIdsCallCount, 0)
        XCTAssertEqual(store.statusMessage, VaultStore.appsToolsVaultPathConflictStatus)
        XCTAssertFalse(store.statusMessage.contains(selectedPath))

        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertEqual(service.authorizedCredentialIdsCallCount, 0)
        XCTAssertEqual(store.statusMessage, VaultStore.appsToolsVaultPathConflictStatus)

        store.lock()
        XCTAssertFalse(store.isUnlocked)
        XCTAssertFalse(store.appsToolsVaultPathConflict)
        XCTAssertTrue(store.appsToolsAuthorizationInventoryAvailable)
    }

    func testCreateUnlockSearchCopyAndManualLockWorkflow() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let convenienceUnlockStore = FakeConvenienceUnlockStore()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: convenienceUnlockStore,
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/Personal.pswvault")

        store.createVault(
            url: vaultURL,
            displayName: "Personal",
            password: "correct horse",
            confirmation: "correct horse",
            rememberForConvenience: true
        )

        XCTAssertEqual(service.createdPath, vaultURL.path)
        XCTAssertEqual(store.sessionId, 7)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertTrue(store.convenienceUnlockAvailable)
        XCTAssertEqual(convenienceUnlockStore.material(for: vaultURL), "local-material-7")
        XCTAssertNotEqual(convenienceUnlockStore.material(for: vaultURL), "correct horse")
        XCTAssertEqual(service.localUnlockMaterialRequests, [7])

        var form = LoginForm()
        form.title = "Example"
        form.username = "alice"
        form.password = "secret"
        form.url = "https://example.com"
        form.tagsText = "work, primary, work"
        store.saveLogin(form: form)

        XCTAssertEqual(store.items.count, 1)
        XCTAssertEqual(store.selectedDetail?.tags, ["work", "primary"])
        XCTAssertFalse(store.canCopySecureNoteBody)

        store.searchText = "alice"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Example"])

        store.copyUsername()
        store.copyPassword()

        XCTAssertEqual(clipboard.copied.map(\.value), ["alice", "secret"])
        XCTAssertEqual(clipboard.copied.map(\.timeout), [45, 45])
        XCTAssertEqual(clipboard.currentValue, "secret")

        store.lock()

        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertNil(clipboard.currentValue)
        XCTAssertEqual(clipboard.clearManagedSecretCallCount, 1)

        store.unlockWithConvenience()
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.sessionId, 9)
        XCTAssertEqual(service.localMaterialUnlockPath, vaultURL.path)
        XCTAssertEqual(service.localMaterialUsed, "local-material-7")
        XCTAssertEqual(store.statusMessage, "Vault unlocked with Keychain")

        store.disableConvenienceUnlock()
        XCTAssertFalse(store.convenienceUnlockAvailable)
    }

    func testTemplateCredentialCreateSearchRevealAndCopyWorkflow() throws {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/Developer.pswvault"))
        store.unlock(password: "correct horse")

        let secretMarker = "kn-test-api-token-never-index"
        var form = TemplateCredentialForm(template: .apiToken)
        form.title = "Build API"
        form.secret = secretMarker
        form.notes = "Integration environment"
        form.tagsText = "automation, local"

        XCTAssertEqual(store.saveTemplateCredential(form: form), .saved)
        XCTAssertEqual(service.createCredentialCallCount, 1)
        XCTAssertEqual(store.selectedItem?.credentialTemplateKind, .apiToken)
        XCTAssertEqual(store.selectedItem?.secretKinds, ["api-token"])
        let detail = try XCTUnwrap(store.selectedCredentialDetail)
        XCTAssertEqual(detail.textFields.map(\.text), ["Integration environment"])
        XCTAssertFalse(String(reflecting: detail).contains(secretMarker))

        let secretFieldId = try XCTUnwrap(detail.secretFields.first?.secretFieldId)
        XCTAssertEqual(
            store.revealSelectedCredentialSecret(secretFieldId: secretFieldId),
            secretMarker
        )
        XCTAssertNil(
            store.revealSelectedCredentialSecret(secretFieldId: "field_not_authorized")
        )
        store.copyCredentialSecret(secretFieldId: secretFieldId)
        XCTAssertEqual(clipboard.currentValue, secretMarker)
        XCTAssertEqual(
            service.credentialSecretFieldRequests,
            [secretFieldId, secretFieldId]
        )

        store.searchText = "Integration environment"
        XCTAssertTrue(store.search())
        XCTAssertEqual(store.items.map(\.title), ["Build API"])

        store.searchText = secretMarker
        XCTAssertTrue(store.search())
        XCTAssertTrue(store.items.isEmpty)
    }

    func testCredentialEditorFormKeepsSavedSecretsOutOfTheDraft() throws {
        let detail = CredentialDetail(
            id: "credential_stable",
            revision: "revision_stable",
            title: "Build API",
            templateId: CredentialTemplateKind.apiToken.rawValue,
            fields: [
                .text(.init(role: "account", label: "Account", text: "chasechou007")),
                .secret(.init(
                    role: "token",
                    label: "Build token",
                    secretFieldId: "secret_field_stable",
                    secretKind: CredentialSecretKind.apiToken.rawValue,
                    hasValue: true
                ))
            ],
            favorite: true,
            tags: ["automation"],
            status: "active"
        )

        var form = CredentialEditorForm(detail: detail)

        XCTAssertEqual(form.revision, detail.revision)
        XCTAssertEqual(form.fields.map(\.role), ["account", "token"])
        XCTAssertEqual(form.fields[1].secretFieldId, "secret_field_stable")
        XCTAssertEqual(form.fields[1].secretInput, "")
        XCTAssertTrue(form.fields[1].hasSavedSecret)
        XCTAssertTrue(form.isValidForSave)

        form.addSecretField()
        XCTAssertFalse(form.isValidForSave)
        form.fields[2].secretInput = "new-secret-marker"
        XCTAssertTrue(form.isValidForSave)
        let originalSecretRowId = form.fields[1].id
        form.moveField(id: originalSecretRowId, offset: -1)
        XCTAssertEqual(form.fields[0].secretFieldId, "secret_field_stable")
        form.fields[0].label = "Renamed token"
        XCTAssertEqual(form.fields[0].secretFieldId, "secret_field_stable")
    }

    func testFieldAwareCredentialEditPreservesReplacesAddsAndRemovesSecrets() throws {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/FieldAware.pswvault"))
        store.unlock(password: "correct horse")

        var creation = TemplateCredentialForm(template: .apiToken)
        creation.title = "Build API"
        creation.secret = "saved-secret-marker"
        creation.notes = "Initial notes"
        XCTAssertEqual(store.saveTemplateCredential(form: creation), .saved)
        let originalDetail = try XCTUnwrap(store.selectedCredentialDetail)
        let originalSecretFieldId = try XCTUnwrap(
            originalDetail.secretFields.first?.secretFieldId
        )

        var edit = CredentialEditorForm(detail: originalDetail)
        edit.title = "Build API Renamed"
        edit.fields[0].role = "access-token"
        edit.fields[0].label = "Build token"
        XCTAssertEqual(edit.fields[0].secretInput, "")
        edit.addTextField()
        edit.fields[edit.fields.count - 1].role = "account"
        edit.fields[edit.fields.count - 1].text = "chasechou007"
        edit.addSecretField()
        edit.fields[edit.fields.count - 1].role = "fallback"
        edit.fields[edit.fields.count - 1].label = "Fallback"
        edit.fields[edit.fields.count - 1].secretKind =
            CredentialSecretKind.genericSecret.rawValue
        edit.fields[edit.fields.count - 1].secretInput = "new-secret-marker"
        edit.tagsText = "automation, local"
        edit.favorite = true

        XCTAssertEqual(store.saveCredential(form: edit), .saved)
        XCTAssertEqual(service.updateCredentialCallCount, 1)
        XCTAssertEqual(
            service.lastCredentialUpdateForm?.fields.first?.secretInput,
            ""
        )
        let updatedDetail = try XCTUnwrap(store.selectedCredentialDetail)
        XCTAssertEqual(updatedDetail.title, "Build API Renamed")
        XCTAssertEqual(updatedDetail.fields.map {
            switch $0 {
            case let .text(field): return field.role
            case let .secret(field): return field.role
            }
        }, ["access-token", "notes", "account", "fallback"])
        XCTAssertEqual(
            updatedDetail.secretFields.first?.secretFieldId,
            originalSecretFieldId
        )
        let addedSecretFieldId = try XCTUnwrap(
            updatedDetail.secretFields.last?.secretFieldId
        )
        XCTAssertNotEqual(addedSecretFieldId, originalSecretFieldId)
        XCTAssertEqual(
            store.revealSelectedCredentialSecret(secretFieldId: originalSecretFieldId),
            "saved-secret-marker"
        )
        XCTAssertEqual(
            store.revealSelectedCredentialSecret(secretFieldId: addedSecretFieldId),
            "new-secret-marker"
        )

        var deletion = CredentialEditorForm(detail: updatedDetail)
        let addedRowId = try XCTUnwrap(
            deletion.fields.first(where: { $0.secretFieldId == addedSecretFieldId })?.id
        )
        deletion.removeField(id: addedRowId)
        XCTAssertEqual(store.saveCredential(form: deletion), .saved)
        XCTAssertEqual(store.selectedCredentialDetail?.secretFields.count, 1)
        XCTAssertEqual(
            store.selectedCredentialDetail?.secretFields.first?.secretFieldId,
            originalSecretFieldId
        )

        var replacement = CredentialEditorForm(
            detail: try XCTUnwrap(store.selectedCredentialDetail)
        )
        replacement.fields[0].secretInput = "replacement-secret-marker"
        XCTAssertEqual(store.saveCredential(form: replacement), .saved)
        XCTAssertEqual(
            store.selectedCredentialDetail?.secretFields.first?.secretFieldId,
            originalSecretFieldId
        )
        XCTAssertEqual(
            store.revealSelectedCredentialSecret(secretFieldId: originalSecretFieldId),
            "replacement-secret-marker"
        )
    }

    func testTemplateCredentialLifecycleUsesStableFieldsAndSafeRustSideDuplication() throws {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/CredentialLifecycle.pswvault"))
        store.unlock(password: "correct horse")

        var creation = TemplateCredentialForm(template: .apiToken)
        creation.title = "Build API"
        creation.secret = "lifecycle-secret-marker"
        XCTAssertEqual(store.saveTemplateCredential(form: creation), .saved)
        let originalItemId = try XCTUnwrap(store.selectedItemId)
        let originalSecretFieldId = try XCTUnwrap(
            store.selectedCredentialDetail?.secretFields.first?.secretFieldId
        )

        XCTAssertTrue(store.toggleFavoriteSelected())
        XCTAssertEqual(service.setFavoriteCallCount, 1)
        XCTAssertEqual(store.selectedItemId, originalItemId)
        XCTAssertEqual(
            store.selectedCredentialDetail?.secretFields.first?.secretFieldId,
            originalSecretFieldId
        )
        XCTAssertEqual(store.selectedCredentialDetail?.favorite, true)

        XCTAssertTrue(store.canDuplicateSelectedItem)
        XCTAssertTrue(store.duplicateSelectedItem())
        XCTAssertEqual(service.duplicateCredentialCallCount, 1)
        let duplicateItemId = try XCTUnwrap(store.selectedItemId)
        XCTAssertNotEqual(duplicateItemId, originalItemId)
        XCTAssertEqual(store.selectedItem?.title, "Build API Copy")
        let duplicateSecretFieldId = try XCTUnwrap(
            store.selectedCredentialDetail?.secretFields.first?.secretFieldId
        )
        XCTAssertNotEqual(duplicateSecretFieldId, originalSecretFieldId)
        XCTAssertEqual(
            store.revealSelectedCredentialSecret(secretFieldId: duplicateSecretFieldId),
            "lifecycle-secret-marker"
        )

        XCTAssertTrue(store.archiveSelected())
        XCTAssertEqual(service.archiveItemCallCount, 1)
        XCTAssertFalse(store.items.contains(where: { $0.id == duplicateItemId }))
        store.includeArchived = true
        store.searchText = ""
        XCTAssertTrue(store.search())
        XCTAssertTrue(store.select(itemId: duplicateItemId))
        XCTAssertTrue(store.canRestoreSelectedArchive)
        XCTAssertEqual(
            store.selectedCredentialDetail?.secretFields.first?.secretFieldId,
            duplicateSecretFieldId
        )

        XCTAssertTrue(store.restoreSelectedArchive())
        XCTAssertEqual(service.restoreItemCallCount, 1)
        XCTAssertEqual(store.selectedItemId, duplicateItemId)
        XCTAssertEqual(store.selectedItem?.status, "active")
        XCTAssertEqual(
            store.selectedCredentialDetail?.secretFields.first?.secretFieldId,
            duplicateSecretFieldId
        )

        XCTAssertTrue(store.deleteSelected())
        XCTAssertEqual(service.deleteItemCallCount, 1)
        XCTAssertFalse(store.items.contains(where: { $0.id == duplicateItemId }))
        XCTAssertTrue(store.items.contains(where: { $0.id == originalItemId }))
    }

    func testStaleCredentialSavePreservesDraftWithoutExposingSecretInput() throws {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/StaleCredential.pswvault"))
        store.unlock(password: "correct horse")

        var creation = TemplateCredentialForm(template: .apiToken)
        creation.title = "Build API"
        creation.secret = "saved-secret-marker"
        XCTAssertEqual(store.saveTemplateCredential(form: creation), .saved)
        let itemId = try XCTUnwrap(store.selectedItemId)
        var staleForm = CredentialEditorForm(
            detail: try XCTUnwrap(store.selectedCredentialDetail)
        )
        staleForm.title = "Stale local title"
        staleForm.fields[0].secretInput = "local-replacement-secret-marker"
        service.forceRevision(itemId: itemId, revision: "rev_remote")
        let currentItems = try service.search(
            sessionId: store.sessionId ?? 0,
            text: "",
            includeArchived: false
        )
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: currentItems.count,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: currentItems
        )

        XCTAssertEqual(store.saveCredential(form: staleForm), .staleDraftPreserved)
        XCTAssertEqual(service.updateCredentialCallCount, 0)
        XCTAssertEqual(store.selectedCredentialDetail?.revision, "rev_remote")
        XCTAssertEqual(store.selectedCredentialDetail?.title, "Build API")
        let review = try XCTUnwrap(store.staleSaveReview)
        let fieldReview = try XCTUnwrap(
            review.rows.first(where: { $0.fieldLabel == "fields" })
        )
        XCTAssertTrue(fieldReview.redacted)
        XCTAssertNil(fieldReview.currentValue)
        XCTAssertNil(fieldReview.draftValue)
        XCTAssertFalse(
            String(reflecting: review).contains("local-replacement-secret-marker")
        )
    }

    func testOpenUnlockFavoriteTagArchiveSearchAndAutoLockWorkflow() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let vaultURL = URL(fileURLWithPath: "/tmp/Synced.pswvault")

        store.openVault(url: vaultURL)
        XCTAssertNil(store.sessionId)

        store.unlock(password: "correct horse")
        XCTAssertEqual(store.items.map(\.title), ["Email"])

        store.select(itemId: "item_1")
        store.toggleFavoriteSelected()
        XCTAssertEqual(store.selectedDetail?.favorite, true)

        var editForm = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        editForm.tagsText = "personal, finance"
        editForm.password = ""
        store.saveLogin(form: editForm)

        XCTAssertEqual(store.selectedDetail?.tags, ["personal", "finance"])
        XCTAssertEqual(service.password(for: "item_1"), "email-password")

        store.archiveSelected()
        XCTAssertTrue(store.items.isEmpty)

        store.includeArchived = true
        store.searchText = ""
        store.search()
        XCTAssertEqual(store.items.map(\.status), ["archived"])

        store.autoLockSeconds = VaultStore.supportedAutoLockDurations[0]
        store.lockIfIdle(now: Date().addingTimeInterval(VaultStore.supportedAutoLockDurations[0] + 1))
        XCTAssertFalse(store.isUnlocked)
    }

    func testFavoriteFilterShowsOnlyFavoriteItemsAndClearsOnLock() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            ),
            SeedLogin(
                title: "Deploy",
                username: "ops",
                password: "deploy-password",
                url: "https://deploy.example.com",
                notes: "Release account",
                tags: ["work"],
                favorite: true
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/FavoriteFilter.pswvault"))
        store.unlock(password: "correct horse")
        store.showFavoritesOnly = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Mail", "Deploy"])

        store.lock()

        assertLockedAndCleared(store, service: service)
    }

    func testFavoriteFilterComposesWithSearchAndArchivedInclusion() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"],
                favorite: true
            ),
            SeedLogin(
                title: "Build",
                username: "ci",
                password: "build-password",
                url: "https://ci.example.com",
                notes: "CI account",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/FavoriteFilterComposed.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_2")
        store.archiveSelected()
        store.showFavoritesOnly = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Mail"])

        store.searchText = "bank"
        store.search()
        XCTAssertTrue(store.items.isEmpty)

        store.includeArchived = true
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Bank"])
        XCTAssertEqual(store.items.map(\.status), ["archived"])
    }

    func testTagFilterOptionsAreUniqueSortedAndNonSecret() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["Personal", "finance"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["personal", "Work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/TagFilterOptions.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertEqual(store.availableTags, ["finance", "Personal", "Work"])
    }

    func testTagFilterComposesWithSearchFavoritesAndArchivedInclusion() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"],
                favorite: true
            ),
            SeedLogin(
                title: "Build",
                username: "ci",
                password: "build-password",
                url: "https://ci.example.com",
                notes: "CI account",
                tags: ["work"]
            ),
            SeedLogin(
                title: "Archive Bank",
                username: "archive",
                password: "archive-password",
                url: "https://archive.example.com",
                notes: "Old account",
                tags: ["finance"],
                favorite: true
            )
        ])
        service.markArchived(itemId: "item_4")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/TagFilterComposed.pswvault"))
        store.unlock(password: "correct horse")
        store.selectedTagFilter = "FINANCE"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank"])
        XCTAssertEqual(store.selectedItemId, "item_2")

        store.searchText = "bank"
        store.showFavoritesOnly = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank"])

        store.includeArchived = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank", "Archive Bank"])
    }

    func testSelectedTagFilterClearsWhenTagDisappearsAfterMutation() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/TagFilterClearsMissing.pswvault"))
        store.unlock(password: "correct horse")
        store.selectedTagFilter = "finance"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank"])

        var form = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        form.tagsText = "personal"
        store.saveLogin(form: form)

        XCTAssertNil(store.selectedTagFilter)
        XCTAssertEqual(store.availableTags, ["personal"])
        XCTAssertEqual(store.items.map(\.title), ["Bank"])
        XCTAssertEqual(store.selectedDetail?.tags, ["personal"])
    }

    func testItemTypeFilterOptionsUseStableKnownOrderAndNonSecretSummaries() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ItemTypeFilterOptions.pswvault"))
        store.unlock(password: "correct horse")

        var license = SoftwareLicenseForm()
        license.title = "Editor License"
        license.product = "TextPro"
        license.licenseKey = "AAAA-BBBB"
        store.select(itemId: nil)
        store.saveSoftwareLicense(form: license)

        var card = CreditCardForm()
        card.title = "Travel Card"
        card.number = "4111111111111111"
        card.verificationCode = "123"
        store.select(itemId: nil)
        store.saveCreditCard(form: card)

        var note = SecureNoteForm()
        note.title = "Recovery Note"
        note.body = "Recovery details"
        store.select(itemId: nil)
        store.saveSecureNote(form: note)

        XCTAssertEqual(store.availableItemTypes, [
            "login",
            "secure note",
            "credit card",
            "software license"
        ])
    }

    func testItemTypeFilterComposesWithSearchTagsFavoritesAndArchivedInclusion() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Bank Login",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"],
                favorite: true
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ItemTypeFilterComposed.pswvault"))
        store.unlock(password: "correct horse")

        var activeCard = CreditCardForm()
        activeCard.title = "Bank Card"
        activeCard.cardholderName = "Alice"
        activeCard.number = "4111111111111111"
        activeCard.verificationCode = "123"
        activeCard.notes = "Primary card"
        activeCard.tagsText = "finance"
        activeCard.favorite = true
        store.select(itemId: nil)
        store.saveCreditCard(form: activeCard)

        var note = SecureNoteForm()
        note.title = "Bank Note"
        note.body = "finance note"
        note.tagsText = "finance"
        note.favorite = true
        store.select(itemId: nil)
        store.saveSecureNote(form: note)

        var archivedCard = CreditCardForm()
        archivedCard.title = "Archive Card"
        archivedCard.cardholderName = "Alice"
        archivedCard.number = "5555555555554444"
        archivedCard.verificationCode = "987"
        archivedCard.notes = "Old card"
        archivedCard.tagsText = "finance"
        archivedCard.favorite = true
        store.select(itemId: nil)
        store.saveCreditCard(form: archivedCard)
        service.markArchived(itemId: "item_4")

        store.selectedItemTypeFilter = "credit card"
        store.selectedTagFilter = "FINANCE"
        store.searchText = "card"
        store.showFavoritesOnly = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank Card"])
        XCTAssertEqual(store.selectedItemId, "item_2")

        store.includeArchived = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank Card", "Archive Card"])
        XCTAssertEqual(store.items.map(\.itemType), ["credit card", "credit card"])
    }

    func testSelectedItemTypeFilterClearsWhenTypeDisappearsAfterMutation() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ItemTypeFilterClearsMissing.pswvault"))
        store.unlock(password: "correct horse")

        var card = CreditCardForm()
        card.title = "Travel Card"
        card.number = "4111111111111111"
        card.verificationCode = "123"
        store.select(itemId: nil)
        store.saveCreditCard(form: card)

        store.selectedItemTypeFilter = "credit card"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Travel Card"])

        store.deleteSelected(discardingUnsavedEdits: true)

        XCTAssertNil(store.selectedItemTypeFilter)
        XCTAssertEqual(store.availableItemTypes, ["login"])
        XCTAssertEqual(store.items.map(\.title), ["Mail"])
        XCTAssertEqual(store.selectedDetail?.title, "Mail")
    }

    func testConflictFilterShowsOnlyConflictedItemsAndClearsOnLock() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            ),
            SeedLogin(
                title: "Deploy",
                username: "ops",
                password: "deploy-password",
                url: "https://deploy.example.com",
                notes: "Release account",
                tags: ["work"]
            )
        ])
        service.markConflicted(itemId: "item_2", conflictId: "conflict_bank")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ConflictFilter.pswvault"))
        store.unlock(password: "correct horse")
        store.showConflictsOnly = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank"])
        XCTAssertEqual(store.selectedItemId, "item_2")

        store.lock()

        assertLockedAndCleared(store, service: service)
    }

    func testConflictFilterComposesWithSearchFavoritesAndArchivedInclusion() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail Conflict",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank Conflict",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            ),
            SeedLogin(
                title: "Mail Active",
                username: "ops",
                password: "deploy-password",
                url: "https://deploy.example.com",
                notes: "Release account",
                tags: ["work"],
                favorite: true
            ),
            SeedLogin(
                title: "Mail Archived",
                username: "old",
                password: "old-password",
                url: "https://old.example.com",
                notes: "Old account",
                tags: ["archive"],
                favorite: true
            )
        ])
        service.markConflicted(itemId: "item_1", conflictId: "conflict_mail")
        service.markConflicted(itemId: "item_2", conflictId: "conflict_bank")
        service.markArchived(itemId: "item_4")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ConflictFilterComposed.pswvault"))
        store.unlock(password: "correct horse")
        store.showConflictsOnly = true
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Mail Conflict", "Bank Conflict"])

        store.searchText = "mail"
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Mail Conflict"])

        store.showFavoritesOnly = true
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Mail Conflict"])

        store.showConflictsOnly = false
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Mail Conflict", "Mail Active"])

        store.includeArchived = true
        store.showConflictsOnly = true
        store.search()
        XCTAssertEqual(store.items.map(\.title), ["Mail Conflict"])
    }

    func testSyncIssueShowConflictsActionEnablesConflictFilterAndPreservesSearchContext() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail Conflict",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank Conflict",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            ),
            SeedLogin(
                title: "Bank Active",
                username: "ops",
                password: "deploy-password",
                url: "https://deploy.example.com",
                notes: "Release account",
                tags: ["work"]
            )
        ])
        service.markConflicted(itemId: "item_1", conflictId: "conflict_mail")
        service.markConflicted(itemId: "item_2", conflictId: "conflict_bank")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ShowConflictsAction.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "bank"
        store.syncReport = SyncRefreshPayload(
            loadedItems: 3,
            appliedTombstones: 0,
            detectedConflicts: 2,
            rejectedRecords: 0,
            items: store.items
        )

        store.showConflictedItems()

        XCTAssertTrue(store.showConflictsOnly)
        XCTAssertEqual(store.searchText, "bank")
        XCTAssertEqual(store.items.map(\.title), ["Bank Conflict"])
        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertEqual(store.statusMessage, "Showing conflicts")
    }

    func testSyncIssueShowConflictsActionPreservesDirtyEditorStateWhenSelectionWouldChange() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail Active",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank Conflict",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        service.markConflicted(itemId: "item_2", conflictId: "conflict_bank")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ShowConflictsDirty.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)
        store.syncReport = SyncRefreshPayload(
            loadedItems: 2,
            appliedTombstones: 0,
            detectedConflicts: 1,
            rejectedRecords: 0,
            items: store.items
        )

        store.showConflictedItems()

        XCTAssertFalse(store.showConflictsOnly)
        XCTAssertEqual(store.items.map(\.title), ["Mail Active", "Bank Conflict"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")
    }

    func testFilterPreservesSelectionWhenSelectedItemRemainsVisible() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Mail Admin",
                username: "admin",
                password: "admin-password",
                url: "https://admin.example.com",
                notes: "Admin inbox",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/FilterSelectionPreserve.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "mail"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Mail", "Mail Admin"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Mail")
    }

    func testListFilterStateDetectsActiveFilters() {
        let store = VaultStore(
            service: FakeCoreService(),
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        XCTAssertFalse(store.hasActiveListFilters)

        store.searchText = "   "
        XCTAssertFalse(store.hasActiveListFilters)

        store.searchText = "mail"
        XCTAssertTrue(store.hasActiveListFilters)

        store.searchText = ""
        store.includeArchived = true
        XCTAssertTrue(store.hasActiveListFilters)

        store.includeArchived = false
        store.showFavoritesOnly = true
        XCTAssertTrue(store.hasActiveListFilters)

        store.showFavoritesOnly = false
        store.showConflictsOnly = true
        XCTAssertTrue(store.hasActiveListFilters)

        store.showConflictsOnly = false
        store.selectedItemTypeFilter = "credit card"
        XCTAssertTrue(store.hasActiveListFilters)

        store.selectedItemTypeFilter = nil
        store.selectedTagFilter = "finance"
        XCTAssertTrue(store.hasActiveListFilters)

        store.selectedTagFilter = nil
        store.selectedSmartView = .developerCredentials
        XCTAssertTrue(store.hasActiveListFilters)
    }

    func testClearListFiltersRefreshesVisibleItems() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"],
                favorite: false
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ClearListFilters.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "missing"
        store.showFavoritesOnly = true
        store.showConflictsOnly = true
        store.selectedItemTypeFilter = "login"
        store.selectedTagFilter = "finance"
        store.includeArchived = true
        store.search()

        XCTAssertTrue(store.items.isEmpty)
        XCTAssertTrue(store.hasActiveListFilters)

        XCTAssertTrue(store.clearListFilters())

        XCTAssertFalse(store.hasActiveListFilters)
        XCTAssertEqual(store.searchText, "")
        XCTAssertFalse(store.showFavoritesOnly)
        XCTAssertFalse(store.showConflictsOnly)
        XCTAssertNil(store.selectedItemTypeFilter)
        XCTAssertNil(store.selectedTagFilter)
        XCTAssertFalse(store.includeArchived)
        XCTAssertEqual(store.items.map(\.title), ["Mail", "Bank"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.statusMessage, "Filters cleared")
    }

    func testFilterMovesSelectionToFirstVisibleResultWhenSelectedItemIsHidden() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/FilterSelectionMove.pswvault"))
        store.unlock(password: "correct horse")
        store.searchText = "bank"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Bank"])
        XCTAssertEqual(store.selectedItemId, "item_2")
        XCTAssertEqual(store.selectedDetail?.title, "Bank")
    }

    func testFilterClearsSelectionAndDetailsWhenNoResultsRemain() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/FilterSelectionEmpty.pswvault"))
        store.unlock(password: "correct horse")
        store.conflictCandidates = sampleLoginConflictCandidates()
        store.searchText = "missing"
        store.search()

        XCTAssertTrue(store.items.isEmpty)
        XCTAssertNil(store.selectedItemId)
        XCTAssertNil(store.selectedDetail)
        XCTAssertNil(store.selectedSecureNoteDetail)
        XCTAssertNil(store.selectedCreditCardDetail)
        XCTAssertNil(store.selectedSoftwareLicenseDetail)
        XCTAssertTrue(store.conflictCandidates.isEmpty)
    }

    func testDirtyEditorBlocksFilterDrivenSelectionChange() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyFilterSelection.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)
        store.searchText = "bank"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Mail", "Bank"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Mail")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")
    }

    func testDirtyEditorBlocksTagFilterDrivenSelectionChange() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "Checking",
                tags: ["finance"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyTagFilterSelection.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)
        store.selectedTagFilter = "finance"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Mail", "Bank"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Mail")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")
    }

    func testDirtyEditorBlocksItemTypeFilterDrivenSelectionChange() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/DirtyItemTypeFilterSelection.pswvault"))
        store.unlock(password: "correct horse")

        var card = CreditCardForm()
        card.title = "Travel Card"
        card.number = "4111111111111111"
        card.verificationCode = "123"
        store.select(itemId: nil)
        store.saveCreditCard(form: card)

        XCTAssertTrue(store.select(itemId: "item_1"))
        store.setEditorHasUnsavedChanges(true)
        store.selectedItemTypeFilter = "credit card"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Mail", "Travel Card"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Mail")
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")
    }

    func testExistingLoginPasswordCanBeExplicitlyClearedAndReplaced() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ClearPassword.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")

        var metadataEdit = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        metadataEdit.title = "Email Edited"
        metadataEdit.password = ""
        store.saveLogin(form: metadataEdit)

        XCTAssertEqual(service.password(for: "item_1"), "email-password")

        store.copyPassword()
        XCTAssertEqual(clipboard.copied.map(\.value), ["email-password"])

        var clearForm = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        clearForm.clearPasswordOnSave = true
        store.saveLogin(form: clearForm)

        XCTAssertNil(service.password(for: "item_1"))

        store.copyPassword()
        XCTAssertEqual(clipboard.copied.map(\.value), ["email-password"])
        XCTAssertEqual(store.statusMessage, "login item has no password")

        var replaceForm = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        replaceForm.clearPasswordOnSave = true
        replaceForm.password = "replacement-password"
        store.saveLogin(form: replaceForm)

        XCTAssertEqual(service.password(for: "item_1"), "replacement-password")

        store.copyPassword()
        XCTAssertEqual(clipboard.copied.map(\.value), ["email-password", "replacement-password"])
        XCTAssertEqual(store.statusMessage, "Password copied")
    }

    func testSelectedLoginURLCanBeOpenedWhenValidAndIsRejectedWhenInvalid() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com/login",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let urlOpener = FakeURLOpener()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            urlOpener: urlOpener,
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/OpenURL.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")

        XCTAssertTrue(store.canOpenSelectedLoginURL)
        XCTAssertTrue(store.openSelectedLoginURL())
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), ["https://mail.example.com/login"])
        XCTAssertEqual(store.statusMessage, "URL opened")

        var form = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        form.url = "example.com/account"
        store.saveLogin(form: form)

        XCTAssertTrue(store.openSelectedLoginURL())
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), [
            "https://mail.example.com/login",
            "https://example.com/account"
        ])

        form = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        form.url = "ftp://example.com/secret"
        store.saveLogin(form: form)

        XCTAssertFalse(store.openSelectedLoginURL())
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), [
            "https://mail.example.com/login",
            "https://example.com/account"
        ])
        XCTAssertEqual(store.statusMessage, "login item has no valid URL")

        form = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        form.url = "   "
        store.saveLogin(form: form)

        XCTAssertFalse(store.openSelectedLoginURL())
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), [
            "https://mail.example.com/login",
            "https://example.com/account"
        ])
        XCTAssertEqual(store.statusMessage, "login item has no valid URL")
    }

    func testReadOnlyURLActionsTargetOnlyURLsFromCurrentSelection() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com/login",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let clipboard = FakeClipboard()
        let urlOpener = FakeURLOpener()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            urlOpener: urlOpener,
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/ReadOnlyURLActions.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")

        var form = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        form.urlsText = """
        https://mail.example.com/login
        portal.example.com/account
        """
        XCTAssertEqual(store.saveLogin(form: form), .saved)

        store.copySelectedLoginURL("portal.example.com/account")
        XCTAssertEqual(clipboard.copied.map(\.value), ["portal.example.com/account"])
        XCTAssertEqual(store.statusMessage, "URL copied")

        XCTAssertTrue(store.openSelectedLoginURL("portal.example.com/account"))
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), ["https://portal.example.com/account"])

        store.copySelectedLoginURL("https://outside.example.com")
        XCTAssertEqual(clipboard.copied.map(\.value), ["portal.example.com/account"])
        XCTAssertEqual(store.statusMessage, "login item has no URL")

        XCTAssertFalse(store.openSelectedLoginURL("https://outside.example.com"))
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), ["https://portal.example.com/account"])
        XCTAssertEqual(store.statusMessage, "login item has no valid URL")
    }

    func testLoginDetailDecodesLegacyURLAsURLArray() throws {
        let data = Data("""
        {
          "id": "item_1",
          "revision": "rev_1",
          "title": "Email",
          "username": "me@example.com",
          "url": "https://mail.example.com",
          "notes": null,
          "totp_secret": null,
          "favorite": false,
          "tags": ["personal"],
          "status": "active"
        }
        """.utf8)

        let detail = try JSONDecoder().decode(LoginDetail.self, from: data)

        XCTAssertEqual(detail.url, "https://mail.example.com")
        XCTAssertEqual(detail.urls, ["https://mail.example.com"])
    }

    func testLoginEditorPreservesSearchesAndSavesMultipleURLs() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Portal",
                username: "me@example.com",
                password: "portal-password",
                url: "https://primary.example.com",
                urls: ["https://primary.example.com", "https://secondary.example.com/login"],
                notes: "Multiple entry points",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/MultiURL.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")

        let initialDetail = try! XCTUnwrap(store.selectedDetail)
        XCTAssertEqual(initialDetail.urls, [
            "https://primary.example.com",
            "https://secondary.example.com/login"
        ])

        var form = LoginForm(detail: initialDetail)
        XCTAssertEqual(form.urlsText, "https://primary.example.com\nhttps://secondary.example.com/login")
        form.urlsText = """
          https://updated.example.com

        https://backup.example.com/login
        """
        store.saveLogin(form: form)

        XCTAssertEqual(store.selectedDetail?.urls, [
            "https://updated.example.com",
            "https://backup.example.com/login"
        ])

        store.searchText = "backup.example.com"
        store.search()

        XCTAssertEqual(store.items.map(\.title), ["Portal"])
    }

    func testOpenSelectedLoginURLSkipsUnsafeValuesAndUsesFirstSafeURL() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Portal",
                username: "me@example.com",
                password: "portal-password",
                url: "ftp://unsafe.example.com",
                urls: [
                    "ftp://unsafe.example.com",
                    "file:///tmp/secret",
                    "portal.example.com/login",
                    "https://backup.example.com"
                ],
                notes: "Multiple URLs",
                tags: ["work"]
            )
        ])
        let urlOpener = FakeURLOpener()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            urlOpener: urlOpener,
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/MultiURLOpen.pswvault"))
        store.unlock(password: "correct horse")
        store.select(itemId: "item_1")

        XCTAssertTrue(store.openSelectedLoginURL())
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), ["https://portal.example.com/login"])
        XCTAssertEqual(store.statusMessage, "URL opened")
    }

    func testOpenURLActionIsUnavailableForNonLoginItems() {
        let service = FakeCoreService()
        let urlOpener = FakeURLOpener()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            urlOpener: urlOpener,
            userDefaults: makeIsolatedDefaults()
        )
        store.createVault(
            url: URL(fileURLWithPath: "/tmp/OpenURLNote.pswvault"),
            displayName: "Notes",
            password: "correct horse",
            confirmation: "correct horse"
        )

        var form = SecureNoteForm()
        form.title = "Recovery"
        form.body = "offline backup codes"
        store.saveSecureNote(form: form)

        XCTAssertFalse(store.canOpenSelectedLoginURL)
        XCTAssertFalse(store.openSelectedLoginURL())
        XCTAssertTrue(urlOpener.openedURLs.isEmpty)
    }

    func testStaleLoginSavePreservesDraftAndReloadsCurrentSyncedItem() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let refreshTime = Date(timeIntervalSince1970: 1_800_000_040)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            now: { refreshTime },
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/StaleSave.pswvault"))
        store.unlock(password: "correct horse")
        var staleForm = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        XCTAssertEqual(staleForm.revision, "rev_1")

        service.forceRevision(itemId: "item_1", revision: "rev_remote")
        staleForm.title = "Stale Local Edit"
        staleForm.tagsText = "personal, stale"
        staleForm.password = "local-secret-password"
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 1,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    revision: "rev_remote",
                    title: "Email",
                    itemType: "login",
                    status: "active",
                    favorite: false,
                    tags: ["personal"]
                )
            ]
        )

        let outcome = store.saveLogin(form: staleForm)

        XCTAssertEqual(outcome, .staleDraftPreserved)
        XCTAssertEqual(store.statusMessage, "Local edit kept; current synced item reloaded")
        XCTAssertEqual(service.updateLoginCallCount, 0)
        XCTAssertEqual(service.refreshCallCount, 1)
        XCTAssertEqual(store.lastSyncRefreshAt, refreshTime)
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertEqual(store.selectedDetail?.revision, "rev_remote")
        let review = try! XCTUnwrap(store.staleSaveReview)
        XCTAssertEqual(review.itemId, "item_1")
        XCTAssertEqual(review.itemTitle, "Email")
        let rowsByLabel = Dictionary(uniqueKeysWithValues: review.rows.map { ($0.fieldLabel, $0) })
        XCTAssertEqual(rowsByLabel["title"]?.currentValue, "Email")
        XCTAssertEqual(rowsByLabel["title"]?.draftValue, "Stale Local Edit")
        XCTAssertEqual(rowsByLabel["tags"]?.currentValue, "personal")
        XCTAssertEqual(rowsByLabel["tags"]?.draftValue, "personal, stale")
        XCTAssertEqual(rowsByLabel["password"]?.redacted, true)
        XCTAssertNil(rowsByLabel["password"]?.currentValue)
        XCTAssertNil(rowsByLabel["password"]?.draftValue)
        XCTAssertNil(rowsByLabel["username"])

        var preservedDraft = staleForm
        preservedDraft.revision = try! XCTUnwrap(store.selectedDetail?.revision)
        let savedOutcome = store.saveLogin(form: preservedDraft)

        XCTAssertEqual(savedOutcome, .saved)
        XCTAssertEqual(service.updateLoginCallCount, 1)
        XCTAssertEqual(store.statusMessage, "Saved")
        XCTAssertEqual(store.selectedDetail?.title, "Stale Local Edit")
        XCTAssertEqual(store.selectedDetail?.tags, ["personal", "stale"])
        XCTAssertNotEqual(store.selectedDetail?.revision, "rev_remote")
        XCTAssertNil(store.staleSaveReview)
    }

    func testStaleSaveReviewClearsWhenSelectionChanges() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Admin",
                username: "admin@example.com",
                password: "admin-password",
                url: "https://admin.example.com",
                notes: "Admin console",
                tags: ["work"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/StaleSaveSelection.pswvault"))
        store.unlock(password: "correct horse")
        var staleForm = LoginForm(detail: try! XCTUnwrap(store.selectedDetail))
        service.forceRevision(itemId: "item_1", revision: "rev_remote")
        staleForm.title = "Stale Local Edit"
        service.nextRefreshPayload = SyncRefreshPayload(
            loadedItems: 2,
            appliedTombstones: 0,
            detectedConflicts: 0,
            rejectedRecords: 0,
            items: [
                VaultItemView(
                    id: "item_1",
                    revision: "rev_remote",
                    title: "Email",
                    itemType: "login",
                    status: "active",
                    favorite: false,
                    tags: ["personal"]
                ),
                VaultItemView(
                    id: "item_2",
                    revision: "rev_2",
                    title: "Admin",
                    itemType: "login",
                    status: "active",
                    favorite: false,
                    tags: ["work"]
                )
            ]
        )

        XCTAssertEqual(store.saveLogin(form: staleForm), .staleDraftPreserved)
        XCTAssertNotNil(store.staleSaveReview)

        XCTAssertTrue(store.select(itemId: "item_2"))

        XCTAssertNil(store.staleSaveReview)
        XCTAssertEqual(store.selectedItemId, "item_2")
    }

    func testRestoreArchivedLoginReturnsItToActiveList() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Email",
                username: "me@example.com",
                password: "email-password",
                url: "https://mail.example.com",
                notes: "Primary inbox",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/Restore.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertFalse(store.canRestoreSelectedArchive)
        XCTAssertEqual(service.restoreItemCallCount, 0)

        store.restoreSelectedArchive()

        XCTAssertEqual(service.restoreItemCallCount, 0)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.statusMessage, "Only archived items can be restored")

        store.archiveSelected()
        XCTAssertTrue(store.items.isEmpty)

        store.includeArchived = true
        store.searchText = ""
        store.search()
        XCTAssertEqual(store.items.map(\.status), ["archived"])
        store.select(itemId: "item_1")
        XCTAssertTrue(store.canRestoreSelectedArchive)

        store.restoreSelectedArchive()

        XCTAssertEqual(service.restoreItemCallCount, 1)
        XCTAssertEqual(store.items.map(\.status), ["active"])
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertEqual(store.selectedDetail?.title, "Email")
        XCTAssertFalse(store.canRestoreSelectedArchive)
        XCTAssertEqual(store.statusMessage, "Restored")
    }

    func testSmartViewClassificationUsesSecretKindsAndAllowsOverlappingMembership() {
        let mixed = VaultItemView(
            id: "mixed",
            title: "Unified Account",
            itemType: "custom",
            templateId: "custom",
            secretKinds: ["password", "api-token", "private-key"],
            status: "active",
            favorite: false,
            tags: []
        )
        let apiKey = VaultItemView(
            id: "api-key",
            title: "Build Key",
            itemType: "api key",
            templateId: "api-key",
            secretKinds: ["api-key"],
            status: "active",
            favorite: false,
            tags: []
        )
        let certificate = VaultItemView(
            id: "certificate",
            title: "Signing Certificate",
            itemType: "certificate",
            templateId: "certificate",
            secretKinds: ["certificate"],
            status: "active",
            favorite: false,
            tags: []
        )
        let custom = VaultItemView(
            id: "custom",
            title: "Opaque Secret",
            itemType: "custom",
            templateId: "custom",
            secretKinds: ["generic-secret"],
            status: "active",
            favorite: false,
            tags: []
        )
        let archivedKey = VaultItemView(
            id: "archived-key",
            title: "Old SSH Key",
            itemType: "ssh key",
            templateId: "ssh-key",
            secretKinds: ["private-key"],
            status: "archived",
            favorite: false,
            tags: []
        )
        let authorizedIds: Set<String> = ["mixed", "custom", "archived-key"]

        XCTAssertTrue(mixed.appears(in: .logins, authorizedCredentialIds: authorizedIds))
        XCTAssertTrue(mixed.appears(in: .developerCredentials, authorizedCredentialIds: authorizedIds))
        XCTAssertTrue(mixed.appears(in: .keysAndCertificates, authorizedCredentialIds: authorizedIds))
        XCTAssertTrue(mixed.appears(in: .appsToolsAuthorized, authorizedCredentialIds: authorizedIds))
        XCTAssertTrue(apiKey.appears(in: .developerCredentials, authorizedCredentialIds: authorizedIds))
        XCTAssertFalse(apiKey.appears(in: .keysAndCertificates, authorizedCredentialIds: authorizedIds))
        XCTAssertFalse(custom.appears(in: .developerCredentials, authorizedCredentialIds: authorizedIds))
        XCTAssertTrue(VaultItemView(
            id: "legacy-token",
            title: "Legacy Token",
            itemType: "api token",
            status: "active",
            favorite: false,
            tags: []
        ).appears(in: .developerCredentials, authorizedCredentialIds: authorizedIds))

        let counts = VaultNavigationCounts(
            items: [mixed, apiKey, certificate, custom, archivedKey],
            passwordHealth: nil,
            authorizedCredentialIds: authorizedIds
        )
        XCTAssertEqual(counts.logins, 1)
        XCTAssertEqual(counts.developerCredentials, 3)
        XCTAssertEqual(counts.keysAndCertificates, 2)
        XCTAssertEqual(counts.appsToolsAuthorized, 2)
        XCTAssertEqual(counts.count(for: .smartView(.developerCredentials)), 3)
        XCTAssertEqual(counts.count(for: .smartView(.appsToolsAuthorized)), 2)
        XCTAssertEqual(counts.count(for: .appsAndTools), 2)
    }

    func testAppsToolsIsAFirstLevelDestinationWithoutBecomingAnItemFilter() throws {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: ["personal"]
            )
        ])
        var credential = TemplateCredentialForm(template: .apiToken)
        credential.title = "Deploy Token"
        credential.secret = "seeded-secret-marker"
        _ = try service.createCredentialFromTemplate(sessionId: 7, form: credential)
        service.nextAuthorizedCredentialIds = ["item_2"]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/AppsToolsDestination.pswvault"))
        store.unlock(password: "correct horse")
        let originalItems = store.items

        XCTAssertFalse(VaultNavigationDestination.appsAndTools.isItemDestination)
        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertEqual(store.navigationDestination, .appsAndTools)
        XCTAssertEqual(store.items, originalItems)
        XCTAssertEqual(store.navigationCounts.count(for: .appsAndTools), 1)
        XCTAssertEqual(service.authorizedCredentialIdsCallCount, 2)

        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertEqual(service.authorizedCredentialIdsCallCount, 3)
        XCTAssertEqual(store.items, originalItems)

        XCTAssertTrue(store.applyNavigationDestination(.smartView(.appsToolsAuthorized)))
        XCTAssertEqual(store.items.map(\.title), ["Deploy Token"])
    }

    func testAppsToolsGlobalPauseWorksWithoutConsumersAndPreservesHumanVaultSession() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: ["personal"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/AppsToolsGlobalPause.pswvault"))
        store.unlock(password: "correct horse")
        let humanItems = store.items

        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertTrue(store.appsToolsSnapshot.consumers.isEmpty)
        XCTAssertNil(store.selectedAppsToolsConsumerId)

        store.setAppsToolsPaused(true)
        XCTAssertTrue(store.appsToolsSnapshot.paused)
        XCTAssertEqual(service.appsToolsPauseRequests, [true])
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.items, humanItems)

        XCTAssertTrue(store.applyNavigationDestination(.allItems))
        XCTAssertTrue(store.select(itemId: humanItems.first?.id))
        XCTAssertEqual(store.selectedItem?.title, "Mail")

        store.setAppsToolsPaused(false)
        XCTAssertFalse(store.appsToolsSnapshot.paused)
        XCTAssertEqual(service.appsToolsPauseRequests, [true, false])
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.selectedItem?.title, "Mail")
        XCTAssertEqual(store.items, humanItems)
    }

    func testAppsToolsConsumerDetailPauseAndRevocationRemainSeparateFromHumanVaultAccess() throws {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: ["personal"]
            )
        ])
        var credential = TemplateCredentialForm(template: .apiToken)
        credential.title = "Deploy Token"
        credential.secret = "seeded-secret-marker"
        _ = try service.createCredentialFromTemplate(sessionId: 7, form: credential)

        let identity = AppsToolsConsumerIdentity(
            executableName: "codex",
            bundleIdentifier: "com.openai.codex",
            teamIdentifier: "OPENAI",
            codeSigningEvidence: "verified-with-team-identifier",
            codeSignatureFingerprint: "0102-0304-0506-0708"
        )
        let consumer = AppsToolsConsumerSummary(
            consumerId: "consumer_000102030405060708090a0b0c0d0e0f",
            label: "Codex local adapter",
            identity: identity,
            accessRuleCount: 1,
            usageProfileCount: 1,
            createdAtMilliseconds: 1_800_000_000_000
        )
        let field = AppsToolsFieldReference(
            vaultId: "vault_000102030405060708090a0b0c0d0e0f",
            credentialId: "item_2",
            secretFieldId: "secret_field_000102030405060708090a0b0c0d0e0f",
            currentVault: true,
            credentialTitle: "Deploy Token",
            fieldLabel: "Token",
            secretKind: "api-token"
        )
        let grant = AppsToolsFieldGrant(
            accessRuleId: "access_rule_000102030405060708090a0b0c0d0e0f",
            field: field,
            capability: "process.run",
            capabilityVersion: 1,
            confirmationPolicy: "every-use",
            lifetime: "persistent",
            expiresAtMilliseconds: nil,
            createdAtMilliseconds: 1_800_000_001_000,
            active: true
        )
        let profile = AppsToolsUsageProfile(
            usageProfileId: "usage_profile_000102030405060708090a0b0c0d0e0f",
            label: "GitHub CLI",
            capability: "process.run",
            capabilityVersion: 1,
            placement: AppsToolsUsagePlacement(
                kind: "process-environment",
                variableName: "GH_TOKEN",
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: nil
            ),
            createdAtMilliseconds: 1_800_000_002_000
        )
        let audit = AppsToolsAuditEvent(
            auditEventId: "audit_event_000102030405060708090a0b0c0d0e0f",
            occurredAtMilliseconds: 1_800_000_003_000,
            kind: "credential-use",
            field: field,
            capability: "process.run",
            capabilityVersion: 1,
            decision: "allowed",
            confirmationMethod: "user-approval"
        )
        service.nextAuthorizedCredentialIds = ["item_2"]
        service.nextAppsToolsConsumers = [consumer]
        service.nextAppsToolsConsumerDetails[consumer.consumerId] = AppsToolsConsumerDetail(
            consumer: consumer,
            fieldGrants: [grant],
            usageProfiles: [profile],
            recentAuditEvents: [audit]
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/AppsToolsConsumer.pswvault"))
        store.unlock(password: "correct horse")
        let humanItems = store.items

        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertEqual(store.selectedAppsToolsConsumerId, consumer.consumerId)
        XCTAssertEqual(store.selectedAppsToolsConsumerDetail?.fieldGrants, [grant])
        XCTAssertEqual(store.selectedAppsToolsConsumerDetail?.usageProfiles, [profile])
        XCTAssertEqual(store.selectedAppsToolsConsumerDetail?.recentAuditEvents, [audit])
        XCTAssertEqual(service.appsToolsConsumerDetailRequests, [consumer.consumerId])

        store.setAppsToolsPaused(true)
        XCTAssertTrue(store.appsToolsSnapshot.paused)
        XCTAssertEqual(service.appsToolsPauseRequests, [true])
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.items, humanItems)

        store.revokeAppsToolsField(grant)
        XCTAssertEqual(service.revokedAppsToolsFields, [field])
        XCTAssertTrue(store.selectedAppsToolsConsumerDetail?.fieldGrants.isEmpty == true)
        XCTAssertTrue(store.authorizedCredentialIds.isEmpty)
        XCTAssertTrue(store.isUnlocked)

        store.revokeSelectedAppsToolsConsumer()
        XCTAssertEqual(service.revokedAppsToolsConsumers, [consumer.consumerId])
        XCTAssertTrue(store.appsToolsSnapshot.consumers.isEmpty)
        XCTAssertNil(store.selectedAppsToolsConsumerId)
        XCTAssertNil(store.selectedAppsToolsConsumerDetail)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.items, humanItems)
    }

    func testAppsToolsUsageProfileRecommendationCreateAndRemoveStayConsumerBound() throws {
        let service = FakeCoreService()
        let consumer = AppsToolsConsumerSummary(
            consumerId: "consumer_000102030405060708090a0b0c0d0e0f",
            label: "GitHub CLI",
            identity: AppsToolsConsumerIdentity(
                executableName: "gh",
                bundleIdentifier: nil,
                teamIdentifier: nil,
                codeSigningEvidence: "no-verified-signature",
                codeSignatureFingerprint: nil
            ),
            accessRuleCount: 0,
            usageProfileCount: 0,
            createdAtMilliseconds: 100
        )
        service.nextAppsToolsConsumers = [consumer]
        service.nextAppsToolsConsumerDetails[consumer.consumerId] = AppsToolsConsumerDetail(
            consumer: consumer,
            fieldGrants: [],
            usageProfiles: [],
            recentAuditEvents: []
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/AppsToolsUsageProfile.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertEqual(store.selectedAppsToolsConsumerDetail?.consumer, consumer)
        XCTAssertEqual(service.appsToolsUsageProfileSetupRequests, [consumer.consumerId])
        XCTAssertEqual(
            store.appsToolsUsageProfileSetup?.recommendation,
            AppsToolsUsageProfileRecommendation(
                recommendationId: "github-cli",
                templateId: "cli-environment-variable",
                technicalName: "GH_TOKEN"
            )
        )

        let draft = AppsToolsUsageProfileDraft(
            label: "GitHub CLI Token",
            templateId: "cli-environment-variable",
            technicalName: "GH_TOKEN"
        )
        XCTAssertTrue(store.createAppsToolsUsageProfile(draft))
        XCTAssertEqual(service.createdAppsToolsUsageProfiles.count, 1)
        XCTAssertEqual(service.createdAppsToolsUsageProfiles.first?.sessionId, 7)
        XCTAssertEqual(
            service.createdAppsToolsUsageProfiles.first?.consumerId,
            consumer.consumerId
        )
        XCTAssertEqual(service.createdAppsToolsUsageProfiles.first?.draft, draft)
        XCTAssertEqual(store.selectedAppsToolsConsumerDetail?.usageProfiles.count, 1)
        XCTAssertEqual(store.appsToolsSnapshot.consumers.first?.usageProfileCount, 1)
        XCTAssertFalse(store.appsToolsUsageProfileActionFailed)

        let profile = try XCTUnwrap(store.selectedAppsToolsConsumerDetail?.usageProfiles.first)
        XCTAssertEqual(profile.placement.variableName, "GH_TOKEN")
        XCTAssertTrue(store.removeAppsToolsUsageProfile(profile))
        XCTAssertEqual(service.removedAppsToolsUsageProfiles.count, 1)
        XCTAssertEqual(
            service.removedAppsToolsUsageProfiles.first?.usageProfileId,
            profile.usageProfileId
        )
        XCTAssertTrue(store.selectedAppsToolsConsumerDetail?.usageProfiles.isEmpty == true)
        XCTAssertEqual(store.appsToolsSnapshot.consumers.first?.usageProfileCount, 0)
        XCTAssertTrue(store.isUnlocked)
    }

    func testAppsToolsUsageProfileFailuresPreserveReadableConsumerState() throws {
        let service = FakeCoreService()
        let consumer = AppsToolsConsumerSummary(
            consumerId: "consumer_101112131415161718191a1b1c1d1e1f",
            label: "Local tool",
            identity: AppsToolsConsumerIdentity(
                executableName: "local-tool",
                bundleIdentifier: nil,
                teamIdentifier: nil,
                codeSigningEvidence: "no-verified-signature",
                codeSignatureFingerprint: nil
            ),
            accessRuleCount: 0,
            usageProfileCount: 1,
            createdAtMilliseconds: 100
        )
        let profile = AppsToolsUsageProfile(
            usageProfileId: "usage_profile_existing",
            label: "Existing API",
            capability: "http.request",
            capabilityVersion: 1,
            placement: AppsToolsUsagePlacement(
                kind: "http-bearer-authorization",
                variableName: nil,
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: nil
            ),
            createdAtMilliseconds: 110
        )
        service.nextAppsToolsConsumers = [consumer]
        service.nextAppsToolsConsumerDetails[consumer.consumerId] = AppsToolsConsumerDetail(
            consumer: consumer,
            fieldGrants: [],
            usageProfiles: [profile],
            recentAuditEvents: []
        )
        service.appsToolsUsageProfileError = CoreBridgeError.commandFailed(
            "seeded-backend-detail"
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/AppsToolsUsageProfileFailure.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertEqual(store.selectedAppsToolsConsumerDetail?.usageProfiles, [profile])
        XCTAssertNil(store.appsToolsUsageProfileSetup)
        XCTAssertTrue(store.appsToolsUsageProfileActionFailed)
        XCTAssertFalse(store.statusMessage.contains("seeded-backend-detail"))

        service.appsToolsUsageProfileError = nil
        store.selectAppsToolsConsumer(consumer.consumerId)
        XCTAssertNotNil(store.appsToolsUsageProfileSetup)
        service.appsToolsUsageProfileError = CoreBridgeError.commandFailed(
            "seeded-remove-detail"
        )

        XCTAssertFalse(store.removeAppsToolsUsageProfile(profile))
        XCTAssertEqual(store.selectedAppsToolsConsumerDetail?.usageProfiles, [profile])
        XCTAssertEqual(store.appsToolsSnapshot.consumers.first?.usageProfileCount, 1)
        XCTAssertTrue(store.appsToolsUsageProfileActionFailed)
        XCTAssertFalse(store.statusMessage.contains("seeded-remove-detail"))
        XCTAssertTrue(store.isUnlocked)
    }

    func testPendingRequestMonitoringCountsNotifiesOnceAndFailsClosed() {
        let service = FakeCoreService()
        let notifications = FakeApprovalNotificationScheduler()
        let defaults = makeIsolatedDefaults()
        defaults.set(
            AppLanguage.simplifiedChinese.rawValue,
            forKey: AppLanguage.storageKey
        )
        let first = AppsToolsPendingRequest(
            requestSource: "approval",
            requestId: "approval_request_01",
            kind: "credential-access",
            consumerId: "consumer_01",
            consumerLabel: "Codex adapter",
            identity: AppsToolsConsumerIdentity(
                executableName: "codex",
                bundleIdentifier: "com.openai.codex",
                teamIdentifier: nil,
                codeSigningEvidence: "verified-without-team-identifier",
                codeSignatureFingerprint: "0102-0304-0506-0708"
            ),
            pairingComparisonCode: nil,
            pairingKeyFingerprint: nil,
            vaultId: "vault_01",
            credentialId: nil,
            secretFieldId: nil,
            capability: "http.request",
            capabilityVersion: 1,
            requestDescription: "GitHub release credential",
            createdAtMilliseconds: 100,
            expiresAtMilliseconds: 200,
            remainingMilliseconds: nil
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [first]
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            approvalNotificationScheduler: notifications,
            userDefaults: defaults
        )

        store.startApprovalMonitoring()

        XCTAssertEqual(notifications.prepareCallCount, 1)
        XCTAssertEqual(service.appsToolsPendingRequestsCallCount, 1)
        XCTAssertEqual(store.appsToolsPendingRequests.pendingCount, 1)
        XCTAssertTrue(store.appsToolsPendingRequestsAvailable)
        XCTAssertEqual(notifications.posted.map(\.identifier), [first.id])
        XCTAssertEqual(notifications.posted.first?.title, "KeptNear 需要你的确认")
        XCTAssertFalse(notifications.posted.first?.body.contains("Codex") == true)
        XCTAssertFalse(notifications.posted.first?.body.contains("GitHub") == true)
        XCTAssertEqual(notifications.reconciled.last, Set([first.id]))

        store.refreshAppsToolsPendingRequests()
        XCTAssertEqual(notifications.posted.map(\.identifier), [first.id])

        let second = AppsToolsPendingRequest(
            requestSource: "pairing",
            requestId: "pairing_request_02",
            kind: "pairing",
            consumerId: nil,
            consumerLabel: nil,
            identity: AppsToolsConsumerIdentity(
                executableName: "claude",
                bundleIdentifier: nil,
                teamIdentifier: nil,
                codeSigningEvidence: "no-verified-signature",
                codeSignatureFingerprint: nil
            ),
            pairingComparisonCode: "0123456789",
            pairingKeyFingerprint: "1112-1314-1516-1718",
            vaultId: nil,
            credentialId: nil,
            secretFieldId: nil,
            capability: nil,
            capabilityVersion: nil,
            requestDescription: nil,
            createdAtMilliseconds: nil,
            expiresAtMilliseconds: nil,
            remainingMilliseconds: 300_000
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 2,
            requests: [first, second]
        )
        store.refreshAppsToolsPendingRequests()
        XCTAssertEqual(notifications.posted.map(\.identifier), [first.id, second.id])
        XCTAssertEqual(store.appsToolsPendingRequests.pendingCount, 2)

        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [second]
        )
        store.refreshAppsToolsPendingRequests()
        XCTAssertEqual(notifications.reconciled.last, Set([second.id]))

        service.appsToolsPendingRequestsError = CoreBridgeError.commandFailed(
            "pending requests unavailable"
        )
        store.refreshAppsToolsPendingRequests()
        XCTAssertFalse(store.appsToolsPendingRequestsAvailable)
        XCTAssertEqual(store.appsToolsPendingRequests, .empty)
        XCTAssertEqual(notifications.posted.count, 2)
    }

    func testPendingRequestDenyWorksWhileLockedAndOtherApprovalFailsClosed() {
        let service = FakeCoreService()
        let request = makeAppsToolsPendingRequest(
            requestId: "approval_request_locked",
            kind: "access",
            credentialId: "credential_01",
            secretFieldId: "secret_field_01"
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [request]
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.refreshAppsToolsPendingRequests()

        XCTAssertFalse(store.allowAppsToolsPendingRequestOnce(request))
        XCTAssertTrue(store.appsToolsPendingRequestActionFailed)
        XCTAssertTrue(service.allowedOnceAppsToolsRequests.isEmpty)

        store.clearAppsToolsPendingRequestActionError()
        service.appsToolsPendingRequestDecisionError = CoreBridgeError.commandFailed(
            "seeded-secret-marker"
        )
        XCTAssertFalse(store.denyAppsToolsPendingRequest(request))
        XCTAssertTrue(store.appsToolsPendingRequestActionFailed)
        XCTAssertEqual(store.appsToolsPendingRequests.pendingCount, 1)
        XCTAssertFalse(store.statusMessage.contains("seeded-secret-marker"))

        service.appsToolsPendingRequestDecisionError = nil
        XCTAssertTrue(store.denyAppsToolsPendingRequest(request))
        XCTAssertEqual(service.deniedAppsToolsPendingRequests.first?.requestSource, "approval")
        XCTAssertEqual(service.deniedAppsToolsPendingRequests.first?.requestId, request.requestId)
        XCTAssertEqual(store.appsToolsPendingRequests, .empty)
        XCTAssertFalse(store.appsToolsPendingRequestActionFailed)
    }

    func testPendingAccessActionsBindExactSelectionAndLongTermPolicy() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/PendingAccess.pswvault"))
        store.unlock(password: "correct horse")

        let exact = makeAppsToolsPendingRequest(
            requestId: "approval_request_exact",
            kind: "access",
            credentialId: "credential_exact",
            secretFieldId: "secret_field_exact"
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [exact]
        )
        store.refreshAppsToolsPendingRequests()
        XCTAssertTrue(store.allowAppsToolsPendingRequestOnce(exact))
        XCTAssertEqual(service.allowedOnceAppsToolsRequests.count, 1)
        XCTAssertEqual(service.allowedOnceAppsToolsRequests[0].sessionId, 7)
        XCTAssertNil(service.allowedOnceAppsToolsRequests[0].credentialId)
        XCTAssertNil(service.allowedOnceAppsToolsRequests[0].secretFieldId)

        let credentialRequest = makeAppsToolsPendingRequest(
            requestId: "approval_request_credential",
            kind: "credential-access"
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [credentialRequest]
        )
        service.nextAppsToolsCredentialReview = AppsToolsCredentialReview(
            requestId: credentialRequest.requestId,
            requestDescription: "release credential",
            capability: "process.run",
            capabilityVersion: 1,
            truncated: false,
            candidates: [
                AppsToolsCredentialCandidate(
                    credentialId: "credential_selected",
                    title: "Release Token",
                    templateId: "api-token",
                    tags: ["release"],
                    favorite: true,
                    secretFields: [
                        AppsToolsCredentialFieldCandidate(
                            secretFieldId: "secret_field_selected",
                            role: "token",
                            label: "Production",
                            kind: "api-token"
                        )
                    ]
                )
            ]
        )
        store.refreshAppsToolsPendingRequests()
        let review = store.reviewAppsToolsPendingCredential(credentialRequest)
        XCTAssertEqual(review?.candidates.first?.title, "Release Token")
        XCTAssertEqual(service.reviewedAppsToolsCredentials.first?.sessionId, 7)
        XCTAssertEqual(
            service.reviewedAppsToolsCredentials.first?.requestId,
            credentialRequest.requestId
        )

        XCTAssertFalse(store.allowAppsToolsPendingRequestOnce(credentialRequest))
        XCTAssertEqual(service.allowedOnceAppsToolsRequests.count, 1)
        store.clearAppsToolsPendingRequestActionError()

        let selection = AppsToolsCredentialSelection(
            credentialId: "credential_selected",
            secretFieldId: "secret_field_selected"
        )
        XCTAssertTrue(
            store.configureAppsToolsLongTermAccess(
                credentialRequest,
                selection: selection,
                confirmationPolicy: .automaticWhileUnlocked
            )
        )
        XCTAssertEqual(service.configuredLongTermAppsToolsRequests.count, 1)
        XCTAssertEqual(
            service.configuredLongTermAppsToolsRequests[0].credentialId,
            selection.credentialId
        )
        XCTAssertEqual(
            service.configuredLongTermAppsToolsRequests[0].secretFieldId,
            selection.secretFieldId
        )
        XCTAssertEqual(
            service.configuredLongTermAppsToolsRequests[0].confirmationPolicy,
            .automaticWhileUnlocked
        )
        XCTAssertEqual(store.appsToolsPendingRequests, .empty)

        let exactPersistent = makeAppsToolsPendingRequest(
            requestId: "approval_request_exact_persistent",
            kind: "access",
            credentialId: "credential_exact",
            secretFieldId: "secret_field_exact"
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [exactPersistent]
        )
        store.refreshAppsToolsPendingRequests()
        XCTAssertTrue(
            store.configureAppsToolsLongTermAccess(
                exactPersistent,
                confirmationPolicy: .everyUse
            )
        )
        XCTAssertNil(service.configuredLongTermAppsToolsRequests[1].credentialId)
        XCTAssertNil(service.configuredLongTermAppsToolsRequests[1].secretFieldId)
        XCTAssertEqual(
            service.configuredLongTermAppsToolsRequests[1].confirmationPolicy,
            .everyUse
        )
    }

    func testPendingPairingAndUnlockUseRequestSpecificActions() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        let pairing = makeAppsToolsPendingRequest(
            requestSource: "pairing",
            requestId: "pairing_request_01",
            kind: "pairing"
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [pairing]
        )
        store.refreshAppsToolsPendingRequests()

        XCTAssertFalse(store.approveAppsToolsPairing(pairing, label: "   "))
        XCTAssertTrue(service.approvedAppsToolsPairings.isEmpty)
        store.clearAppsToolsPendingRequestActionError()
        XCTAssertTrue(store.approveAppsToolsPairing(pairing, label: "  Codex CLI  "))
        XCTAssertEqual(service.approvedAppsToolsPairings.first?.label, "Codex CLI")

        let unlock = makeAppsToolsPendingRequest(
            requestId: "approval_request_unlock",
            kind: "unlock"
        )
        service.nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: 1,
            requests: [unlock]
        )
        store.refreshAppsToolsPendingRequests()
        XCTAssertFalse(store.approveAppsToolsPendingUnlock(unlock))
        XCTAssertTrue(service.approvedAppsToolsUnlocks.isEmpty)

        store.openVault(url: URL(fileURLWithPath: "/tmp/PendingUnlock.pswvault"))
        store.unlock(password: "correct horse")
        store.clearAppsToolsPendingRequestActionError()
        XCTAssertTrue(store.approveAppsToolsPendingUnlock(unlock))
        XCTAssertEqual(service.approvedAppsToolsUnlocks.first?.sessionId, 7)
        XCTAssertEqual(service.approvedAppsToolsUnlocks.first?.requestId, unlock.requestId)
    }

    func testSmartViewNavigationFiltersOneVaultAndUsesBrokerAuthorizationProjection() throws {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: ["personal"]
            )
        ])
        for (template, title) in [
            (CredentialTemplateKind.apiToken, "Deploy Token"),
            (.apiKey, "Build API Key"),
            (.sshKey, "Production SSH Key"),
            (.certificate, "Signing Certificate"),
            (.custom, "Opaque Secret")
        ] {
            var form = TemplateCredentialForm()
            form.template = template
            form.title = title
            form.secret = "seeded-secret-marker"
            _ = try service.createCredentialFromTemplate(sessionId: 7, form: form)
        }
        service.nextAuthorizedCredentialIds = ["item_2", "item_6"]
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/SmartViews.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertEqual(store.navigationCounts.logins, 1)
        XCTAssertEqual(store.navigationCounts.developerCredentials, 4)
        XCTAssertEqual(store.navigationCounts.keysAndCertificates, 2)
        XCTAssertEqual(store.navigationCounts.appsToolsAuthorized, 2)
        XCTAssertEqual(service.authorizedCredentialIdsCallCount, 1)

        XCTAssertTrue(store.applyNavigationDestination(.smartView(.logins)))
        XCTAssertEqual(store.items.map(\.title), ["Mail"])

        XCTAssertTrue(store.applyNavigationDestination(.smartView(.developerCredentials)))
        XCTAssertEqual(
            store.items.map(\.title),
            ["Deploy Token", "Build API Key", "Production SSH Key", "Signing Certificate"]
        )

        XCTAssertTrue(store.applyNavigationDestination(.smartView(.keysAndCertificates)))
        XCTAssertEqual(store.items.map(\.title), ["Production SSH Key", "Signing Certificate"])

        XCTAssertTrue(store.applyNavigationDestination(.smartView(.appsToolsAuthorized)))
        XCTAssertEqual(store.items.map(\.title), ["Deploy Token", "Opaque Secret"])
        XCTAssertEqual(service.authorizedCredentialIdsCallCount, 2)

        XCTAssertTrue(store.clearListFilters())
        XCTAssertEqual(store.navigationDestination, .allItems)
        XCTAssertEqual(store.items.count, 6)

        store.select(itemId: "item_1")
        store.setEditorHasUnsavedChanges(true)
        XCTAssertTrue(store.navigationDestinationHidesSelectedItem(.smartView(.developerCredentials)))
        XCTAssertFalse(store.applyNavigationDestination(.smartView(.developerCredentials)))
        XCTAssertEqual(store.navigationDestination, .allItems)
        XCTAssertEqual(store.selectedItemId, "item_1")
        XCTAssertTrue(store.applyNavigationDestination(
            .smartView(.developerCredentials),
            discardingUnsavedEdits: true
        ))
    }

    func testAuthorizedSmartViewFailsClosedWhenBrokerInventoryIsUnavailable() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: []
            )
        ])
        service.nextAuthorizedCredentialIds = ["item_1"]
        service.authorizationInventoryError = CoreBridgeError.commandFailed(
            "device state unavailable"
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/UnavailableAuthorization.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertFalse(store.appsToolsAuthorizationInventoryAvailable)
        XCTAssertTrue(store.authorizedCredentialIds.isEmpty)
        XCTAssertTrue(store.applyNavigationDestination(.appsAndTools))
        XCTAssertEqual(store.navigationDestination, .appsAndTools)
        XCTAssertEqual(
            store.statusMessage,
            "Apps & Tools authorization inventory unavailable"
        )
        XCTAssertTrue(store.applyNavigationDestination(.smartView(.appsToolsAuthorized)))
        XCTAssertTrue(store.items.isEmpty)
        XCTAssertEqual(
            store.statusMessage,
            "Apps & Tools authorization inventory unavailable"
        )
    }

    func testVaultNavigationCountsUseStableNonSecretSummaries() {
        let items = [
            VaultItemView(
                id: "login_favorite",
                title: "Mail",
                itemType: "login",
                status: "active",
                favorite: true,
                tags: ["personal"]
            ),
            VaultItemView(
                id: "card",
                title: "Bank Card",
                itemType: "credit card",
                status: "active",
                favorite: false,
                tags: ["finance"]
            ),
            VaultItemView(
                id: "login_conflict",
                title: "Forum",
                itemType: "login",
                status: "conflicted",
                conflictId: "conflict_1",
                favorite: false,
                tags: ["Personal"]
            ),
            VaultItemView(
                id: "archived_note",
                title: "Old Note",
                itemType: "secure note",
                status: "archived",
                favorite: true,
                tags: ["legacy"]
            )
        ]
        let health = PasswordHealthPayload(
            checkedLoginPasswords: 3,
            weakPasswords: 1,
            reusedPasswords: 2,
            issues: [
                PasswordHealthIssue(itemId: "login_favorite", title: "Mail", kind: .weakPassword),
                PasswordHealthIssue(itemId: "login_favorite", title: "Mail", kind: .reusedPassword),
                PasswordHealthIssue(itemId: "login_conflict", title: "Forum", kind: .reusedPassword)
            ]
        )

        let counts = VaultNavigationCounts(items: items, passwordHealth: health)

        XCTAssertEqual(counts.allItems, 3)
        XCTAssertEqual(counts.favorites, 1)
        XCTAssertEqual(counts.logins, 2)
        XCTAssertEqual(counts.developerCredentials, 0)
        XCTAssertEqual(counts.keysAndCertificates, 0)
        XCTAssertEqual(counts.appsToolsAuthorized, 0)
        XCTAssertEqual(counts.security, 2)
        XCTAssertEqual(counts.conflicts, 1)
        XCTAssertEqual(counts.archived, 1)
        XCTAssertEqual(counts.itemTypes.map(\.value), ["login", "credit card"])
        XCTAssertEqual(counts.itemTypes.map(\.count), [2, 1])
        XCTAssertEqual(counts.tags.map(\.value), ["finance", "personal"])
        XCTAssertEqual(counts.tags.map(\.count), [1, 2])
        XCTAssertEqual(counts.count(for: .itemType("LOGIN")), 2)
        XCTAssertEqual(counts.count(for: .tag("PERSONAL")), 2)
    }

    func testNavigationDestinationsFilterItemsAndKeepStableCounts() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "",
                tags: ["finance"]
            ),
            SeedLogin(
                title: "Old",
                username: "old",
                password: "old-password",
                url: "https://old.example.com",
                notes: "",
                tags: ["legacy"]
            )
        ])
        service.markArchived(itemId: "item_3")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/NavigationDestinations.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertEqual(store.navigationCounts.allItems, 2)
        XCTAssertEqual(store.navigationCounts.archived, 1)
        XCTAssertEqual(store.navigationItems.count, 3)

        XCTAssertTrue(store.applyNavigationDestination(.favorites))
        XCTAssertEqual(store.items.map(\.title), ["Mail"])
        XCTAssertEqual(store.navigationCounts.allItems, 2)

        XCTAssertTrue(store.applyNavigationDestination(.archive))
        XCTAssertEqual(store.items.map(\.title), ["Old"])
        XCTAssertTrue(store.includeArchived)
        XCTAssertTrue(store.showArchivedOnly)

        XCTAssertTrue(store.applyNavigationDestination(.tag("finance")))
        XCTAssertEqual(store.items.map(\.title), ["Bank"])
        XCTAssertFalse(store.includeArchived)
        XCTAssertFalse(store.showArchivedOnly)

        store.searchText = "Mail"
        store.search()
        XCTAssertEqual(store.navigationCounts.allItems, 2)
        XCTAssertEqual(store.navigationCounts.archived, 1)

        XCTAssertTrue(store.applyNavigationDestination(.allItems))
        XCTAssertEqual(store.items.map(\.title), ["Mail"])
        XCTAssertEqual(store.searchText, "Mail")
    }

    func testNavigationDestinationOnlyRequiresDiscardWhenSelectionIsHidden() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: ["personal"],
                favorite: true
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "",
                tags: ["finance"]
            )
        ])
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/NavigationDirtyGuard.pswvault"))
        store.unlock(password: "correct horse")
        store.setEditorHasUnsavedChanges(true)

        XCTAssertFalse(store.navigationDestinationHidesSelectedItem(.favorites))
        XCTAssertTrue(store.applyNavigationDestination(.favorites))
        XCTAssertEqual(store.selectedItemId, "item_1")

        XCTAssertTrue(store.navigationDestinationHidesSelectedItem(.tag("finance")))
        XCTAssertFalse(store.applyNavigationDestination(.tag("finance")))
        XCTAssertEqual(store.navigationDestination, .favorites)
        XCTAssertEqual(store.items.map(\.title), ["Mail"])
        XCTAssertEqual(store.statusMessage, "Save or discard edits before changing selection")

        XCTAssertTrue(store.applyNavigationDestination(.tag("finance"), discardingUnsavedEdits: true))
        XCTAssertEqual(store.navigationDestination, .tag("finance"))
        XCTAssertEqual(store.items.map(\.title), ["Bank"])
        XCTAssertEqual(store.selectedItemId, "item_2")
    }

    func testNavigationInventoryRefreshesAfterMutationAndClearsOnLock() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Mail",
                username: "me@example.com",
                password: "mail-password",
                url: "https://mail.example.com",
                notes: "",
                tags: ["personal"]
            ),
            SeedLogin(
                title: "Bank",
                username: "alice",
                password: "bank-password",
                url: "https://bank.example.com",
                notes: "",
                tags: ["finance"]
            )
        ])
        service.nextPasswordHealthPayload = PasswordHealthPayload(
            checkedLoginPasswords: 2,
            weakPasswords: 1,
            reusedPasswords: 1,
            issues: [
                PasswordHealthIssue(itemId: "item_1", title: "Mail", kind: .weakPassword),
                PasswordHealthIssue(itemId: "item_1", title: "Mail", kind: .reusedPassword)
            ]
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: URL(fileURLWithPath: "/tmp/NavigationLifecycle.pswvault"))
        store.unlock(password: "correct horse")
        store.refreshPasswordHealth()
        XCTAssertEqual(store.navigationCounts.security, 1)

        XCTAssertTrue(store.archiveSelected())
        XCTAssertEqual(store.navigationCounts.allItems, 1)
        XCTAssertEqual(store.navigationCounts.archived, 1)
        XCTAssertEqual(store.navigationCounts.security, 0)

        store.lock()
        XCTAssertTrue(store.navigationItems.isEmpty)
        XCTAssertEqual(store.navigationCounts, .empty)
        XCTAssertEqual(store.navigationDestination, .allItems)
    }

    func testNavigationLabelsAreLocalizedAcrossSupportedLanguages() {
        let english = AppText(AppLanguage.english.rawValue)
        let chinese = AppText(AppLanguage.simplifiedChinese.rawValue)
        let japanese = AppText(AppLanguage.japanese.rawValue)

        XCTAssertEqual(english.allItems, "All Items")
        XCTAssertEqual(chinese.allItems, "所有项目")
        XCTAssertEqual(japanese.allItems, "すべての項目")
        XCTAssertEqual(english.categories, "Categories")
        XCTAssertEqual(english.smartViews, "Smart Views")
        XCTAssertEqual(english.navigationTitle(.appsAndTools), "Apps & Tools")
        XCTAssertEqual(chinese.appsAndTools, "应用与工具")
        XCTAssertEqual(japanese.appsToolsOverview, "アクセス概要")
        XCTAssertEqual(english.pauseAppsToolsAccess, "Pause Machine Access")
        XCTAssertEqual(chinese.pauseAppsToolsAccess, "暂停机器访问")
        XCTAssertEqual(japanese.pauseAppsToolsAccess, "マシンアクセスを一時停止")
        XCTAssertEqual(english.inactive, "Inactive")
        XCTAssertEqual(chinese.selected, "已选择")
        XCTAssertEqual(japanese.notSelected, "未選択")
        XCTAssertEqual(english.accessRuleCount(1), "1 access rule")
        XCTAssertEqual(english.accessRuleCount(2), "2 access rules")
        XCTAssertEqual(chinese.accessRuleCount(2), "2 条访问规则")
        XCTAssertEqual(japanese.accessRuleCount(2), "アクセスルール 2 件")
        XCTAssertEqual(japanese.unpairConsumer, "コンシューマーのペアリングを解除")
        XCTAssertEqual(english.pendingRequests, "Pending Requests")
        XCTAssertEqual(chinese.reviewPendingRequests, "查看待处理请求")
        XCTAssertEqual(japanese.approvalNotificationTitle, "KeptNearの確認が必要です")
        XCTAssertEqual(chinese.pendingRequestKind("credential-access"), "匹配凭据")
        XCTAssertEqual(english.allowOnce, "Allow Once")
        XCTAssertEqual(chinese.configureLongTermAccess, "配置长期访问")
        XCTAssertEqual(japanese.deny, "拒否")
        XCTAssertEqual(chinese.requestActionFailed, "无法更新请求，请刷新后重试。")
        XCTAssertEqual(english.addUsageProfile, "Add Usage Profile")
        XCTAssertEqual(chinese.usageProfileSetupTitle, "凭据使用方式")
        XCTAssertEqual(japanese.advancedSettings, "詳細設定")
        XCTAssertEqual(chinese.environmentVariableName, "环境变量名称")
        XCTAssertEqual(japanese.httpHeaderName, "HTTPヘッダー名")
        XCTAssertEqual(
            english.usageProfileRecommendation("github-cli", toolName: "gh"),
            "Use an approved token with GitHub CLI."
        )
        XCTAssertEqual(
            chinese.usageProfileRecommendationName("gitlab-cli", fallback: "glab"),
            "GitLab CLI 令牌"
        )
        XCTAssertEqual(
            japanese.removeUsageProfileMessage("GitHub CLI"),
            "GitHub CLIを削除しますか？認証情報へのアクセス権は取り消されません。"
        )
        XCTAssertTrue(
            english.processCompatibilityDisclosure.contains("Rotate the credential")
        )
        XCTAssertTrue(
            chinese.processCompatibilityDisclosure.contains("轮换")
        )
        XCTAssertTrue(
            japanese.processCompatibilityDisclosure.contains("ローテーション")
        )
        XCTAssertTrue(
            english.unpairConsumerMessage("Codex").contains("stops future KeptNear delivery")
        )
        XCTAssertTrue(
            AppsToolsCompatibilityDisclosurePolicy.requiresDisclosure(
                capability: "process.run"
            )
        )
        XCTAssertFalse(
            AppsToolsCompatibilityDisclosurePolicy.requiresDisclosure(
                capability: "http.request"
            )
        )
        XCTAssertFalse(
            AppsToolsCompatibilityDisclosurePolicy.requiresDisclosure(capability: nil)
        )
        XCTAssertEqual(
            japanese.confirmationPolicyDetail(.oncePerUnlockSession),
            "保管庫をロック解除するたびに1回確認します。"
        )
        XCTAssertEqual(
            english.confirmationPolicy("automatic-while-unlocked"),
            "Automatic while unlocked"
        )
        XCTAssertEqual(
            chinese.credentialSelectionAccessibilityLabel(
                credentialTitle: "Deploy",
                fieldName: "Token",
                secretKind: chinese.credentialSecretKindName("api-token")
            ),
            "Deploy，Token，API 令牌"
        )
        XCTAssertEqual(
            japanese.credentialFieldAccessibilityName(
                role: "",
                label: nil,
                secretKind: "api-key"
            ),
            "APIキー"
        )
        XCTAssertEqual(
            chinese.credentialFieldAction(
                chinese.removeField,
                fieldName: "API 令牌"
            ),
            "移除字段：API 令牌"
        )
        let consumer = AppsToolsConsumerSummary(
            consumerId: "consumer_localization",
            label: "Codex",
            identity: AppsToolsConsumerIdentity(
                executableName: "codex",
                bundleIdentifier: nil,
                teamIdentifier: nil,
                codeSigningEvidence: "verified-without-team-identifier",
                codeSignatureFingerprint: nil
            ),
            accessRuleCount: 2,
            usageProfileCount: 0,
            createdAtMilliseconds: 1_700_000_000_000
        )
        XCTAssertEqual(
            english.consumerAccessibilityValue(consumer),
            "codex, 2 access rules"
        )
        XCTAssertEqual(
            chinese.consumerAccessibilityValue(consumer),
            "codex，2 条访问规则"
        )
        XCTAssertEqual(
            japanese.consumerAccessibilityValue(consumer),
            "codex、アクセスルール 2 件"
        )
        let localizedDates = [
            english.formattedDateTime(consumer.createdAtMilliseconds),
            chinese.formattedDateTime(consumer.createdAtMilliseconds),
            japanese.formattedDateTime(consumer.createdAtMilliseconds)
        ]
        XCTAssertTrue(localizedDates.allSatisfy { $0.contains("2023") })
        XCTAssertEqual(Set(localizedDates).count, 3)
        XCTAssertEqual(
            chinese.statusMessage("Apps & Tools field access revoked"),
            "字段访问已撤销"
        )
        XCTAssertEqual(
            japanese.statusMessage("Apps & Tools access paused"),
            "App・ツールのアクセスを一時停止しました"
        )
        XCTAssertEqual(chinese.developerCredentialsSmartView, "开发者凭据")
        XCTAssertEqual(japanese.keysAndCertificatesSmartView, "鍵と証明書")
        XCTAssertEqual(
            english.navigationTitle(.smartView(.appsToolsAuthorized)),
            "Apps & Tools Access"
        )
        XCTAssertEqual(
            chinese.statusMessage("Apps & Tools authorization inventory unavailable"),
            "应用与工具授权数据不可用"
        )
        XCTAssertEqual(chinese.vaultStatus, "密码库状态")
        XCTAssertEqual(japanese.unlockToViewItems, "項目を表示するにはロックを解除")
        XCTAssertEqual(english.navigationTitle(.itemType("credit card")), "Credit Card")
        XCTAssertEqual(chinese.navigationTitle(.tag("财务")), "财务")
        XCTAssertEqual(japanese.noItemSelected, "項目が選択されていません")
    }

    func testCreatingVaultBeginsRecoverySetupWithoutCopyingRecoveryMaterial() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let recoveryHandler = FakeRecoveryKitHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            recoveryKitHandler: recoveryHandler,
            userDefaults: makeIsolatedDefaults()
        )

        XCTAssertTrue(store.createVault(
            url: URL(fileURLWithPath: "/tmp/RecoverySetup.pswvault"),
            displayName: "Recovery Setup",
            password: "correct horse",
            confirmation: "correct horse"
        ))

        XCTAssertEqual(service.beginRecoverySetupCallCount, 1)
        XCTAssertEqual(store.recoveryKit?.workflowKind, .setup)
        XCTAssertEqual(store.recoveryStatus?.hasRecoveryEnvelope, true)
        XCTAssertFalse(store.recoveryKitHasExternalCopy)
        XCTAssertTrue(clipboard.copied.isEmpty)
        XCTAssertTrue(recoveryHandler.saved.isEmpty)
        XCTAssertTrue(recoveryHandler.printed.isEmpty)
    }

    func testRecoveryConfirmationRequiresExternalCopyAndRetainsKitAfterMismatch() {
        let service = FakeCoreService()
        let clipboard = FakeClipboard()
        let recoveryHandler = FakeRecoveryKitHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            recoveryKitHandler: recoveryHandler,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RecoveryConfirmation.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertTrue(store.beginRecoverySetup())
        let kit = try! XCTUnwrap(store.recoveryKit)
        XCTAssertFalse(store.confirmRecoveryKit(recoveryCode: kit.canonicalCode))
        XCTAssertTrue(service.recoveryConfirmations.isEmpty)

        let destination = URL(fileURLWithPath: "/tmp/KeptNear-Recovery-Kit.pdf")
        XCTAssertTrue(store.saveRecoveryKit(
            destinationURL: destination,
            copy: sampleRecoveryDocumentCopy()
        ))
        XCTAssertTrue(store.recoveryKitHasExternalCopy)
        XCTAssertEqual(recoveryHandler.saved.map(\.destinationURL), [destination])

        let exportedMaterial = [
            kit.vaultId,
            kit.recoveryKeyId,
            kit.canonicalCode,
            kit.groupedCode,
            kit.qrPayload,
            kit.verificationGroups.joined(separator: " ")
        ].joined(separator: " ")
        XCTAssertFalse(exportedMaterial.contains("/tmp/RecoveryConfirmation.pswvault"))
        XCTAssertFalse(exportedMaterial.contains("RecoveryConfirmation.pswvault"))

        XCTAssertFalse(store.confirmRecoveryKit(recoveryCode: "wrong recovery code"))
        XCTAssertEqual(store.recoveryKit, kit)
        XCTAssertEqual(service.recoveryConfirmations.count, 1)

        XCTAssertTrue(store.confirmRecoveryKit(recoveryCode: kit.canonicalCode))
        XCTAssertNil(store.recoveryKit)
        XCTAssertFalse(store.recoveryKitHasExternalCopy)
        XCTAssertEqual(store.recoveryStatus?.recoveryKeyId, kit.recoveryKeyId)
        XCTAssertEqual(service.recoveryConfirmations.count, 2)
        XCTAssertTrue(clipboard.copied.isEmpty)
    }

    func testPrintedRecoveryRotationCanBeDeferredWithoutReplacingExistingKey() {
        let service = FakeCoreService()
        service.nextRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        let clipboard = FakeClipboard()
        let recoveryHandler = FakeRecoveryKitHandler()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            recoveryKitHandler: recoveryHandler,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RecoveryRotation.pswvault"))
        store.unlock(password: "correct horse")

        XCTAssertTrue(store.beginRecoveryRotation())
        let kit = try! XCTUnwrap(store.recoveryKit)
        XCTAssertTrue(store.printRecoveryKit(copy: sampleRecoveryDocumentCopy()))
        XCTAssertEqual(recoveryHandler.printed, [kit])
        XCTAssertTrue(store.recoveryKitHasExternalCopy)

        store.deferRecoveryKit()

        XCTAssertEqual(service.cancelledRecoveryWorkflows.map(\.sessionId), [7])
        XCTAssertEqual(service.cancelledRecoveryWorkflows.map(\.workflowId), [kit.workflowId])
        XCTAssertNil(store.recoveryKit)
        XCTAssertEqual(store.recoveryStatus?.recoveryKeyId, "recovery_key_existing")
        XCTAssertEqual(
            store.statusMessage,
            "Recovery rotation cancelled; the existing recovery key remains active"
        )
        XCTAssertTrue(clipboard.copied.isEmpty)
    }

    func testLockClearsPendingRecoveryMaterialWithoutUsingClipboard() {
        let service = FakeCoreService()
        service.nextRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        let clipboard = FakeClipboard()
        let store = VaultStore(
            service: service,
            clipboard: clipboard,
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            recoveryKitHandler: FakeRecoveryKitHandler(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RecoveryLock.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertTrue(store.beginRecoveryRotation())
        XCTAssertNotNil(store.recoveryKit)

        store.lock()

        XCTAssertNil(store.recoveryKit)
        XCTAssertNil(store.recoveryStatus)
        XCTAssertEqual(service.lockedSessionIds, [7])
        XCTAssertTrue(clipboard.copied.isEmpty)
    }

    func testRecoveryCancellationFailureKeepsPendingKitVisible() {
        let service = FakeCoreService()
        service.nextRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        service.cancelRecoveryWorkflowError = CoreBridgeError.commandFailed(
            "recovery cancellation failed"
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            recoveryKitHandler: FakeRecoveryKitHandler(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RecoveryCancelFailure.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertTrue(store.beginRecoveryRotation())
        let kit = store.recoveryKit

        store.deferRecoveryKit()

        XCTAssertEqual(store.recoveryKit, kit)
        XCTAssertEqual(store.statusMessage, "recovery cancellation failed")
        XCTAssertTrue(service.cancelledRecoveryWorkflows.isEmpty)
    }

    func testRecoveryRotationCommitFailureClearsInvalidatedCandidate() {
        let service = FakeCoreService()
        service.nextRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        service.recoveryConfirmationError = CoreBridgeError.commandFailed(
            "recovery rotation commit failed; start again: stale candidate"
        )
        let recoveryHandler = FakeRecoveryKitHandler()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            recoveryKitHandler: recoveryHandler,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/RecoveryCommitFailure.pswvault"))
        store.unlock(password: "correct horse")
        XCTAssertTrue(store.beginRecoveryRotation())
        let kit = try! XCTUnwrap(store.recoveryKit)
        XCTAssertTrue(store.printRecoveryKit(copy: sampleRecoveryDocumentCopy()))

        XCTAssertFalse(store.confirmRecoveryKit(recoveryCode: kit.canonicalCode))

        XCTAssertNil(store.recoveryKit)
        XCTAssertFalse(store.recoveryKitHasExternalCopy)
        XCTAssertEqual(store.recoveryStatus?.recoveryKeyId, "recovery_key_existing")
        XCTAssertEqual(store.statusMessage, "Recovery rotation failed; start again")
    }

    func testRecoveryKitHandlerWritesPDFOnlyToExplicitDestination() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("KeptNearRecoveryKitTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let destination = directory.appendingPathComponent("chosen-recovery-kit.pdf")

        try MacRecoveryKitHandler().savePDF(
            kit: makeFakeRecoveryKit(
                workflowId: 901,
                workflowKind: .setup,
                recoveryKeyId: "recovery_key_pdf"
            ),
            copy: sampleRecoveryDocumentCopy(),
            destinationURL: destination
        )

        let data = try Data(contentsOf: destination)
        XCTAssertTrue(data.starts(with: Data("%PDF".utf8)))
        XCTAssertGreaterThan(data.count, 1_000)
        XCTAssertEqual(
            try FileManager.default.contentsOfDirectory(atPath: directory.path),
            ["chosen-recovery-kit.pdf"]
        )
    }

    func testRecoveryKitPayloadDecodesMinimalFFIContract() throws {
        let json = """
        {
          "ok": true,
          "payload": {
            "type": "recoveryKit",
            "workflow_id": 42,
            "workflow_kind": "setup",
            "vault_id": "vault_000102030405060708090a0b0c0d0e0f",
            "recovery_key_id": "recovery_key_101112131415161718191a1b1c1d1e1f",
            "generated_at_unix_seconds": 1800000000,
            "canonical_code": "knr1example",
            "grouped_code": "KNR1 EXAM PLE",
            "qr_payload": "knr1example",
            "verification_groups": ["EXAM"]
          }
        }
        """

        let response = try JSONDecoder().decode(
            CoreResponse.self,
            from: Data(json.utf8)
        )
        guard case let .recoveryKit(payload) = response.payload else {
            return XCTFail("expected recovery kit payload")
        }
        XCTAssertEqual(payload.workflowId, 42)
        XCTAssertEqual(payload.workflowKind, .setup)
        XCTAssertEqual(payload.canonicalCode, "knr1example")
        XCTAssertEqual(payload.verificationGroups, ["EXAM"])
        XCTAssertFalse(json.contains("\"path\""))
        XCTAssertFalse(json.contains("\"items\""))
    }

    func testLockedVaultRecoveryUsesRecoveryFirstFlowAndRevokesKeychainMaterial() {
        let service = FakeCoreService(seedItems: [
            SeedLogin(
                title: "Recovered Login",
                username: "alice",
                password: "secret",
                url: "https://example.com",
                notes: "",
                tags: []
            )
        ])
        service.nextLockedRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        let keychain = FakeConvenienceUnlockStore()
        let vaultURL = URL(fileURLWithPath: "/tmp/LockedRecovery.pswvault")
        try! keychain.saveMaterial("old-local-material", for: vaultURL)
        keychain.saveLegacyPasswordMaterial("old-password", for: vaultURL)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: keychain,
            userDefaults: makeIsolatedDefaults()
        )

        store.openVault(url: vaultURL)
        XCTAssertTrue(store.lockedRecoveryStatus?.hasRecoveryEnvelope == true)
        XCTAssertTrue(store.convenienceUnlockAvailable)

        XCTAssertTrue(store.recoverVault(
            recoveryCode: service.expectedRecoveryCode,
            newPassword: "new correct horse",
            confirmation: "new correct horse"
        ))

        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.items.map(\.title), ["Recovered Login"])
        XCTAssertEqual(service.recoveredVaultRequests.count, 1)
        XCTAssertEqual(service.recoveredVaultRequests.first?.path, vaultURL.path)
        XCTAssertEqual(service.recoveredVaultRequests.first?.recoveryCode, service.expectedRecoveryCode)
        XCTAssertEqual(service.recoveredVaultRequests.first?.newPassword, "new correct horse")
        XCTAssertEqual(keychain.deleteMaterialURLs, [vaultURL])
        XCTAssertEqual(keychain.deleteLegacyMaterialURLs, [vaultURL])
        XCTAssertNil(keychain.material(for: vaultURL))
        XCTAssertEqual(keychain.legacyPasswordMaterialCount(for: vaultURL), 0)
        XCTAssertFalse(store.convenienceUnlockAvailable)
        XCTAssertEqual(store.statusMessage, "Vault recovered")
    }

    func testLockedVaultRecoveryValidationDoesNotCallCore() {
        let service = FakeCoreService()
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: URL(fileURLWithPath: "/tmp/NoRecovery.pswvault"))

        XCTAssertFalse(store.recoverVault(
            recoveryCode: "code",
            newPassword: "new password",
            confirmation: "new password"
        ))
        XCTAssertEqual(store.statusMessage, "Offline recovery is not available for this vault")

        service.nextLockedRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        store.refreshLockedRecoveryStatus()
        XCTAssertFalse(store.recoverVault(
            recoveryCode: "",
            newPassword: "new password",
            confirmation: "new password"
        ))
        XCTAssertEqual(store.statusMessage, "Recovery code is required")
        XCTAssertFalse(store.recoverVault(
            recoveryCode: "code",
            newPassword: "",
            confirmation: ""
        ))
        XCTAssertEqual(store.statusMessage, "New master password is required")
        XCTAssertFalse(store.recoverVault(
            recoveryCode: "code",
            newPassword: "one",
            confirmation: "two"
        ))
        XCTAssertEqual(store.statusMessage, "New master passwords do not match")
        XCTAssertTrue(service.recoveredVaultRequests.isEmpty)
    }

    func testInvalidRecoveryCodeKeepsVaultLockedAndPreservesKeychainMaterial() {
        let service = FakeCoreService()
        service.nextLockedRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        service.recoverVaultError = CoreBridgeError.commandFailed("invalid vault credentials")
        let keychain = FakeConvenienceUnlockStore()
        let vaultURL = URL(fileURLWithPath: "/tmp/InvalidRecovery.pswvault")
        try! keychain.saveMaterial("working-local-material", for: vaultURL)
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: keychain,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)

        XCTAssertFalse(store.recoverVault(
            recoveryCode: "knr1wrong",
            newPassword: "new password",
            confirmation: "new password"
        ))

        XCTAssertFalse(store.isUnlocked)
        XCTAssertEqual(store.statusMessage, "Recovery code is invalid or does not match this vault")
        XCTAssertEqual(keychain.material(for: vaultURL), "working-local-material")
        XCTAssertTrue(keychain.deleteMaterialURLs.isEmpty)
        XCTAssertTrue(keychain.deleteLegacyMaterialURLs.isEmpty)
    }

    func testRecoveredVaultReportsPartialSuccessWhenKeychainRevocationFails() {
        let service = FakeCoreService()
        service.nextLockedRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: "recovery_key_existing"
        )
        let keychain = FakeConvenienceUnlockStore()
        let vaultURL = URL(fileURLWithPath: "/tmp/RecoveryCleanupFailure.pswvault")
        try! keychain.saveMaterial("old-local-material", for: vaultURL)
        keychain.deleteMaterialError = CoreBridgeError.commandFailed("keychain unavailable")
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: keychain,
            userDefaults: makeIsolatedDefaults()
        )
        store.openVault(url: vaultURL)

        XCTAssertTrue(store.recoverVault(
            recoveryCode: service.expectedRecoveryCode,
            newPassword: "new password",
            confirmation: "new password"
        ))

        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.statusMessage, "Vault recovered, but Keychain cleanup failed")
        XCTAssertEqual(keychain.material(for: vaultURL), "old-local-material")
        XCTAssertTrue(store.convenienceUnlockAvailable)
    }

    func testLockedRecoveryStatusFailureKeepsReplacementFallbackAvailable() {
        let service = FakeCoreService()
        service.lockedRecoveryStatusError = CoreBridgeError.commandFailed(
            "recovery envelope could not be inspected"
        )
        let store = VaultStore(
            service: service,
            clipboard: FakeClipboard(),
            convenienceUnlockStore: FakeConvenienceUnlockStore(),
            userDefaults: makeIsolatedDefaults()
        )

        XCTAssertTrue(store.openVault(
            url: URL(fileURLWithPath: "/tmp/UnknownRecoveryStatus.pswvault")
        ))

        XCTAssertNil(store.lockedRecoveryStatus)
        XCTAssertTrue(store.lockedRecoveryStatusCheckFailed)
        XCTAssertFalse(store.recoverVault(
            recoveryCode: service.expectedRecoveryCode,
            newPassword: "new password",
            confirmation: "new password"
        ))
        XCTAssertEqual(store.statusMessage, "Offline recovery is not available for this vault")
        XCTAssertTrue(service.recoveredVaultRequests.isEmpty)
    }

    private func sampleRecoveryDocumentCopy() -> RecoveryKitDocumentCopy {
        RecoveryKitDocumentCopy(
            title: "KeptNear Recovery Kit",
            authorityWarningTitle: "Recovery authority",
            authorityWarningMessage: "Keep this offline.",
            recoveryCodeLabel: "Recovery Code",
            vaultIdLabel: "Vault ID",
            recoveryKeyIdLabel: "Recovery Key ID",
            generatedLabel: "Generated",
            offlineStorageMessage: "Store separately from the vault."
        )
    }
}

private struct SeedLogin {
    var title: String
    var username: String
    var password: String
    var url: String
    var urls: [String]? = nil
    var notes: String
    var tags: [String]
    var totpSecret: String? = nil
    var favorite = false

    var normalizedURLs: [String] {
        urls ?? LoginForm.normalizedURLs(from: url)
    }
}

private struct SeedSecureNote {
    var title: String
    var body: String
    var tags: [String]
    var favorite = false
}

private struct SeedCreditCard {
    var title: String
    var cardholderName: String
    var number: String
    var expiryMonth: Int?
    var expiryYear: Int?
    var verificationCode: String
    var notes: String
    var tags: [String]
    var favorite = false
}

private struct SeedSoftwareLicense {
    var title: String
    var product: String
    var licenseKey: String
    var licensedTo: String
    var notes: String
    var tags: [String]
    var favorite = false
}

private final class FakeClipboard: ClipboardManaging {
    private(set) var copied: [(value: String, timeout: TimeInterval)] = []
    private(set) var currentValue: String?
    private(set) var clearManagedSecretCallCount = 0

    func copy(_ value: String, clearAfter seconds: TimeInterval) {
        copied.append((value, seconds))
        currentValue = value
    }

    func clearManagedSecret() {
        clearManagedSecretCallCount += 1
        currentValue = nil
    }
}

private final class FakePasteboard: PasteboardStoring {
    private var values: [NSPasteboard.PasteboardType: String] = [:]

    @discardableResult
    func clearContents() -> Int {
        values.removeAll()
        return 0
    }

    @discardableResult
    func setString(_ string: String, forType dataType: NSPasteboard.PasteboardType) -> Bool {
        values[dataType] = string
        return true
    }

    func string(forType dataType: NSPasteboard.PasteboardType) -> String? {
        values[dataType]
    }
}

private final class FakeImportSourceHandler: ImportSourceHandling {
    private(set) var revealedURLs: [URL] = []
    private(set) var trashedURLs: [URL] = []
    var trashError: Error?

    func revealInFinder(_ url: URL) {
        revealedURLs.append(url)
    }

    func moveToTrash(_ url: URL) throws {
        trashedURLs.append(url)
        if let trashError {
            throw trashError
        }
    }
}

private final class FakeURLOpener: URLOpening {
    private(set) var openedURLs: [URL] = []

    func open(_ url: URL) {
        openedURLs.append(url)
    }
}

@MainActor
private final class FakeRecoveryKitHandler: RecoveryKitHandling {
    struct SavedRecoveryKit {
        let kit: RecoveryKitPayload
        let copy: RecoveryKitDocumentCopy
        let destinationURL: URL
    }

    private(set) var saved: [SavedRecoveryKit] = []
    private(set) var printed: [RecoveryKitPayload] = []
    var saveError: Error?
    var printError: Error?

    func savePDF(
        kit: RecoveryKitPayload,
        copy: RecoveryKitDocumentCopy,
        destinationURL: URL
    ) throws {
        if let saveError {
            throw saveError
        }
        saved.append(SavedRecoveryKit(
            kit: kit,
            copy: copy,
            destinationURL: destinationURL
        ))
    }

    func printKit(kit: RecoveryKitPayload, copy: RecoveryKitDocumentCopy) throws {
        if let printError {
            throw printError
        }
        printed.append(kit)
    }
}

private final class FakeConvenienceUnlockStore: ConvenienceUnlockStoring {
    private var materials: [String: String] = [:]
    private var legacyPasswordMaterials: [String: [String: String]] = [:]
    private(set) var deleteMaterialURLs: [URL] = []
    private(set) var deleteLegacyMaterialURLs: [URL] = []
    var deleteMaterialError: Error?
    var deleteLegacyMaterialError: Error?

    func containsMaterial(for vaultURL: URL) -> Bool {
        materials[key(for: vaultURL)] != nil
    }

    func loadMaterial(for vaultURL: URL) throws -> String? {
        materials[key(for: vaultURL)]
    }

    func saveMaterial(_ material: String, for vaultURL: URL) throws {
        materials[key(for: vaultURL)] = material
    }

    func deleteMaterial(for vaultURL: URL) throws {
        deleteMaterialURLs.append(vaultURL.standardizedFileURL)
        if let deleteMaterialError {
            throw deleteMaterialError
        }
        materials[key(for: vaultURL)] = nil
    }

    func deleteLegacyPasswordMaterial(for vaultURL: URL) throws -> Int {
        deleteLegacyMaterialURLs.append(vaultURL.standardizedFileURL)
        if let deleteLegacyMaterialError {
            throw deleteLegacyMaterialError
        }
        let vaultKey = key(for: vaultURL)
        let removed = legacyPasswordMaterials[vaultKey]?.count ?? 0
        legacyPasswordMaterials[vaultKey] = nil
        return removed
    }

    func material(for vaultURL: URL) -> String? {
        materials[key(for: vaultURL)]
    }

    func saveLegacyPasswordMaterial(_ material: String, service: String = "legacy", for vaultURL: URL) {
        var services = legacyPasswordMaterials[key(for: vaultURL), default: [:]]
        services[service] = material
        legacyPasswordMaterials[key(for: vaultURL)] = services
    }

    func legacyPasswordMaterialCount(for vaultURL: URL) -> Int {
        legacyPasswordMaterials[key(for: vaultURL)]?.count ?? 0
    }

    func resetDeleteCallHistory() {
        deleteMaterialURLs = []
        deleteLegacyMaterialURLs = []
    }

    private func key(for vaultURL: URL) -> String {
        vaultURL.standardizedFileURL.path
    }
}

private func makeFakeRecoveryKit(
    workflowId: UInt64,
    workflowKind: RecoveryWorkflowKind,
    recoveryKeyId: String
) -> RecoveryKitPayload {
    let canonicalCode = "knr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7a7n6ss"
    let payloadCharacters = Array(canonicalCode.uppercased().dropFirst(4))
    let groups = stride(from: 0, to: payloadCharacters.count, by: 4).map { start in
        String(payloadCharacters[start ..< min(start + 4, payloadCharacters.count)])
    }
    return RecoveryKitPayload(
        workflowId: workflowId,
        workflowKind: workflowKind,
        vaultId: "vault_000102030405060708090a0b0c0d0e0f",
        recoveryKeyId: recoveryKeyId,
        generatedAtUnixSeconds: 1_800_000_000,
        canonicalCode: canonicalCode,
        groupedCode: "KNR1 \(groups.joined(separator: " "))",
        qrPayload: canonicalCode,
        verificationGroups: groups.filter { $0.count == 4 }
    )
}

@MainActor
private final class FakeApprovalNotificationScheduler: ApprovalNotificationScheduling {
    struct Posted: Equatable {
        let identifier: String
        let title: String
        let body: String
    }

    var prepareCallCount = 0
    var posted: [Posted] = []
    var reconciled: [Set<String>] = []

    func prepare() {
        prepareCallCount += 1
    }

    func postPendingRequest(identifier: String, title: String, body: String) {
        posted.append(
            Posted(identifier: identifier, title: title, body: body)
        )
    }

    func reconcile(activeRequestIdentifiers: Set<String>) {
        reconciled.append(activeRequestIdentifiers)
    }
}

private func makeAppsToolsPendingRequest(
    requestSource: String = "approval",
    requestId: String,
    kind: String,
    credentialId: String? = nil,
    secretFieldId: String? = nil
) -> AppsToolsPendingRequest {
    AppsToolsPendingRequest(
        requestSource: requestSource,
        requestId: requestId,
        kind: kind,
        consumerId: requestSource == "approval" ? "consumer_01" : nil,
        consumerLabel: requestSource == "approval" ? "Local adapter" : nil,
        identity: nil,
        pairingComparisonCode: requestSource == "pairing" ? "0123456789" : nil,
        pairingKeyFingerprint: requestSource == "pairing" ? "1112-1314-1516-1718" : nil,
        vaultId: requestSource == "approval" ? "vault_01" : nil,
        credentialId: credentialId,
        secretFieldId: secretFieldId,
        capability: kind == "access" || kind == "credential-access" ? "process.run" : nil,
        capabilityVersion: kind == "access" || kind == "credential-access" ? 1 : nil,
        requestDescription: kind == "credential-access" ? "release credential" : nil,
        createdAtMilliseconds: 100,
        expiresAtMilliseconds: 200,
        remainingMilliseconds: nil
    )
}

private final class FakeCoreService: CoreService {
    var isAvailable = true
    var status = "Fake core connected"
    var createdPath: String?
    var openedPath: String?
    var lockedSessionIds: [UInt64] = []
    var previewedImportPath: String?
    var previewedImportFormat: String?
    var committedImportPath: String?
    var committedImportFormat: String?
    var committedKeepDuplicates: Bool?
    var exportedPath: String?
    var exportedFormat: String?
    var exportedCurrentPassword: String?
    var backupDestinationPath: String?
    var restoreSourcePath: String?
    var restoreDestinationPath: String?
    var backupCallCount = 0
    var restoreBackupCallCount = 0
    var refreshCallCount = 0
    var passwordHealthCallCount = 0
    var authorizedCredentialIdsCallCount = 0
    var appsToolsVaultPathConflict = false
    var nextAuthorizedCredentialIds: Set<String> = []
    var nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue.empty
    var appsToolsPendingRequestsCallCount = 0
    var appsToolsPendingRequestsError: Error?
    var appsToolsPendingRequestDecisionError: Error?
    var deniedAppsToolsPendingRequests: [(requestSource: String, requestId: String)] = []
    var approvedAppsToolsPairings: [(requestId: String, label: String)] = []
    var approvedAppsToolsUnlocks: [(sessionId: UInt64, requestId: String)] = []
    var reviewedAppsToolsCredentials: [(sessionId: UInt64, requestId: String)] = []
    var nextAppsToolsCredentialReview: AppsToolsCredentialReview?
    var allowedOnceAppsToolsRequests: [
        (
            sessionId: UInt64,
            requestId: String,
            credentialId: String?,
            secretFieldId: String?
        )
    ] = []
    var configuredLongTermAppsToolsRequests: [
        (
            sessionId: UInt64,
            requestId: String,
            credentialId: String?,
            secretFieldId: String?,
            confirmationPolicy: AppsToolsConfirmationPolicy
        )
    ] = []
    var nextAppsToolsPaused = false
    var nextAppsToolsConsumers: [AppsToolsConsumerSummary] = []
    var nextAppsToolsConsumerDetails: [String: AppsToolsConsumerDetail] = [:]
    var appsToolsConsumerDetailRequests: [String] = []
    var nextAppsToolsUsageProfileSetups: [String: AppsToolsUsageProfileSetup] = [:]
    var appsToolsUsageProfileSetupRequests: [String] = []
    var createdAppsToolsUsageProfiles: [
        (sessionId: UInt64, consumerId: String, draft: AppsToolsUsageProfileDraft)
    ] = []
    var removedAppsToolsUsageProfiles: [
        (sessionId: UInt64, consumerId: String, usageProfileId: String)
    ] = []
    var appsToolsUsageProfileError: Error?
    var appsToolsPauseRequests: [Bool] = []
    var revokedAppsToolsFields: [AppsToolsFieldReference] = []
    var revokedAppsToolsConsumers: [String] = []
    var createCredentialCallCount = 0
    var updateCredentialCallCount = 0
    var duplicateCredentialCallCount = 0
    var lastCredentialUpdateForm: CredentialEditorForm?
    var createLoginCallCount = 0
    var updateLoginCallCount = 0
    var createSecureNoteCallCount = 0
    var updateSecureNoteCallCount = 0
    var createCreditCardCallCount = 0
    var updateCreditCardCallCount = 0
    var createSoftwareLicenseCallCount = 0
    var updateSoftwareLicenseCallCount = 0
    var archiveItemCallCount = 0
    var restoreItemCallCount = 0
    var deleteItemCallCount = 0
    var setFavoriteCallCount = 0
    var totpCodeCallCount = 0
    var loginFieldRequests: [String] = []
    var creditCardFieldRequests: [String] = []
    var softwareLicenseFieldRequests: [String] = []
    var credentialSecretFieldRequests: [String] = []
    var quarantineRejectedCallCount = 0
    var importSecureNoteOnCommit = false
    var importCreditCardOnCommit = false
    var localUnlockMaterialRequests: [UInt64] = []
    var localMaterialUnlockPath: String?
    var localMaterialUsed: String?
    var masterPasswordChanges: [(sessionId: UInt64, currentPassword: String, newPassword: String)] = []
    var localMaterialUnlockError: Error?
    var changeMasterPasswordError: Error?
    var lockedRecoveryStatusError: Error?
    var recoverVaultError: Error?
    var recoveryStatusError: Error?
    var beginRecoverySetupError: Error?
    var beginRecoveryRotationError: Error?
    var recoveryConfirmationError: Error?
    var cancelRecoveryWorkflowError: Error?
    var refreshError: Error?
    var authorizationInventoryError: Error?
    var recoveryStatusCallCount = 0
    var lockedRecoveryStatusRequests: [String] = []
    var recoveredVaultRequests: [(path: String, recoveryCode: String, newPassword: String)] = []
    let expectedRecoveryCode = "knr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7a7n6ss"
    var nextLockedRecoveryStatus = RecoveryStatusPayload(
        hasRecoveryEnvelope: false,
        recoveryKeyId: nil
    )
    var beginRecoverySetupCallCount = 0
    var beginRecoveryRotationCallCount = 0
    var recoveryConfirmations: [(sessionId: UInt64, workflowId: UInt64, recoveryCode: String)] = []
    var cancelledRecoveryWorkflows: [(sessionId: UInt64, workflowId: UInt64)] = []
    var nextRecoveryStatus = RecoveryStatusPayload(
        hasRecoveryEnvelope: false,
        recoveryKeyId: nil
    )
    var nextRecoverySetupKit = makeFakeRecoveryKit(
        workflowId: 801,
        workflowKind: .setup,
        recoveryKeyId: "recovery_key_setup"
    )
    var nextRecoveryRotationKit = makeFakeRecoveryKit(
        workflowId: 802,
        workflowKind: .rotation,
        recoveryKeyId: "recovery_key_rotation"
    )
    var resolvedConflictIds: [String] = []
    var loadedConflictIds: [String] = []
    var resolvedConflictCandidateRevisions: [String] = []
    var resolvedConflictMergeRequests: [(conflictId: String, baseRevision: String, fieldSelections: [ConflictMergeFieldSelection])] = []
    var nextConflictCandidates: [ConflictCandidateView] = []
    var nextRefreshPayload = SyncRefreshPayload(
        loadedItems: 0,
        appliedTombstones: 0,
        detectedConflicts: 0,
        rejectedRecords: 0,
        items: []
    )
    var nextRefreshPayloadAfterQuarantine: SyncRefreshPayload?
    var nextQuarantinePayload = SyncQuarantinePayload(
        movedRecords: 0,
        movedItemRecords: 0,
        movedTombstoneRecords: 0
    )
    var nextExportResult = ExportResultPayload(
        exportedRecords: 0,
        skippedRecords: 0,
        warnings: []
    )
    var nextBackupResult = BackupResultPayload(
        copiedItemFiles: 0,
        copiedAttachmentFiles: 0,
        copiedTombstoneFiles: 0
    )
    var nextRestoreBackupResult = RestoreBackupResultPayload(
        copiedItemFiles: 0,
        copiedAttachmentFiles: 0,
        copiedTombstoneFiles: 0
    )
    var nextPasswordHealthPayload = PasswordHealthPayload(
        checkedLoginPasswords: 0,
        weakPasswords: 0,
        reusedPasswords: 0,
        issues: []
    )

    private var items: [VaultItemView] = []
    private var details: [String: LoginDetail] = [:]
    private var credentialDetails: [String: CredentialDetail] = [:]
    private var credentialSecrets: [String: [String: String]] = [:]
    private var secureNoteDetails: [String: SecureNoteDetail] = [:]
    private var creditCardDetails: [String: CreditCardDetail] = [:]
    private var softwareLicenseDetails: [String: SoftwareLicenseDetail] = [:]
    private var passwords: [String: String] = [:]
    private var cardNumbers: [String: String] = [:]
    private var cardVerificationCodes: [String: String] = [:]
    private var licenseKeys: [String: String] = [:]
    private var nextId = 1
    private var nextRevision = 1
    private var nextUsageProfileId = 1

    init(seedItems: [SeedLogin] = []) {
        for seed in seedItems {
            insert(seed: seed)
        }
    }

    func forceRevision(itemId: String, revision: String) {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            return
        }
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: items[index].title,
            itemType: items[index].itemType,
            templateId: items[index].templateId,
            secretKinds: items[index].secretKinds,
            status: items[index].status,
            conflictId: items[index].conflictId,
            favorite: items[index].favorite,
            tags: items[index].tags
        )
        setDetailRevision(itemId: itemId, revision: revision)
    }

    func markConflicted(itemId: String, conflictId: String, revision: String = "rev_conflict") {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            return
        }
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: items[index].title,
            itemType: items[index].itemType,
            templateId: items[index].templateId,
            secretKinds: items[index].secretKinds,
            status: "conflicted",
            conflictId: conflictId,
            favorite: items[index].favorite,
            tags: items[index].tags
        )
        setDetailRevision(itemId: itemId, revision: revision)
    }

    func markArchived(itemId: String, revision: String = "rev_archived") {
        setStatus(itemId: itemId, status: "archived", revision: revision)
    }

    func createVault(path: String, displayName: String?, password: String) throws {
        createdPath = path
    }

    func openVault(path: String) throws {
        openedPath = path
    }

    func lockedRecoveryStatus(path: String) throws -> RecoveryStatusPayload {
        lockedRecoveryStatusRequests.append(path)
        if let lockedRecoveryStatusError {
            throw lockedRecoveryStatusError
        }
        return nextLockedRecoveryStatus
    }

    func unlock(path: String, password: String) throws -> UnlockedPayload {
        UnlockedPayload(
            sessionId: 7,
            items: visibleItems(includeArchived: false),
            appsToolsVaultPathConflict: appsToolsVaultPathConflict
        )
    }

    func unlockWithLocalMaterial(path: String, localMaterial: String) throws -> UnlockedPayload {
        localMaterialUnlockPath = path
        localMaterialUsed = localMaterial
        if let localMaterialUnlockError {
            throw localMaterialUnlockError
        }
        return UnlockedPayload(
            sessionId: 9,
            items: visibleItems(includeArchived: false),
            appsToolsVaultPathConflict: appsToolsVaultPathConflict
        )
    }

    func recoverVault(
        path: String,
        recoveryCode: String,
        newPassword: String
    ) throws -> UnlockedPayload {
        recoveredVaultRequests.append((
            path: path,
            recoveryCode: recoveryCode,
            newPassword: newPassword
        ))
        if let recoverVaultError {
            throw recoverVaultError
        }
        guard recoveryCode == expectedRecoveryCode else {
            throw CoreBridgeError.commandFailed("invalid vault credentials")
        }
        nextRecoveryStatus = nextLockedRecoveryStatus
        return UnlockedPayload(
            sessionId: 11,
            items: visibleItems(includeArchived: false),
            appsToolsVaultPathConflict: appsToolsVaultPathConflict
        )
    }

    func localUnlockMaterial(sessionId: UInt64) throws -> String {
        localUnlockMaterialRequests.append(sessionId)
        return "local-material-\(sessionId)"
    }

    func changeMasterPassword(sessionId: UInt64, currentPassword: String, newPassword: String) throws {
        if let changeMasterPasswordError {
            throw changeMasterPasswordError
        }
        masterPasswordChanges.append((sessionId, currentPassword, newPassword))
    }

    func recoveryStatus(sessionId: UInt64) throws -> RecoveryStatusPayload {
        recoveryStatusCallCount += 1
        if let recoveryStatusError {
            throw recoveryStatusError
        }
        return nextRecoveryStatus
    }

    func beginRecoverySetup(sessionId: UInt64) throws -> RecoveryKitPayload {
        beginRecoverySetupCallCount += 1
        if let beginRecoverySetupError {
            throw beginRecoverySetupError
        }
        nextRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: nextRecoverySetupKit.recoveryKeyId
        )
        nextLockedRecoveryStatus = nextRecoveryStatus
        return nextRecoverySetupKit
    }

    func beginRecoveryRotation(sessionId: UInt64) throws -> RecoveryKitPayload {
        beginRecoveryRotationCallCount += 1
        if let beginRecoveryRotationError {
            throw beginRecoveryRotationError
        }
        return nextRecoveryRotationKit
    }

    func confirmRecoveryWorkflow(
        sessionId: UInt64,
        workflowId: UInt64,
        recoveryCode: String
    ) throws -> RecoveryConfirmationPayload {
        recoveryConfirmations.append((
            sessionId: sessionId,
            workflowId: workflowId,
            recoveryCode: recoveryCode
        ))
        if let recoveryConfirmationError {
            throw recoveryConfirmationError
        }
        let kit: RecoveryKitPayload
        if workflowId == nextRecoverySetupKit.workflowId {
            kit = nextRecoverySetupKit
        } else if workflowId == nextRecoveryRotationKit.workflowId {
            kit = nextRecoveryRotationKit
        } else {
            throw CoreBridgeError.commandFailed("unknown recovery workflow")
        }
        guard recoveryCode == kit.canonicalCode || recoveryCode == kit.groupedCode else {
            throw CoreBridgeError.commandFailed("recovery confirmation did not match")
        }
        nextRecoveryStatus = RecoveryStatusPayload(
            hasRecoveryEnvelope: true,
            recoveryKeyId: kit.recoveryKeyId
        )
        nextLockedRecoveryStatus = nextRecoveryStatus
        return RecoveryConfirmationPayload(
            workflowKind: kit.workflowKind,
            recoveryKeyId: kit.recoveryKeyId
        )
    }

    func cancelRecoveryWorkflow(sessionId: UInt64, workflowId: UInt64) throws {
        if let cancelRecoveryWorkflowError {
            throw cancelRecoveryWorkflowError
        }
        cancelledRecoveryWorkflows.append((
            sessionId: sessionId,
            workflowId: workflowId
        ))
    }

    func lock(sessionId: UInt64) throws {
        lockedSessionIds.append(sessionId)
    }

    func listItems(sessionId: UInt64) throws -> [VaultItemView] {
        visibleItems(includeArchived: false)
    }

    func passwordHealth(sessionId: UInt64) throws -> PasswordHealthPayload {
        passwordHealthCallCount += 1
        return nextPasswordHealthPayload
    }

    func refreshFromDisk(sessionId: UInt64) throws -> SyncRefreshPayload {
        refreshCallCount += 1
        if let refreshError {
            throw refreshError
        }
        items = nextRefreshPayload.items
        return nextRefreshPayload
    }

    func quarantineRejectedRecords(sessionId: UInt64) throws -> SyncQuarantinePayload {
        quarantineRejectedCallCount += 1
        if let nextRefreshPayloadAfterQuarantine {
            nextRefreshPayload = nextRefreshPayloadAfterQuarantine
        }
        return nextQuarantinePayload
    }

    func search(sessionId: UInt64, text: String, includeArchived: Bool) throws -> [VaultItemView] {
        let candidates = visibleItems(includeArchived: includeArchived)
        let needle = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else {
            return candidates
        }
        return candidates.filter { item in
            let haystack: String
            if let detail = details[item.id] {
                haystack = [
                    item.title,
                    detail.username ?? "",
                    detail.urls.joined(separator: " "),
                    detail.notes ?? "",
                    item.tags.joined(separator: " "),
                    item.itemType
                ]
                .joined(separator: " ")
                .lowercased()
            } else if let detail = secureNoteDetails[item.id] {
                haystack = [
                    item.title,
                    detail.body,
                    item.tags.joined(separator: " "),
                    item.itemType
                ]
                .joined(separator: " ")
                .lowercased()
            } else if let detail = creditCardDetails[item.id] {
                haystack = [
                    item.title,
                    detail.cardholderName ?? "",
                    detail.notes ?? "",
                    item.tags.joined(separator: " "),
                    item.itemType
                ]
                .joined(separator: " ")
                .lowercased()
            } else if let detail = softwareLicenseDetails[item.id] {
                haystack = [
                    item.title,
                    detail.product ?? "",
                    detail.licensedTo ?? "",
                    detail.notes ?? "",
                    item.tags.joined(separator: " "),
                    item.itemType
                ]
                .joined(separator: " ")
                .lowercased()
            } else if let detail = credentialDetails[item.id] {
                haystack = [
                    item.title,
                    detail.textFields.map(\.text).joined(separator: " "),
                    item.tags.joined(separator: " "),
                    item.itemType
                ]
                .joined(separator: " ")
                .lowercased()
            } else {
                return false
            }
            return haystack.contains(needle)
        }
    }

    func listAuthorizedCredentialIds(sessionId: UInt64) throws -> Set<String> {
        authorizedCredentialIdsCallCount += 1
        if let authorizationInventoryError {
            throw authorizationInventoryError
        }
        return nextAuthorizedCredentialIds
    }

    func appsToolsSnapshot(sessionId: UInt64) throws -> AppsToolsSnapshot {
        authorizedCredentialIdsCallCount += 1
        if let authorizationInventoryError {
            throw authorizationInventoryError
        }
        return currentAppsToolsSnapshot()
    }

    func appsToolsPendingRequests() throws -> AppsToolsPendingRequestQueue {
        appsToolsPendingRequestsCallCount += 1
        if let appsToolsPendingRequestsError {
            throw appsToolsPendingRequestsError
        }
        return nextAppsToolsPendingRequests
    }

    func denyAppsToolsPendingRequest(
        requestSource: String,
        requestId: String
    ) throws -> AppsToolsPendingRequestDecision {
        if let appsToolsPendingRequestDecisionError {
            throw appsToolsPendingRequestDecisionError
        }
        deniedAppsToolsPendingRequests.append((requestSource, requestId))
        removeAppsToolsPendingRequest(requestSource: requestSource, requestId: requestId)
        return AppsToolsPendingRequestDecision(
            action: "deny",
            status: "denied",
            useGrantId: nil,
            accessRuleId: nil
        )
    }

    func approveAppsToolsPairing(
        requestId: String,
        label: String
    ) throws -> AppsToolsPendingRequestDecision {
        if let appsToolsPendingRequestDecisionError {
            throw appsToolsPendingRequestDecisionError
        }
        approvedAppsToolsPairings.append((requestId, label))
        removeAppsToolsPendingRequest(requestSource: "pairing", requestId: requestId)
        return AppsToolsPendingRequestDecision(
            action: "pair",
            status: "awaiting-proof",
            useGrantId: nil,
            accessRuleId: nil
        )
    }

    func approveAppsToolsPendingUnlock(
        sessionId: UInt64,
        requestId: String
    ) throws -> AppsToolsPendingRequestDecision {
        if let appsToolsPendingRequestDecisionError {
            throw appsToolsPendingRequestDecisionError
        }
        approvedAppsToolsUnlocks.append((sessionId, requestId))
        removeAppsToolsPendingRequest(requestSource: "approval", requestId: requestId)
        return AppsToolsPendingRequestDecision(
            action: "approve-unlock",
            status: "approved",
            useGrantId: nil,
            accessRuleId: nil
        )
    }

    func reviewAppsToolsPendingCredential(
        sessionId: UInt64,
        requestId: String
    ) throws -> AppsToolsCredentialReview {
        if let appsToolsPendingRequestDecisionError {
            throw appsToolsPendingRequestDecisionError
        }
        reviewedAppsToolsCredentials.append((sessionId, requestId))
        guard let nextAppsToolsCredentialReview else {
            throw CoreBridgeError.commandFailed("Apps & Tools credential review unavailable")
        }
        return nextAppsToolsCredentialReview
    }

    func allowAppsToolsPendingRequestOnce(
        sessionId: UInt64,
        requestId: String,
        credentialId: String?,
        secretFieldId: String?
    ) throws -> AppsToolsPendingRequestDecision {
        if let appsToolsPendingRequestDecisionError {
            throw appsToolsPendingRequestDecisionError
        }
        allowedOnceAppsToolsRequests.append(
            (sessionId, requestId, credentialId, secretFieldId)
        )
        removeAppsToolsPendingRequest(requestSource: "approval", requestId: requestId)
        return AppsToolsPendingRequestDecision(
            action: "allow-once",
            status: "approved",
            useGrantId: "use_grant_test",
            accessRuleId: nil
        )
    }

    func configureAppsToolsLongTermAccess(
        sessionId: UInt64,
        requestId: String,
        credentialId: String?,
        secretFieldId: String?,
        confirmationPolicy: AppsToolsConfirmationPolicy
    ) throws -> AppsToolsPendingRequestDecision {
        if let appsToolsPendingRequestDecisionError {
            throw appsToolsPendingRequestDecisionError
        }
        configuredLongTermAppsToolsRequests.append(
            (sessionId, requestId, credentialId, secretFieldId, confirmationPolicy)
        )
        removeAppsToolsPendingRequest(requestSource: "approval", requestId: requestId)
        return AppsToolsPendingRequestDecision(
            action: "configure-long-term-access",
            status: "approved",
            useGrantId: nil,
            accessRuleId: "access_rule_test"
        )
    }

    func appsToolsConsumerDetail(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsConsumerDetail {
        appsToolsConsumerDetailRequests.append(consumerId)
        if let authorizationInventoryError {
            throw authorizationInventoryError
        }
        guard let detail = nextAppsToolsConsumerDetails[consumerId] else {
            throw CoreBridgeError.commandFailed("Apps & Tools Consumer is unavailable")
        }
        return detail
    }

    func appsToolsUsageProfileSetup(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsUsageProfileSetup {
        appsToolsUsageProfileSetupRequests.append(consumerId)
        if let appsToolsUsageProfileError {
            throw appsToolsUsageProfileError
        }
        if let setup = nextAppsToolsUsageProfileSetups[consumerId] {
            return setup
        }
        guard let detail = nextAppsToolsConsumerDetails[consumerId] else {
            throw CoreBridgeError.commandFailed("Apps & Tools Consumer is unavailable")
        }
        let recommendation: AppsToolsUsageProfileRecommendation?
        switch detail.consumer.identity.executableName?.lowercased() {
        case "gh":
            recommendation = AppsToolsUsageProfileRecommendation(
                recommendationId: "github-cli",
                templateId: "cli-environment-variable",
                technicalName: "GH_TOKEN"
            )
        case "glab":
            recommendation = AppsToolsUsageProfileRecommendation(
                recommendationId: "gitlab-cli",
                templateId: "cli-environment-variable",
                technicalName: "GITLAB_TOKEN"
            )
        default:
            recommendation = nil
        }
        return AppsToolsUsageProfileSetup(
            consumerId: consumerId,
            templates: [
                AppsToolsUsageProfileTemplate(
                    templateId: "http-bearer-authorization",
                    capability: "http.request",
                    capabilityVersion: 1,
                    technicalField: "none",
                    suggestedValue: nil
                ),
                AppsToolsUsageProfileTemplate(
                    templateId: "http-api-key-header",
                    capability: "http.request",
                    capabilityVersion: 1,
                    technicalField: "http-header-name",
                    suggestedValue: "X-API-Key"
                ),
                AppsToolsUsageProfileTemplate(
                    templateId: "cli-environment-variable",
                    capability: "process.run",
                    capabilityVersion: 1,
                    technicalField: "environment-variable-name",
                    suggestedValue: nil
                ),
            ],
            recommendation: recommendation
        )
    }

    func createAppsToolsUsageProfile(
        sessionId: UInt64,
        consumerId: String,
        draft: AppsToolsUsageProfileDraft
    ) throws -> AppsToolsUsageProfile {
        if let appsToolsUsageProfileError {
            throw appsToolsUsageProfileError
        }
        guard let detail = nextAppsToolsConsumerDetails[consumerId] else {
            throw CoreBridgeError.commandFailed("Apps & Tools Consumer is unavailable")
        }
        let placement: AppsToolsUsagePlacement
        switch draft.templateId {
        case "http-bearer-authorization":
            placement = AppsToolsUsagePlacement(
                kind: "http-bearer-authorization",
                variableName: nil,
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: nil
            )
        case "http-api-key-header":
            placement = AppsToolsUsagePlacement(
                kind: "http-header",
                variableName: nil,
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: draft.technicalName ?? "X-API-Key"
            )
        case "cli-environment-variable":
            guard let technicalName = draft.technicalName, !technicalName.isEmpty else {
                throw CoreBridgeError.commandFailed("Usage Profile configuration is invalid")
            }
            placement = AppsToolsUsagePlacement(
                kind: "process-environment",
                variableName: technicalName,
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: nil
            )
        default:
            throw CoreBridgeError.commandFailed("Usage Profile template is unavailable")
        }

        let profile = AppsToolsUsageProfile(
            usageProfileId: "usage_profile_test_\(nextUsageProfileId)",
            label: draft.label,
            capability: draft.templateId == "cli-environment-variable"
                ? "process.run"
                : "http.request",
            capabilityVersion: 1,
            placement: placement,
            createdAtMilliseconds: Int64(1_000 + nextUsageProfileId)
        )
        nextUsageProfileId += 1
        createdAppsToolsUsageProfiles.append((sessionId, consumerId, draft))
        updateFakeAppsToolsUsageProfiles(
            detail.usageProfiles + [profile],
            consumerId: consumerId
        )
        return profile
    }

    func removeAppsToolsUsageProfile(
        sessionId: UInt64,
        consumerId: String,
        usageProfileId: String
    ) throws -> Bool {
        if let appsToolsUsageProfileError {
            throw appsToolsUsageProfileError
        }
        removedAppsToolsUsageProfiles.append((sessionId, consumerId, usageProfileId))
        guard let detail = nextAppsToolsConsumerDetails[consumerId],
              detail.usageProfiles.contains(where: {
                  $0.usageProfileId == usageProfileId
              })
        else {
            return false
        }
        updateFakeAppsToolsUsageProfiles(
            detail.usageProfiles.filter {
                $0.usageProfileId != usageProfileId
            },
            consumerId: consumerId
        )
        return true
    }

    func setAppsToolsPaused(sessionId: UInt64, paused: Bool) throws -> AppsToolsSnapshot {
        if let authorizationInventoryError {
            throw authorizationInventoryError
        }
        appsToolsPauseRequests.append(paused)
        nextAppsToolsPaused = paused
        return currentAppsToolsSnapshot()
    }

    func revokeAppsToolsField(
        sessionId: UInt64,
        consumerId: String,
        field: AppsToolsFieldReference
    ) throws -> AppsToolsSnapshot {
        if let authorizationInventoryError {
            throw authorizationInventoryError
        }
        revokedAppsToolsFields.append(field)
        if let detail = nextAppsToolsConsumerDetails[consumerId] {
            let remainingGrants = detail.fieldGrants.filter { $0.field != field }
            let summary = appsToolsConsumerSummary(
                detail.consumer,
                accessRuleCount: remainingGrants.count,
                usageProfileCount: detail.usageProfiles.count
            )
            nextAppsToolsConsumerDetails[consumerId] = AppsToolsConsumerDetail(
                consumer: summary,
                fieldGrants: remainingGrants,
                usageProfiles: detail.usageProfiles,
                recentAuditEvents: detail.recentAuditEvents
            )
            replaceAppsToolsConsumer(summary)
            let stillAuthorized = nextAppsToolsConsumerDetails.values.contains { candidate in
                candidate.fieldGrants.contains {
                    $0.field.credentialId == field.credentialId
                }
            }
            if !stillAuthorized {
                nextAuthorizedCredentialIds.remove(field.credentialId)
            }
        }
        return currentAppsToolsSnapshot()
    }

    func revokeAppsToolsConsumer(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsSnapshot {
        if let authorizationInventoryError {
            throw authorizationInventoryError
        }
        revokedAppsToolsConsumers.append(consumerId)
        nextAppsToolsConsumers.removeAll { $0.consumerId == consumerId }
        nextAppsToolsConsumerDetails.removeValue(forKey: consumerId)
        nextAuthorizedCredentialIds = Set(
            nextAppsToolsConsumerDetails.values.flatMap { detail in
                detail.fieldGrants.map(\.field.credentialId)
            }
        )
        return currentAppsToolsSnapshot()
    }

    private func currentAppsToolsSnapshot() -> AppsToolsSnapshot {
        AppsToolsSnapshot(
            paused: nextAppsToolsPaused,
            authorizedCredentialIds: nextAuthorizedCredentialIds.sorted(),
            consumers: nextAppsToolsConsumers
        )
    }

    private func updateFakeAppsToolsUsageProfiles(
        _ usageProfiles: [AppsToolsUsageProfile],
        consumerId: String
    ) {
        guard let detail = nextAppsToolsConsumerDetails[consumerId] else { return }
        let summary = appsToolsConsumerSummary(
            detail.consumer,
            accessRuleCount: detail.fieldGrants.count,
            usageProfileCount: usageProfiles.count
        )
        nextAppsToolsConsumerDetails[consumerId] = AppsToolsConsumerDetail(
            consumer: summary,
            fieldGrants: detail.fieldGrants,
            usageProfiles: usageProfiles,
            recentAuditEvents: detail.recentAuditEvents
        )
        replaceAppsToolsConsumer(summary)
    }

    private func removeAppsToolsPendingRequest(requestSource: String, requestId: String) {
        let remaining = nextAppsToolsPendingRequests.requests.filter {
            $0.requestSource != requestSource || $0.requestId != requestId
        }
        nextAppsToolsPendingRequests = AppsToolsPendingRequestQueue(
            pendingCount: remaining.count,
            requests: remaining
        )
    }

    private func appsToolsConsumerSummary(
        _ summary: AppsToolsConsumerSummary,
        accessRuleCount: Int,
        usageProfileCount: Int
    ) -> AppsToolsConsumerSummary {
        AppsToolsConsumerSummary(
            consumerId: summary.consumerId,
            label: summary.label,
            identity: summary.identity,
            accessRuleCount: accessRuleCount,
            usageProfileCount: usageProfileCount,
            createdAtMilliseconds: summary.createdAtMilliseconds
        )
    }

    private func replaceAppsToolsConsumer(_ summary: AppsToolsConsumerSummary) {
        guard let index = nextAppsToolsConsumers.firstIndex(where: {
            $0.consumerId == summary.consumerId
        }) else {
            return
        }
        nextAppsToolsConsumers[index] = summary
    }

    func createCredentialFromTemplate(
        sessionId: UInt64,
        form: TemplateCredentialForm
    ) throws -> [VaultItemView] {
        guard form.isValidForSave else {
            throw CoreBridgeError.commandFailed("invalid template credential")
        }
        createCredentialCallCount += 1
        let id = "item_\(nextId)"
        let revision = freshRevision()
        nextId += 1
        let secretFieldId = "field_\(id)_primary"
        var fields: [CredentialDetailField] = [
            .secret(.init(
                role: credentialSecretRole(form.template),
                label: nil,
                secretFieldId: secretFieldId,
                secretKind: form.template.primarySecretKind ?? "generic-secret",
                hasValue: true
            ))
        ]
        if form.template.supportsExpiry, let expiry = form.expiry.nilIfEmpty {
            fields.append(.text(.init(role: "expiry", label: nil, text: expiry)))
        }
        if let notes = form.notes.nilIfEmpty {
            fields.append(.text(.init(role: "notes", label: nil, text: notes)))
        }
        items.append(VaultItemView(
            id: id,
            revision: revision,
            title: form.normalizedTitle,
            itemType: credentialItemType(form.template),
            templateId: form.template.rawValue,
            secretKinds: [form.template.primarySecretKind ?? "generic-secret"],
            status: "active",
            favorite: form.favorite,
            tags: form.tags
        ))
        credentialDetails[id] = CredentialDetail(
            id: id,
            revision: revision,
            title: form.normalizedTitle,
            templateId: form.template.rawValue,
            fields: fields,
            favorite: form.favorite,
            tags: form.tags,
            status: "active"
        )
        credentialSecrets[id] = [secretFieldId: form.secret]
        return visibleItems(includeArchived: false)
    }

    func updateCredential(
        sessionId: UInt64,
        credentialId: String,
        form: CredentialEditorForm
    ) throws -> [VaultItemView] {
        guard let itemIndex = items.firstIndex(where: { $0.id == credentialId }),
              let currentDetail = credentialDetails[credentialId]
        else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        guard form.revision == currentDetail.revision else {
            throw CoreBridgeError.commandFailed("item changed on disk; refresh sync before editing")
        }
        updateCredentialCallCount += 1
        lastCredentialUpdateForm = form
        let revision = freshRevision()
        var nextSecrets: [String: String] = [:]
        var nextFields: [CredentialDetailField] = []
        for field in form.fields {
            switch field.fieldType {
            case .text:
                nextFields.append(.text(.init(
                    role: field.normalizedRole,
                    label: field.normalizedLabel,
                    text: field.text
                )))
            case .existingSecret:
                guard let secretFieldId = field.secretFieldId,
                      let savedSecret = credentialSecrets[credentialId]?[secretFieldId]
                else {
                    throw CoreBridgeError.commandFailed("missing secret field")
                }
                let value = field.secretInput.isEmpty ? savedSecret : field.secretInput
                nextSecrets[secretFieldId] = value
                nextFields.append(.secret(.init(
                    role: field.normalizedRole,
                    label: field.normalizedLabel,
                    secretFieldId: secretFieldId,
                    secretKind: field.secretKind,
                    hasValue: !value.isEmpty
                )))
            case .newSecret:
                let secretFieldId = "field_\(credentialId)_\(UUID().uuidString)"
                nextSecrets[secretFieldId] = field.secretInput
                nextFields.append(.secret(.init(
                    role: field.normalizedRole,
                    label: field.normalizedLabel,
                    secretFieldId: secretFieldId,
                    secretKind: field.secretKind,
                    hasValue: !field.secretInput.isEmpty
                )))
            }
        }
        credentialSecrets[credentialId] = nextSecrets
        credentialDetails[credentialId] = CredentialDetail(
            id: credentialId,
            revision: revision,
            title: form.normalizedTitle,
            templateId: form.templateId,
            fields: nextFields,
            favorite: form.favorite,
            tags: form.tags,
            status: currentDetail.status
        )
        items[itemIndex] = VaultItemView(
            id: credentialId,
            revision: revision,
            title: form.normalizedTitle,
            itemType: credentialItemType(
                CredentialTemplateKind(rawValue: form.templateId ?? "") ?? .custom
            ),
            templateId: form.templateId,
            secretKinds: nextFields.compactMap(\.secretField?.secretKind),
            status: items[itemIndex].status,
            favorite: form.favorite,
            tags: form.tags
        )
        return visibleItems(includeArchived: false)
    }

    func duplicateCredential(
        sessionId: UInt64,
        credentialId: String,
        expectedRevision: String,
        title: String
    ) throws -> [VaultItemView] {
        guard let sourceItem = items.first(where: { $0.id == credentialId }),
              let sourceDetail = credentialDetails[credentialId]
        else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(expectedRevision, matches: sourceItem)
        duplicateCredentialCallCount += 1
        let duplicateId = "item_\(nextId)"
        nextId += 1
        let duplicateRevision = freshRevision()
        var duplicateSecrets: [String: String] = [:]
        let duplicateFields = sourceDetail.fields.enumerated().map { index, field in
            switch field {
            case let .text(textField):
                return CredentialDetailField.text(textField)
            case let .secret(secretField):
                let duplicateSecretFieldId = "field_\(duplicateId)_\(index)"
                duplicateSecrets[duplicateSecretFieldId] =
                    credentialSecrets[credentialId]?[secretField.secretFieldId] ?? ""
                return CredentialDetailField.secret(.init(
                    role: secretField.role,
                    label: secretField.label,
                    secretFieldId: duplicateSecretFieldId,
                    secretKind: secretField.secretKind,
                    hasValue: secretField.hasValue
                ))
            }
        }
        items.append(VaultItemView(
            id: duplicateId,
            revision: duplicateRevision,
            title: title,
            itemType: sourceItem.itemType,
            templateId: sourceItem.templateId,
            secretKinds: sourceItem.secretKinds,
            status: "active",
            favorite: sourceItem.favorite,
            tags: sourceItem.tags
        ))
        credentialDetails[duplicateId] = CredentialDetail(
            id: duplicateId,
            revision: duplicateRevision,
            title: title,
            templateId: sourceDetail.templateId,
            fields: duplicateFields,
            favorite: sourceDetail.favorite,
            tags: sourceDetail.tags,
            status: "active"
        )
        credentialSecrets[duplicateId] = duplicateSecrets
        return visibleItems(includeArchived: false)
    }

    func getCredential(sessionId: UInt64, credentialId: String) throws -> CredentialDetail {
        guard let detail = credentialDetails[credentialId] else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        return detail
    }

    func getCredentialSecretField(
        sessionId: UInt64,
        credentialId: String,
        secretFieldId: String
    ) throws -> String {
        credentialSecretFieldRequests.append(secretFieldId)
        guard let value = credentialSecrets[credentialId]?[secretFieldId] else {
            throw CoreBridgeError.commandFailed("missing secret field")
        }
        return value
    }

    func createLogin(sessionId: UInt64, form: LoginForm) throws -> [VaultItemView] {
        createLoginCallCount += 1
        insert(seed: SeedLogin(
            title: form.title,
            username: form.username,
            password: form.password,
            url: form.url,
            urls: form.urls,
            notes: form.notes,
            tags: form.tags,
            totpSecret: normalizedTestTotpSecret(form.totpSecretForSave),
            favorite: form.favorite
        ))
        return visibleItems(includeArchived: false)
    }

    func updateLogin(sessionId: UInt64, itemId: String, form: LoginForm) throws -> [VaultItemView] {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(form.revision, matches: items[index])
        updateLoginCallCount += 1
        let revision = freshRevision()
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: form.title,
            itemType: "login",
            status: items[index].status,
            favorite: form.favorite,
            tags: form.tags
        )
        details[itemId] = LoginDetail(
            id: itemId,
            revision: revision,
            title: form.title,
            username: form.username.nilIfEmpty,
            url: form.url.nilIfEmpty,
            urls: form.urls,
            notes: form.notes.nilIfEmpty,
            totpSecret: normalizedTestTotpSecret(form.totpSecretForSave),
            favorite: form.favorite,
            tags: form.tags,
            status: items[index].status
        )
        if let password = form.password.nilIfEmpty {
            passwords[itemId] = password
        } else if form.clearPasswordOnSave {
            passwords[itemId] = nil
        }
        return visibleItems(includeArchived: false)
    }

    func getLogin(sessionId: UInt64, itemId: String) throws -> LoginDetail {
        guard let detail = details[itemId] else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        return detail
    }

    private func normalizedTestTotpSecret(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let rawSecret: String
        if trimmed.lowercased().hasPrefix("otpauth://") {
            guard
                let components = URLComponents(string: trimmed),
                let secret = components.queryItems?.first(where: { queryItem in
                    queryItem.name.caseInsensitiveCompare("secret") == .orderedSame
                })?.value
            else {
                return nil
            }
            rawSecret = secret
        } else {
            rawSecret = trimmed
        }

        let normalized = rawSecret
            .filter { character in
                !character.isWhitespace && character != "-" && character != "="
            }
            .uppercased()
        return normalized.isEmpty ? nil : normalized
    }

    func createSecureNote(sessionId: UInt64, form: SecureNoteForm) throws -> [VaultItemView] {
        createSecureNoteCallCount += 1
        insert(seed: SeedSecureNote(
            title: form.title,
            body: form.body,
            tags: form.tags,
            favorite: form.favorite
        ))
        return visibleItems(includeArchived: false)
    }

    func updateSecureNote(sessionId: UInt64, itemId: String, form: SecureNoteForm) throws -> [VaultItemView] {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(form.revision, matches: items[index])
        updateSecureNoteCallCount += 1
        let revision = freshRevision()
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: form.title,
            itemType: "secure note",
            status: items[index].status,
            favorite: form.favorite,
            tags: form.tags
        )
        secureNoteDetails[itemId] = SecureNoteDetail(
            id: itemId,
            revision: revision,
            title: form.title,
            body: form.body,
            favorite: form.favorite,
            tags: form.tags,
            status: items[index].status
        )
        return visibleItems(includeArchived: false)
    }

    func getSecureNote(sessionId: UInt64, itemId: String) throws -> SecureNoteDetail {
        guard let detail = secureNoteDetails[itemId] else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        return detail
    }

    func createCreditCard(sessionId: UInt64, form: CreditCardForm) throws -> [VaultItemView] {
        createCreditCardCallCount += 1
        insert(seed: SeedCreditCard(
            title: form.title,
            cardholderName: form.cardholderName,
            number: form.number,
            expiryMonth: form.expiryMonthValue,
            expiryYear: form.expiryYearValue,
            verificationCode: form.verificationCode,
            notes: form.notes,
            tags: form.tags,
            favorite: form.favorite
        ))
        return visibleItems(includeArchived: false)
    }

    func updateCreditCard(sessionId: UInt64, itemId: String, form: CreditCardForm) throws -> [VaultItemView] {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(form.revision, matches: items[index])
        updateCreditCardCallCount += 1
        let revision = freshRevision()
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: form.title,
            itemType: "credit card",
            status: items[index].status,
            favorite: form.favorite,
            tags: form.tags
        )
        creditCardDetails[itemId] = CreditCardDetail(
            id: itemId,
            revision: revision,
            title: form.title,
            cardholderName: form.cardholderName.nilIfEmpty,
            expiryMonth: form.expiryMonthValue,
            expiryYear: form.expiryYearValue,
            notes: form.notes.nilIfEmpty,
            favorite: form.favorite,
            tags: form.tags,
            status: items[index].status
        )
        if let number = form.numberForUpdate {
            cardNumbers[itemId] = number.nilIfEmpty
        }
        if let code = form.verificationCodeForUpdate {
            cardVerificationCodes[itemId] = code.nilIfEmpty
        }
        return visibleItems(includeArchived: false)
    }

    func getCreditCard(sessionId: UInt64, itemId: String) throws -> CreditCardDetail {
        guard let detail = creditCardDetails[itemId] else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        return detail
    }

    func getCreditCardField(sessionId: UInt64, itemId: String, field: String) throws -> String {
        creditCardFieldRequests.append(field)
        switch field {
        case "number":
            return cardNumbers[itemId] ?? ""
        case "verification_code", "verificationCode":
            return cardVerificationCodes[itemId] ?? ""
        default:
            throw CoreBridgeError.commandFailed("unsupported field")
        }
    }

    func createSoftwareLicense(sessionId: UInt64, form: SoftwareLicenseForm) throws -> [VaultItemView] {
        createSoftwareLicenseCallCount += 1
        insert(seed: SeedSoftwareLicense(
            title: form.title,
            product: form.product,
            licenseKey: form.licenseKey,
            licensedTo: form.licensedTo,
            notes: form.notes,
            tags: form.tags,
            favorite: form.favorite
        ))
        return visibleItems(includeArchived: false)
    }

    func updateSoftwareLicense(sessionId: UInt64, itemId: String, form: SoftwareLicenseForm) throws -> [VaultItemView] {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(form.revision, matches: items[index])
        updateSoftwareLicenseCallCount += 1
        let revision = freshRevision()
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: form.title,
            itemType: "software license",
            status: items[index].status,
            favorite: form.favorite,
            tags: form.tags
        )
        softwareLicenseDetails[itemId] = SoftwareLicenseDetail(
            id: itemId,
            revision: revision,
            title: form.title,
            product: form.product.nilIfEmpty,
            licensedTo: form.licensedTo.nilIfEmpty,
            notes: form.notes.nilIfEmpty,
            favorite: form.favorite,
            tags: form.tags,
            status: items[index].status
        )
        if let licenseKey = form.licenseKeyForUpdate {
            licenseKeys[itemId] = licenseKey.nilIfEmpty
        }
        return visibleItems(includeArchived: false)
    }

    func getSoftwareLicense(sessionId: UInt64, itemId: String) throws -> SoftwareLicenseDetail {
        guard let detail = softwareLicenseDetails[itemId] else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        return detail
    }

    func getSoftwareLicenseField(sessionId: UInt64, itemId: String, field: String) throws -> String {
        softwareLicenseFieldRequests.append(field)
        switch field {
        case "license_key", "licenseKey":
            return licenseKeys[itemId] ?? ""
        default:
            throw CoreBridgeError.commandFailed("unsupported field")
        }
    }

    func getLoginField(sessionId: UInt64, itemId: String, field: String) throws -> String {
        loginFieldRequests.append(field)
        guard let detail = details[itemId] else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        switch field {
        case "username":
            return detail.username ?? ""
        case "password":
            return passwords[itemId] ?? ""
        default:
            throw CoreBridgeError.commandFailed("unsupported field")
        }
    }

    func archiveItem(sessionId: UInt64, itemId: String, expectedRevision: String?) throws -> [VaultItemView] {
        guard let item = items.first(where: { $0.id == itemId }) else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(expectedRevision, matches: item)
        archiveItemCallCount += 1
        setStatus(itemId: itemId, status: "archived", revision: freshRevision())
        return visibleItems(includeArchived: false)
    }

    func restoreItem(sessionId: UInt64, itemId: String) throws -> [VaultItemView] {
        guard items.first(where: { $0.id == itemId })?.status == "archived" else {
            throw CoreBridgeError.commandFailed("only archived items can be restored")
        }
        restoreItemCallCount += 1
        setStatus(itemId: itemId, status: "active", revision: freshRevision())
        return visibleItems(includeArchived: false)
    }

    func deleteItem(sessionId: UInt64, itemId: String, expectedRevision: String?) throws -> [VaultItemView] {
        guard let item = items.first(where: { $0.id == itemId }) else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(expectedRevision, matches: item)
        deleteItemCallCount += 1
        items.removeAll { $0.id == itemId }
        details[itemId] = nil
        secureNoteDetails[itemId] = nil
        creditCardDetails[itemId] = nil
        softwareLicenseDetails[itemId] = nil
        credentialDetails[itemId] = nil
        passwords[itemId] = nil
        cardNumbers[itemId] = nil
        cardVerificationCodes[itemId] = nil
        licenseKeys[itemId] = nil
        credentialSecrets[itemId] = nil
        return visibleItems(includeArchived: false)
    }

    func resolveConflict(sessionId: UInt64, conflictId: String) throws -> [VaultItemView] {
        guard items.contains(where: { $0.conflictId == conflictId }) else {
            throw CoreBridgeError.commandFailed("missing conflict")
        }
        resolvedConflictIds.append(conflictId)
        var resolvedRevisions: [(itemId: String, revision: String)] = []
        items = items.map { item in
            guard item.conflictId == conflictId else { return item }
            let revision = freshRevision()
            resolvedRevisions.append((item.id, revision))
            return VaultItemView(
                id: item.id,
                revision: revision,
                title: item.title,
                itemType: item.itemType,
                status: "active",
                favorite: item.favorite,
                tags: item.tags
            )
        }
        for resolvedRevision in resolvedRevisions {
            setDetailRevision(itemId: resolvedRevision.itemId, revision: resolvedRevision.revision)
        }
        nextRefreshPayload = SyncRefreshPayload(
            loadedItems: items.count,
            appliedTombstones: 0,
            detectedConflicts: items.filter(\.isConflicted).count,
            rejectedRecords: 0,
            items: items
        )
        return visibleItems(includeArchived: false)
    }

    func getConflictCandidates(sessionId: UInt64, conflictId: String) throws -> [ConflictCandidateView] {
        guard items.contains(where: { $0.conflictId == conflictId }) else {
            throw CoreBridgeError.commandFailed("missing conflict")
        }
        loadedConflictIds.append(conflictId)
        return nextConflictCandidates
    }

    func resolveConflictCandidate(sessionId: UInt64, conflictId: String, revision: String) throws -> [VaultItemView] {
        guard nextConflictCandidates.contains(where: { $0.revision == revision }) else {
            throw CoreBridgeError.commandFailed("missing conflict candidate")
        }
        resolvedConflictCandidateRevisions.append(revision)
        return try resolveConflict(sessionId: sessionId, conflictId: conflictId)
    }

    func resolveConflictMerge(sessionId: UInt64, conflictId: String, baseRevision: String, fieldSelections: [ConflictMergeFieldSelection]) throws -> [VaultItemView] {
        guard nextConflictCandidates.contains(where: { $0.revision == baseRevision }) else {
            throw CoreBridgeError.commandFailed("missing conflict merge base")
        }
        for selection in fieldSelections {
            guard nextConflictCandidates.contains(where: { $0.revision == selection.revision }) else {
                throw CoreBridgeError.commandFailed("missing conflict merge field revision")
            }
        }
        resolvedConflictMergeRequests.append((
            conflictId: conflictId,
            baseRevision: baseRevision,
            fieldSelections: fieldSelections
        ))
        return try resolveConflict(sessionId: sessionId, conflictId: conflictId)
    }

    func setFavorite(sessionId: UInt64, itemId: String, expectedRevision: String?, favorite: Bool) throws -> [VaultItemView] {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        try validateExpectedRevision(expectedRevision, matches: items[index])
        setFavoriteCallCount += 1
        let revision = freshRevision()
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: items[index].title,
            itemType: items[index].itemType,
            templateId: items[index].templateId,
            secretKinds: items[index].secretKinds,
            status: items[index].status,
            favorite: favorite,
            tags: items[index].tags
        )
        if var detail = details[itemId] {
            detail.revision = revision
            detail.favorite = favorite
            details[itemId] = detail
        } else if var detail = secureNoteDetails[itemId] {
            detail.revision = revision
            detail.favorite = favorite
            secureNoteDetails[itemId] = detail
        } else if var detail = creditCardDetails[itemId] {
            detail.revision = revision
            detail.favorite = favorite
            creditCardDetails[itemId] = detail
        } else if var detail = softwareLicenseDetails[itemId] {
            detail.revision = revision
            detail.favorite = favorite
            softwareLicenseDetails[itemId] = detail
        } else if let detail = credentialDetails[itemId] {
            credentialDetails[itemId] = CredentialDetail(
                id: detail.id,
                revision: revision,
                title: detail.title,
                templateId: detail.templateId,
                fields: detail.fields,
                favorite: favorite,
                tags: detail.tags,
                status: detail.status
            )
        } else {
            throw CoreBridgeError.commandFailed("missing item")
        }
        return visibleItems(includeArchived: false)
    }

    func totpCode(sessionId: UInt64, itemId: String) throws -> TotpPayload {
        totpCodeCallCount += 1
        guard details[itemId]?.totpSecret?.isEmpty == false else {
            throw CoreBridgeError.commandFailed("login item has no TOTP secret")
        }
        return TotpPayload(code: "123456", remainingSeconds: 20)
    }

    func previewImport(sessionId: UInt64, sourcePath: String, sourceFormat: String) throws -> ImportPreviewPayload {
        previewedImportPath = sourcePath
        previewedImportFormat = sourceFormat
        return ImportPreviewPayload(
            importableRecords: 1,
            skippedRecords: 0,
            duplicateRecords: 0,
            warnings: ["Delete the source export after import."]
        )
    }

    func commitImport(sessionId: UInt64, sourcePath: String, sourceFormat: String, keepDuplicates: Bool) throws -> ImportPreviewPayload {
        committedImportPath = sourcePath
        committedImportFormat = sourceFormat
        committedKeepDuplicates = keepDuplicates
        items.removeAll()
        details.removeAll()
        secureNoteDetails.removeAll()
        creditCardDetails.removeAll()
        softwareLicenseDetails.removeAll()
        passwords.removeAll()
        cardNumbers.removeAll()
        cardVerificationCodes.removeAll()
        licenseKeys.removeAll()
        nextId = 1
        nextRevision = 1
        if importCreditCardOnCommit {
            insert(seed: SeedCreditCard(
                title: "Imported Card",
                cardholderName: "Alice Imported",
                number: "4111111111111111",
                expiryMonth: 4,
                expiryYear: 2030,
                verificationCode: "123",
                notes: "Imported travel card",
                tags: ["imported"]
            ))
        } else if importSecureNoteOnCommit {
            insert(seed: SeedSecureNote(
                title: "Imported Note",
                body: "Imported secure note",
                tags: ["imported"]
            ))
        } else {
            insert(seed: SeedLogin(
                title: "Imported",
                username: "imported@example.com",
                password: "imported-password",
                url: "https://example.com",
                notes: "Imported item",
                tags: ["imported"]
            ))
        }
        return ImportPreviewPayload(
            importableRecords: 1,
            skippedRecords: 0,
            duplicateRecords: 0,
            warnings: []
        )
    }

    func exportItems(
        sessionId: UInt64,
        destinationPath: String,
        exportFormat: String,
        currentPassword: String
    ) throws -> ExportResultPayload {
        exportedPath = destinationPath
        exportedFormat = exportFormat
        exportedCurrentPassword = currentPassword
        return nextExportResult
    }

    func backupVault(sessionId: UInt64, destinationPath: String) throws -> BackupResultPayload {
        backupCallCount += 1
        backupDestinationPath = destinationPath
        return nextBackupResult
    }

    func restoreVaultBackup(sourcePath: String, destinationPath: String) throws -> RestoreBackupResultPayload {
        restoreBackupCallCount += 1
        restoreSourcePath = sourcePath
        restoreDestinationPath = destinationPath
        return nextRestoreBackupResult
    }

    func password(for itemId: String) -> String? {
        passwords[itemId]
    }

    func cardNumber(for itemId: String) -> String? {
        cardNumbers[itemId]
    }

    func cardVerificationCode(for itemId: String) -> String? {
        cardVerificationCodes[itemId]
    }

    func licenseKey(for itemId: String) -> String? {
        licenseKeys[itemId]
    }

    private func insert(seed: SeedLogin) {
        let id = "item_\(nextId)"
        let revision = freshRevision()
        nextId += 1
        items.append(VaultItemView(
            id: id,
            revision: revision,
            title: seed.title,
            itemType: "login",
            status: "active",
            favorite: seed.favorite,
            tags: seed.tags
        ))
        details[id] = LoginDetail(
            id: id,
            revision: revision,
            title: seed.title,
            username: seed.username.nilIfEmpty,
            url: seed.url.nilIfEmpty,
            urls: seed.normalizedURLs,
            notes: seed.notes.nilIfEmpty,
            totpSecret: seed.totpSecret,
            favorite: seed.favorite,
            tags: seed.tags,
            status: "active"
        )
        passwords[id] = seed.password
    }

    private func insert(seed: SeedSecureNote) {
        let id = "item_\(nextId)"
        let revision = freshRevision()
        nextId += 1
        items.append(VaultItemView(
            id: id,
            revision: revision,
            title: seed.title,
            itemType: "secure note",
            status: "active",
            favorite: seed.favorite,
            tags: seed.tags
        ))
        secureNoteDetails[id] = SecureNoteDetail(
            id: id,
            revision: revision,
            title: seed.title,
            body: seed.body,
            favorite: seed.favorite,
            tags: seed.tags,
            status: "active"
        )
    }

    private func insert(seed: SeedCreditCard) {
        let id = "item_\(nextId)"
        let revision = freshRevision()
        nextId += 1
        items.append(VaultItemView(
            id: id,
            revision: revision,
            title: seed.title,
            itemType: "credit card",
            status: "active",
            favorite: seed.favorite,
            tags: seed.tags
        ))
        creditCardDetails[id] = CreditCardDetail(
            id: id,
            revision: revision,
            title: seed.title,
            cardholderName: seed.cardholderName.nilIfEmpty,
            expiryMonth: seed.expiryMonth,
            expiryYear: seed.expiryYear,
            notes: seed.notes.nilIfEmpty,
            favorite: seed.favorite,
            tags: seed.tags,
            status: "active"
        )
        cardNumbers[id] = seed.number
        cardVerificationCodes[id] = seed.verificationCode
    }

    private func insert(seed: SeedSoftwareLicense) {
        let id = "item_\(nextId)"
        let revision = freshRevision()
        nextId += 1
        items.append(VaultItemView(
            id: id,
            revision: revision,
            title: seed.title,
            itemType: "software license",
            status: "active",
            favorite: seed.favorite,
            tags: seed.tags
        ))
        softwareLicenseDetails[id] = SoftwareLicenseDetail(
            id: id,
            revision: revision,
            title: seed.title,
            product: seed.product.nilIfEmpty,
            licensedTo: seed.licensedTo.nilIfEmpty,
            notes: seed.notes.nilIfEmpty,
            favorite: seed.favorite,
            tags: seed.tags,
            status: "active"
        )
        licenseKeys[id] = seed.licenseKey
    }

    private func credentialItemType(_ template: CredentialTemplateKind) -> String {
        switch template {
        case .apiToken:
            return "api token"
        case .apiKey:
            return "api key"
        case .sshKey:
            return "ssh key"
        case .certificate:
            return "certificate"
        case .custom:
            return "custom"
        case .login, .secureNote, .creditCard, .softwareLicense:
            return template.rawValue.replacingOccurrences(of: "-", with: " ")
        }
    }

    private func credentialSecretRole(_ template: CredentialTemplateKind) -> String {
        switch template {
        case .apiToken:
            return "token"
        case .apiKey:
            return "api-key"
        case .sshKey:
            return "private-key"
        case .certificate:
            return "certificate"
        case .custom:
            return "secret"
        case .login, .secureNote, .creditCard, .softwareLicense:
            return "secret"
        }
    }

    private func setStatus(itemId: String, status: String, revision: String) {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            return
        }
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: items[index].title,
            itemType: items[index].itemType,
            templateId: items[index].templateId,
            secretKinds: items[index].secretKinds,
            status: status,
            favorite: items[index].favorite,
            tags: items[index].tags
        )
        if var detail = details[itemId] {
            detail.revision = revision
            detail.status = status
            details[itemId] = detail
        } else if var detail = secureNoteDetails[itemId] {
            detail.revision = revision
            detail.status = status
            secureNoteDetails[itemId] = detail
        } else if var detail = creditCardDetails[itemId] {
            detail.revision = revision
            detail.status = status
            creditCardDetails[itemId] = detail
        } else if var detail = softwareLicenseDetails[itemId] {
            detail.revision = revision
            detail.status = status
            softwareLicenseDetails[itemId] = detail
        } else if let detail = credentialDetails[itemId] {
            credentialDetails[itemId] = CredentialDetail(
                id: detail.id,
                revision: revision,
                title: detail.title,
                templateId: detail.templateId,
                fields: detail.fields,
                favorite: detail.favorite,
                tags: detail.tags,
                status: status
            )
        }
    }

    private func freshRevision() -> String {
        let revision = "rev_\(nextRevision)"
        nextRevision += 1
        return revision
    }

    private func validateExpectedRevision(_ expectedRevision: String?, matches item: VaultItemView) throws {
        guard let expectedRevision else { return }
        guard expectedRevision == item.revision else {
            throw CoreBridgeError.commandFailed("item changed on disk; refresh sync before editing")
        }
    }

    private func setDetailRevision(itemId: String, revision: String) {
        if var detail = details[itemId] {
            detail.revision = revision
            details[itemId] = detail
        } else if var detail = secureNoteDetails[itemId] {
            detail.revision = revision
            secureNoteDetails[itemId] = detail
        } else if var detail = creditCardDetails[itemId] {
            detail.revision = revision
            creditCardDetails[itemId] = detail
        } else if var detail = softwareLicenseDetails[itemId] {
            detail.revision = revision
            softwareLicenseDetails[itemId] = detail
        } else if let detail = credentialDetails[itemId] {
            credentialDetails[itemId] = CredentialDetail(
                id: detail.id,
                revision: revision,
                title: detail.title,
                templateId: detail.templateId,
                fields: detail.fields,
                favorite: detail.favorite,
                tags: detail.tags,
                status: detail.status
            )
        }
    }

    private func visibleItems(includeArchived: Bool) -> [VaultItemView] {
        items.filter { includeArchived || $0.status == "active" || $0.status == "conflicted" }
    }
}
