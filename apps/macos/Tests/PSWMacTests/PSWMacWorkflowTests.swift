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

    func testLanguageTextSupportsEnglishAndSimplifiedChinese() {
        let english = AppText(AppLanguage.english.rawValue)
        let chinese = AppText(AppLanguage.simplifiedChinese.rawValue)

        XCTAssertEqual(english.newVault, "New Vault")
        XCTAssertEqual(chinese.newVault, "新建密码库")
        XCTAssertEqual(english.exportItems, "Export")
        XCTAssertEqual(chinese.exportItems, "导出")
        XCTAssertEqual(chinese.exported, "已导出")
        XCTAssertEqual(chinese.plaintextExportTitle, "要导出明文秘密吗？")
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
        XCTAssertEqual(english.closeVault, "Close Vault")
        XCTAssertEqual(chinese.closeVault, "关闭密码库")
        XCTAssertEqual(chinese.statusMessage("Vault closed"), "密码库已关闭")
        XCTAssertEqual(english.firstRunTitle, "Start with a local vault")
        XCTAssertEqual(chinese.firstRunTitle, "从本地密码库开始")
        XCTAssertEqual(english.lockedVaultTitle, "Vault Locked")
        XCTAssertEqual(chinese.lockedVaultTitle, "密码库已锁定")
        XCTAssertEqual(english.emptyVaultTitle, "No Items Yet")
        XCTAssertEqual(chinese.emptyVaultTitle, "还没有项目")
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
        XCTAssertEqual(japanese.masterPassword, "マスターパスワード")
        XCTAssertEqual(japanese.enterMasterPasswordToUnlock, "マスターパスワードを入力")
        XCTAssertEqual(
            japanese.statusMessage("invalid vault credentials"),
            "マスターパスワードが正しくありません。もう一度お試しください。"
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
            "backup.json に保管庫データを平文で書き込みますか？このファイルを入手した人は誰でも、エクスポートした秘密情報を読み取れます。"
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

        for command in PSWMacCommand.allCases {
            XCTAssertFalse(locked.isEnabled(command))
        }

        let unlocked = PSWMacCommandAvailability(
            isUnlocked: true,
            canSaveCurrentEditor: true,
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
            canCopyUsername: false,
            canCopyPassword: false,
            canCopyTotp: false,
            canCopySecureNoteBody: false,
            canCopyCardNumber: false,
            canCopyCardVerificationCode: false,
            canCopyLicenseKey: false
        )

        XCTAssertTrue(ineligibleLoginSelection.isEnabled(.newItem))
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

        XCTAssertTrue(performedCommands.isEmpty)

        let guardedHandler = PSWMacCommandHandler(
            availability: PSWMacCommandAvailability(
                isUnlocked: true,
                canSaveCurrentEditor: false,
                canCopyUsername: true,
                canCopyPassword: true,
                canCopyTotp: false,
                canCopySecureNoteBody: true,
                canCopyCardNumber: true,
                canCopyCardVerificationCode: false,
                canCopyLicenseKey: true
            ),
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
            guardedHandler.perform(command)
        }

        XCTAssertEqual(performedCommands, [
            .newItem,
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
                    title: "Confidential Bank",
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
        XCTAssertFalse(report.contains("Email"))
        XCTAssertFalse(report.contains("Confidential Bank"))
        XCTAssertFalse(report.contains("me@example.com"))
        XCTAssertFalse(report.contains("email-password"))
        XCTAssertFalse(report.contains("correct horse"))
        XCTAssertFalse(report.contains("Strength"))
        XCTAssertFalse(report.contains("Weak"))
        XCTAssertFalse(report.contains("Very strong"))
        XCTAssertFalse(report.contains("https://mail.example.com"))
        XCTAssertFalse(report.contains("Primary inbox"))
        XCTAssertFalse(report.contains("bitwarden-export.json"))
        XCTAssertFalse(report.contains(importURL.path))
        XCTAssertFalse(report.contains("psw-plaintext-export.json"))
        XCTAssertFalse(report.contains(exportURL.path))
        XCTAssertFalse(report.contains("bad_bank.enc"))
        XCTAssertFalse(report.contains("bad_delete.enc"))

        store.copyDiagnostics(languageRaw: AppLanguage.english.rawValue)
        XCTAssertEqual(store.statusMessage, "Diagnostics copied")
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
        XCTAssertFalse(store.exportItems(destinationURL: exportURL))
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
            warnings: ["Export file contains plaintext secrets."]
        )

        XCTAssertTrue(store.canExport)
        XCTAssertTrue(store.exportItems(destinationURL: exportURL))

        XCTAssertEqual(service.exportedPath, exportURL.path)
        XCTAssertEqual(service.exportedFormat, "bitwarden-json")
        XCTAssertEqual(store.exportResult?.exportedRecords, 2)
        XCTAssertEqual(store.exportResult?.skippedRecords, 1)
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
        XCTAssertFalse(store.exportItems(destinationURL: exportURL))
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
        XCTAssertTrue(store.exportItems(destinationURL: exportURL))

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
        XCTAssertTrue(store.exportItems(destinationURL: URL(fileURLWithPath: "/tmp/structured-export.json")))
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

private final class FakeConvenienceUnlockStore: ConvenienceUnlockStoring {
    private var materials: [String: String] = [:]
    private var legacyPasswordMaterials: [String: [String: String]] = [:]

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
        materials[key(for: vaultURL)] = nil
    }

    func deleteLegacyPasswordMaterial(for vaultURL: URL) throws -> Int {
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

    private func key(for vaultURL: URL) -> String {
        vaultURL.standardizedFileURL.path
    }
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
    var backupDestinationPath: String?
    var restoreSourcePath: String?
    var restoreDestinationPath: String?
    var backupCallCount = 0
    var restoreBackupCallCount = 0
    var refreshCallCount = 0
    var passwordHealthCallCount = 0
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
    var quarantineRejectedCallCount = 0
    var importSecureNoteOnCommit = false
    var importCreditCardOnCommit = false
    var localUnlockMaterialRequests: [UInt64] = []
    var localMaterialUnlockPath: String?
    var localMaterialUsed: String?
    var masterPasswordChanges: [(sessionId: UInt64, currentPassword: String, newPassword: String)] = []
    var localMaterialUnlockError: Error?
    var changeMasterPasswordError: Error?
    var refreshError: Error?
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
    private var secureNoteDetails: [String: SecureNoteDetail] = [:]
    private var creditCardDetails: [String: CreditCardDetail] = [:]
    private var softwareLicenseDetails: [String: SoftwareLicenseDetail] = [:]
    private var passwords: [String: String] = [:]
    private var cardNumbers: [String: String] = [:]
    private var cardVerificationCodes: [String: String] = [:]
    private var licenseKeys: [String: String] = [:]
    private var nextId = 1
    private var nextRevision = 1

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

    func unlock(path: String, password: String) throws -> UnlockedPayload {
        UnlockedPayload(sessionId: 7, items: visibleItems(includeArchived: false))
    }

    func unlockWithLocalMaterial(path: String, localMaterial: String) throws -> UnlockedPayload {
        localMaterialUnlockPath = path
        localMaterialUsed = localMaterial
        if let localMaterialUnlockError {
            throw localMaterialUnlockError
        }
        return UnlockedPayload(sessionId: 9, items: visibleItems(includeArchived: false))
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
            } else {
                return false
            }
            return haystack.contains(needle)
        }
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
        passwords[itemId] = nil
        cardNumbers[itemId] = nil
        cardVerificationCodes[itemId] = nil
        licenseKeys[itemId] = nil
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

    func exportItems(sessionId: UInt64, destinationPath: String, exportFormat: String) throws -> ExportResultPayload {
        exportedPath = destinationPath
        exportedFormat = exportFormat
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

    private func setStatus(itemId: String, status: String, revision: String) {
        guard let index = items.firstIndex(where: { $0.id == itemId }) else {
            return
        }
        items[index] = VaultItemView(
            id: itemId,
            revision: revision,
            title: items[index].title,
            itemType: items[index].itemType,
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
        }
    }

    private func visibleItems(includeArchived: Bool) -> [VaultItemView] {
        items.filter { includeArchived || $0.status == "active" || $0.status == "conflicted" }
    }
}
