import AppKit
import Combine
import Foundation

enum EditorSaveOutcome: Equatable {
    case saved
    case staleDraftPreserved
    case failed
}

enum ForgottenVaultTrashOutcome: Equatable {
    case moved
    case movedWithKeychainCleanupFailure
    case failed

    var didMove: Bool {
        self != .failed
    }
}

private enum ForgottenVaultRecoveryError: Error {
    case unsupportedTrashTarget
}

@MainActor
final class VaultStore: ObservableObject {
    static let supportedClipboardTimeouts: [TimeInterval] = [15, 30, 45, 60, 120]
    static let supportedAutoLockDurations: [TimeInterval] = [60, 300, 600, 900]
    static let defaultClipboardTimeout: TimeInterval = 45
    static let defaultAutoLockSeconds: TimeInterval = 300
    static let clipboardTimeoutKey = "security.clipboardTimeoutSeconds"
    static let autoLockSecondsKey = "security.autoLockSeconds"
    static let bitwardenJsonImportFormat = "bitwarden-json"
    static let genericLoginCsvImportFormat = "generic-login-csv"
    static let knownItemTypeOrder = ["login", "secure note", "credit card", "software license"]

    @MainActor
    private struct NavigationFilterState {
        let destination: VaultNavigationDestination
        let includeArchived: Bool
        let showArchivedOnly: Bool
        let showFavoritesOnly: Bool
        let showConflictsOnly: Bool
        let selectedItemTypeFilter: String?
        let selectedTagFilter: String?

        init(store: VaultStore) {
            destination = store.navigationDestination
            includeArchived = store.includeArchived
            showArchivedOnly = store.showArchivedOnly
            showFavoritesOnly = store.showFavoritesOnly
            showConflictsOnly = store.showConflictsOnly
            selectedItemTypeFilter = store.selectedItemTypeFilter
            selectedTagFilter = store.selectedTagFilter
        }

        func restore(to store: VaultStore) {
            store.navigationDestination = destination
            store.includeArchived = includeArchived
            store.showArchivedOnly = showArchivedOnly
            store.showFavoritesOnly = showFavoritesOnly
            store.showConflictsOnly = showConflictsOnly
            store.selectedItemTypeFilter = selectedItemTypeFilter
            store.selectedTagFilter = selectedTagFilter
        }
    }

    @Published var vaultURL: URL?
    @Published var sessionId: UInt64?
    @Published var items: [VaultItemView] = []
    @Published var selectedItemId: String?
    @Published var selectedDetail: LoginDetail?
    @Published var selectedSecureNoteDetail: SecureNoteDetail?
    @Published var selectedCreditCardDetail: CreditCardDetail?
    @Published var selectedSoftwareLicenseDetail: SoftwareLicenseDetail?
    @Published var conflictCandidates: [ConflictCandidateView] = []
    @Published var searchText = ""
    @Published var statusMessage = ""
    @Published var isBusy = false
    @Published var includeArchived = false
    @Published var showArchivedOnly = false
    @Published var showFavoritesOnly = false
    @Published var showConflictsOnly = false
    @Published var selectedItemTypeFilter: String?
    @Published private(set) var availableItemTypes: [String] = []
    @Published var selectedTagFilter: String?
    @Published private(set) var availableTags: [String] = []
    @Published private(set) var navigationDestination = VaultNavigationDestination.allItems
    @Published private(set) var navigationItems: [VaultItemView] = []
    @Published var clipboardTimeout: TimeInterval = VaultStore.defaultClipboardTimeout {
        didSet {
            let normalizedValue = normalizePreference(
                clipboardTimeout,
                supportedValues: Self.supportedClipboardTimeouts,
                defaultValue: Self.defaultClipboardTimeout
            )
            if clipboardTimeout != normalizedValue {
                clipboardTimeout = normalizedValue
                return
            }
            userDefaults.set(clipboardTimeout, forKey: Self.clipboardTimeoutKey)
        }
    }
    @Published var autoLockSeconds: TimeInterval = VaultStore.defaultAutoLockSeconds {
        didSet {
            let normalizedValue = normalizePreference(
                autoLockSeconds,
                supportedValues: Self.supportedAutoLockDurations,
                defaultValue: Self.defaultAutoLockSeconds
            )
            if autoLockSeconds != normalizedValue {
                autoLockSeconds = normalizedValue
                return
            }
            userDefaults.set(autoLockSeconds, forKey: Self.autoLockSecondsKey)
        }
    }
    @Published var convenienceUnlockAvailable = false
    @Published var recentVaultURL: URL?
    @Published var importSourceURL: URL?
    @Published var importPreview: ImportPreviewPayload?
    @Published var importCompleted = false
    @Published var exportResult: ExportResultPayload?
    @Published var backupResult: BackupResultPayload?
    @Published var restoreBackupResult: RestoreBackupResultPayload?
    @Published var copyVaultToSyncResult: RestoreBackupResultPayload?
    @Published var plaintextExportURL: URL?
    @Published var backupDestinationURL: URL?
    @Published var restoredBackupURL: URL?
    @Published var copiedSyncVaultURL: URL?
    @Published var syncReport: SyncRefreshPayload?
    @Published var lastSyncQuarantine: SyncQuarantinePayload?
    @Published var passwordHealth: PasswordHealthPayload?
    @Published var staleSaveReview: StaleSaveReview?
    @Published var lastSyncRefreshAt: Date?
    @Published private(set) var syncRefreshDeferredByUnsavedEdits = false

    let service: CoreService
    private let clipboard: ClipboardManaging
    private let diagnosticsPasteboard: PasteboardStoring
    private let convenienceUnlockStore: ConvenienceUnlockStoring
    private let importSourceHandler: ImportSourceHandling
    private let urlOpener: URLOpening
    private let userDefaults: UserDefaults
    private let now: () -> Date
    private var autoLockTimer: Timer?
    private var syncPollTimer: Timer?
    private var cancellables = Set<AnyCancellable>()
    private var lastActivity = Date()
    private var lastVaultSignature: String?
    private var editorHasUnsavedChanges = false
    private var importSourceFormat = VaultStore.bitwardenJsonImportFormat
    private let recentVaultPathKey = "recentVaultPath"

    var isUnlocked: Bool {
        sessionId != nil
    }

    var selectedItem: VaultItemView? {
        items.first { $0.id == selectedItemId }
    }

    var navigationCounts: VaultNavigationCounts {
        VaultNavigationCounts(items: navigationItems, passwordHealth: passwordHealth)
    }

    var hasActiveListFilters: Bool {
        includeArchived
            || showArchivedOnly
            || showFavoritesOnly
            || showConflictsOnly
            || selectedItemTypeFilter != nil
            || selectedTagFilter != nil
            || !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func importFormat(for url: URL) -> String {
        if url.pathExtension.caseInsensitiveCompare("csv") == .orderedSame {
            return genericLoginCsvImportFormat
        }
        return bitwardenJsonImportFormat
    }

    var canResolveSelectedConflict: Bool {
        selectedItem?.isConflicted == true
    }

    var canRestoreSelectedArchive: Bool {
        selectedItem?.isArchived == true
    }

    var canSaveCurrentEditor: Bool {
        guard selectedItemId != nil else { return true }
        return selectedItem.map { !$0.isConflicted } ?? false
    }

    var canMutateSelectedItem: Bool {
        selectedItem.map { !$0.isConflicted } ?? false
    }

    var canDuplicateSelectedItem: Bool {
        guard isUnlocked, let selectedItem, !selectedItem.isConflicted else { return false }
        return selectedItem.isLogin
            || selectedItem.isSecureNote
            || selectedItem.isCreditCard
            || selectedItem.isSoftwareLicense
    }

    var canCopyLoginFields: Bool {
        selectedItem?.isLogin == true && canMutateSelectedItem
    }

    var canCopyTotpCode: Bool {
        guard selectedItem?.isLogin == true, canMutateSelectedItem else { return false }
        return selectedDetail?.totpSecret?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }

    var canOpenSelectedLoginURL: Bool {
        selectedItem?.isLogin == true && canMutateSelectedItem
    }

    var canCopySecureNoteBody: Bool {
        selectedItem?.isSecureNote == true && canMutateSelectedItem
    }

    var canCopyCreditCardFields: Bool {
        selectedItem?.isCreditCard == true && canMutateSelectedItem
    }

    var canCopySoftwareLicenseFields: Bool {
        selectedItem?.isSoftwareLicense == true && canMutateSelectedItem
    }

    var canExport: Bool {
        isUnlocked && !editorHasUnsavedChanges
    }

    var canBackup: Bool {
        isUnlocked
    }

    var canRestoreBackup: Bool {
        service.isAvailable
    }

    var canCopyVaultToSyncLocation: Bool {
        vaultURL != nil && service.isAvailable
    }

    var hasSyncIssues: Bool {
        guard let syncReport else { return false }
        return syncReport.detectedConflicts > 0 || syncReport.rejectedRecords > 0
    }

    var canQuarantineRejectedRecords: Bool {
        isUnlocked && (syncReport?.rejectedRecords ?? 0) > 0
    }

    var canShowConflictedItems: Bool {
        isUnlocked && (syncReport?.detectedConflicts ?? 0) > 0
    }

    var syncLocationHint: VaultSyncLocationHint {
        VaultSyncLocationHint.classify(url: vaultURL)
    }

    var syncReadiness: VaultSyncReadiness? {
        VaultSyncReadiness.inspect(url: vaultURL)
    }

    func diagnosticsSnapshot(languageRaw: String) -> DiagnosticsSnapshot {
        let readiness = syncReadiness
        return DiagnosticsSnapshot(
            appName: bundleValue("CFBundleName", fallback: KeptNearBrand.name),
            appVersion: bundleValue("CFBundleShortVersionString", fallback: "development"),
            appBuild: bundleValue("CFBundleVersion", fallback: "development"),
            coreAvailable: service.isAvailable,
            coreStatus: service.status,
            vaultSelected: vaultURL != nil,
            vaultName: vaultURL?.lastPathComponent,
            unlocked: isUnlocked,
            itemCount: items.count,
            plaintextImportCleanupPending: importSourceURL != nil,
            plaintextExportCleanupPending: plaintextExportURL != nil,
            convenienceUnlockAvailable: convenienceUnlockAvailable,
            syncReadiness: readiness.map {
                SyncReadinessDiagnosticsSnapshot(
                    status: $0.status,
                    requiredStructureComplete: $0.requiredStructureComplete,
                    missingOrInvalidRequiredPathLabels: $0.missingOrInvalidRequiredPathLabels,
                    likelyProviderName: $0.locationHint.provider?.displayName,
                    localUnlockEnvelopePresent: $0.localUnlockEnvelopePresent
                )
            },
            sync: syncReport.map {
                SyncDiagnosticsSnapshot(
                    loadedItems: $0.loadedItems,
                    appliedTombstones: $0.appliedTombstones,
                    detectedConflicts: $0.detectedConflicts,
                    rejectedRecords: $0.rejectedRecords,
                    rejectedItemRecords: $0.rejectedItemRecords,
                    rejectedTombstoneRecords: $0.rejectedTombstoneRecords
                )
            },
            syncRefreshDeferredByUnsavedEdits: syncRefreshDeferredByUnsavedEdits,
            clipboardTimeoutSeconds: Int(clipboardTimeout),
            autoLockSeconds: Int(autoLockSeconds),
            language: AppLanguage.resolve(languageRaw)
        )
    }

    func diagnosticsReport(languageRaw: String) -> String {
        DiagnosticsFormatter.report(for: diagnosticsSnapshot(languageRaw: languageRaw))
    }

    func copyDiagnostics(languageRaw: String) {
        diagnosticsPasteboard.clearContents()
        diagnosticsPasteboard.setString(diagnosticsReport(languageRaw: languageRaw), forType: .string)
        statusMessage = "Diagnostics copied"
    }

    func copySyncIssueDiagnostics(languageRaw: String) {
        copyDiagnostics(languageRaw: languageRaw)
    }

    func copySyncReadinessDiagnostics(languageRaw: String) {
        copyDiagnostics(languageRaw: languageRaw)
    }

    func recordStaleSaveReview(_ review: StaleSaveReview) {
        staleSaveReview = review
    }

    func clearStaleSaveReview() {
        staleSaveReview = nil
    }

    func revealVaultInFinder() {
        guard let vaultURL else { return }
        importSourceHandler.revealInFinder(vaultURL)
        statusMessage = "Vault revealed in Finder"
    }

    init(
        service: CoreService,
        clipboard: ClipboardManaging = ClipboardManager(),
        diagnosticsPasteboard: PasteboardStoring = NSPasteboard.general,
        convenienceUnlockStore: ConvenienceUnlockStoring = KeychainConvenienceUnlockStore(),
        importSourceHandler: ImportSourceHandling = MacImportSourceHandler(),
        urlOpener: URLOpening = MacURLOpener(),
        now: @escaping () -> Date = Date.init,
        userDefaults: UserDefaults = .standard
    ) {
        self.service = service
        self.clipboard = clipboard
        self.diagnosticsPasteboard = diagnosticsPasteboard
        self.convenienceUnlockStore = convenienceUnlockStore
        self.importSourceHandler = importSourceHandler
        self.urlOpener = urlOpener
        self.now = now
        self.userDefaults = userDefaults
        statusMessage = service.status
        loadSecurityPreferences()
        loadRecentVault()
        startAutoLock()
        observeSystemLock()
    }

    func touch() {
        lastActivity = Date()
    }

    @discardableResult
    func validateCreateVaultPassword(password: String, confirmation: String) -> Bool {
        guard !password.isEmpty else {
            statusMessage = "Master password is required"
            return false
        }
        guard password == confirmation else {
            statusMessage = "Master passwords do not match"
            return false
        }
        return true
    }

    @discardableResult
    func createVault(
        url: URL,
        displayName: String?,
        password: String,
        confirmation: String,
        rememberForConvenience: Bool = false,
        discardingUnsavedEdits: Bool = false
    ) -> Bool {
        guard validateCreateVaultPassword(password: password, confirmation: confirmation) else {
            return false
        }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before switching vaults"
            return false
        }
        var didCreate = false
        perform {
            try service.createVault(path: url.path, displayName: displayName, password: password)
            clearActiveVaultSession()
            vaultURL = url
            rememberVault(url)
            try unlockVault(password: password)
            if rememberForConvenience {
                try saveConvenienceUnlockMaterial(for: url)
            }
            refreshConvenienceUnlockAvailability()
            resetVaultSignature()
            startSyncPolling()
            statusMessage = "Vault created"
            didCreate = true
        }
        return didCreate
    }

    @discardableResult
    func openVault(url: URL, discardingUnsavedEdits: Bool = false) -> Bool {
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before switching vaults"
            return false
        }
        var didOpen = false
        perform {
            try service.openVault(path: url.path)
            clearActiveVaultSession()
            vaultURL = url
            rememberVault(url)
            refreshConvenienceUnlockAvailability()
            statusMessage = url.lastPathComponent
            didOpen = true
        }
        return didOpen
    }

    @discardableResult
    func openRecentVault(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let recentVaultURL else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before switching vaults"
            return false
        }
        guard FileManager.default.fileExists(atPath: recentVaultURL.path) else {
            forgetRecentVault()
            statusMessage = "Recent vault not found"
            return false
        }
        return openVault(url: recentVaultURL, discardingUnsavedEdits: discardingUnsavedEdits)
    }

    func unlock(password: String, rememberForConvenience: Bool = false) {
        perform {
            try unlockVault(password: password)
            if rememberForConvenience, let vaultURL {
                try saveConvenienceUnlockMaterial(for: vaultURL)
                refreshConvenienceUnlockAvailability()
            }
            statusMessage = "Vault unlocked"
        }
    }

    func unlockWithConvenience() {
        perform {
            guard let vaultURL else {
                throw CoreBridgeError.commandFailed("No vault selected")
            }
            guard let material = try convenienceUnlockStore.loadMaterial(for: vaultURL) else {
                refreshConvenienceUnlockAvailability()
                throw ConvenienceUnlockError.unavailable
            }
            do {
                try unlockVault(localMaterial: material)
            } catch {
                try? convenienceUnlockStore.deleteMaterial(for: vaultURL)
                refreshConvenienceUnlockAvailability()
                throw error
            }
            statusMessage = "Vault unlocked with Keychain"
        }
    }

    func disableConvenienceUnlock() {
        perform {
            guard let vaultURL else { return }
            try convenienceUnlockStore.deleteMaterial(for: vaultURL)
            refreshConvenienceUnlockAvailability()
            statusMessage = "Keychain unlock disabled"
        }
    }

    func cleanupLegacyKeychainPasswords() {
        perform {
            guard let vaultURL else {
                statusMessage = "Open a vault first"
                return
            }
            let removed = try convenienceUnlockStore.deleteLegacyPasswordMaterial(for: vaultURL)
            refreshConvenienceUnlockAvailability()
            statusMessage = removed > 0
                ? "Legacy Keychain entries removed"
                : "No legacy Keychain entries found"
        }
    }

    @discardableResult
    func changeMasterPassword(
        currentPassword: String,
        newPassword: String,
        confirmation: String
    ) -> Bool {
        guard let sessionId, let vaultURL else {
            statusMessage = "Unlock a vault first"
            return false
        }
        guard !currentPassword.isEmpty else {
            statusMessage = "Current master password is required"
            return false
        }
        guard !newPassword.isEmpty else {
            statusMessage = "New master password is required"
            return false
        }
        guard newPassword == confirmation else {
            statusMessage = "New master passwords do not match"
            return false
        }

        touch()
        isBusy = true
        defer { isBusy = false }
        do {
            try service.changeMasterPassword(
                sessionId: sessionId,
                currentPassword: currentPassword,
                newPassword: newPassword
            )
            try convenienceUnlockStore.deleteMaterial(for: vaultURL)
            refreshConvenienceUnlockAvailability()
            statusMessage = "Master password changed"
            return true
        } catch {
            statusMessage = statusMessage(for: error)
            return false
        }
    }

    func lock() {
        guard let sessionId else { return }
        perform {
            clearActiveVaultSession(sessionId: sessionId)
            refreshConvenienceUnlockAvailability()
            statusMessage = "Vault locked"
        }
    }

    @discardableResult
    func closeVault(discardingUnsavedEdits: Bool = false) -> Bool {
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before closing vault"
            return false
        }
        var didClose = false
        perform {
            clearActiveVaultSession()
            vaultURL = nil
            convenienceUnlockAvailable = false
            statusMessage = "Vault closed"
            didClose = true
        }
        return didClose
    }

    @discardableResult
    func moveForgottenVaultToTrash() -> ForgottenVaultTrashOutcome {
        guard !isUnlocked else {
            statusMessage = "Lock the vault before moving it to Trash"
            return .failed
        }
        guard let vaultURL else {
            statusMessage = "No vault selected"
            return .failed
        }

        let trashTarget: URL
        do {
            trashTarget = try validatedForgottenVaultTrashTarget(vaultURL)
        } catch {
            statusMessage = "Only a local .pswvault directory can be moved to Trash"
            return .failed
        }

        touch()
        isBusy = true
        defer { isBusy = false }

        do {
            try importSourceHandler.moveToTrash(trashTarget)
        } catch {
            statusMessage = "Vault could not be moved to Trash"
            return .failed
        }

        let keychainCleanupSucceeded = clearConvenienceUnlockMaterial(for: trashTarget)
        clearActiveVaultSession()
        self.vaultURL = nil
        convenienceUnlockAvailable = false
        if recentVaultURL?.standardizedFileURL.path == trashTarget.path {
            forgetRecentVault()
        }
        statusMessage = keychainCleanupSucceeded
            ? "Vault moved to Trash"
            : "Vault moved to Trash, but Keychain cleanup failed"
        return keychainCleanupSucceeded ? .moved : .movedWithKeychainCleanupFailure
    }

    func refreshItems() {
        guard let sessionId else { return }
        perform {
            if applyVisibleItems(try service.listItems(sessionId: sessionId)) {
                refreshNavigationInventory()
                resetVaultSignature()
                statusMessage = "\(items.count) items"
            }
        }
    }

    func refreshPasswordHealth() {
        guard let sessionId else {
            passwordHealth = nil
            return
        }
        perform {
            passwordHealth = try service.passwordHealth(sessionId: sessionId)
            statusMessage = "Password health refreshed"
        }
    }

    @discardableResult
    func showPasswordHealthIssue(_ issue: PasswordHealthIssue, discardingUnsavedEdits: Bool = false) -> Bool {
        guard isUnlocked else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before changing selection"
            return false
        }

        if discardingUnsavedEdits {
            editorHasUnsavedChanges = false
        }
        searchText = ""
        includeArchived = true
        showArchivedOnly = false
        showFavoritesOnly = false
        showConflictsOnly = false
        selectedItemTypeFilter = nil
        selectedTagFilter = nil
        _ = search()
        let selected = select(itemId: issue.itemId, discardingUnsavedEdits: discardingUnsavedEdits)
        if selected {
            navigationDestination = .security
        }
        return selected
    }

    @discardableResult
    func prepareItemListAction(itemId: String, discardingUnsavedEdits: Bool = false) -> Bool {
        guard isUnlocked else { return false }
        return select(itemId: itemId, discardingUnsavedEdits: discardingUnsavedEdits)
    }

    @discardableResult
    func clearListFilters() -> Bool {
        guard isUnlocked else { return false }
        searchText = ""
        includeArchived = false
        showArchivedOnly = false
        showFavoritesOnly = false
        showConflictsOnly = false
        selectedItemTypeFilter = nil
        selectedTagFilter = nil
        let applied = search()
        if applied {
            navigationDestination = .allItems
            statusMessage = "Filters cleared"
        }
        return applied
    }

    @discardableResult
    func applyNavigationDestination(
        _ destination: VaultNavigationDestination,
        discardingUnsavedEdits: Bool = false
    ) -> Bool {
        guard isUnlocked else { return false }
        guard destination != navigationDestination else { return true }

        if destination == .security {
            navigationDestination = .security
            return true
        }

        let previousState = NavigationFilterState(store: self)
        if discardingUnsavedEdits {
            editorHasUnsavedChanges = false
        }
        applyFilterState(for: destination)

        guard search() else {
            previousState.restore(to: self)
            return false
        }

        navigationDestination = destination
        return true
    }

    func navigationDestinationHidesSelectedItem(
        _ destination: VaultNavigationDestination
    ) -> Bool {
        guard destination.isItemDestination, let selectedItem else { return false }

        switch destination {
        case .allItems:
            return selectedItem.isArchived
        case .favorites:
            return selectedItem.isArchived || !selectedItem.favorite
        case .security:
            return false
        case .conflicts:
            return selectedItem.isArchived || !selectedItem.isConflicted
        case .archive:
            return !selectedItem.isArchived
        case let .itemType(itemType):
            return selectedItem.isArchived
                || Self.normalizedItemType(selectedItem.itemType) != Self.normalizedItemType(itemType)
        case let .tag(tag):
            return selectedItem.isArchived
                || !selectedItem.tags.contains { Self.normalizedTag($0) == Self.normalizedTag(tag) }
        }
    }

    private func applyFilterState(for destination: VaultNavigationDestination) {
        includeArchived = false
        showArchivedOnly = false
        showFavoritesOnly = false
        showConflictsOnly = false
        selectedItemTypeFilter = nil
        selectedTagFilter = nil

        switch destination {
        case .allItems:
            break
        case .favorites:
            showFavoritesOnly = true
        case .security:
            break
        case .conflicts:
            showConflictsOnly = true
        case .archive:
            includeArchived = true
            showArchivedOnly = true
        case let .itemType(itemType):
            selectedItemTypeFilter = itemType
        case let .tag(tag):
            selectedTagFilter = tag
        }
    }

    func refreshFromDisk(discardingUnsavedEdits: Bool = false) {
        guard let sessionId else { return }
        if editorHasUnsavedChanges && !discardingUnsavedEdits {
            statusMessage = "Sync refresh paused for unsaved edits"
            return
        }
        perform {
            clearStaleSaveReview()
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            syncRefreshDeferredByUnsavedEdits = false
            let previousSelection = selectedItemId
            let report = try refreshFromDiskForSyncStatus(sessionId: sessionId)
            try applySyncRefreshReport(report, sessionId: sessionId, preferredSelection: previousSelection)
            statusMessage = "Sync refreshed"
        }
    }

    func setEditorHasUnsavedChanges(_ hasUnsavedChanges: Bool) {
        let wasDirty = editorHasUnsavedChanges
        editorHasUnsavedChanges = hasUnsavedChanges
        guard wasDirty, !hasUnsavedChanges, syncRefreshDeferredByUnsavedEdits else { return }
        syncRefreshDeferredByUnsavedEdits = false
        refreshFromDisk()
    }

    @discardableResult
    func quarantineRejectedRecords(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before sync recovery"
            return false
        }
        var quarantined = false
        perform {
            let previousSelection = selectedItemId
            let quarantine = try service.quarantineRejectedRecords(sessionId: sessionId)
            let report = try refreshFromDiskForSyncStatus(sessionId: sessionId)
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            try applySyncRefreshReport(
                report,
                sessionId: sessionId,
                preferredSelection: previousSelection,
                clearQuarantineResult: false
            )
            lastSyncQuarantine = quarantine
            statusMessage = "Quarantined \(quarantine.movedRecords) rejected records"
            quarantined = true
        }
        return quarantined
    }

    private func refreshConvenienceUnlockAvailability() {
        guard let vaultURL else {
            convenienceUnlockAvailable = false
            return
        }
        convenienceUnlockAvailable = convenienceUnlockStore.containsMaterial(for: vaultURL)
    }

    @discardableResult
    func search() -> Bool {
        guard let sessionId else { return false }
        var applied = false
        perform {
            let results = try service.search(sessionId: sessionId, text: searchText, includeArchived: includeArchived)
            applied = applyVisibleItems(results)
        }
        return applied
    }

    func showConflictedItems() {
        guard canShowConflictedItems else { return }
        if applyNavigationDestination(.conflicts) {
            statusMessage = "Showing conflicts"
        }
    }

    @discardableResult
    func select(itemId: String?, discardingUnsavedEdits: Bool = false) -> Bool {
        if itemId == selectedItemId {
            return true
        }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before changing selection"
            return false
        }
        clearStaleSaveReview()
        selectedItemId = itemId
        clearSelectedDetails()
        conflictCandidates = []
        guard let sessionId, let itemId else { return true }
        var selected = false
        perform {
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            try loadSelectedDetail(sessionId: sessionId, itemId: itemId)
            selected = true
        }
        return selected
    }

    @discardableResult
    func saveLogin(form: LoginForm) -> EditorSaveOutcome {
        guard let sessionId else { return .failed }
        guard form.isValidForSave else {
            statusMessage = "Title is required"
            return .failed
        }
        guard canSaveCurrentEditor else {
            statusMessage = "Resolve conflict before editing"
            return .failed
        }
        let currentSelectedItemId = selectedItemId
        return performSave(
            sessionId: sessionId,
            staleItemId: currentSelectedItemId,
            staleReviewBuilder: { [form] in
                self.selectedDetail.map { Self.staleLoginReview(current: $0, draft: form) }
            }
        ) {
            if let selectedItemId = currentSelectedItemId {
                guard selectedItem?.isLogin == true else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var guardedForm = form
                guardedForm.revision = guardedForm.revision ?? selectedDetail?.revision
                let updatedItems = try service.updateLogin(sessionId: sessionId, itemId: selectedItemId, form: guardedForm)
                if applyMutationItems(updatedItems, preferredSelection: selectedItemId), self.selectedItemId == selectedItemId {
                    selectedDetail = try service.getLogin(sessionId: sessionId, itemId: selectedItemId)
                    selectedSecureNoteDetail = nil
                    selectedCreditCardDetail = nil
                    selectedSoftwareLicenseDetail = nil
                }
            } else {
                let existingIds = Set(items.map(\.id))
                let createdItems = try service.createLogin(sessionId: sessionId, form: form)
                let newItem = createdItems.first(where: { !existingIds.contains($0.id) })
                if applyMutationItems(createdItems, preferredSelection: newItem?.id), let newItem, selectedItemId == newItem.id {
                    selectedDetail = try? service.getLogin(sessionId: sessionId, itemId: newItem.id)
                    selectedSecureNoteDetail = nil
                    selectedCreditCardDetail = nil
                    selectedSoftwareLicenseDetail = nil
                }
            }
            recordVaultContentChange()
            statusMessage = "Saved"
        }
    }

    @discardableResult
    func saveSecureNote(form: SecureNoteForm) -> EditorSaveOutcome {
        guard let sessionId else { return .failed }
        guard form.isValidForSave else {
            statusMessage = "Title is required"
            return .failed
        }
        guard canSaveCurrentEditor else {
            statusMessage = "Resolve conflict before editing"
            return .failed
        }
        let currentSelectedItemId = selectedItemId
        return performSave(
            sessionId: sessionId,
            staleItemId: currentSelectedItemId,
            staleReviewBuilder: { [form] in
                self.selectedSecureNoteDetail.map { Self.staleSecureNoteReview(current: $0, draft: form) }
            }
        ) {
            if let selectedItemId = currentSelectedItemId {
                guard selectedItem?.isSecureNote == true else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var guardedForm = form
                guardedForm.revision = guardedForm.revision ?? selectedSecureNoteDetail?.revision
                let updatedItems = try service.updateSecureNote(sessionId: sessionId, itemId: selectedItemId, form: guardedForm)
                if applyMutationItems(updatedItems, preferredSelection: selectedItemId), self.selectedItemId == selectedItemId {
                    selectedDetail = nil
                    selectedSecureNoteDetail = try service.getSecureNote(sessionId: sessionId, itemId: selectedItemId)
                    selectedCreditCardDetail = nil
                    selectedSoftwareLicenseDetail = nil
                }
            } else {
                let existingIds = Set(items.map(\.id))
                let createdItems = try service.createSecureNote(sessionId: sessionId, form: form)
                let newItem = createdItems.first(where: { !existingIds.contains($0.id) })
                if applyMutationItems(createdItems, preferredSelection: newItem?.id), let newItem, selectedItemId == newItem.id {
                    selectedDetail = nil
                    selectedSecureNoteDetail = try? service.getSecureNote(sessionId: sessionId, itemId: newItem.id)
                    selectedCreditCardDetail = nil
                    selectedSoftwareLicenseDetail = nil
                }
            }
            recordVaultContentChange()
            statusMessage = "Saved"
        }
    }

    @discardableResult
    func saveCreditCard(form: CreditCardForm) -> EditorSaveOutcome {
        guard let sessionId else { return .failed }
        guard form.isValidForSave else {
            statusMessage = "Title is required"
            return .failed
        }
        guard canSaveCurrentEditor else {
            statusMessage = "Resolve conflict before editing"
            return .failed
        }
        let currentSelectedItemId = selectedItemId
        return performSave(
            sessionId: sessionId,
            staleItemId: currentSelectedItemId,
            staleReviewBuilder: { [form] in
                self.selectedCreditCardDetail.map { Self.staleCreditCardReview(current: $0, draft: form) }
            }
        ) {
            if let selectedItemId = currentSelectedItemId {
                guard selectedItem?.isCreditCard == true else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var guardedForm = form
                guardedForm.revision = guardedForm.revision ?? selectedCreditCardDetail?.revision
                let updatedItems = try service.updateCreditCard(sessionId: sessionId, itemId: selectedItemId, form: guardedForm)
                if applyMutationItems(updatedItems, preferredSelection: selectedItemId), self.selectedItemId == selectedItemId {
                    selectedDetail = nil
                    selectedSecureNoteDetail = nil
                    selectedCreditCardDetail = try service.getCreditCard(sessionId: sessionId, itemId: selectedItemId)
                    selectedSoftwareLicenseDetail = nil
                }
            } else {
                let existingIds = Set(items.map(\.id))
                let createdItems = try service.createCreditCard(sessionId: sessionId, form: form)
                let newItem = createdItems.first(where: { !existingIds.contains($0.id) })
                if applyMutationItems(createdItems, preferredSelection: newItem?.id), let newItem, selectedItemId == newItem.id {
                    selectedDetail = nil
                    selectedSecureNoteDetail = nil
                    selectedCreditCardDetail = try? service.getCreditCard(sessionId: sessionId, itemId: newItem.id)
                    selectedSoftwareLicenseDetail = nil
                }
            }
            recordVaultContentChange()
            statusMessage = "Saved"
        }
    }

    @discardableResult
    func saveSoftwareLicense(form: SoftwareLicenseForm) -> EditorSaveOutcome {
        guard let sessionId else { return .failed }
        guard form.isValidForSave else {
            statusMessage = "Title is required"
            return .failed
        }
        guard canSaveCurrentEditor else {
            statusMessage = "Resolve conflict before editing"
            return .failed
        }
        let currentSelectedItemId = selectedItemId
        return performSave(
            sessionId: sessionId,
            staleItemId: currentSelectedItemId,
            staleReviewBuilder: { [form] in
                self.selectedSoftwareLicenseDetail.map { Self.staleSoftwareLicenseReview(current: $0, draft: form) }
            }
        ) {
            if let selectedItemId = currentSelectedItemId {
                guard selectedItem?.isSoftwareLicense == true else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var guardedForm = form
                guardedForm.revision = guardedForm.revision ?? selectedSoftwareLicenseDetail?.revision
                let updatedItems = try service.updateSoftwareLicense(sessionId: sessionId, itemId: selectedItemId, form: guardedForm)
                if applyMutationItems(updatedItems, preferredSelection: selectedItemId), self.selectedItemId == selectedItemId {
                    selectedDetail = nil
                    selectedSecureNoteDetail = nil
                    selectedCreditCardDetail = nil
                    selectedSoftwareLicenseDetail = try service.getSoftwareLicense(sessionId: sessionId, itemId: selectedItemId)
                }
            } else {
                let existingIds = Set(items.map(\.id))
                let createdItems = try service.createSoftwareLicense(sessionId: sessionId, form: form)
                let newItem = createdItems.first(where: { !existingIds.contains($0.id) })
                if applyMutationItems(createdItems, preferredSelection: newItem?.id), let newItem, selectedItemId == newItem.id {
                    selectedItemId = newItem.id
                    selectedDetail = nil
                    selectedSecureNoteDetail = nil
                    selectedCreditCardDetail = nil
                    selectedSoftwareLicenseDetail = try? service.getSoftwareLicense(sessionId: sessionId, itemId: newItem.id)
                }
            }
            recordVaultContentChange()
            statusMessage = "Saved"
        }
    }

    @discardableResult
    func duplicateSelectedItem(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let selectedItem else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before duplicating"
            return false
        }
        guard canDuplicateSelectedItem else {
            statusMessage = selectedItem.isConflicted ? "Resolve conflict before editing" : "Unsupported item type"
            return false
        }

        var duplicated = false
        perform {
            let existingIds = Set(
                try service.search(sessionId: sessionId, text: "", includeArchived: true).map(\.id)
            )
            if selectedItem.isLogin {
                guard let selectedDetail else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var duplicateForm = LoginForm(detail: selectedDetail)
                duplicateForm.revision = nil
                duplicateForm.title = Self.duplicateTitle(selectedDetail.title)
                duplicateForm.password = try service.getLoginField(
                    sessionId: sessionId,
                    itemId: selectedDetail.id,
                    field: "password"
                )
                duplicateForm.clearPasswordOnSave = false
                let createdItems = try service.createLogin(sessionId: sessionId, form: duplicateForm)
                applyMutationItems(createdItems)
            } else if selectedItem.isSecureNote {
                guard let selectedSecureNoteDetail else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var duplicateForm = SecureNoteForm(detail: selectedSecureNoteDetail)
                duplicateForm.revision = nil
                duplicateForm.title = Self.duplicateTitle(selectedSecureNoteDetail.title)
                let createdItems = try service.createSecureNote(sessionId: sessionId, form: duplicateForm)
                applyMutationItems(createdItems)
            } else if selectedItem.isCreditCard {
                guard let selectedCreditCardDetail else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var duplicateForm = CreditCardForm(detail: selectedCreditCardDetail)
                duplicateForm.revision = nil
                duplicateForm.title = Self.duplicateTitle(selectedCreditCardDetail.title)
                duplicateForm.number = try service.getCreditCardField(
                    sessionId: sessionId,
                    itemId: selectedCreditCardDetail.id,
                    field: "number"
                )
                duplicateForm.verificationCode = try service.getCreditCardField(
                    sessionId: sessionId,
                    itemId: selectedCreditCardDetail.id,
                    field: "verification_code"
                )
                let createdItems = try service.createCreditCard(sessionId: sessionId, form: duplicateForm)
                applyMutationItems(createdItems)
            } else if selectedItem.isSoftwareLicense {
                guard let selectedSoftwareLicenseDetail else {
                    throw CoreBridgeError.commandFailed("Unsupported item type")
                }
                var duplicateForm = SoftwareLicenseForm(detail: selectedSoftwareLicenseDetail)
                duplicateForm.revision = nil
                duplicateForm.title = Self.duplicateTitle(selectedSoftwareLicenseDetail.title)
                duplicateForm.licenseKey = try service.getSoftwareLicenseField(
                    sessionId: sessionId,
                    itemId: selectedSoftwareLicenseDetail.id,
                    field: "license_key"
                )
                let createdItems = try service.createSoftwareLicense(sessionId: sessionId, form: duplicateForm)
                applyMutationItems(createdItems)
            }
            try selectNewlyCreatedItem(existingIds: existingIds, sessionId: sessionId)
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            recordVaultContentChange()
            statusMessage = "Duplicated"
            duplicated = true
        }
        return duplicated
    }

    @discardableResult
    func archiveSelected(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let selectedItem else { return false }
        let selectedItemId = selectedItem.id
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before archiving"
            return false
        }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before editing"
            return false
        }
        var archived = false
        perform {
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            let updatedItems = try service.archiveItem(
                sessionId: sessionId,
                itemId: selectedItemId,
                expectedRevision: selectedItem.revision
            )
            applyMutationItems(updatedItems)
            recordVaultContentChange()
            statusMessage = "Archived"
            archived = true
        }
        return archived
    }

    @discardableResult
    func restoreSelectedArchive(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let selectedItemId else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before restoring"
            return false
        }
        guard canRestoreSelectedArchive else {
            statusMessage = "Only archived items can be restored"
            return false
        }
        var restored = false
        perform {
            let restoredItems = try service.restoreItem(sessionId: sessionId, itemId: selectedItemId)
            applyMutationItems(restoredItems, preferredSelection: selectedItemId)
            conflictCandidates = []
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            recordVaultContentChange()
            statusMessage = "Restored"
            restored = true
        }
        return restored
    }

    @discardableResult
    func deleteSelected(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let selectedItem else { return false }
        let selectedItemId = selectedItem.id
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before deleting"
            return false
        }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before editing"
            return false
        }
        var deleted = false
        perform {
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            let updatedItems = try service.deleteItem(
                sessionId: sessionId,
                itemId: selectedItemId,
                expectedRevision: selectedItem.revision
            )
            applyMutationItems(updatedItems)
            recordVaultContentChange()
            statusMessage = "Deleted"
            deleted = true
        }
        return deleted
    }

    @discardableResult
    func resolveSelectedConflict(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let selectedConflictItemId = selectedItemId, let conflictId = selectedItem?.conflictId else {
            statusMessage = "No selected conflict"
            return false
        }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before resolving conflict"
            return false
        }
        var resolved = false
        perform {
            _ = try service.resolveConflict(sessionId: sessionId, conflictId: conflictId)
            let report = try refreshFromDiskForSyncStatus(sessionId: sessionId)
            try applySyncRefreshReport(report, sessionId: sessionId, preferredSelection: selectedConflictItemId)
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            statusMessage = "Conflict resolved"
            resolved = true
        }
        return resolved
    }

    func loadSelectedConflictCandidates() {
        guard let sessionId, let conflictId = selectedItem?.conflictId else {
            statusMessage = "No selected conflict"
            conflictCandidates = []
            return
        }
        perform {
            conflictCandidates = try service.getConflictCandidates(sessionId: sessionId, conflictId: conflictId)
            statusMessage = "\(conflictCandidates.count) conflict versions"
        }
    }

    @discardableResult
    func resolveSelectedConflictCandidate(revision: String, discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let selectedConflictItemId = selectedItemId, let conflictId = selectedItem?.conflictId else {
            statusMessage = "No selected conflict"
            return false
        }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before resolving conflict"
            return false
        }
        var resolved = false
        perform {
            _ = try service.resolveConflictCandidate(
                sessionId: sessionId,
                conflictId: conflictId,
                revision: revision
            )
            let report = try refreshFromDiskForSyncStatus(sessionId: sessionId)
            try applySyncRefreshReport(report, sessionId: sessionId, preferredSelection: selectedConflictItemId)
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            statusMessage = "Conflict resolved"
            resolved = true
        }
        return resolved
    }

    @discardableResult
    func resolveSelectedConflictMerge(
        baseRevision: String,
        fieldSelections: [ConflictMergeFieldSelection],
        discardingUnsavedEdits: Bool = false
    ) -> Bool {
        guard let sessionId, let selectedConflictItemId = selectedItemId, let conflictId = selectedItem?.conflictId else {
            statusMessage = "No selected conflict"
            return false
        }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before resolving conflict"
            return false
        }
        var resolved = false
        perform {
            _ = try service.resolveConflictMerge(
                sessionId: sessionId,
                conflictId: conflictId,
                baseRevision: baseRevision,
                fieldSelections: fieldSelections
            )
            let report = try refreshFromDiskForSyncStatus(sessionId: sessionId)
            try applySyncRefreshReport(report, sessionId: sessionId, preferredSelection: selectedConflictItemId)
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            statusMessage = "Conflict merged"
            resolved = true
        }
        return resolved
    }

    @discardableResult
    func toggleFavoriteSelected(discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let selectedItem else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before updating favorite"
            return false
        }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before editing"
            return false
        }
        var updated = false
        perform {
            let updatedItems = try service.setFavorite(
                sessionId: sessionId,
                itemId: selectedItem.id,
                expectedRevision: selectedItem.revision,
                favorite: !selectedItem.favorite
            )
            applyMutationItems(updatedItems, preferredSelection: selectedItem.id)
            conflictCandidates = []
            loadSelectedDetailIfAvailable()
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            recordVaultContentChange()
            updated = true
        }
        return updated
    }

    func copyUsername() {
        copyLoginField("username", label: "Username copied", emptyLabel: "login item has no username")
    }

    func copyPassword() {
        copyLoginField("password", label: "Password copied", emptyLabel: "login item has no password")
    }

    func copyTotp() {
        guard let sessionId, let selectedItemId, selectedItem?.isLogin == true else { return }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before copying"
            return
        }
        guard canCopyTotpCode else {
            statusMessage = "login item has no TOTP secret"
            return
        }
        perform {
            let code = try service.totpCode(sessionId: sessionId, itemId: selectedItemId)
            clipboard.copy(code.code, clearAfter: clipboardTimeout)
            statusMessage = "TOTP copied"
        }
    }

    @discardableResult
    func openSelectedLoginURL() -> Bool {
        guard canOpenSelectedLoginURL else { return false }
        guard let url = selectedDetail.flatMap({ Self.firstNormalizedWebURL(from: $0.urls) }) else {
            statusMessage = "login item has no valid URL"
            return false
        }
        urlOpener.open(url)
        statusMessage = "URL opened"
        return true
    }

    func copySecureNoteBody() {
        guard selectedItem?.isSecureNote == true else { return }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before copying"
            return
        }
        let body = selectedSecureNoteDetail?.body.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !body.isEmpty else {
            statusMessage = "secure note has no body"
            return
        }
        clipboard.copy(selectedSecureNoteDetail?.body ?? "", clearAfter: clipboardTimeout)
        statusMessage = "Secure note body copied"
    }

    func copyCardNumber() {
        copyCreditCardField("number", label: "Card number copied", emptyLabel: "credit card has no card number")
    }

    func copyCardVerificationCode() {
        copyCreditCardField(
            "verification_code",
            label: "Verification code copied",
            emptyLabel: "credit card has no verification code"
        )
    }

    func copyLicenseKey() {
        copySoftwareLicenseField("license_key", label: "License key copied", emptyLabel: "software license has no license key")
    }

    func revealSelectedLoginPassword() -> String? {
        revealLoginField("password", emptyLabel: "login item has no password")
    }

    func revealSelectedLoginTotpSecret() -> String? {
        guard selectedItem?.isLogin == true else { return nil }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before revealing"
            return nil
        }
        let value = selectedDetail?.totpSecret?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !value.isEmpty else {
            statusMessage = "login item has no TOTP secret"
            return nil
        }
        return selectedDetail?.totpSecret
    }

    func revealSelectedCardNumber() -> String? {
        revealCreditCardField("number", emptyLabel: "credit card has no card number")
    }

    func revealSelectedCardVerificationCode() -> String? {
        revealCreditCardField("verification_code", emptyLabel: "credit card has no verification code")
    }

    func revealSelectedLicenseKey() -> String? {
        revealSoftwareLicenseField("license_key", emptyLabel: "software license has no license key")
    }

    func previewImport(url: URL) {
        guard let sessionId else { return }
        let sourceFormat = Self.importFormat(for: url)
        perform {
            importSourceURL = url
            importSourceFormat = sourceFormat
            importCompleted = false
            importPreview = try service.previewImport(
                sessionId: sessionId,
                sourcePath: url.path,
                sourceFormat: sourceFormat
            )
            statusMessage = "Import preview ready"
        }
    }

    @discardableResult
    func commitImport(keepDuplicates: Bool, discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId, let importSourceURL else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before importing"
            return false
        }
        var imported = false
        perform {
            let result = try service.commitImport(
                sessionId: sessionId,
                sourcePath: importSourceURL.path,
                sourceFormat: importSourceFormat,
                keepDuplicates: keepDuplicates
            )
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            importPreview = result
            let listedItems = try service.listItems(sessionId: sessionId)
            applyMutationItems(listedItems)
            importCompleted = true
            statusMessage = "Import completed"
            recordVaultContentChange()
            imported = true
        }
        return imported
    }

    @discardableResult
    func exportItems(destinationURL: URL) -> Bool {
        guard let sessionId else { return false }
        guard !editorHasUnsavedChanges else {
            statusMessage = "Save or discard edits before exporting"
            return false
        }
        var exported = false
        perform {
            let result = try service.exportItems(
                sessionId: sessionId,
                destinationPath: destinationURL.path,
                exportFormat: "bitwarden-json"
            )
            exportResult = result
            plaintextExportURL = destinationURL
            statusMessage = "Export completed: \(result.exportedRecords) exported, \(result.skippedRecords) skipped"
            exported = true
        }
        return exported
    }

    @discardableResult
    func backupVault(destinationURL: URL, discardingUnsavedEdits: Bool = false) -> Bool {
        guard let sessionId else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before backing up"
            return false
        }
        var backedUp = false
        perform {
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            backupResult = nil
            backupDestinationURL = nil
            let result = try service.backupVault(
                sessionId: sessionId,
                destinationPath: destinationURL.path
            )
            backupResult = result
            backupDestinationURL = destinationURL
            statusMessage = "Backup completed: \(result.copiedItemFiles) items, \(result.copiedAttachmentFiles) attachments, \(result.copiedTombstoneFiles) tombstones"
            backedUp = true
        }
        return backedUp
    }

    @discardableResult
    func restoreVaultBackup(
        sourceURL: URL,
        destinationURL: URL,
        discardingUnsavedEdits: Bool = false
    ) -> Bool {
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before restoring backup"
            return false
        }
        var restored = false
        perform {
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            restoreBackupResult = nil
            restoredBackupURL = nil
            let result = try service.restoreVaultBackup(
                sourcePath: sourceURL.path,
                destinationPath: destinationURL.path
            )
            clearActiveVaultSession()
            vaultURL = destinationURL
            rememberVault(destinationURL)
            refreshConvenienceUnlockAvailability()
            resetVaultSignature()
            restoreBackupResult = result
            restoredBackupURL = destinationURL
            statusMessage = "Restore completed: \(result.copiedItemFiles) items, \(result.copiedAttachmentFiles) attachments, \(result.copiedTombstoneFiles) tombstones"
            restored = true
        }
        return restored
    }

    @discardableResult
    func copyVaultToSyncLocation(
        destinationURL: URL,
        discardingUnsavedEdits: Bool = false
    ) -> Bool {
        guard let sourceURL = vaultURL else { return false }
        guard !editorHasUnsavedChanges || discardingUnsavedEdits else {
            statusMessage = "Save or discard edits before copying to sync"
            return false
        }
        var copied = false
        perform {
            if discardingUnsavedEdits {
                editorHasUnsavedChanges = false
            }
            copyVaultToSyncResult = nil
            copiedSyncVaultURL = nil
            let result = try service.restoreVaultBackup(
                sourcePath: sourceURL.path,
                destinationPath: destinationURL.path
            )
            clearActiveVaultSession()
            vaultURL = destinationURL
            rememberVault(destinationURL)
            refreshConvenienceUnlockAvailability()
            resetVaultSignature()
            copyVaultToSyncResult = result
            copiedSyncVaultURL = destinationURL
            statusMessage = "Vault copied to sync location: \(result.copiedItemFiles) items, \(result.copiedAttachmentFiles) attachments, \(result.copiedTombstoneFiles) tombstones"
            copied = true
        }
        return copied
    }

    func clearImport() {
        importSourceURL = nil
        importSourceFormat = Self.bitwardenJsonImportFormat
        importPreview = nil
        importCompleted = false
    }

    func revealImportSource() {
        guard let importSourceURL else { return }
        importSourceHandler.revealInFinder(importSourceURL)
        statusMessage = "Import source revealed"
    }

    func moveImportSourceToTrash() {
        guard let importSourceURL else { return }
        perform {
            try importSourceHandler.moveToTrash(importSourceURL)
            self.importSourceURL = nil
            importSourceFormat = Self.bitwardenJsonImportFormat
            importCompleted = false
            statusMessage = "Import source moved to Trash"
        }
    }

    func revealPlaintextExport() {
        guard let plaintextExportURL else { return }
        importSourceHandler.revealInFinder(plaintextExportURL)
        statusMessage = "Plaintext export revealed"
    }

    func revealBackupDestination() {
        guard let backupDestinationURL else { return }
        importSourceHandler.revealInFinder(backupDestinationURL)
        statusMessage = "Backup destination revealed"
    }

    func revealRestoredBackup() {
        guard let restoredBackupURL else { return }
        importSourceHandler.revealInFinder(restoredBackupURL)
        statusMessage = "Restored vault revealed"
    }

    func revealCopiedSyncVault() {
        guard let copiedSyncVaultURL else { return }
        importSourceHandler.revealInFinder(copiedSyncVaultURL)
        statusMessage = "Copied sync vault revealed"
    }

    func movePlaintextExportToTrash() {
        guard let plaintextExportURL else { return }
        perform {
            try importSourceHandler.moveToTrash(plaintextExportURL)
            self.plaintextExportURL = nil
            statusMessage = "Plaintext export moved to Trash"
        }
    }

    private func copyLoginField(_ field: String, label: String, emptyLabel: String? = nil) {
        guard selectedItem?.isLogin == true else { return }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before copying"
            return
        }
        guard let sessionId, let selectedItemId else { return }
        perform {
            let value = try service.getLoginField(sessionId: sessionId, itemId: selectedItemId, field: field)
            if value.isEmpty, let emptyLabel {
                statusMessage = emptyLabel
                return
            }
            clipboard.copy(value, clearAfter: clipboardTimeout)
            statusMessage = label
        }
    }

    private func revealLoginField(_ field: String, emptyLabel: String) -> String? {
        guard selectedItem?.isLogin == true else { return nil }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before revealing"
            return nil
        }
        guard let sessionId, let selectedItemId else { return nil }
        var revealedValue: String?
        perform {
            let value = try service.getLoginField(sessionId: sessionId, itemId: selectedItemId, field: field)
            if value.isEmpty {
                statusMessage = emptyLabel
                return
            }
            revealedValue = value
        }
        return revealedValue
    }

    private func copyCreditCardField(_ field: String, label: String, emptyLabel: String) {
        guard selectedItem?.isCreditCard == true else { return }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before copying"
            return
        }
        guard let sessionId, let selectedItemId else { return }
        perform {
            let value = try service.getCreditCardField(sessionId: sessionId, itemId: selectedItemId, field: field)
            if value.isEmpty {
                statusMessage = emptyLabel
                return
            }
            clipboard.copy(value, clearAfter: clipboardTimeout)
            statusMessage = label
        }
    }

    private func revealCreditCardField(_ field: String, emptyLabel: String) -> String? {
        guard selectedItem?.isCreditCard == true else { return nil }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before revealing"
            return nil
        }
        guard let sessionId, let selectedItemId else { return nil }
        var revealedValue: String?
        perform {
            let value = try service.getCreditCardField(sessionId: sessionId, itemId: selectedItemId, field: field)
            if value.isEmpty {
                statusMessage = emptyLabel
                return
            }
            revealedValue = value
        }
        return revealedValue
    }

    private func copySoftwareLicenseField(_ field: String, label: String, emptyLabel: String) {
        guard selectedItem?.isSoftwareLicense == true else { return }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before copying"
            return
        }
        guard let sessionId, let selectedItemId else { return }
        perform {
            let value = try service.getSoftwareLicenseField(sessionId: sessionId, itemId: selectedItemId, field: field)
            if value.isEmpty {
                statusMessage = emptyLabel
                return
            }
            clipboard.copy(value, clearAfter: clipboardTimeout)
            statusMessage = label
        }
    }

    private func revealSoftwareLicenseField(_ field: String, emptyLabel: String) -> String? {
        guard selectedItem?.isSoftwareLicense == true else { return nil }
        guard canMutateSelectedItem else {
            statusMessage = "Resolve conflict before revealing"
            return nil
        }
        guard let sessionId, let selectedItemId else { return nil }
        var revealedValue: String?
        perform {
            let value = try service.getSoftwareLicenseField(sessionId: sessionId, itemId: selectedItemId, field: field)
            if value.isEmpty {
                statusMessage = emptyLabel
                return
            }
            revealedValue = value
        }
        return revealedValue
    }

    static func normalizedWebURL(from value: String?) -> URL? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard var components = URLComponents(string: candidate),
              let scheme = components.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              let host = components.host,
              !host.isEmpty
        else {
            return nil
        }
        components.scheme = scheme
        return components.url
    }

    static func firstNormalizedWebURL(from values: [String]) -> URL? {
        values.lazy.compactMap { normalizedWebURL(from: $0) }.first
    }

    private func unlockVault(password: String) throws {
        guard let vaultURL else {
            throw CoreBridgeError.commandFailed("No vault selected")
        }
        let unlocked = try service.unlock(path: vaultURL.path, password: password)
        applyUnlocked(unlocked)
    }

    private func unlockVault(localMaterial: String) throws {
        guard let vaultURL else {
            throw CoreBridgeError.commandFailed("No vault selected")
        }
        let unlocked = try service.unlockWithLocalMaterial(path: vaultURL.path, localMaterial: localMaterial)
        applyUnlocked(unlocked)
    }

    private func applyUnlocked(_ unlocked: UnlockedPayload) {
        sessionId = unlocked.sessionId
        includeArchived = false
        showArchivedOnly = false
        showFavoritesOnly = false
        showConflictsOnly = false
        selectedItemTypeFilter = nil
        availableItemTypes = Self.availableItemTypes(from: unlocked.items)
        selectedTagFilter = nil
        availableTags = Self.availableTags(from: unlocked.items)
        navigationDestination = .allItems
        items = unlocked.items
        refreshNavigationInventory()
        selectedItemId = items.first?.id
        conflictCandidates = []
        loadSelectedDetailIfAvailable()
        resetVaultSignature()
        startSyncPolling()
        touch()
    }

    private func saveConvenienceUnlockMaterial(for vaultURL: URL) throws {
        guard let sessionId else {
            throw CoreBridgeError.commandFailed("No unlocked vault session")
        }
        let material = try service.localUnlockMaterial(sessionId: sessionId)
        try convenienceUnlockStore.saveMaterial(material, for: vaultURL)
    }

    private func perform(_ operation: () throws -> Void) {
        touch()
        isBusy = true
        defer { isBusy = false }
        do {
            try operation()
        } catch {
            statusMessage = statusMessage(for: error)
        }
    }

    private func performSave(
        sessionId: UInt64,
        staleItemId: String?,
        staleReviewBuilder: (() -> StaleSaveReview?)? = nil,
        operation: () throws -> Void
    ) -> EditorSaveOutcome {
        touch()
        isBusy = true
        defer { isBusy = false }
        do {
            try operation()
            return .saved
        } catch {
            if let staleItemId, isStaleRevisionError(error) {
                do {
                    try refreshSelectedItemAfterStaleSave(sessionId: sessionId, itemId: staleItemId)
                    staleSaveReview = staleReviewBuilder?()
                    return .staleDraftPreserved
                } catch {
                    statusMessage = statusMessage(for: error)
                    return .failed
                }
            }
            statusMessage = statusMessage(for: error)
            return .failed
        }
    }

    private func refreshSelectedItemAfterStaleSave(sessionId: UInt64, itemId: String) throws {
        let report = try refreshFromDiskForSyncStatus(sessionId: sessionId)
        try applySyncRefreshReport(report, sessionId: sessionId, preferredSelection: itemId)
        statusMessage = "Local edit kept; current synced item reloaded"
    }

    private func refreshFromDiskForSyncStatus(sessionId: UInt64) throws -> SyncRefreshPayload {
        do {
            return try service.refreshFromDisk(sessionId: sessionId)
        } catch {
            clearSyncState()
            throw error
        }
    }

    private func applySyncRefreshReport(
        _ report: SyncRefreshPayload,
        sessionId: UInt64,
        preferredSelection: String?,
        clearQuarantineResult: Bool = true
    ) throws {
        recordSyncRefresh(report, clearQuarantineResult: clearQuarantineResult)
        let refreshedItems: [VaultItemView]
        if shouldApplyListFiltersAfterSyncRefresh {
            refreshedItems = try service.search(sessionId: sessionId, text: searchText, includeArchived: includeArchived)
        } else {
            refreshedItems = report.items
        }
        _ = applyVisibleItems(
            refreshedItems,
            preferredSelection: preferredSelection,
            clearMissingItemTypeFilter: true,
            clearMissingTagFilter: true,
            reloadSelectedDetail: true
        )
        recordVaultContentChange()
    }

    private var shouldApplyListFiltersAfterSyncRefresh: Bool {
        includeArchived
            || showArchivedOnly
            || showFavoritesOnly
            || showConflictsOnly
            || selectedItemTypeFilter != nil
            || selectedTagFilter != nil
            || !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func filteredItems(
        _ candidates: [VaultItemView],
        selectedItemTypeFilter: String?,
        selectedTagFilter: String?
    ) -> [VaultItemView] {
        let normalizedSelectedItemType = selectedItemTypeFilter.map(Self.normalizedItemType)
        let normalizedSelectedTag = selectedTagFilter.map(Self.normalizedTag)
        return candidates.filter { item in
            (!showArchivedOnly || item.isArchived)
                && (!showFavoritesOnly || item.favorite)
                && (!showConflictsOnly || item.isConflicted)
                && (normalizedSelectedItemType == nil || Self.normalizedItemType(item.itemType) == normalizedSelectedItemType)
                && (normalizedSelectedTag == nil || item.tags.contains { Self.normalizedTag($0) == normalizedSelectedTag })
        }
    }

    @discardableResult
    private func applyVisibleItems(
        _ candidates: [VaultItemView],
        preferredSelection: String? = nil,
        clearMissingItemTypeFilter: Bool = false,
        clearMissingTagFilter: Bool = false,
        reloadSelectedDetail: Bool = false
    ) -> Bool {
        let nextSelectedItemTypeFilter = nextSelectedItemTypeFilter(
            from: candidates,
            clearMissingItemTypeFilter: clearMissingItemTypeFilter
        )
        let nextSelectedTagFilter = nextSelectedTagFilter(
            from: candidates,
            clearMissingTagFilter: clearMissingTagFilter
        )
        let visibleItems = filteredItems(
            candidates,
            selectedItemTypeFilter: nextSelectedItemTypeFilter,
            selectedTagFilter: nextSelectedTagFilter
        )
        let currentSelection = preferredSelection ?? selectedItemId
        let currentSelectionRemainsVisible = currentSelection.map { selectedId in
            visibleItems.contains { $0.id == selectedId }
        } ?? false

        let wouldChangeSelection: Bool
        if currentSelection == nil {
            wouldChangeSelection = !visibleItems.isEmpty
        } else {
            wouldChangeSelection = !currentSelectionRemainsVisible
        }
        if wouldChangeSelection, editorHasUnsavedChanges {
            statusMessage = "Save or discard edits before changing selection"
            return false
        }

        selectedItemTypeFilter = nextSelectedItemTypeFilter
        availableItemTypes = Self.availableItemTypes(from: candidates, preserving: nextSelectedItemTypeFilter)
        selectedTagFilter = nextSelectedTagFilter
        availableTags = Self.availableTags(from: candidates, preserving: nextSelectedTagFilter)
        items = visibleItems
        let nextSelection: String?
        if currentSelectionRemainsVisible {
            nextSelection = currentSelection
        } else {
            nextSelection = items.first?.id
        }

        let selectionChanged = selectedItemId != nextSelection
        selectedItemId = nextSelection
        if selectionChanged || nextSelection == nil || reloadSelectedDetail {
            conflictCandidates = []
            loadSelectedDetailIfAvailable()
        }
        return true
    }

    @discardableResult
    private func applyMutationItems(_ candidates: [VaultItemView], preferredSelection: String? = nil) -> Bool {
        applyVisibleItems(
            candidates,
            preferredSelection: preferredSelection,
            clearMissingItemTypeFilter: true,
            clearMissingTagFilter: true,
            reloadSelectedDetail: true
        )
    }

    private func nextSelectedItemTypeFilter(
        from candidates: [VaultItemView],
        clearMissingItemTypeFilter: Bool
    ) -> String? {
        guard let selectedItemTypeFilter else { return nil }
        guard clearMissingItemTypeFilter, searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return selectedItemTypeFilter
        }
        return candidates.contains {
            Self.normalizedItemType($0.itemType) == Self.normalizedItemType(selectedItemTypeFilter)
        } ? selectedItemTypeFilter : nil
    }

    private func nextSelectedTagFilter(from candidates: [VaultItemView], clearMissingTagFilter: Bool) -> String? {
        guard let selectedTagFilter else { return nil }
        guard clearMissingTagFilter, searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return selectedTagFilter
        }
        return candidates.contains { item in
            item.tags.contains { Self.normalizedTag($0) == Self.normalizedTag(selectedTagFilter) }
        } ? selectedTagFilter : nil
    }

    static func availableItemTypes(from items: [VaultItemView], preserving selectedItemTypeFilter: String? = nil) -> [String] {
        var typesByNormalizedValue: [String: String] = [:]
        for type in items.map(\.itemType) {
            let trimmed = type.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let normalized = normalizedItemType(trimmed)
            if typesByNormalizedValue[normalized] == nil {
                typesByNormalizedValue[normalized] = trimmed
            }
        }
        if let selectedItemTypeFilter {
            let trimmed = selectedItemTypeFilter.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                let normalized = normalizedItemType(trimmed)
                if typesByNormalizedValue[normalized] == nil {
                    typesByNormalizedValue[normalized] = trimmed
                }
            }
        }
        return typesByNormalizedValue.values.sorted { lhs, rhs in
            let lhsIndex = knownItemTypeOrder.firstIndex(of: normalizedItemType(lhs))
            let rhsIndex = knownItemTypeOrder.firstIndex(of: normalizedItemType(rhs))
            switch (lhsIndex, rhsIndex) {
            case let (lhsIndex?, rhsIndex?):
                return lhsIndex < rhsIndex
            case (_?, nil):
                return true
            case (nil, _?):
                return false
            case (nil, nil):
                return lhs.localizedCaseInsensitiveCompare(rhs) == .orderedAscending
            }
        }
    }

    static func availableTags(from items: [VaultItemView], preserving selectedTagFilter: String? = nil) -> [String] {
        var tagsByNormalizedValue: [String: String] = [:]
        for tag in items.flatMap(\.tags) {
            let trimmed = tag.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let normalized = normalizedTag(trimmed)
            if tagsByNormalizedValue[normalized] == nil {
                tagsByNormalizedValue[normalized] = trimmed
            }
        }
        if let selectedTagFilter {
            let trimmed = selectedTagFilter.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                let normalized = normalizedTag(trimmed)
                if tagsByNormalizedValue[normalized] == nil {
                    tagsByNormalizedValue[normalized] = trimmed
                }
            }
        }
        return tagsByNormalizedValue.values.sorted {
            $0.localizedCaseInsensitiveCompare($1) == .orderedAscending
        }
    }

    private static func normalizedTag(_ tag: String) -> String {
        tag.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func normalizedItemType(_ itemType: String) -> String {
        itemType.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func staleLoginReview(current: LoginDetail, draft: LoginForm) -> StaleSaveReview {
        var rows = [
            staleTextRow("title", current: current.title, draft: draft.title),
            staleTextRow("username", current: current.username, draft: draft.username),
            staleTextRow("URLs", current: current.urls.joined(separator: "\n"), draft: draft.urls.joined(separator: "\n")),
            staleTextRow("notes", current: current.notes, draft: draft.notes),
            staleTagsRow(current: current.tags, draft: draft.tags),
            staleBooleanRow("favorite", current: current.favorite, draft: draft.favorite)
        ].compactMap { $0 }
        if draft.passwordForUpdate != nil {
            rows.append(staleRedactedRow("password"))
        }
        let currentTotp = current.totpSecret?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if draft.totpSecretForSave != currentTotp {
            rows.append(staleRedactedRow("TOTP secret"))
        }
        return StaleSaveReview(itemId: current.id, itemTitle: current.title, itemType: "login", rows: rows)
    }

    private static func staleSecureNoteReview(current: SecureNoteDetail, draft: SecureNoteForm) -> StaleSaveReview {
        var rows = [
            staleTextRow("title", current: current.title, draft: draft.title),
            staleTagsRow(current: current.tags, draft: draft.tags),
            staleBooleanRow("favorite", current: current.favorite, draft: draft.favorite)
        ].compactMap { $0 }
        if normalizedStaleValue(current.body) != normalizedStaleValue(draft.body) {
            rows.append(staleRedactedRow("body"))
        }
        return StaleSaveReview(itemId: current.id, itemTitle: current.title, itemType: "secure note", rows: rows)
    }

    private static func staleCreditCardReview(current: CreditCardDetail, draft: CreditCardForm) -> StaleSaveReview {
        var rows = [
            staleTextRow("title", current: current.title, draft: draft.title),
            staleTextRow("cardholder name", current: current.cardholderName, draft: draft.cardholderName),
            staleTextRow(
                "expiration",
                current: expirationValue(month: current.expiryMonth, year: current.expiryYear),
                draft: expirationValue(month: draft.expiryMonthValue, year: draft.expiryYearValue)
            ),
            staleTextRow("notes", current: current.notes, draft: draft.notes),
            staleTagsRow(current: current.tags, draft: draft.tags),
            staleBooleanRow("favorite", current: current.favorite, draft: draft.favorite)
        ].compactMap { $0 }
        if draft.numberForUpdate != nil {
            rows.append(staleRedactedRow("card number"))
        }
        if draft.verificationCodeForUpdate != nil {
            rows.append(staleRedactedRow("verification code"))
        }
        return StaleSaveReview(itemId: current.id, itemTitle: current.title, itemType: "credit card", rows: rows)
    }

    private static func staleSoftwareLicenseReview(
        current: SoftwareLicenseDetail,
        draft: SoftwareLicenseForm
    ) -> StaleSaveReview {
        var rows = [
            staleTextRow("title", current: current.title, draft: draft.title),
            staleTextRow("product", current: current.product, draft: draft.product),
            staleTextRow("licensed to", current: current.licensedTo, draft: draft.licensedTo),
            staleTextRow("notes", current: current.notes, draft: draft.notes),
            staleTagsRow(current: current.tags, draft: draft.tags),
            staleBooleanRow("favorite", current: current.favorite, draft: draft.favorite)
        ].compactMap { $0 }
        if draft.licenseKeyForUpdate != nil {
            rows.append(staleRedactedRow("license key"))
        }
        return StaleSaveReview(itemId: current.id, itemTitle: current.title, itemType: "software license", rows: rows)
    }

    private static func staleTextRow(_ fieldLabel: String, current: String?, draft: String?) -> StaleSaveReviewRow? {
        let currentValue = normalizedStaleValue(current)
        let draftValue = normalizedStaleValue(draft)
        guard currentValue != draftValue else { return nil }
        return StaleSaveReviewRow(
            fieldLabel: fieldLabel,
            currentValue: currentValue.nilIfEmpty,
            draftValue: draftValue.nilIfEmpty,
            redacted: false
        )
    }

    private static func staleTagsRow(current: [String], draft: [String]) -> StaleSaveReviewRow? {
        staleTextRow("tags", current: current.joined(separator: ", "), draft: draft.joined(separator: ", "))
    }

    private static func staleBooleanRow(_ fieldLabel: String, current: Bool, draft: Bool) -> StaleSaveReviewRow? {
        guard current != draft else { return nil }
        return StaleSaveReviewRow(
            fieldLabel: fieldLabel,
            currentValue: current ? "true" : "false",
            draftValue: draft ? "true" : "false",
            redacted: false
        )
    }

    private static func staleRedactedRow(_ fieldLabel: String) -> StaleSaveReviewRow {
        StaleSaveReviewRow(fieldLabel: fieldLabel, currentValue: nil, draftValue: nil, redacted: true)
    }

    private static func normalizedStaleValue(_ value: String?) -> String {
        value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private static func expirationValue(month: Int?, year: Int?) -> String? {
        guard month != nil || year != nil else { return nil }
        let monthValue = month.map { String(format: "%02d", $0) } ?? "--"
        let yearValue = year.map(String.init) ?? "----"
        return "\(monthValue)/\(yearValue)"
    }

    private func statusMessage(for error: Error) -> String {
        let message = error.localizedDescription
        if isStaleRevisionError(error) {
            return "Refresh sync before editing this item"
        }
        return message
    }

    private func validatedForgottenVaultTrashTarget(_ url: URL) throws -> URL {
        let standardizedURL = url.standardizedFileURL
        guard standardizedURL.isFileURL,
              standardizedURL.pathExtension.caseInsensitiveCompare("pswvault") == .orderedSame,
              let values = try? standardizedURL.resourceValues(
                  forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
              ),
              values.isDirectory == true,
              values.isSymbolicLink != true
        else {
            throw ForgottenVaultRecoveryError.unsupportedTrashTarget
        }
        return standardizedURL
    }

    private func clearConvenienceUnlockMaterial(for vaultURL: URL) -> Bool {
        var succeeded = true
        do {
            try convenienceUnlockStore.deleteMaterial(for: vaultURL)
        } catch {
            succeeded = false
        }
        do {
            _ = try convenienceUnlockStore.deleteLegacyPasswordMaterial(for: vaultURL)
        } catch {
            succeeded = false
        }
        return succeeded
    }

    private func isStaleRevisionError(_ error: Error) -> Bool {
        error.localizedDescription.contains("item changed on disk")
    }

    private func recordSyncRefresh(
        _ report: SyncRefreshPayload,
        clearQuarantineResult: Bool = true
    ) {
        syncReport = report
        lastSyncRefreshAt = now()
        if clearQuarantineResult {
            lastSyncQuarantine = nil
        }
    }

    private func clearSyncState() {
        syncReport = nil
        lastSyncQuarantine = nil
        lastSyncRefreshAt = nil
    }

    private func recordVaultContentChange() {
        clearStaleSaveReview()
        clearPasswordHealth()
        refreshNavigationInventory()
        resetVaultSignature()
    }

    private func refreshNavigationInventory() {
        guard let sessionId else {
            navigationItems = []
            return
        }
        do {
            navigationItems = try service.search(
                sessionId: sessionId,
                text: "",
                includeArchived: true
            )
        } catch {
            if navigationItems.isEmpty {
                navigationItems = items
            }
        }
    }

    private func clearPasswordHealth() {
        passwordHealth = nil
    }

    private func clearActiveVaultSession(sessionId activeSessionId: UInt64? = nil) {
        let sessionToLock = activeSessionId ?? sessionId
        if let sessionToLock {
            clipboard.clearManagedSecret()
            try? service.lock(sessionId: sessionToLock)
        }
        sessionId = nil
        items = []
        selectedItemId = nil
        clearStaleSaveReview()
        clearSelectedDetails()
        conflictCandidates = []
        searchText = ""
        includeArchived = false
        showArchivedOnly = false
        showFavoritesOnly = false
        showConflictsOnly = false
        selectedItemTypeFilter = nil
        availableItemTypes = []
        selectedTagFilter = nil
        availableTags = []
        navigationDestination = .allItems
        navigationItems = []
        importSourceURL = nil
        importSourceFormat = Self.bitwardenJsonImportFormat
        importPreview = nil
        importCompleted = false
        exportResult = nil
        backupResult = nil
        restoreBackupResult = nil
        copyVaultToSyncResult = nil
        plaintextExportURL = nil
        backupDestinationURL = nil
        restoredBackupURL = nil
        copiedSyncVaultURL = nil
        clearPasswordHealth()
        clearSyncState()
        editorHasUnsavedChanges = false
        syncRefreshDeferredByUnsavedEdits = false
        stopSyncPolling()
    }

    private func clearSelectedDetails() {
        selectedDetail = nil
        selectedSecureNoteDetail = nil
        selectedCreditCardDetail = nil
        selectedSoftwareLicenseDetail = nil
    }

    private func loadSelectedDetailIfAvailable() {
        guard let sessionId, let selectedItemId else {
            clearSelectedDetails()
            return
        }
        try? loadSelectedDetail(sessionId: sessionId, itemId: selectedItemId)
    }

    private func loadSelectedDetail(sessionId: UInt64, itemId: String) throws {
        clearSelectedDetails()
        guard let item = items.first(where: { $0.id == itemId }) else { return }
        if item.isLogin {
            selectedDetail = try service.getLogin(sessionId: sessionId, itemId: itemId)
        } else if item.isSecureNote {
            selectedSecureNoteDetail = try service.getSecureNote(sessionId: sessionId, itemId: itemId)
        } else if item.isCreditCard {
            selectedCreditCardDetail = try service.getCreditCard(sessionId: sessionId, itemId: itemId)
        } else if item.isSoftwareLicense {
            selectedSoftwareLicenseDetail = try service.getSoftwareLicense(sessionId: sessionId, itemId: itemId)
        } else {
            statusMessage = "Unsupported item type"
        }
    }

    private func selectNewlyCreatedItem(existingIds: Set<String>, sessionId: UInt64) throws {
        guard let newItem = items.first(where: { !existingIds.contains($0.id) }) else {
            throw CoreBridgeError.commandFailed("Duplicated item not returned")
        }
        selectedItemId = newItem.id
        conflictCandidates = []
        try loadSelectedDetail(sessionId: sessionId, itemId: newItem.id)
    }

    private static func duplicateTitle(_ title: String) -> String {
        let trimmedTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmedTitle.isEmpty ? "Copy" : "\(trimmedTitle) Copy"
    }

    private func loadRecentVault() {
        guard let path = userDefaults.string(forKey: recentVaultPathKey), !path.isEmpty else {
            recentVaultURL = nil
            return
        }
        recentVaultURL = URL(fileURLWithPath: path)
    }

    private func rememberVault(_ url: URL) {
        let path = url.standardizedFileURL.path
        userDefaults.set(path, forKey: recentVaultPathKey)
        recentVaultURL = URL(fileURLWithPath: path)
    }

    private func forgetRecentVault() {
        userDefaults.removeObject(forKey: recentVaultPathKey)
        recentVaultURL = nil
    }

    private func loadSecurityPreferences() {
        clipboardTimeout = loadPreference(
            key: Self.clipboardTimeoutKey,
            supportedValues: Self.supportedClipboardTimeouts,
            defaultValue: Self.defaultClipboardTimeout
        )
        autoLockSeconds = loadPreference(
            key: Self.autoLockSecondsKey,
            supportedValues: Self.supportedAutoLockDurations,
            defaultValue: Self.defaultAutoLockSeconds
        )
        userDefaults.set(clipboardTimeout, forKey: Self.clipboardTimeoutKey)
        userDefaults.set(autoLockSeconds, forKey: Self.autoLockSecondsKey)
    }

    private func loadPreference(
        key: String,
        supportedValues: [TimeInterval],
        defaultValue: TimeInterval
    ) -> TimeInterval {
        let rawValue = userDefaults.object(forKey: key) as? Double
        return normalizePreference(
            rawValue ?? defaultValue,
            supportedValues: supportedValues,
            defaultValue: defaultValue
        )
    }

    private func normalizePreference(
        _ value: TimeInterval,
        supportedValues: [TimeInterval],
        defaultValue: TimeInterval
    ) -> TimeInterval {
        supportedValues.contains(value) ? value : defaultValue
    }

    private func bundleValue(_ key: String, fallback: String) -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String, !value.isEmpty else {
            return fallback
        }
        return value
    }

    private func startAutoLock() {
        autoLockTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                self.lockIfIdle()
            }
        }
    }

    private func startSyncPolling() {
        stopSyncPolling()
        guard isUnlocked else { return }
        syncPollTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                self.checkForVaultFileChanges()
            }
        }
    }

    private func stopSyncPolling() {
        syncPollTimer?.invalidate()
        syncPollTimer = nil
        lastVaultSignature = nil
    }

    func checkForVaultFileChanges() {
        guard isUnlocked, let signature = currentVaultSignature() else { return }
        if lastVaultSignature == nil {
            lastVaultSignature = signature
            return
        }
        guard signature != lastVaultSignature else { return }
        if editorHasUnsavedChanges {
            lastVaultSignature = signature
            syncRefreshDeferredByUnsavedEdits = true
            statusMessage = "Sync refresh paused for unsaved edits"
            return
        }
        refreshFromDisk()
    }

    func lockIfIdle(now: Date = Date()) {
        guard isUnlocked else { return }
        if now.timeIntervalSince(lastActivity) >= autoLockSeconds {
            lock()
        }
    }

    private func observeSystemLock() {
        let lockVault: (Notification) -> Void = { [weak self] _ in
            Task { @MainActor in self?.lock() }
        }

        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)
            .sink(receiveValue: lockVault)
            .store(in: &cancellables)
        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)
            .sink(receiveValue: lockVault)
            .store(in: &cancellables)
        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.sessionDidResignActiveNotification)
            .sink(receiveValue: lockVault)
            .store(in: &cancellables)
    }

    private func resetVaultSignature() {
        lastVaultSignature = currentVaultSignature()
    }

    private func currentVaultSignature() -> String? {
        guard let vaultURL else { return nil }
        var parts = [
            requiredPathSignature(
                label: "vault.json",
                url: vaultURL.appendingPathComponent("vault.json"),
                expectedDirectory: false
            ),
            requiredPathSignature(
                label: "keys.enc",
                url: vaultURL.appendingPathComponent("keys.enc"),
                expectedDirectory: false
            ),
            requiredPathSignature(
                label: "items",
                url: vaultURL.appendingPathComponent("items", isDirectory: true),
                expectedDirectory: true
            ),
            requiredPathSignature(
                label: "attachments",
                url: vaultURL.appendingPathComponent("attachments", isDirectory: true),
                expectedDirectory: true
            ),
            requiredPathSignature(
                label: "tombstones",
                url: vaultURL.appendingPathComponent("tombstones", isDirectory: true),
                expectedDirectory: true
            )
        ]
        let roots = [
            vaultURL.appendingPathComponent("items", isDirectory: true),
            vaultURL.appendingPathComponent("tombstones", isDirectory: true)
        ]
        let fileManager = FileManager.default
        for root in roots {
            guard let enumerator = fileManager.enumerator(
                at: root,
                includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
                options: [.skipsHiddenFiles]
            ) else {
                continue
            }
            for case let fileURL as URL in enumerator {
                guard fileURL.pathExtension == "enc" else { continue }
                let values = try? fileURL.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
                let modified = values?.contentModificationDate?.timeIntervalSince1970 ?? 0
                let size = values?.fileSize ?? 0
                let relativePath = fileURL.path
                    .replacingOccurrences(of: root.path + "/", with: "")
                parts.append("\(root.lastPathComponent)/\(relativePath):\(modified):\(size)")
            }
        }
        return parts.sorted().joined(separator: "|")
    }

    private func requiredPathSignature(label: String, url: URL, expectedDirectory: Bool) -> String {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            return "\(label):missing"
        }
        let actualDirectory = isDirectory.boolValue
        let kind: String
        if actualDirectory == expectedDirectory {
            kind = expectedDirectory ? "dir" : "file"
        } else {
            kind = actualDirectory ? "unexpected-dir" : "unexpected-file"
        }
        let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
        let modified = values?.contentModificationDate?.timeIntervalSince1970 ?? 0
        let size = values?.fileSize ?? 0
        return "\(label):\(kind):\(modified):\(size)"
    }
}
