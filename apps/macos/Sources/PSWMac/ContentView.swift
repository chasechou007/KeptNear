import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var store: VaultStore
    @AppStorage(AppLanguage.storageKey) private var languageRaw = AppLanguage.english.rawValue
    @State private var unlockPassword = ""
    @State private var createPassword = ""
    @State private var createPasswordConfirmation = ""
    @State private var showingCreateVaultPasswords = false
    @State private var createVaultFeedback = ""
    @State private var displayName = "Personal"
    @State private var createVaultDiscardConfirmed = false
    @State private var form = LoginForm()
    @State private var secureNoteForm = SecureNoteForm()
    @State private var creditCardForm = CreditCardForm()
    @State private var softwareLicenseForm = SoftwareLicenseForm()
    @State private var showingCreateSheet = false
    @State private var showingSecurityControls = false
    @State private var showingForgottenPasswordRecovery = false
    @State private var showingForgottenVaultTrashConfirmation = false
    @State private var createVaultAfterForgottenPasswordRecovery = false
    @State private var forgottenPasswordRecoveryFeedback = ""
    @State private var forgottenPasswordRecoveryHandoffFeedback = ""
    @State private var rememberUnlockInKeychain = false
    @State private var rememberCreatedVaultInKeychain = false
    @State private var showingPasswordGenerator = false
    @State private var passwordGeneratorOptions = PasswordGeneratorPreferences().loadOptions()
    @State private var showingImportSheet = false
    @State private var keepImportDuplicates = false
    @State private var pendingExportURL: URL?
    @State private var showingExportConfirmation = false
    @State private var showingExportResult = false
    @State private var showingBackupResult = false
    @State private var showingRestoreBackupResult = false
    @State private var showingCopyVaultToSyncResult = false
    @State private var baselineForm = LoginForm()
    @State private var baselineSecureNoteForm = SecureNoteForm()
    @State private var baselineCreditCardForm = CreditCardForm()
    @State private var baselineSoftwareLicenseForm = SoftwareLicenseForm()
    @State private var isCreatingItem = false
    @State private var newItemKind = NewItemKind.login
    @State private var pendingEditorAction: EditorAction?
    @State private var showingDiscardChangesAlert = false
    @State private var pendingDestructiveAction: DestructiveAction?
    @State private var pendingDestructiveDiscardConfirmed = false
    @State private var conflictMergeBaseRevision: String?
    @State private var conflictMergeFieldRevisions: [String: String] = [:]
    @State private var revealedSecrets = SavedSecretRevealCache()
    @FocusState private var focusedField: FocusedField?

    private static let safeConflictMergeFieldLabels: Set<String> = [
        "title",
        "favorite",
        "tags",
        "username",
        "URLs",
        "cardholder name",
        "expiration",
        "product",
        "licensed to"
    ]

    private enum EditorAction: Equatable {
        case createVault
        case select(String?)
        case showPasswordHealthIssue(PasswordHealthIssue)
        case itemListAction(String, ItemListRowAction)
        case itemListDestructiveAction(String, DestructiveAction)
        case newItem
        case lockVault
        case closeVault
        case openVault
        case openRecentVault
        case refreshSync
        case commitImport
        case backupVault
        case restoreBackup
        case copyVaultToSyncLocation
        case quarantineRejectedRecords
        case toggleFavorite
        case duplicateItem
        case resolveConflict
        case resolveConflictCandidate(String)
        case resolveConflictMerge(baseRevision: String, fieldSelections: [ConflictMergeFieldSelection])
        case restoreArchive
        case confirmDestructive(DestructiveAction)

        var guardedAction: EditorGuardedAction {
            switch self {
            case .createVault:
                return .createVault
            case .refreshSync:
                return .manualSyncRefresh
            case .commitImport:
                return .importCommit
            case .backupVault:
                return .backupVault
            case .restoreBackup:
                return .restoreBackup
            case .copyVaultToSyncLocation:
                return .copyVaultToSyncLocation
            case .quarantineRejectedRecords:
                return .syncRecovery
            case .itemListDestructiveAction, .confirmDestructive:
                return .destructiveItemMutation
            case .select, .showPasswordHealthIssue, .itemListAction, .newItem, .lockVault, .closeVault, .openVault, .openRecentVault, .toggleFavorite, .duplicateItem, .resolveConflict, .resolveConflictCandidate, .resolveConflictMerge, .restoreArchive:
                return .editorNavigation
            }
        }
    }

    private enum FocusedField {
        case search
        case unlockPassword
    }

    private enum NewItemKind: String, CaseIterable, Identifiable {
        case login
        case secureNote
        case creditCard
        case softwareLicense

        var id: String { rawValue }

        var editorKind: ItemEditorKind {
            switch self {
            case .login:
                return .login
            case .secureNote:
                return .secureNote
            case .creditCard:
                return .creditCard
            case .softwareLicense:
                return .softwareLicense
            }
        }
    }

    private var text: AppText {
        AppText(languageRaw)
    }

    private var loginPasswordBinding: Binding<String> {
        Binding(
            get: { form.password },
            set: { value in
                form.password = value
                if value.nilIfEmpty != nil {
                    form.clearPasswordOnSave = false
                }
            }
        )
    }

    private var creditCardNumberBinding: Binding<String> {
        Binding(
            get: { creditCardForm.number },
            set: { value in
                creditCardForm.number = value
                if value.nilIfEmpty != nil {
                    creditCardForm.clearNumberOnSave = false
                }
            }
        )
    }

    private var creditCardVerificationCodeBinding: Binding<String> {
        Binding(
            get: { creditCardForm.verificationCode },
            set: { value in
                creditCardForm.verificationCode = value
                if value.nilIfEmpty != nil {
                    creditCardForm.clearVerificationCodeOnSave = false
                }
            }
        )
    }

    private var softwareLicenseKeyBinding: Binding<String> {
        Binding(
            get: { softwareLicenseForm.licenseKey },
            set: { value in
                softwareLicenseForm.licenseKey = value
                if value.nilIfEmpty != nil {
                    softwareLicenseForm.clearLicenseKeyOnSave = false
                }
            }
        )
    }

    private var hasUnsavedEditorChanges: Bool {
        shouldConfirmDiscard(before: .editorNavigation)
    }

    private var editorDraftState: EditorDraftState {
        EditorDraftState(
            login: form,
            baselineLogin: baselineForm,
            secureNote: secureNoteForm,
            baselineSecureNote: baselineSecureNoteForm,
            creditCard: creditCardForm,
            baselineCreditCard: baselineCreditCardForm,
            softwareLicense: softwareLicenseForm,
            baselineSoftwareLicense: baselineSoftwareLicenseForm
        )
    }

    private var activeEditorKind: ItemEditorKind {
        if store.selectedItem?.isCreditCard == true {
            return .creditCard
        }
        if store.selectedItem?.isSoftwareLicense == true {
            return .softwareLicense
        }
        if store.selectedItem?.isSecureNote == true {
            return .secureNote
        }
        if store.selectedItem?.isLogin == true {
            return .login
        }
        return newItemKind.editorKind
    }

    private var macCommandHandler: PSWMacCommandHandler {
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
            createNewItem: { requestEditorAction(.newItem) },
            saveCurrentEditor: { saveCurrentEditorFromCommand() },
            focusSearch: { focusedField = .search },
            copyUsername: { store.copyUsername() },
            copyPassword: { store.copyPassword() },
            copyTotp: { store.copyTotp() },
            copySecureNoteBody: { store.copySecureNoteBody() },
            copyCardNumber: { store.copyCardNumber() },
            copyCardVerificationCode: { store.copyCardVerificationCode() },
            copyLicenseKey: { store.copyLicenseKey() },
            refreshSync: { requestEditorAction(.refreshSync) },
            lockVault: { requestEditorAction(.lockVault) }
        )
    }

    private func shouldConfirmDiscard(before action: EditorGuardedAction) -> Bool {
        EditorActionGuard.shouldConfirmDiscard(
            before: action,
            drafts: editorDraftState,
            isUnlocked: store.isUnlocked,
            activeKind: activeEditorKind
        )
    }

    private var itemSelection: Binding<String?> {
        Binding(
            get: { store.selectedItemId },
            set: { requestEditorAction(.select($0)) }
        )
    }

    private var destructiveActionBinding: Binding<Bool> {
        Binding(
            get: { pendingDestructiveAction != nil },
            set: { isPresented in
                if !isPresented {
                    pendingDestructiveAction = nil
                    pendingDestructiveDiscardConfirmed = false
                }
            }
        )
    }

    private var destructiveActionTitle: String {
        switch pendingDestructiveAction {
        case .archive:
            return text.confirmArchiveTitle
        case .delete:
            return text.confirmDeleteTitle
        case nil:
            return text.confirmActionTitle
        }
    }

    private var destructiveActionMessage: String {
        switch pendingDestructiveAction {
        case .archive:
            return text.confirmArchiveMessage
        case .delete:
            return text.confirmDeleteMessage
        case nil:
            return ""
        }
    }

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detail
        }
        .toolbar {
            ToolbarItemGroup {
                Button {
                    requestEditorAction(.createVault)
                } label: {
                    Label(text.newVault, systemImage: "plus")
                }
                Button {
                    requestEditorAction(.openVault)
                } label: {
                    Label(text.openVault, systemImage: "folder")
                }
                Button {
                    requestEditorAction(.openRecentVault)
                } label: {
                    Label(text.openRecentVault, systemImage: "clock.arrow.circlepath")
                }
                .disabled(store.recentVaultURL == nil)
                Button {
                    store.clearImport()
                    keepImportDuplicates = false
                    showingImportSheet = true
                } label: {
                    Label(text.importItems, systemImage: "square.and.arrow.down")
                }
                .disabled(!store.isUnlocked)
                Button {
                    chooseExportDestination()
                } label: {
                    Label(text.exportItems, systemImage: "square.and.arrow.up")
                }
                .disabled(!store.canExport)
                Button {
                    requestEditorAction(.backupVault)
                } label: {
                    Label(text.backupVault, systemImage: "externaldrive.badge.plus")
                }
                .disabled(!store.canBackup)
                Button {
                    requestEditorAction(.restoreBackup)
                } label: {
                    Label(text.restoreBackup, systemImage: "externaldrive.badge.arrow.down")
                }
                .disabled(!store.canRestoreBackup)
                Button {
                    requestEditorAction(.copyVaultToSyncLocation)
                } label: {
                    Label(text.copyVaultToSyncLocation, systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(!store.canCopyVaultToSyncLocation)
                Button {
                    requestEditorAction(.refreshSync)
                } label: {
                    Label(text.syncRefresh, systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(!store.isUnlocked)
                Button {
                    if store.isUnlocked {
                        requestEditorAction(.lockVault)
                    } else {
                        focusedField = .unlockPassword
                    }
                } label: {
                    Label(
                        store.isUnlocked ? text.lock : text.unlock,
                        systemImage: store.isUnlocked ? "lock" : "lock.open"
                    )
                }
                .disabled(store.vaultURL == nil)
                Button {
                    requestEditorAction(.closeVault)
                } label: {
                    Label(text.closeVault, systemImage: "xmark.circle")
                }
                .disabled(store.vaultURL == nil)
            }
            ToolbarItem(placement: .primaryAction) {
                SettingsToolbarButton(text: text)
            }
        }
        .sheet(isPresented: $showingCreateSheet) {
            createVaultSheet
        }
        .sheet(
            isPresented: $showingForgottenPasswordRecovery,
            onDismiss: presentReplacementVaultAfterForgottenPasswordRecovery
        ) {
            forgottenPasswordRecoverySheet
        }
        .sheet(isPresented: $showingImportSheet) {
            importSheet
        }
        .sheet(isPresented: $showingExportResult) {
            exportResultSheet
        }
        .sheet(isPresented: $showingBackupResult) {
            backupResultSheet
        }
        .sheet(isPresented: $showingRestoreBackupResult) {
            restoreBackupResultSheet
        }
        .sheet(isPresented: $showingCopyVaultToSyncResult) {
            copyVaultToSyncResultSheet
        }
        .alert(text.plaintextExportTitle, isPresented: $showingExportConfirmation) {
            Button(text.exportNow, role: .destructive) {
                if let pendingExportURL, store.exportItems(destinationURL: pendingExportURL) {
                    showingExportResult = true
                }
                self.pendingExportURL = nil
            }
            Button(text.cancel, role: .cancel) {
                pendingExportURL = nil
            }
        } message: {
            Text(text.plaintextExportMessage(pendingExportURL?.lastPathComponent ?? "export.json"))
        }
        .alert(text.unsavedChangesTitle, isPresented: $showingDiscardChangesAlert) {
            Button(text.discardChanges, role: .destructive) {
                if let pendingEditorAction {
                    performEditorAction(pendingEditorAction, discardConfirmed: true)
                }
                pendingEditorAction = nil
            }
            Button(text.cancel, role: .cancel) {
                pendingEditorAction = nil
            }
        } message: {
            Text(text.unsavedChangesMessage)
        }
        .alert(destructiveActionTitle, isPresented: destructiveActionBinding) {
            Button(text.confirm, role: .destructive) {
                performDestructiveAction()
            }
            Button(text.cancel, role: .cancel) {
                pendingDestructiveAction = nil
            }
        } message: {
            Text(destructiveActionMessage)
        }
        .onChange(of: store.selectedDetail) { detail in
            if let detail {
                setEditorForm(LoginForm(detail: detail))
            }
        }
        .onChange(of: store.selectedSecureNoteDetail) { detail in
            if let detail {
                setSecureNoteEditorForm(SecureNoteForm(detail: detail))
            }
        }
        .onChange(of: store.selectedCreditCardDetail) { detail in
            if let detail {
                setCreditCardEditorForm(CreditCardForm(detail: detail))
            }
        }
        .onChange(of: store.selectedSoftwareLicenseDetail) { detail in
            if let detail {
                setSoftwareLicenseEditorForm(SoftwareLicenseForm(detail: detail))
            }
        }
        .onChange(of: store.isUnlocked) { isUnlocked in
            if !isUnlocked {
                clearLockSensitiveViewState()
            }
            updateEditorDirtyState()
        }
        .onChange(of: store.selectedItemId) { _ in
            revealedSecrets.clearAll()
            resetConflictMergeSelections()
            updateEditorDirtyState()
        }
        .onChange(of: store.conflictCandidates) { _ in
            initializeConflictMergeSelections()
        }
        .onChange(of: editorDraftState) { _ in
            updateEditorDirtyState()
        }
        .onAppear {
            updateEditorDirtyState()
        }
        .focusedSceneValue(\.pswMacCommandHandler, macCommandHandler)
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    KeptNearMark()
                        .frame(width: 20, height: 20)
                        .accessibilityHidden(true)
                    Text(store.vaultURL?.lastPathComponent ?? KeptNearBrand.name)
                        .font(.headline)
                    Spacer()
                }
                if store.vaultURL != nil {
                    Label(
                        text.syncLocationHint(store.syncLocationHint),
                        systemImage: store.syncLocationHint.isLikelySynced ? "arrow.triangle.2.circlepath" : "externaldrive"
                    )
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(12)

            syncReadinessPanel

            if store.isUnlocked {
                searchBar
                securityControls
                syncStatusPanel
                List(selection: itemSelection) {
                    ForEach(store.items) { item in
                        HStack(spacing: 8) {
                            Image(systemName: itemIcon(item))
                                .foregroundStyle(item.isConflicted ? .orange : (item.favorite ? .yellow : .secondary))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.title)
                                    .lineLimit(1)
                                Text(text.itemStatus(item.status))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .tag(item.id)
                        .contextMenu {
                            itemListContextMenu(for: item)
                        }
                    }
                }
            } else {
                lockedPanel
            }

            statusBar
        }
        .navigationSplitViewColumnWidth(min: 260, ideal: 300)
    }

    private var searchBar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField(text.search, text: $store.searchText)
                    .textFieldStyle(.plain)
                    .focused($focusedField, equals: .search)
                    .onSubmit { store.search() }
                    .onChange(of: store.searchText) { _ in store.search() }
            }
            HStack(spacing: 12) {
                Toggle(text.archive, isOn: $store.includeArchived)
                    .toggleStyle(.checkbox)
                    .onChange(of: store.includeArchived) { _ in store.search() }
                Toggle(text.favoritesFilter, isOn: $store.showFavoritesOnly)
                    .toggleStyle(.checkbox)
                    .onChange(of: store.showFavoritesOnly) { _ in store.search() }
                Toggle(text.conflictsFilter, isOn: $store.showConflictsOnly)
                    .toggleStyle(.checkbox)
                    .onChange(of: store.showConflictsOnly) { _ in store.search() }
            }
            .controlSize(.small)
            Picker(text.itemType, selection: $store.selectedItemTypeFilter) {
                Text(text.allTypes).tag(String?.none)
                ForEach(store.availableItemTypes, id: \.self) { itemType in
                    Text(text.itemTypeName(itemType)).tag(Optional(itemType))
                }
            }
            .disabled(store.availableItemTypes.isEmpty)
            .controlSize(.small)
            .onChange(of: store.selectedItemTypeFilter) { _ in store.search() }
            Picker(text.tags, selection: $store.selectedTagFilter) {
                Text(text.allTags).tag(String?.none)
                ForEach(store.availableTags, id: \.self) { tag in
                    Text(tag).tag(Optional(tag))
                }
            }
            .disabled(store.availableTags.isEmpty)
            .controlSize(.small)
            .onChange(of: store.selectedTagFilter) { _ in store.search() }
        }
        .padding(8)
    }

    @ViewBuilder
    private func itemListContextMenu(for item: VaultItemView) -> some View {
        ForEach(ItemListRowAction.actions(for: item)) { action in
            Button(role: action.buttonRole) {
                requestItemListRowAction(action, item: item)
            } label: {
                Label(action.title(text: text, item: item), systemImage: action.systemImage(item: item))
            }
        }
    }

    private var syncReadinessPanel: some View {
        Group {
            if let readiness = store.syncReadiness {
                VStack(alignment: .leading, spacing: 6) {
                    Label(text.syncReadiness, systemImage: syncReadinessIcon(readiness))
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundStyle(syncReadinessColor(readiness))
                    Text(text.syncReadinessStatus(readiness))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Label(
                        text.requiredVaultStructure(readiness.requiredStructureComplete),
                        systemImage: readiness.requiredStructureComplete ? "checkmark.circle" : "exclamationmark.triangle"
                    )
                    .font(.caption2)
                    .foregroundStyle(requiredStructureColor(readiness))
                    if !readiness.missingOrInvalidRequiredPathLabels.isEmpty {
                        Text(text.missingRequiredPaths(readiness.missingOrInvalidRequiredPathLabels))
                            .font(.caption2)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if readiness.localUnlockEnvelopePresent {
                        Label(text.localUnlockEnvelopePresent, systemImage: "key")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if readiness.status == .incomplete {
                        HStack(spacing: 6) {
                            Button {
                                store.revealVaultInFinder()
                            } label: {
                                Label(text.revealInFinder, systemImage: "folder")
                            }
                            .disabled(store.vaultURL == nil)
                            Button {
                                store.copySyncReadinessDiagnostics(languageRaw: languageRaw)
                            } label: {
                                Label(text.copySyncDiagnostics, systemImage: "doc.on.doc")
                            }
                        }
                        .controlSize(.small)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.bottom, 8)
            }
        }
    }

    private func syncReadinessIcon(_ readiness: VaultSyncReadiness) -> String {
        switch readiness.status {
        case .completeLikelySynced:
            return "checkmark.icloud"
        case .completeLocalOrUnknown:
            return "externaldrive"
        case .incomplete:
            return "exclamationmark.triangle"
        }
    }

    private func syncReadinessColor(_ readiness: VaultSyncReadiness) -> Color {
        switch readiness.status {
        case .completeLikelySynced:
            return .green
        case .completeLocalOrUnknown:
            return .secondary
        case .incomplete:
            return .orange
        }
    }

    private func requiredStructureColor(_ readiness: VaultSyncReadiness) -> Color {
        readiness.requiredStructureComplete ? .secondary : .orange
    }

    private var syncStatusPanel: some View {
        Group {
            if store.syncReport != nil || store.syncRefreshDeferredByUnsavedEdits {
                VStack(alignment: .leading, spacing: 6) {
                    Label(text.syncStatus, systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if store.syncRefreshDeferredByUnsavedEdits {
                        Label(text.syncRefreshPaused, systemImage: "pause.circle")
                            .font(.caption2)
                            .fontWeight(.semibold)
                            .foregroundStyle(.orange)
                        Text(text.syncRefreshPausedMessage)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let report = store.syncReport {
                        if let lastSyncRefreshAt = store.lastSyncRefreshAt {
                            Label(
                                "\(text.lastRefreshed): \(lastSyncRefreshAt.formatted(date: .omitted, time: .shortened))",
                                systemImage: "clock"
                            )
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 10) {
                            syncMetric(text.loadedItems, report.loadedItems)
                            syncMetric(text.tombstones, report.appliedTombstones)
                            syncMetric(text.conflicts, report.detectedConflicts)
                            syncMetric(text.rejectedRecords, report.rejectedRecords)
                        }
                        if let quarantine = store.lastSyncQuarantine {
                            Label(text.quarantineResult(quarantine), systemImage: "tray.and.arrow.down")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        if report.rejectedRecords > 0 {
                            HStack(spacing: 10) {
                                syncMetric(text.rejectedItems, report.rejectedItemRecords)
                                syncMetric(text.rejectedTombstones, report.rejectedTombstoneRecords)
                            }
                            if !report.rejectedRecordFiles.isEmpty {
                                VStack(alignment: .leading, spacing: 3) {
                                    Label(text.rejectedFiles, systemImage: "doc.badge.exclamationmark")
                                        .font(.caption2)
                                        .foregroundStyle(.orange)
                                    ForEach(Array(report.rejectedRecordFiles.enumerated()), id: \.offset) { _, rejectedFile in
                                        Text("\(text.rejectedRecordKind(rejectedFile.kind)): \(rejectedFile.fileName)")
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                    }
                                }
                            }
                        }
                        if store.hasSyncIssues {
                            Divider()
                                .padding(.vertical, 2)
                            Label(text.syncIssueTitle, systemImage: "exclamationmark.triangle")
                                .font(.caption)
                                .fontWeight(.semibold)
                                .foregroundStyle(.orange)
                            Text(text.syncIssueMessage)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            HStack(spacing: 6) {
                                Button {
                                    requestEditorAction(.refreshSync)
                                } label: {
                                    Label(text.syncRefresh, systemImage: "arrow.triangle.2.circlepath")
                                }
                                Button {
                                    store.revealVaultInFinder()
                                } label: {
                                    Label(text.revealInFinder, systemImage: "folder")
                                }
                                .disabled(store.vaultURL == nil)
                                if report.detectedConflicts > 0 {
                                    Button {
                                        store.showConflictedItems()
                                    } label: {
                                        Label(text.showConflicts, systemImage: "line.3.horizontal.decrease.circle")
                                    }
                                    .disabled(!store.canShowConflictedItems)
                                }
                                if report.rejectedRecords > 0 {
                                    Button {
                                        requestEditorAction(.quarantineRejectedRecords)
                                    } label: {
                                        Label(text.quarantineRejectedRecords, systemImage: "tray.and.arrow.down")
                                    }
                                    .disabled(!store.canQuarantineRejectedRecords)
                                }
                                Button {
                                    store.copySyncIssueDiagnostics(languageRaw: languageRaw)
                                } label: {
                                    Label(text.copySyncDiagnostics, systemImage: "doc.on.doc")
                                }
                            }
                            .controlSize(.small)
                        }
                    }
                }
                .padding(.horizontal, 10)
                .padding(.bottom, 8)
            }
        }
    }

    private func syncMetric(_ label: String, _ value: Int) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text("\(value)")
                .font(.caption)
                .fontWeight(value > 0 ? .semibold : .regular)
        }
    }

    private var securityControls: some View {
        DisclosureGroup(text.security, isExpanded: $showingSecurityControls) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(text.clipboard)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Picker(text.clipboard, selection: $store.clipboardTimeout) {
                        ForEach(VaultStore.supportedClipboardTimeouts, id: \.self) { seconds in
                            Text(text.durationOption(seconds)).tag(seconds)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .frame(width: 92)
                }

                HStack {
                    Text(text.autoLock)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Picker(text.autoLock, selection: $store.autoLockSeconds) {
                        ForEach(VaultStore.supportedAutoLockDurations, id: \.self) { seconds in
                            Text(text.durationOption(seconds)).tag(seconds)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .frame(width: 92)
                }

                if store.convenienceUnlockAvailable {
                    Button {
                        store.disableConvenienceUnlock()
                    } label: {
                        Label(text.disableKeychain, systemImage: "key.slash")
                    }
                    .buttonStyle(.link)
                }

                Divider()

                passwordHealthPanel
            }
            .padding(.top, 6)
        }
        .font(.caption)
        .padding(.horizontal, 10)
        .padding(.bottom, 6)
    }

    private var passwordHealthPanel: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Label(text.passwordHealth, systemImage: "checkmark.shield")
                    .font(.caption)
                    .fontWeight(.semibold)
                Spacer()
                Button {
                    store.refreshPasswordHealth()
                } label: {
                    Label(text.refreshPasswordHealth, systemImage: "arrow.clockwise")
                }
                .controlSize(.small)
                .disabled(!store.isUnlocked || store.isBusy)
            }

            if let health = store.passwordHealth {
                HStack(spacing: 14) {
                    syncMetric(text.checkedLogins, health.checkedLoginPasswords)
                    syncMetric(text.weakPasswords, health.weakPasswords)
                    syncMetric(text.reusedPasswords, health.reusedPasswords)
                }

                if health.issues.isEmpty {
                    Label(text.noPasswordHealthIssues, systemImage: "checkmark.circle")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(health.issues) { issue in
                            HStack(spacing: 6) {
                                Image(systemName: passwordHealthIssueIcon(issue.kind))
                                    .foregroundStyle(passwordHealthIssueColor(issue.kind))
                                    .frame(width: 12)
                                Text(issue.title)
                                    .lineLimit(1)
                                Spacer(minLength: 4)
                                Text(text.passwordHealthIssueLabel(issue))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                Button {
                                    requestEditorAction(.showPasswordHealthIssue(issue))
                                } label: {
                                    Label(text.showItem, systemImage: "arrow.right.circle")
                                }
                                .labelStyle(.iconOnly)
                                .help(text.showItem)
                                .buttonStyle(.borderless)
                            }
                            .font(.caption2)
                        }
                    }
                }
            } else {
                Text(text.passwordHealthNotChecked)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func passwordHealthIssueIcon(_ kind: PasswordHealthIssueKind) -> String {
        switch kind {
        case .weakPassword:
            return "exclamationmark.triangle"
        case .reusedPassword:
            return "link"
        }
    }

    private func passwordHealthIssueColor(_ kind: PasswordHealthIssueKind) -> Color {
        switch kind {
        case .weakPassword:
            return .orange
        case .reusedPassword:
            return .red
        }
    }

    private var lockedPanel: some View {
        Group {
            if store.vaultURL == nil {
                firstRunSidebarPanel
            } else {
                unlockSidebarPanel
            }
        }
        .padding(12)
    }

    private var firstRunSidebarPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                KeptNearMark()
                    .frame(width: 24, height: 24)
                    .accessibilityHidden(true)
                Text(text.firstRunTitle)
                    .font(.headline)
            }
            Text(text.firstRunSubtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                requestEditorAction(.createVault)
            } label: {
                Label(text.newVault, systemImage: "plus")
            }
            Button {
                requestEditorAction(.openVault)
            } label: {
                Label(text.openVault, systemImage: "folder")
            }
            Button {
                requestEditorAction(.openRecentVault)
            } label: {
                Label(text.openRecentVault, systemImage: "clock.arrow.circlepath")
            }
            .disabled(store.recentVaultURL == nil)
            Spacer()
        }
    }

    private var unlockSidebarPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(text.lockedVaultTitle, systemImage: "lock")
                .font(.headline)
            if let vaultURL = store.vaultURL {
                Text(vaultURL.lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Text(text.lockedVaultSubtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                focusedField = .unlockPassword
            } label: {
                Label(text.enterMasterPasswordToUnlock, systemImage: "lock.open")
            }
            .buttonStyle(.borderedProminent)
            .disabled(store.vaultURL == nil)
            Button {
                presentForgottenPasswordRecovery()
            } label: {
                Label(text.forgotMasterPassword, systemImage: "questionmark.circle")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var detail: some View {
        VStack(spacing: 0) {
            if store.isUnlocked {
                if store.items.isEmpty && !isCreatingItem {
                    if store.hasActiveListFilters {
                        filteredEmptyPanel
                    } else {
                        emptyVaultPanel
                    }
                } else {
                    editor
                }
            } else if store.vaultURL == nil {
                firstRunDetailPanel
            } else {
                lockedVaultDetailPanel
            }
        }
    }

    private var lockedVaultDetailPanel: some View {
        VStack(spacing: 16) {
            KeptNearMark()
                .frame(width: 58, height: 58)
                .accessibilityHidden(true)
            Text(text.lockedVaultTitle)
                .font(.title3)
                .fontWeight(.semibold)
            Text(text.lockedVaultSubtitle)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            VStack(alignment: .leading, spacing: 10) {
                SecureField(text.masterPassword, text: $unlockPassword)
                    .textFieldStyle(.roundedBorder)
                    .focused($focusedField, equals: .unlockPassword)
                    .onSubmit {
                        unlockWithPassword()
                    }
                Toggle(text.enableKeychainUnlock, isOn: $rememberUnlockInKeychain)
                    .toggleStyle(.checkbox)
                    .disabled(unlockPassword.isEmpty)
                Button {
                    unlockWithPassword()
                } label: {
                    Label(text.unlock, systemImage: "lock.open")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(unlockPassword.isEmpty)

                if store.convenienceUnlockAvailable {
                    Button {
                        store.unlockWithConvenience()
                    } label: {
                        Label(text.unlockWithKeychain, systemImage: "key.viewfinder")
                            .frame(maxWidth: .infinity)
                    }
                    .controlSize(.large)
                }

                Button {
                    presentForgottenPasswordRecovery()
                } label: {
                    Label(text.forgotMasterPassword, systemImage: "questionmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            .frame(maxWidth: 360)

            if text.isErrorStatusMessage(store.statusMessage) {
                Label(
                    text.statusMessage(store.statusMessage),
                    systemImage: "exclamationmark.circle.fill"
                )
                .font(.caption)
                .foregroundStyle(.red)
            } else {
                Text(text.statusMessage(store.statusMessage))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            DispatchQueue.main.async {
                focusedField = .unlockPassword
            }
        }
    }

    private var firstRunDetailPanel: some View {
        VStack(spacing: 14) {
            KeptNearMark()
                .frame(width: 64, height: 64)
                .accessibilityHidden(true)
            Text(text.firstRunTitle)
                .font(.title3)
                .fontWeight(.semibold)
            Text(text.firstRunSubtitle)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
            HStack {
                Button {
                    requestEditorAction(.createVault)
                } label: {
                    Label(text.newVault, systemImage: "plus")
                }
                Button {
                    requestEditorAction(.openVault)
                } label: {
                    Label(text.openVault, systemImage: "folder")
                }
                Button {
                    requestEditorAction(.openRecentVault)
                } label: {
                    Label(text.openRecentVault, systemImage: "clock.arrow.circlepath")
                }
                .disabled(store.recentVaultURL == nil)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyVaultPanel: some View {
        VStack(spacing: 14) {
            Image(systemName: "key")
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text(text.emptyVaultTitle)
                .font(.title3)
                .fontWeight(.semibold)
            Text(text.emptyVaultSubtitle)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
            HStack {
                Button {
                    requestEditorAction(.newItem)
                } label: {
                    Label(text.newItem, systemImage: "plus")
                }
                Button {
                    store.clearImport()
                    keepImportDuplicates = false
                    showingImportSheet = true
                } label: {
                    Label(text.importItems, systemImage: "square.and.arrow.down")
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var filteredEmptyPanel: some View {
        VStack(spacing: 14) {
            Image(systemName: "line.3.horizontal.decrease.circle")
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text(text.noMatchingItemsTitle)
                .font(.title3)
                .fontWeight(.semibold)
            Text(text.noMatchingItemsSubtitle)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
            Button {
                store.clearListFilters()
            } label: {
                Label(text.clearFilters, systemImage: "xmark.circle")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var savedPasswordControl: some View {
        HStack(spacing: 8) {
            if form.clearPasswordOnSave {
                Label(text.savedPasswordWillBeCleared, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
                Button {
                    form.clearPasswordOnSave = false
                } label: {
                    Label(text.keepSavedPassword, systemImage: "arrow.uturn.backward")
                }
                .disabled(!store.canMutateSelectedItem)
            } else {
                Button {
                    form.password = ""
                    form.clearPasswordOnSave = true
                } label: {
                    Label(text.clearSavedPassword, systemImage: "trash")
                }
                .disabled(!store.canMutateSelectedItem)
            }
        }
    }

    private func savedStructuredSecretClearControl(
        clearLabel: String,
        keepLabel: String,
        pendingLabel: String,
        isMarkedForClear: Binding<Bool>,
        secretText: Binding<String>,
        field: SavedSecretRevealField
    ) -> some View {
        HStack(spacing: 8) {
            if isMarkedForClear.wrappedValue {
                Label(pendingLabel, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
                Button {
                    isMarkedForClear.wrappedValue = false
                } label: {
                    Label(keepLabel, systemImage: "arrow.uturn.backward")
                }
                .disabled(!store.canMutateSelectedItem)
            } else {
                Button {
                    secretText.wrappedValue = ""
                    isMarkedForClear.wrappedValue = true
                    if let itemId = store.selectedItemId {
                        revealedSecrets.hide(SavedSecretRevealKey(itemId: itemId, field: field))
                    }
                } label: {
                    Label(clearLabel, systemImage: "trash")
                }
                .disabled(!store.canMutateSelectedItem)
            }
        }
    }

    @ViewBuilder
    private func savedSecretRevealRow(
        _ label: String,
        field: SavedSecretRevealField,
        systemImage: String,
        reveal: @escaping () -> String?
    ) -> some View {
        if let itemId = store.selectedItemId {
            let key = SavedSecretRevealKey(itemId: itemId, field: field)
            HStack(spacing: 8) {
                Label(label, systemImage: systemImage)
                    .foregroundStyle(.secondary)
                Spacer()
                if let value = revealedSecrets.value(for: key) {
                    Text(value)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    Button {
                        revealedSecrets.hide(key)
                    } label: {
                        Label(text.hide, systemImage: "eye.slash")
                    }
                } else {
                    Text(text.redactedValue)
                        .foregroundStyle(.secondary)
                    Button {
                        if let value = reveal() {
                            revealedSecrets.reveal(value, for: key)
                        }
                    } label: {
                        Label(text.reveal, systemImage: "eye")
                    }
                    .disabled(!store.canMutateSelectedItem)
                }
            }
        }
    }

    private var loginEditor: some View {
        Form {
            staleSaveReviewSection
            Section {
                if store.selectedItemId == nil {
                    itemKindPicker
                }
                TextField(text.title, text: $form.title)
                TextField(text.username, text: $form.username)
                SecureField(text.password, text: loginPasswordBinding)
                if store.selectedItemId != nil {
                    savedSecretRevealRow(text.savedPassword, field: .loginPassword, systemImage: "key") {
                        store.revealSelectedLoginPassword()
                    }
                    savedPasswordControl
                }
                TextField(text.urls, text: $form.urlsText, axis: .vertical)
                    .lineLimit(2...5)
                SecureField(text.totpSecret, text: $form.totpSecret)
                if store.selectedItemId != nil {
                    savedSecretRevealRow(text.savedTotpSecret, field: .loginTotpSecret, systemImage: "timer") {
                        store.revealSelectedLoginTotpSecret()
                    }
                }
                TextField(text.tags, text: $form.tagsText)
                TextField(text.notes, text: $form.notes, axis: .vertical)
                    .lineLimit(4...8)
            }
            Section {
                DisclosureGroup(text.passwordGenerator, isExpanded: $showingPasswordGenerator) {
                    VStack(alignment: .leading, spacing: 10) {
                        Stepper("\(text.length): \(passwordGeneratorOptions.length)", value: $passwordGeneratorOptions.length, in: 8...64)
                        HStack {
                            Toggle(text.uppercase, isOn: $passwordGeneratorOptions.includeUppercase)
                            Toggle(text.lowercase, isOn: $passwordGeneratorOptions.includeLowercase)
                            Toggle(text.numbers, isOn: $passwordGeneratorOptions.includeNumbers)
                            Toggle(text.symbols, isOn: $passwordGeneratorOptions.includeSymbols)
                        }
                        Toggle(text.avoidAmbiguousCharacters, isOn: $passwordGeneratorOptions.avoidAmbiguousCharacters)
                        Button {
                            generatePassword()
                        } label: {
                            Label(text.generatePassword, systemImage: "sparkles")
                        }
                        .disabled(!passwordGeneratorOptions.hasSelectedCharacterClass)
                    }
                    .padding(.top, 6)
                    .onChange(of: passwordGeneratorOptions) { options in
                        PasswordGeneratorPreferences().saveOptions(options)
                    }
                }
            }
            Section {
                HStack {
                    Button {
                        saveCurrentLogin()
                    } label: {
                        Label(store.selectedItemId == nil ? text.create : text.save, systemImage: "checkmark")
                    }
                    .disabled(!store.canSaveCurrentEditor)
                    Button {
                        requestEditorAction(.newItem)
                    } label: {
                        Label(text.newItem, systemImage: "plus")
                    }
                    Spacer()
                    Button {
                        store.copyUsername()
                    } label: {
                        Label(text.username, systemImage: "person.crop.circle")
                    }
                    .disabled(!store.canCopyLoginFields)
                    Button {
                        store.copyPassword()
                    } label: {
                        Label(text.password, systemImage: "key")
                    }
                    .disabled(!store.canCopyLoginFields)
                    Button {
                        store.copyTotp()
                    } label: {
                        Label(text.totp, systemImage: "timer")
                    }
                    .disabled(!store.canCopyTotpCode)
                    Button {
                        store.openSelectedLoginURL()
                    } label: {
                        Label(text.openURL, systemImage: "safari")
                    }
                    .disabled(!store.canOpenSelectedLoginURL)
                }
                HStack {
                    Button {
                        requestEditorAction(.toggleFavorite)
                    } label: {
                        Label(form.favorite ? text.unfavorite : text.favorite, systemImage: form.favorite ? "star.fill" : "star")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Button {
                        requestEditorAction(.duplicateItem)
                    } label: {
                        Label(text.duplicate, systemImage: "plus.square.on.square")
                    }
                    .disabled(!store.canDuplicateSelectedItem)
                    Button {
                        requestEditorAction(.resolveConflict)
                    } label: {
                        Label(text.resolveConflict, systemImage: "checkmark.seal")
                    }
                    .disabled(!store.canResolveSelectedConflict)
                    .help(text.conflictResolutionHint)
                    Button {
                        requestEditorAction(.restoreArchive)
                    } label: {
                        Label(text.restore, systemImage: "arrow.uturn.backward")
                    }
                    .disabled(!store.canRestoreSelectedArchive)
                    Button {
                        requestDestructiveAction(.archive)
                    } label: {
                        Label(text.archive, systemImage: "archivebox")
                    }
                    .disabled(!store.canMutateSelectedItem || store.canRestoreSelectedArchive)
                    Button(role: .destructive) {
                        requestDestructiveAction(.delete)
                    } label: {
                        Label(text.delete, systemImage: "trash")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Spacer()
                }
            }
            if store.canResolveSelectedConflict {
                conflictCandidatesSection
            }
        }
        .formStyle(.grouped)
        .padding(16)
        .onChange(of: form) { _ in store.touch() }
    }

    private var secureNoteEditor: some View {
        Form {
            staleSaveReviewSection
            Section {
                if store.selectedItemId == nil {
                    itemKindPicker
                }
                TextField(text.title, text: $secureNoteForm.title)
                TextField(text.body, text: $secureNoteForm.body, axis: .vertical)
                    .lineLimit(8...18)
                TextField(text.tags, text: $secureNoteForm.tagsText)
            }
            Section {
                HStack {
                    Button {
                        saveCurrentSecureNote()
                    } label: {
                        Label(store.selectedItemId == nil ? text.create : text.save, systemImage: "checkmark")
                    }
                    .disabled(!store.canSaveCurrentEditor)
                    Button {
                        requestEditorAction(.newItem)
                    } label: {
                        Label(text.newItem, systemImage: "plus")
                    }
                    Spacer()
                    Button {
                        store.copySecureNoteBody()
                    } label: {
                        Label(text.copyBody, systemImage: "doc.on.doc")
                    }
                    .disabled(!store.canCopySecureNoteBody)
                }
                HStack {
                    Button {
                        requestEditorAction(.toggleFavorite)
                    } label: {
                        Label(secureNoteForm.favorite ? text.unfavorite : text.favorite, systemImage: secureNoteForm.favorite ? "star.fill" : "star")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Button {
                        requestEditorAction(.duplicateItem)
                    } label: {
                        Label(text.duplicate, systemImage: "plus.square.on.square")
                    }
                    .disabled(!store.canDuplicateSelectedItem)
                    Button {
                        requestEditorAction(.resolveConflict)
                    } label: {
                        Label(text.resolveConflict, systemImage: "checkmark.seal")
                    }
                    .disabled(!store.canResolveSelectedConflict)
                    .help(text.conflictResolutionHint)
                    Button {
                        requestEditorAction(.restoreArchive)
                    } label: {
                        Label(text.restore, systemImage: "arrow.uturn.backward")
                    }
                    .disabled(!store.canRestoreSelectedArchive)
                    Button {
                        requestDestructiveAction(.archive)
                    } label: {
                        Label(text.archive, systemImage: "archivebox")
                    }
                    .disabled(!store.canMutateSelectedItem || store.canRestoreSelectedArchive)
                    Button(role: .destructive) {
                        requestDestructiveAction(.delete)
                    } label: {
                        Label(text.delete, systemImage: "trash")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Spacer()
                }
            }
            if store.canResolveSelectedConflict {
                conflictCandidatesSection
            }
        }
        .formStyle(.grouped)
        .padding(16)
        .onChange(of: secureNoteForm) { _ in store.touch() }
    }

    private var creditCardEditor: some View {
        Form {
            staleSaveReviewSection
            Section {
                if store.selectedItemId == nil {
                    itemKindPicker
                }
                TextField(text.title, text: $creditCardForm.title)
                TextField(text.cardholderName, text: $creditCardForm.cardholderName)
                SecureField(text.cardNumber, text: creditCardNumberBinding)
                if store.selectedItemId != nil {
                    savedSecretRevealRow(text.savedCardNumber, field: .creditCardNumber, systemImage: "creditcard") {
                        store.revealSelectedCardNumber()
                    }
                    savedStructuredSecretClearControl(
                        clearLabel: text.clearSavedCardNumber,
                        keepLabel: text.keepSavedCardNumber,
                        pendingLabel: text.savedCardNumberWillBeCleared,
                        isMarkedForClear: $creditCardForm.clearNumberOnSave,
                        secretText: $creditCardForm.number,
                        field: .creditCardNumber
                    )
                }
                HStack {
                    TextField(text.expiryMonth, text: $creditCardForm.expiryMonth)
                    TextField(text.expiryYear, text: $creditCardForm.expiryYear)
                    SecureField(text.verificationCode, text: creditCardVerificationCodeBinding)
                }
                if store.selectedItemId != nil {
                    savedSecretRevealRow(text.savedVerificationCode, field: .creditCardVerificationCode, systemImage: "number") {
                        store.revealSelectedCardVerificationCode()
                    }
                    savedStructuredSecretClearControl(
                        clearLabel: text.clearSavedVerificationCode,
                        keepLabel: text.keepSavedVerificationCode,
                        pendingLabel: text.savedVerificationCodeWillBeCleared,
                        isMarkedForClear: $creditCardForm.clearVerificationCodeOnSave,
                        secretText: $creditCardForm.verificationCode,
                        field: .creditCardVerificationCode
                    )
                }
                TextField(text.tags, text: $creditCardForm.tagsText)
                TextField(text.notes, text: $creditCardForm.notes, axis: .vertical)
                    .lineLimit(4...8)
            }
            Section {
                HStack {
                    Button {
                        saveCurrentCreditCard()
                    } label: {
                        Label(store.selectedItemId == nil ? text.create : text.save, systemImage: "checkmark")
                    }
                    .disabled(!store.canSaveCurrentEditor)
                    Button {
                        requestEditorAction(.newItem)
                    } label: {
                        Label(text.newItem, systemImage: "plus")
                    }
                    Spacer()
                    Button {
                        store.copyCardNumber()
                    } label: {
                        Label(text.cardNumber, systemImage: "creditcard")
                    }
                    .disabled(!store.canCopyCreditCardFields)
                    Button {
                        store.copyCardVerificationCode()
                    } label: {
                        Label(text.verificationCode, systemImage: "number")
                    }
                    .disabled(!store.canCopyCreditCardFields)
                }
                HStack {
                    Button {
                        requestEditorAction(.toggleFavorite)
                    } label: {
                        Label(creditCardForm.favorite ? text.unfavorite : text.favorite, systemImage: creditCardForm.favorite ? "star.fill" : "star")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Button {
                        requestEditorAction(.duplicateItem)
                    } label: {
                        Label(text.duplicate, systemImage: "plus.square.on.square")
                    }
                    .disabled(!store.canDuplicateSelectedItem)
                    Button {
                        requestEditorAction(.resolveConflict)
                    } label: {
                        Label(text.resolveConflict, systemImage: "checkmark.seal")
                    }
                    .disabled(!store.canResolveSelectedConflict)
                    .help(text.conflictResolutionHint)
                    Button {
                        requestEditorAction(.restoreArchive)
                    } label: {
                        Label(text.restore, systemImage: "arrow.uturn.backward")
                    }
                    .disabled(!store.canRestoreSelectedArchive)
                    Button {
                        requestDestructiveAction(.archive)
                    } label: {
                        Label(text.archive, systemImage: "archivebox")
                    }
                    .disabled(!store.canMutateSelectedItem || store.canRestoreSelectedArchive)
                    Button(role: .destructive) {
                        requestDestructiveAction(.delete)
                    } label: {
                        Label(text.delete, systemImage: "trash")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Spacer()
                }
            }
            if store.canResolveSelectedConflict {
                conflictCandidatesSection
            }
        }
        .formStyle(.grouped)
        .padding(16)
        .onChange(of: creditCardForm) { _ in store.touch() }
    }

    private var softwareLicenseEditor: some View {
        Form {
            staleSaveReviewSection
            Section {
                if store.selectedItemId == nil {
                    itemKindPicker
                }
                TextField(text.title, text: $softwareLicenseForm.title)
                TextField(text.product, text: $softwareLicenseForm.product)
                SecureField(text.licenseKey, text: softwareLicenseKeyBinding)
                if store.selectedItemId != nil {
                    savedSecretRevealRow(text.savedLicenseKey, field: .softwareLicenseKey, systemImage: "seal") {
                        store.revealSelectedLicenseKey()
                    }
                    savedStructuredSecretClearControl(
                        clearLabel: text.clearSavedLicenseKey,
                        keepLabel: text.keepSavedLicenseKey,
                        pendingLabel: text.savedLicenseKeyWillBeCleared,
                        isMarkedForClear: $softwareLicenseForm.clearLicenseKeyOnSave,
                        secretText: $softwareLicenseForm.licenseKey,
                        field: .softwareLicenseKey
                    )
                }
                TextField(text.licensedTo, text: $softwareLicenseForm.licensedTo)
                TextField(text.tags, text: $softwareLicenseForm.tagsText)
                TextField(text.notes, text: $softwareLicenseForm.notes, axis: .vertical)
                    .lineLimit(4...8)
            }
            Section {
                HStack {
                    Button {
                        saveCurrentSoftwareLicense()
                    } label: {
                        Label(store.selectedItemId == nil ? text.create : text.save, systemImage: "checkmark")
                    }
                    .disabled(!store.canSaveCurrentEditor)
                    Button {
                        requestEditorAction(.newItem)
                    } label: {
                        Label(text.newItem, systemImage: "plus")
                    }
                    Spacer()
                    Button {
                        store.copyLicenseKey()
                    } label: {
                        Label(text.licenseKey, systemImage: "seal")
                    }
                    .disabled(!store.canCopySoftwareLicenseFields)
                }
                HStack {
                    Button {
                        requestEditorAction(.toggleFavorite)
                    } label: {
                        Label(softwareLicenseForm.favorite ? text.unfavorite : text.favorite, systemImage: softwareLicenseForm.favorite ? "star.fill" : "star")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Button {
                        requestEditorAction(.duplicateItem)
                    } label: {
                        Label(text.duplicate, systemImage: "plus.square.on.square")
                    }
                    .disabled(!store.canDuplicateSelectedItem)
                    Button {
                        requestEditorAction(.resolveConflict)
                    } label: {
                        Label(text.resolveConflict, systemImage: "checkmark.seal")
                    }
                    .disabled(!store.canResolveSelectedConflict)
                    .help(text.conflictResolutionHint)
                    Button {
                        requestEditorAction(.restoreArchive)
                    } label: {
                        Label(text.restore, systemImage: "arrow.uturn.backward")
                    }
                    .disabled(!store.canRestoreSelectedArchive)
                    Button {
                        requestDestructiveAction(.archive)
                    } label: {
                        Label(text.archive, systemImage: "archivebox")
                    }
                    .disabled(!store.canMutateSelectedItem || store.canRestoreSelectedArchive)
                    Button(role: .destructive) {
                        requestDestructiveAction(.delete)
                    } label: {
                        Label(text.delete, systemImage: "trash")
                    }
                    .disabled(!store.canMutateSelectedItem)
                    Spacer()
                }
            }
            if store.canResolveSelectedConflict {
                conflictCandidatesSection
            }
        }
        .formStyle(.grouped)
        .padding(16)
        .onChange(of: softwareLicenseForm) { _ in store.touch() }
    }

    private var editor: some View {
        Group {
            switch activeEditorKind {
            case .login:
                loginEditor
            case .secureNote:
                secureNoteEditor
            case .creditCard:
                creditCardEditor
            case .softwareLicense:
                softwareLicenseEditor
            }
        }
    }

    private var itemKindPicker: some View {
        Picker(text.itemType, selection: $newItemKind) {
            Label(text.login, systemImage: "key").tag(NewItemKind.login)
            Label(text.secureNote, systemImage: "note.text").tag(NewItemKind.secureNote)
            Label(text.creditCard, systemImage: "creditcard").tag(NewItemKind.creditCard)
            Label(text.softwareLicense, systemImage: "seal").tag(NewItemKind.softwareLicense)
        }
        .pickerStyle(.segmented)
    }

    @ViewBuilder
    private var staleSaveReviewSection: some View {
        if let review = store.staleSaveReview, review.itemId == store.selectedItemId {
            Section(text.staleSaveReviewTitle) {
                Text(text.staleSaveReviewMessage(review.itemTitle))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if review.hasVisibleRows {
                    ForEach(review.rows) { row in
                        staleSaveReviewRow(row)
                    }
                } else {
                    Text(text.noVisibleStaleSaveDifferences)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func staleSaveReviewRow(_ row: StaleSaveReviewRow) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(localizedStaleSaveFieldLabel(row.fieldLabel))
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 12) {
                staleSaveReviewValueColumn(text.currentSyncedVersion, value: staleSaveReviewValue(row.currentValue, row: row))
                Divider()
                staleSaveReviewValueColumn(text.preservedLocalDraft, value: staleSaveReviewValue(row.draftValue, row: row))
            }
        }
        .padding(.vertical, 4)
    }

    private func staleSaveReviewValueColumn(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption2)
                .foregroundStyle(.tertiary)
            Text(value)
                .font(.caption)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func staleSaveReviewValue(_ value: String?, row: StaleSaveReviewRow) -> String {
        if row.redacted {
            return text.redactedValue
        }
        guard let value, !value.isEmpty else {
            return "-"
        }
        if row.fieldLabel == "favorite" {
            if value == "true" { return text.yes }
            if value == "false" { return text.no }
        }
        return value
    }

    private var conflictCandidatesSection: some View {
        Section(text.conflictVersions) {
            Button {
                loadConflictCandidatesForMerge()
            } label: {
                Label(text.loadConflictVersions, systemImage: "list.bullet.rectangle")
            }
            .disabled(!store.canResolveSelectedConflict)

            if !store.conflictCandidates.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Picker(text.mergeBase, selection: conflictMergeBaseBinding) {
                        ForEach(store.conflictCandidates) { candidate in
                            Text(conflictCandidatePickerTitle(candidate))
                                .tag(candidate.revision)
                        }
                    }
                    .pickerStyle(.menu)

                    ForEach(mergeableConflictFieldLabels, id: \.self) { fieldLabel in
                        conflictMergeFieldPicker(fieldLabel)
                    }

                    Button {
                        resolveConflictMerge()
                    } label: {
                        Label(text.mergeFields, systemImage: "arrow.triangle.merge")
                    }
                    .disabled(conflictMergeBaseRevision == nil || selectedConflictMergeFieldSelections.isEmpty)
                }
                .padding(.vertical, 4)
            }

            ForEach(store.conflictCandidates) { candidate in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(candidate.title)
                                .font(.headline)
                            Text("\(text.revision): \(String(candidate.revision.prefix(18)))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button {
                            requestEditorAction(.resolveConflictCandidate(candidate.revision))
                        } label: {
                            Label(text.keepVersion, systemImage: "checkmark.seal")
                        }
                    }
                    if let preview = candidate.preview, !preview.isEmpty {
                        Text(preview)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    }
                    if !candidate.comparisonFields.isEmpty {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(candidate.comparisonFields, id: \.label) { field in
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text(field.label)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                        .frame(width: 92, alignment: .leading)
                                    Text(conflictCandidateFieldValue(field))
                                        .font(.caption2)
                                        .foregroundStyle(field.redacted ? .tertiary : .primary)
                                        .lineLimit(2)
                                }
                            }
                        }
                    }
                    if !candidate.changedFields.isEmpty {
                        Text("\(text.changedFields): \(candidate.changedFields.joined(separator: ", "))")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if !candidate.tags.isEmpty {
                        Text(candidate.tags.joined(separator: ", "))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }
        }
    }

    @ViewBuilder
    private func conflictMergeFieldPicker(_ fieldLabel: String) -> some View {
        let options = conflictCandidateOptions(for: fieldLabel)
        if !options.isEmpty {
            Picker(localizedConflictFieldLabel(fieldLabel), selection: conflictMergeSelectionBinding(for: fieldLabel)) {
                ForEach(options) { candidate in
                    Text(conflictCandidatePickerTitle(candidate))
                        .tag(candidate.revision)
                }
            }
            .pickerStyle(.menu)
        }
    }

    private func conflictCandidateFieldValue(_ field: ConflictCandidateField) -> String {
        if field.redacted {
            return text.redactedValue
        }
        if let value = field.value, !value.isEmpty {
            return value
        }
        return "-"
    }

    private var mergeableConflictFieldLabels: [String] {
        guard store.conflictCandidates.count > 1 else { return [] }
        let changedLabels = Set(store.conflictCandidates.flatMap(\.changedFields))
        var labels: [String] = []
        for candidate in store.conflictCandidates {
            for field in candidate.comparisonFields {
                guard Self.safeConflictMergeFieldLabels.contains(field.label),
                      changedLabels.contains(field.label),
                      !field.redacted,
                      !labels.contains(field.label)
                else {
                    continue
                }
                labels.append(field.label)
            }
        }
        return labels
    }

    private var selectedConflictMergeFieldSelections: [ConflictMergeFieldSelection] {
        guard let baseRevision = conflictMergeBaseRevision else { return [] }
        return mergeableConflictFieldLabels.compactMap { fieldLabel in
            let revision = conflictMergeFieldRevisions[fieldLabel] ?? baseRevision
            guard revision != baseRevision else { return nil }
            return ConflictMergeFieldSelection(fieldLabel: fieldLabel, revision: revision)
        }
    }

    private var conflictMergeBaseBinding: Binding<String> {
        Binding(
            get: { conflictMergeBaseRevision ?? store.conflictCandidates.first?.revision ?? "" },
            set: { conflictMergeBaseRevision = $0 }
        )
    }

    private func conflictMergeSelectionBinding(for fieldLabel: String) -> Binding<String> {
        Binding(
            get: { conflictMergeFieldRevisions[fieldLabel] ?? conflictMergeBaseRevision ?? store.conflictCandidates.first?.revision ?? "" },
            set: { conflictMergeFieldRevisions[fieldLabel] = $0 }
        )
    }

    private func conflictCandidateOptions(for fieldLabel: String) -> [ConflictCandidateView] {
        store.conflictCandidates.filter { candidate in
            candidate.comparisonFields.contains { field in
                field.label == fieldLabel && !field.redacted
            }
        }
    }

    private func conflictCandidatePickerTitle(_ candidate: ConflictCandidateView) -> String {
        "\(candidate.title) (\(String(candidate.revision.prefix(10))))"
    }

    private func localizedConflictFieldLabel(_ label: String) -> String {
        switch label {
        case "title":
            return text.title
        case "favorite":
            return text.favorite
        case "tags":
            return text.tags
        case "username":
            return text.username
        case "URLs":
            return text.urls
        case "cardholder name":
            return text.cardholderName
        case "expiration":
            return text.expiration
        case "product":
            return text.product
        case "licensed to":
            return text.licensedTo
        default:
            return label
        }
    }

    private func localizedStaleSaveFieldLabel(_ label: String) -> String {
        switch label {
        case "title":
            return text.title
        case "favorite":
            return text.favorite
        case "tags":
            return text.tags
        case "username":
            return text.username
        case "URL":
            return text.url
        case "URLs":
            return text.urls
        case "notes":
            return text.notes
        case "password":
            return text.password
        case "TOTP secret":
            return text.totpSecret
        case "body":
            return text.body
        case "cardholder name":
            return text.cardholderName
        case "expiration":
            return text.expiration
        case "card number":
            return text.cardNumber
        case "verification code":
            return text.verificationCode
        case "product":
            return text.product
        case "licensed to":
            return text.licensedTo
        case "license key":
            return text.licenseKey
        default:
            return label
        }
    }

    private func loadConflictCandidatesForMerge() {
        store.loadSelectedConflictCandidates()
        initializeConflictMergeSelections()
    }

    private func initializeConflictMergeSelections() {
        guard !store.conflictCandidates.isEmpty else {
            resetConflictMergeSelections()
            return
        }
        let revisions = Set(store.conflictCandidates.map(\.revision))
        if let conflictMergeBaseRevision {
            if !revisions.contains(conflictMergeBaseRevision) {
                self.conflictMergeBaseRevision = store.conflictCandidates.first?.revision
            }
        } else {
            conflictMergeBaseRevision = store.conflictCandidates.first?.revision
        }

        let fieldLabels = Set(mergeableConflictFieldLabels)
        var nextSelections: [String: String] = [:]
        for (fieldLabel, revision) in conflictMergeFieldRevisions
            where fieldLabels.contains(fieldLabel) && revisions.contains(revision)
        {
            nextSelections[fieldLabel] = revision
        }

        let fallbackRevision = conflictMergeBaseRevision ?? store.conflictCandidates.first?.revision ?? ""
        for fieldLabel in mergeableConflictFieldLabels where nextSelections[fieldLabel] == nil {
            nextSelections[fieldLabel] = fallbackRevision
        }
        conflictMergeFieldRevisions = nextSelections
    }

    private func resetConflictMergeSelections() {
        conflictMergeBaseRevision = nil
        conflictMergeFieldRevisions = [:]
    }

    private var statusBar: some View {
        HStack {
            Circle()
                .fill(store.service.isAvailable ? Color.green : Color.orange)
                .frame(width: 8, height: 8)
            Text(text.statusMessage(store.statusMessage))
                .font(.caption)
                .foregroundStyle(
                    text.isErrorStatusMessage(store.statusMessage) ? Color.red : Color.secondary
                )
                .lineLimit(1)
            Spacer()
        }
        .padding(8)
    }

    private var createVaultSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField(text.displayName, text: $displayName)
            RevealablePasswordField(
                title: text.masterPassword,
                text: $createPassword,
                isRevealed: $showingCreateVaultPasswords,
                appText: text
            )
            MasterPasswordStrengthView(password: createPassword, text: text)
            RevealablePasswordField(
                title: text.confirmMasterPassword,
                text: $createPasswordConfirmation,
                isRevealed: $showingCreateVaultPasswords,
                appText: text
            )
            Toggle(text.enableKeychainUnlock, isOn: $rememberCreatedVaultInKeychain)
                .toggleStyle(.checkbox)
            if !createVaultFeedback.isEmpty {
                Label(text.statusMessage(createVaultFeedback), systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(text.cancel) {
                    resetCreateVaultForm()
                    showingCreateSheet = false
                }
                Button(text.create) {
                    createVaultPanel()
                }
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private var forgottenPasswordRecoverySheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(text.forgottenPasswordRecoveryTitle, systemImage: "key.slash")
                .font(.title3)
                .fontWeight(.semibold)

            if let vaultURL = store.vaultURL {
                LabeledContent(text.selectedVault) {
                    Text(vaultURL.lastPathComponent)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Text(text.forgottenPasswordNoRecoveryMessage)
                .fixedSize(horizontal: false, vertical: true)

            Label(
                text.forgottenPasswordLocalCopiesWarning,
                systemImage: "exclamationmark.triangle"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                Button {
                    store.revealVaultInFinder()
                } label: {
                    Label(text.revealInFinder, systemImage: "folder")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                Button {
                    closeForgottenVault(createReplacement: false)
                } label: {
                    Label(text.closeVault, systemImage: "xmark.circle")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                Button {
                    closeForgottenVault(createReplacement: true)
                } label: {
                    Label(text.closeAndCreateNewVault, systemImage: "plus")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                Divider()

                Button(role: .destructive) {
                    showingForgottenVaultTrashConfirmation = true
                } label: {
                    Label(text.moveVaultToTrashAndCreateNew, systemImage: "trash")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            if !forgottenPasswordRecoveryFeedback.isEmpty {
                Label(
                    text.statusMessage(forgottenPasswordRecoveryFeedback),
                    systemImage: "exclamationmark.circle.fill"
                )
                .font(.caption)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button(text.cancel) {
                    showingForgottenPasswordRecovery = false
                }
            }
        }
        .padding(24)
        .frame(width: 500)
        .alert(
            text.moveForgottenVaultToTrashTitle(
                store.vaultURL?.lastPathComponent ?? KeptNearBrand.name
            ),
            isPresented: $showingForgottenVaultTrashConfirmation
        ) {
            Button(text.moveToTrash, role: .destructive) {
                moveForgottenVaultToTrashAndCreateReplacement()
            }
            Button(text.cancel, role: .cancel) {}
        } message: {
            Text(
                text.moveForgottenVaultToTrashMessage(
                    store.vaultURL?.lastPathComponent ?? KeptNearBrand.name
                )
            )
        }
    }

    private var importSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Button {
                    chooseImportFile()
                } label: {
                    Label(text.chooseFile, systemImage: "doc")
                }
                Spacer()
                Button(text.done) {
                    showingImportSheet = false
                    store.clearImport()
                }
            }

            if let sourceURL = store.importSourceURL {
                LabeledContent(text.sourceFile, value: sourceURL.lastPathComponent)
                if store.importCompleted {
                    HStack {
                        Button {
                            store.revealImportSource()
                        } label: {
                            Label(text.revealInFinder, systemImage: "folder")
                        }
                        Button(role: .destructive) {
                            store.moveImportSourceToTrash()
                        } label: {
                            Label(text.moveSourceToTrash, systemImage: "trash")
                        }
                    }
                }
            }

            if let preview = store.importPreview {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                    GridRow {
                        Text(text.importable)
                        Text("\(preview.importableRecords)")
                    }
                    GridRow {
                        Text(text.skipped)
                        Text("\(preview.skippedRecords)")
                    }
                    GridRow {
                        Text(text.duplicates)
                        Text("\(preview.duplicateRecords)")
                    }
                    GridRow {
                        Text(text.warnings)
                        Text("\(preview.warnings.count)")
                    }
                }

                if !preview.warnings.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(preview.warnings, id: \.self) { warning in
                            Text(warning)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Toggle(text.keepDuplicates, isOn: $keepImportDuplicates)
                    .toggleStyle(.checkbox)

                HStack {
                    Spacer()
                    Button {
                        requestEditorAction(.commitImport)
                    } label: {
                        Label(text.importNow, systemImage: "checkmark")
                    }
                    .disabled(preview.importableRecords == 0)
                }
            }

            Text(text.plaintextImportWarning)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(width: 480)
    }

    private var exportResultSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label(text.exportItems, systemImage: "square.and.arrow.up")
                    .font(.headline)
                Spacer()
                Button(text.done) {
                    showingExportResult = false
                }
            }

            if let result = store.exportResult {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                    GridRow {
                        Text(text.exported)
                        Text("\(result.exportedRecords)")
                    }
                    GridRow {
                        Text(text.skipped)
                        Text("\(result.skippedRecords)")
                    }
                    GridRow {
                        Text(text.warnings)
                        Text("\(result.warnings.count)")
                    }
                }

                if !result.warnings.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(result.warnings, id: \.self) { warning in
                            Text(warning)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                if let exportURL = store.plaintextExportURL {
                    LabeledContent(text.exportFile, value: exportURL.lastPathComponent)
                    HStack {
                        Button {
                            store.revealPlaintextExport()
                        } label: {
                            Label(text.revealInFinder, systemImage: "folder")
                        }
                        Button(role: .destructive) {
                            store.movePlaintextExportToTrash()
                        } label: {
                            Label(text.moveExportToTrash, systemImage: "trash")
                        }
                    }
                }
            }

            Text(text.plaintextExportWarning)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(width: 480)
    }

    private var backupResultSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label(text.backupVault, systemImage: "externaldrive.badge.plus")
                    .font(.headline)
                Spacer()
                Button(text.done) {
                    showingBackupResult = false
                }
            }

            if let result = store.backupResult {
                backupTransferCountsGrid(
                    itemFiles: result.copiedItemFiles,
                    attachmentFiles: result.copiedAttachmentFiles,
                    tombstoneFiles: result.copiedTombstoneFiles
                )
            }

            if let destinationURL = store.backupDestinationURL {
                LabeledContent(text.backupDestination, value: destinationURL.lastPathComponent)
                Button {
                    store.revealBackupDestination()
                } label: {
                    Label(text.revealInFinder, systemImage: "folder")
                }
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private var restoreBackupResultSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label(text.restoreBackup, systemImage: "externaldrive.badge.arrow.down")
                    .font(.headline)
                Spacer()
                Button(text.done) {
                    showingRestoreBackupResult = false
                }
            }

            if let result = store.restoreBackupResult {
                backupTransferCountsGrid(
                    itemFiles: result.copiedItemFiles,
                    attachmentFiles: result.copiedAttachmentFiles,
                    tombstoneFiles: result.copiedTombstoneFiles
                )
            }

            if let restoredURL = store.restoredBackupURL {
                LabeledContent(text.restoredVault, value: restoredURL.lastPathComponent)
                Button {
                    store.revealRestoredBackup()
                } label: {
                    Label(text.revealInFinder, systemImage: "folder")
                }
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private var copyVaultToSyncResultSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label(text.copyVaultToSyncLocation, systemImage: "arrow.triangle.2.circlepath")
                    .font(.headline)
                Spacer()
                Button(text.done) {
                    showingCopyVaultToSyncResult = false
                }
            }

            if let result = store.copyVaultToSyncResult {
                backupTransferCountsGrid(
                    itemFiles: result.copiedItemFiles,
                    attachmentFiles: result.copiedAttachmentFiles,
                    tombstoneFiles: result.copiedTombstoneFiles
                )
            }

            if let copiedURL = store.copiedSyncVaultURL {
                LabeledContent(text.syncDestination, value: copiedURL.lastPathComponent)
                Button {
                    store.revealCopiedSyncVault()
                } label: {
                    Label(text.revealInFinder, systemImage: "folder")
                }
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func backupTransferCountsGrid(
        itemFiles: Int,
        attachmentFiles: Int,
        tombstoneFiles: Int
    ) -> some View {
        Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
            GridRow {
                Text(text.itemFiles)
                Text("\(itemFiles)")
            }
            GridRow {
                Text(text.attachments)
                Text("\(attachmentFiles)")
            }
            GridRow {
                Text(text.tombstones)
                Text("\(tombstoneFiles)")
            }
        }
    }

    private func requestEditorAction(_ action: EditorAction) {
        if shouldConfirmDiscard(before: action.guardedAction) {
            pendingEditorAction = action
            showingDiscardChangesAlert = true
        } else {
            performEditorAction(action)
        }
    }

    private func presentForgottenPasswordRecovery() {
        forgottenPasswordRecoveryFeedback = ""
        forgottenPasswordRecoveryHandoffFeedback = ""
        showingForgottenVaultTrashConfirmation = false
        createVaultAfterForgottenPasswordRecovery = false
        showingForgottenPasswordRecovery = true
    }

    private func closeForgottenVault(createReplacement: Bool) {
        guard store.closeVault() else {
            forgottenPasswordRecoveryFeedback = store.statusMessage
            return
        }
        clearLockSensitiveViewState()
        forgottenPasswordRecoveryHandoffFeedback = ""
        createVaultAfterForgottenPasswordRecovery = createReplacement
        showingForgottenPasswordRecovery = false
    }

    private func moveForgottenVaultToTrashAndCreateReplacement() {
        let outcome = store.moveForgottenVaultToTrash()
        guard outcome.didMove else {
            forgottenPasswordRecoveryFeedback = store.statusMessage
            return
        }
        let handoffFeedback = outcome == .movedWithKeychainCleanupFailure
            ? store.statusMessage
            : ""
        clearLockSensitiveViewState()
        forgottenPasswordRecoveryHandoffFeedback = handoffFeedback
        createVaultAfterForgottenPasswordRecovery = true
        showingForgottenPasswordRecovery = false
    }

    private func presentReplacementVaultAfterForgottenPasswordRecovery() {
        showingForgottenVaultTrashConfirmation = false
        forgottenPasswordRecoveryFeedback = ""
        guard createVaultAfterForgottenPasswordRecovery else { return }
        let handoffFeedback = forgottenPasswordRecoveryHandoffFeedback
        createVaultAfterForgottenPasswordRecovery = false
        forgottenPasswordRecoveryHandoffFeedback = ""
        DispatchQueue.main.async {
            performEditorAction(.createVault)
            createVaultFeedback = handoffFeedback
        }
    }

    private func requestDestructiveAction(_ action: DestructiveAction) {
        if shouldConfirmDiscard(before: .destructiveItemMutation) {
            pendingEditorAction = .confirmDestructive(action)
            showingDiscardChangesAlert = true
        } else {
            pendingDestructiveAction = action
            pendingDestructiveDiscardConfirmed = false
        }
    }

    private func requestItemListRowAction(_ action: ItemListRowAction, item: VaultItemView) {
        if let destructiveAction = action.destructiveAction {
            requestEditorAction(.itemListDestructiveAction(item.id, destructiveAction))
        } else {
            requestEditorAction(.itemListAction(item.id, action))
        }
    }

    private func updateEditorDirtyState() {
        store.setEditorHasUnsavedChanges(hasUnsavedEditorChanges)
    }

    private func performEditorAction(_ action: EditorAction, discardConfirmed: Bool = false) {
        switch action {
        case .createVault:
            createVaultDiscardConfirmed = discardConfirmed
            createVaultFeedback = ""
            showingCreateSheet = true
        case let .select(itemId):
            if store.select(itemId: itemId, discardingUnsavedEdits: discardConfirmed) {
                isCreatingItem = false
            }
        case let .showPasswordHealthIssue(issue):
            if store.showPasswordHealthIssue(issue, discardingUnsavedEdits: discardConfirmed) {
                isCreatingItem = false
            }
        case let .itemListAction(itemId, action):
            performItemListRowAction(action, itemId: itemId, discardConfirmed: discardConfirmed)
        case let .itemListDestructiveAction(itemId, action):
            if store.prepareItemListAction(itemId: itemId, discardingUnsavedEdits: discardConfirmed) {
                isCreatingItem = false
                pendingDestructiveAction = action
                pendingDestructiveDiscardConfirmed = discardConfirmed
            }
        case .newItem:
            store.selectedItemId = nil
            store.selectedDetail = nil
            store.selectedSecureNoteDetail = nil
            store.selectedCreditCardDetail = nil
            store.selectedSoftwareLicenseDetail = nil
            newItemKind = .login
            isCreatingItem = true
            resetEditorForms()
        case .lockVault:
            store.lock()
            clearLockSensitiveViewState()
        case .closeVault:
            if store.closeVault(discardingUnsavedEdits: discardConfirmed) {
                clearLockSensitiveViewState()
            }
        case .openVault:
            openVaultPanel(discardingUnsavedEdits: discardConfirmed)
        case .openRecentVault:
            if store.openRecentVault(discardingUnsavedEdits: discardConfirmed) {
                clearLockSensitiveViewState()
            }
        case .refreshSync:
            store.refreshFromDisk(discardingUnsavedEdits: discardConfirmed)
        case .commitImport:
            store.commitImport(keepDuplicates: keepImportDuplicates, discardingUnsavedEdits: discardConfirmed)
            isCreatingItem = false
        case .backupVault:
            if discardConfirmed {
                isCreatingItem = false
                syncFormFromSelectedDetail()
                if store.selectedItemId == nil {
                    resetEditorForms()
                }
                updateEditorDirtyState()
            }
            chooseBackupDestination(discardingUnsavedEdits: discardConfirmed)
        case .restoreBackup:
            if discardConfirmed {
                isCreatingItem = false
                syncFormFromSelectedDetail()
                if store.selectedItemId == nil {
                    resetEditorForms()
                }
                updateEditorDirtyState()
            }
            chooseRestoreBackup(discardingUnsavedEdits: discardConfirmed)
        case .copyVaultToSyncLocation:
            if discardConfirmed {
                isCreatingItem = false
                syncFormFromSelectedDetail()
                if store.selectedItemId == nil {
                    resetEditorForms()
                }
                updateEditorDirtyState()
            }
            chooseCopyVaultToSyncDestination(discardingUnsavedEdits: discardConfirmed)
        case .quarantineRejectedRecords:
            store.quarantineRejectedRecords(discardingUnsavedEdits: discardConfirmed)
        case .toggleFavorite:
            store.toggleFavoriteSelected(discardingUnsavedEdits: discardConfirmed)
        case .duplicateItem:
            if store.duplicateSelectedItem(discardingUnsavedEdits: discardConfirmed) {
                syncFormFromSelectedDetail()
            }
        case .resolveConflict:
            if store.resolveSelectedConflict(discardingUnsavedEdits: discardConfirmed) {
                syncFormFromSelectedDetail()
            }
        case let .resolveConflictCandidate(revision):
            if store.resolveSelectedConflictCandidate(revision: revision, discardingUnsavedEdits: discardConfirmed) {
                resetConflictMergeSelections()
                syncFormFromSelectedDetail()
            }
        case let .resolveConflictMerge(baseRevision, fieldSelections):
            if store.resolveSelectedConflictMerge(
                baseRevision: baseRevision,
                fieldSelections: fieldSelections,
                discardingUnsavedEdits: discardConfirmed
            ) {
                resetConflictMergeSelections()
                syncFormFromSelectedDetail()
            }
        case .restoreArchive:
            if store.restoreSelectedArchive(discardingUnsavedEdits: discardConfirmed) {
                syncFormFromSelectedDetail()
            }
        case let .confirmDestructive(action):
            pendingDestructiveAction = action
            pendingDestructiveDiscardConfirmed = discardConfirmed
        }
    }

    private func performItemListRowAction(
        _ action: ItemListRowAction,
        itemId: String,
        discardConfirmed: Bool
    ) {
        guard store.prepareItemListAction(itemId: itemId, discardingUnsavedEdits: discardConfirmed) else {
            return
        }
        isCreatingItem = false

        switch action {
        case .copyUsername:
            store.copyUsername()
        case .copyPassword:
            store.copyPassword()
        case .copyTotp:
            store.copyTotp()
        case .openURL:
            _ = store.openSelectedLoginURL()
        case .copyBody:
            store.copySecureNoteBody()
        case .copyCardNumber:
            store.copyCardNumber()
        case .copyVerificationCode:
            store.copyCardVerificationCode()
        case .copyLicenseKey:
            store.copyLicenseKey()
        case .favorite:
            if store.toggleFavoriteSelected(discardingUnsavedEdits: discardConfirmed) {
                syncFormFromSelectedDetail()
            }
        case .duplicate:
            if store.duplicateSelectedItem(discardingUnsavedEdits: discardConfirmed) {
                syncFormFromSelectedDetail()
            }
        case .resolveConflict:
            if store.resolveSelectedConflict(discardingUnsavedEdits: discardConfirmed) {
                syncFormFromSelectedDetail()
            }
        case .restoreArchive:
            if store.restoreSelectedArchive(discardingUnsavedEdits: discardConfirmed) {
                syncFormFromSelectedDetail()
            }
        case .archive, .delete:
            break
        }
    }

    private func performDestructiveAction() {
        let discardConfirmed = pendingDestructiveDiscardConfirmed
        switch pendingDestructiveAction {
        case .archive:
            if store.archiveSelected(discardingUnsavedEdits: discardConfirmed) {
                isCreatingItem = false
                resetEditorForms()
            }
        case .delete:
            if store.deleteSelected(discardingUnsavedEdits: discardConfirmed) {
                isCreatingItem = false
                resetEditorForms()
            }
        case nil:
            break
        }
        pendingDestructiveAction = nil
        pendingDestructiveDiscardConfirmed = false
    }

    private func resolveConflictMerge() {
        guard let baseRevision = conflictMergeBaseRevision else { return }
        let fieldSelections = selectedConflictMergeFieldSelections
        guard !fieldSelections.isEmpty else { return }
        requestEditorAction(.resolveConflictMerge(baseRevision: baseRevision, fieldSelections: fieldSelections))
    }

    private func setEditorForm(_ nextForm: LoginForm) {
        revealedSecrets.clearAll()
        form = nextForm
        baselineForm = nextForm
        secureNoteForm = SecureNoteForm()
        baselineSecureNoteForm = SecureNoteForm()
        creditCardForm = CreditCardForm()
        baselineCreditCardForm = CreditCardForm()
        softwareLicenseForm = SoftwareLicenseForm()
        baselineSoftwareLicenseForm = SoftwareLicenseForm()
    }

    private func setSecureNoteEditorForm(_ nextForm: SecureNoteForm) {
        revealedSecrets.clearAll()
        secureNoteForm = nextForm
        baselineSecureNoteForm = nextForm
        form = LoginForm()
        baselineForm = LoginForm()
        creditCardForm = CreditCardForm()
        baselineCreditCardForm = CreditCardForm()
        softwareLicenseForm = SoftwareLicenseForm()
        baselineSoftwareLicenseForm = SoftwareLicenseForm()
    }

    private func setCreditCardEditorForm(_ nextForm: CreditCardForm) {
        revealedSecrets.clearAll()
        creditCardForm = nextForm
        baselineCreditCardForm = nextForm
        form = LoginForm()
        baselineForm = LoginForm()
        secureNoteForm = SecureNoteForm()
        baselineSecureNoteForm = SecureNoteForm()
        softwareLicenseForm = SoftwareLicenseForm()
        baselineSoftwareLicenseForm = SoftwareLicenseForm()
    }

    private func setSoftwareLicenseEditorForm(_ nextForm: SoftwareLicenseForm) {
        revealedSecrets.clearAll()
        softwareLicenseForm = nextForm
        baselineSoftwareLicenseForm = nextForm
        form = LoginForm()
        baselineForm = LoginForm()
        secureNoteForm = SecureNoteForm()
        baselineSecureNoteForm = SecureNoteForm()
        creditCardForm = CreditCardForm()
        baselineCreditCardForm = CreditCardForm()
    }

    private func resetEditorForms() {
        setEditorForm(LoginForm())
        secureNoteForm = SecureNoteForm()
        baselineSecureNoteForm = SecureNoteForm()
        creditCardForm = CreditCardForm()
        baselineCreditCardForm = CreditCardForm()
        softwareLicenseForm = SoftwareLicenseForm()
        baselineSoftwareLicenseForm = SoftwareLicenseForm()
    }

    private func clearLockSensitiveViewState() {
        revealedSecrets.clearAll()
        unlockPassword = ""
        rememberUnlockInKeychain = false
        resetCreateVaultForm()
        showingCreateSheet = false
        showingSecurityControls = false
        showingPasswordGenerator = false
        showingImportSheet = false
        keepImportDuplicates = false
        pendingExportURL = nil
        showingExportConfirmation = false
        showingExportResult = false
        pendingEditorAction = nil
        showingDiscardChangesAlert = false
        pendingDestructiveAction = nil
        resetConflictMergeSelections()
        isCreatingItem = false
        resetEditorForms()
    }

    private func syncFormFromSelectedDetail() {
        if let detail = store.selectedDetail {
            setEditorForm(LoginForm(detail: detail))
        } else if let detail = store.selectedSecureNoteDetail {
            setSecureNoteEditorForm(SecureNoteForm(detail: detail))
        } else if let detail = store.selectedCreditCardDetail {
            setCreditCardEditorForm(CreditCardForm(detail: detail))
        } else if let detail = store.selectedSoftwareLicenseDetail {
            setSoftwareLicenseEditorForm(SoftwareLicenseForm(detail: detail))
        }
    }

    private func openVaultPanel(discardingUnsavedEdits: Bool = false) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            if store.openVault(url: url, discardingUnsavedEdits: discardingUnsavedEdits) {
                clearLockSensitiveViewState()
            }
        }
    }

    private func createVaultPanel() {
        createVaultFeedback = ""
        guard store.validateCreateVaultPassword(
            password: createPassword,
            confirmation: createPasswordConfirmation
        ) else {
            createVaultFeedback = store.statusMessage
            return
        }

        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "\(displayName).pswvault"
        if panel.runModal() == .OK, let url = panel.url {
            let didCreate = store.createVault(
                url: url,
                displayName: displayName,
                password: createPassword,
                confirmation: createPasswordConfirmation,
                rememberForConvenience: rememberCreatedVaultInKeychain,
                discardingUnsavedEdits: createVaultDiscardConfirmed
            )
            if didCreate {
                resetCreateVaultForm()
                showingCreateSheet = false
            } else {
                createVaultFeedback = store.statusMessage.isEmpty
                    ? "Vault creation failed"
                    : store.statusMessage
            }
        } else {
            createVaultFeedback = "Vault creation canceled"
        }
    }

    private func resetCreateVaultForm() {
        createPassword = ""
        createPasswordConfirmation = ""
        showingCreateVaultPasswords = false
        createVaultFeedback = ""
        rememberCreatedVaultInKeychain = false
        createVaultDiscardConfirmed = false
    }

    private func chooseImportFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json] + [UTType(filenameExtension: "csv")].compactMap { $0 }
        if panel.runModal() == .OK, let url = panel.url {
            store.previewImport(url: url)
        }
    }

    private func chooseExportDestination() {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "\(store.vaultURL?.deletingPathExtension().lastPathComponent ?? "psw-export").json"
        if panel.runModal() == .OK, let url = panel.url {
            pendingExportURL = url
            showingExportConfirmation = true
        }
    }

    private func chooseBackupDestination(discardingUnsavedEdits: Bool = false) {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        let baseName = store.vaultURL?.deletingPathExtension().lastPathComponent ?? "psw-vault"
        panel.nameFieldStringValue = "\(baseName)-backup.pswvault"
        if panel.runModal() == .OK, let url = panel.url {
            if store.backupVault(destinationURL: url, discardingUnsavedEdits: discardingUnsavedEdits) {
                showingBackupResult = true
            }
        }
    }

    private func chooseRestoreBackup(discardingUnsavedEdits: Bool = false) {
        let sourcePanel = NSOpenPanel()
        sourcePanel.canChooseDirectories = true
        sourcePanel.canChooseFiles = false
        sourcePanel.allowsMultipleSelection = false
        guard sourcePanel.runModal() == .OK, let sourceURL = sourcePanel.url else { return }

        let destinationPanel = NSSavePanel()
        destinationPanel.canCreateDirectories = true
        let baseName = sourceURL.deletingPathExtension().lastPathComponent
        destinationPanel.nameFieldStringValue = "\(baseName)-restored.pswvault"
        if destinationPanel.runModal() == .OK, let destinationURL = destinationPanel.url {
            if store.restoreVaultBackup(
                sourceURL: sourceURL,
                destinationURL: destinationURL,
                discardingUnsavedEdits: discardingUnsavedEdits
            ) {
                clearLockSensitiveViewState()
                showingRestoreBackupResult = true
            }
        }
    }

    private func chooseCopyVaultToSyncDestination(discardingUnsavedEdits: Bool = false) {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        let baseName = store.vaultURL?.deletingPathExtension().lastPathComponent ?? "psw-vault"
        panel.nameFieldStringValue = "\(baseName).pswvault"
        if panel.runModal() == .OK, let url = panel.url {
            if store.copyVaultToSyncLocation(
                destinationURL: url,
                discardingUnsavedEdits: discardingUnsavedEdits
            ) {
                clearLockSensitiveViewState()
                showingCopyVaultToSyncResult = true
            }
        }
    }

    private func unlockWithPassword() {
        store.unlock(password: unlockPassword, rememberForConvenience: rememberUnlockInKeychain)
        unlockPassword = ""
        rememberUnlockInKeychain = false
    }

    private func saveCurrentEditorFromCommand() {
        switch activeEditorKind {
        case .login:
            saveCurrentLogin()
        case .secureNote:
            saveCurrentSecureNote()
        case .creditCard:
            saveCurrentCreditCard()
        case .softwareLicense:
            saveCurrentSoftwareLicense()
        }
    }

    private func saveCurrentLogin() {
        let submittedForm = form
        switch store.saveLogin(form: submittedForm) {
        case .saved:
            break
        case .staleDraftPreserved:
            preserveStaleLoginDraft(submittedForm)
            return
        case .failed:
            return
        }
        isCreatingItem = false
        if let detail = store.selectedDetail {
            setEditorForm(LoginForm(detail: detail))
        } else {
            var cleanForm = form
            cleanForm.password = ""
            cleanForm.clearPasswordOnSave = false
            setEditorForm(cleanForm)
        }
    }

    private func saveCurrentSecureNote() {
        let submittedForm = secureNoteForm
        switch store.saveSecureNote(form: submittedForm) {
        case .saved:
            break
        case .staleDraftPreserved:
            preserveStaleSecureNoteDraft(submittedForm)
            return
        case .failed:
            return
        }
        isCreatingItem = false
        if let detail = store.selectedSecureNoteDetail {
            setSecureNoteEditorForm(SecureNoteForm(detail: detail))
        } else {
            setSecureNoteEditorForm(secureNoteForm)
        }
    }

    private func saveCurrentCreditCard() {
        let submittedForm = creditCardForm
        switch store.saveCreditCard(form: submittedForm) {
        case .saved:
            break
        case .staleDraftPreserved:
            preserveStaleCreditCardDraft(submittedForm)
            return
        case .failed:
            return
        }
        isCreatingItem = false
        if let detail = store.selectedCreditCardDetail {
            setCreditCardEditorForm(CreditCardForm(detail: detail))
        } else {
            var cleanForm = creditCardForm
            cleanForm.number = ""
            cleanForm.verificationCode = ""
            setCreditCardEditorForm(cleanForm)
        }
    }

    private func saveCurrentSoftwareLicense() {
        let submittedForm = softwareLicenseForm
        switch store.saveSoftwareLicense(form: submittedForm) {
        case .saved:
            break
        case .staleDraftPreserved:
            preserveStaleSoftwareLicenseDraft(submittedForm)
            return
        case .failed:
            return
        }
        isCreatingItem = false
        if let detail = store.selectedSoftwareLicenseDetail {
            setSoftwareLicenseEditorForm(SoftwareLicenseForm(detail: detail))
        } else {
            var cleanForm = softwareLicenseForm
            cleanForm.licenseKey = ""
            setSoftwareLicenseEditorForm(cleanForm)
        }
    }

    private func preserveStaleLoginDraft(_ submittedForm: LoginForm) {
        if let detail = store.selectedDetail {
            setEditorForm(LoginForm(detail: detail))
            var draft = submittedForm
            draft.revision = detail.revision
            form = draft
        } else {
            form = submittedForm
        }
        isCreatingItem = false
    }

    private func preserveStaleSecureNoteDraft(_ submittedForm: SecureNoteForm) {
        if let detail = store.selectedSecureNoteDetail {
            setSecureNoteEditorForm(SecureNoteForm(detail: detail))
            var draft = submittedForm
            draft.revision = detail.revision
            secureNoteForm = draft
        } else {
            secureNoteForm = submittedForm
        }
        isCreatingItem = false
    }

    private func preserveStaleCreditCardDraft(_ submittedForm: CreditCardForm) {
        if let detail = store.selectedCreditCardDetail {
            setCreditCardEditorForm(CreditCardForm(detail: detail))
            var draft = submittedForm
            draft.revision = detail.revision
            creditCardForm = draft
        } else {
            creditCardForm = submittedForm
        }
        isCreatingItem = false
    }

    private func preserveStaleSoftwareLicenseDraft(_ submittedForm: SoftwareLicenseForm) {
        if let detail = store.selectedSoftwareLicenseDetail {
            setSoftwareLicenseEditorForm(SoftwareLicenseForm(detail: detail))
            var draft = submittedForm
            draft.revision = detail.revision
            softwareLicenseForm = draft
        } else {
            softwareLicenseForm = submittedForm
        }
        isCreatingItem = false
    }

    private func generatePassword() {
        do {
            form.password = try PasswordGenerator().generate(options: passwordGeneratorOptions)
            store.touch()
        } catch {
            store.statusMessage = error.localizedDescription
        }
    }

    private func itemIcon(_ item: VaultItemView) -> String {
        if item.isConflicted {
            return "exclamationmark.triangle.fill"
        }
        if item.favorite {
            return "star.fill"
        }
        if item.isSecureNote {
            return "note.text"
        }
        if item.isCreditCard {
            return "creditcard"
        }
        if item.isSoftwareLicense {
            return "seal"
        }
        return "key"
    }
}
