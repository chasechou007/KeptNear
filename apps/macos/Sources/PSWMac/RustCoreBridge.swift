import Darwin
import Foundation

protocol CoreService {
    var isAvailable: Bool { get }
    var status: String { get }

    func createVault(path: String, displayName: String?, password: String) throws
    func openVault(path: String) throws
    func lockedRecoveryStatus(path: String) throws -> RecoveryStatusPayload
    func unlock(path: String, password: String) throws -> UnlockedPayload
    func unlockWithLocalMaterial(path: String, localMaterial: String) throws -> UnlockedPayload
    func recoverVault(path: String, recoveryCode: String, newPassword: String) throws -> UnlockedPayload
    func localUnlockMaterial(sessionId: UInt64) throws -> String
    func changeMasterPassword(sessionId: UInt64, currentPassword: String, newPassword: String) throws
    func recoveryStatus(sessionId: UInt64) throws -> RecoveryStatusPayload
    func beginRecoverySetup(sessionId: UInt64) throws -> RecoveryKitPayload
    func beginRecoveryRotation(sessionId: UInt64) throws -> RecoveryKitPayload
    func confirmRecoveryWorkflow(sessionId: UInt64, workflowId: UInt64, recoveryCode: String) throws -> RecoveryConfirmationPayload
    func cancelRecoveryWorkflow(sessionId: UInt64, workflowId: UInt64) throws
    func lock(sessionId: UInt64) throws
    func listItems(sessionId: UInt64) throws -> [VaultItemView]
    func passwordHealth(sessionId: UInt64) throws -> PasswordHealthPayload
    func refreshFromDisk(sessionId: UInt64) throws -> SyncRefreshPayload
    func quarantineRejectedRecords(sessionId: UInt64) throws -> SyncQuarantinePayload
    func search(sessionId: UInt64, text: String, includeArchived: Bool) throws -> [VaultItemView]
    func listAuthorizedCredentialIds(sessionId: UInt64) throws -> Set<String>
    func appsToolsPendingRequests() throws -> AppsToolsPendingRequestQueue
    func denyAppsToolsPendingRequest(
        requestSource: String,
        requestId: String
    ) throws -> AppsToolsPendingRequestDecision
    func approveAppsToolsPairing(
        requestId: String,
        label: String
    ) throws -> AppsToolsPendingRequestDecision
    func approveAppsToolsPendingUnlock(
        sessionId: UInt64,
        requestId: String
    ) throws -> AppsToolsPendingRequestDecision
    func reviewAppsToolsPendingCredential(
        sessionId: UInt64,
        requestId: String
    ) throws -> AppsToolsCredentialReview
    func allowAppsToolsPendingRequestOnce(
        sessionId: UInt64,
        requestId: String,
        credentialId: String?,
        secretFieldId: String?
    ) throws -> AppsToolsPendingRequestDecision
    func configureAppsToolsLongTermAccess(
        sessionId: UInt64,
        requestId: String,
        credentialId: String?,
        secretFieldId: String?,
        confirmationPolicy: AppsToolsConfirmationPolicy
    ) throws -> AppsToolsPendingRequestDecision
    func appsToolsSnapshot(sessionId: UInt64) throws -> AppsToolsSnapshot
    func appsToolsConsumerDetail(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsConsumerDetail
    func appsToolsUsageProfileSetup(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsUsageProfileSetup
    func createAppsToolsUsageProfile(
        sessionId: UInt64,
        consumerId: String,
        draft: AppsToolsUsageProfileDraft
    ) throws -> AppsToolsUsageProfile
    func removeAppsToolsUsageProfile(
        sessionId: UInt64,
        consumerId: String,
        usageProfileId: String
    ) throws -> Bool
    func setAppsToolsPaused(sessionId: UInt64, paused: Bool) throws -> AppsToolsSnapshot
    func revokeAppsToolsField(
        sessionId: UInt64,
        consumerId: String,
        field: AppsToolsFieldReference
    ) throws -> AppsToolsSnapshot
    func revokeAppsToolsConsumer(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsSnapshot
    func createCredentialFromTemplate(sessionId: UInt64, form: TemplateCredentialForm) throws -> [VaultItemView]
    func updateCredential(sessionId: UInt64, credentialId: String, form: CredentialEditorForm) throws -> [VaultItemView]
    func duplicateCredential(sessionId: UInt64, credentialId: String, expectedRevision: String, title: String) throws -> [VaultItemView]
    func getCredential(sessionId: UInt64, credentialId: String) throws -> CredentialDetail
    func getCredentialSecretField(sessionId: UInt64, credentialId: String, secretFieldId: String) throws -> String
    func createLogin(sessionId: UInt64, form: LoginForm) throws -> [VaultItemView]
    func updateLogin(sessionId: UInt64, itemId: String, form: LoginForm) throws -> [VaultItemView]
    func getLogin(sessionId: UInt64, itemId: String) throws -> LoginDetail
    func createSecureNote(sessionId: UInt64, form: SecureNoteForm) throws -> [VaultItemView]
    func updateSecureNote(sessionId: UInt64, itemId: String, form: SecureNoteForm) throws -> [VaultItemView]
    func getSecureNote(sessionId: UInt64, itemId: String) throws -> SecureNoteDetail
    func createCreditCard(sessionId: UInt64, form: CreditCardForm) throws -> [VaultItemView]
    func updateCreditCard(sessionId: UInt64, itemId: String, form: CreditCardForm) throws -> [VaultItemView]
    func getCreditCard(sessionId: UInt64, itemId: String) throws -> CreditCardDetail
    func getCreditCardField(sessionId: UInt64, itemId: String, field: String) throws -> String
    func createSoftwareLicense(sessionId: UInt64, form: SoftwareLicenseForm) throws -> [VaultItemView]
    func updateSoftwareLicense(sessionId: UInt64, itemId: String, form: SoftwareLicenseForm) throws -> [VaultItemView]
    func getSoftwareLicense(sessionId: UInt64, itemId: String) throws -> SoftwareLicenseDetail
    func getSoftwareLicenseField(sessionId: UInt64, itemId: String, field: String) throws -> String
    func getLoginField(sessionId: UInt64, itemId: String, field: String) throws -> String
    func archiveItem(sessionId: UInt64, itemId: String, expectedRevision: String?) throws -> [VaultItemView]
    func restoreItem(sessionId: UInt64, itemId: String) throws -> [VaultItemView]
    func deleteItem(sessionId: UInt64, itemId: String, expectedRevision: String?) throws -> [VaultItemView]
    func resolveConflict(sessionId: UInt64, conflictId: String) throws -> [VaultItemView]
    func getConflictCandidates(sessionId: UInt64, conflictId: String) throws -> [ConflictCandidateView]
    func resolveConflictCandidate(sessionId: UInt64, conflictId: String, revision: String) throws -> [VaultItemView]
    func resolveConflictMerge(sessionId: UInt64, conflictId: String, baseRevision: String, fieldSelections: [ConflictMergeFieldSelection]) throws -> [VaultItemView]
    func setFavorite(sessionId: UInt64, itemId: String, expectedRevision: String?, favorite: Bool) throws -> [VaultItemView]
    func totpCode(sessionId: UInt64, itemId: String) throws -> TotpPayload
    func previewImport(sessionId: UInt64, sourcePath: String, sourceFormat: String) throws -> ImportPreviewPayload
    func commitImport(sessionId: UInt64, sourcePath: String, sourceFormat: String, keepDuplicates: Bool) throws -> ImportPreviewPayload
    func exportItems(
        sessionId: UInt64,
        destinationPath: String,
        exportFormat: String,
        currentPassword: String
    ) throws -> ExportResultPayload
    func backupVault(sessionId: UInt64, destinationPath: String) throws -> BackupResultPayload
    func restoreVaultBackup(sourcePath: String, destinationPath: String) throws -> RestoreBackupResultPayload
}

final class RustCoreBridge: CoreService {
    static let `default`: RustCoreBridge = RustCoreBridge()

    private typealias CommandFunction = @convention(c) (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
    private typealias FreeFunction = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void

    private let handle: UnsafeMutableRawPointer?
    private let commandFunction: CommandFunction?
    private let freeFunction: FreeFunction?

    init() {
        let candidates = RustCoreBridge.libraryCandidates(
            privateFrameworksPath: Bundle.main.privateFrameworksPath,
            bundlePath: Bundle.main.bundlePath,
            environment: ProcessInfo.processInfo.environment,
            currentDirectoryPath: FileManager.default.currentDirectoryPath,
            includeDevelopmentOverrides: RustCoreBridge.developmentLibraryOverridesEnabled
        )
        var loadedHandle: UnsafeMutableRawPointer?
        for candidate in candidates {
            if let handle = dlopen(candidate, RTLD_NOW) {
                loadedHandle = handle
                break
            }
        }

        handle = loadedHandle
        if let loadedHandle,
           let commandSymbol = dlsym(loadedHandle, "psw_command"),
           let freeSymbol = dlsym(loadedHandle, "psw_string_free")
        {
            commandFunction = unsafeBitCast(commandSymbol, to: CommandFunction.self)
            freeFunction = unsafeBitCast(freeSymbol, to: FreeFunction.self)
        } else {
            commandFunction = nil
            freeFunction = nil
        }
    }

    deinit {
        if let handle {
            dlclose(handle)
        }
    }

    var isAvailable: Bool {
        commandFunction != nil && freeFunction != nil
    }

    var status: String {
        isAvailable ? "Rust core connected" : "Rust core library not loaded"
    }

    func createVault(path: String, displayName: String?, password: String) throws {
        _ = try send([
            "command": "createVault",
            "path": path,
            "display_name": displayName as Any,
            "password": password
        ])
    }

    func openVault(path: String) throws {
        _ = try send([
            "command": "openVault",
            "path": path
        ])
    }

    func lockedRecoveryStatus(path: String) throws -> RecoveryStatusPayload {
        guard case let .recoveryStatus(payload) = try send([
            "command": "lockedRecoveryStatus",
            "path": path
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func unlock(path: String, password: String) throws -> UnlockedPayload {
        guard case let .unlocked(payload) = try send([
            "command": "unlock",
            "path": path,
            "password": password
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func unlockWithLocalMaterial(path: String, localMaterial: String) throws -> UnlockedPayload {
        guard case let .unlocked(payload) = try send([
            "command": "unlockWithLocalMaterial",
            "path": path,
            "local_material": localMaterial
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func recoverVault(
        path: String,
        recoveryCode: String,
        newPassword: String
    ) throws -> UnlockedPayload {
        guard case let .unlocked(payload) = try send([
            "command": "recoverVault",
            "path": path,
            "recovery_code": recoveryCode,
            "new_password": newPassword
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func localUnlockMaterial(sessionId: UInt64) throws -> String {
        guard case let .secret(payload) = try send([
            "command": "localUnlockMaterial",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.value
    }

    func changeMasterPassword(sessionId: UInt64, currentPassword: String, newPassword: String) throws {
        _ = try send([
            "command": "changeMasterPassword",
            "session_id": sessionId,
            "current_password": currentPassword,
            "new_password": newPassword
        ])
    }

    func recoveryStatus(sessionId: UInt64) throws -> RecoveryStatusPayload {
        guard case let .recoveryStatus(payload) = try send([
            "command": "recoveryStatus",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func beginRecoverySetup(sessionId: UInt64) throws -> RecoveryKitPayload {
        guard case let .recoveryKit(payload) = try send([
            "command": "beginRecoverySetup",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func beginRecoveryRotation(sessionId: UInt64) throws -> RecoveryKitPayload {
        guard case let .recoveryKit(payload) = try send([
            "command": "beginRecoveryRotation",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func confirmRecoveryWorkflow(
        sessionId: UInt64,
        workflowId: UInt64,
        recoveryCode: String
    ) throws -> RecoveryConfirmationPayload {
        guard case let .recoveryConfirmed(payload) = try send([
            "command": "confirmRecoveryWorkflow",
            "session_id": sessionId,
            "workflow_id": workflowId,
            "recovery_code": recoveryCode
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func cancelRecoveryWorkflow(sessionId: UInt64, workflowId: UInt64) throws {
        _ = try send([
            "command": "cancelRecoveryWorkflow",
            "session_id": sessionId,
            "workflow_id": workflowId
        ])
    }

    func lock(sessionId: UInt64) throws {
        _ = try send([
            "command": "lock",
            "session_id": sessionId
        ])
    }

    func listItems(sessionId: UInt64) throws -> [VaultItemView] {
        guard case let .items(payload) = try send([
            "command": "listItems",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.items
    }

    func passwordHealth(sessionId: UInt64) throws -> PasswordHealthPayload {
        guard case let .passwordHealth(payload) = try send([
            "command": "passwordHealth",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func refreshFromDisk(sessionId: UInt64) throws -> SyncRefreshPayload {
        guard case let .syncRefreshReport(payload) = try send([
            "command": "refreshFromDisk",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func quarantineRejectedRecords(sessionId: UInt64) throws -> SyncQuarantinePayload {
        guard case let .syncQuarantineReport(payload) = try send([
            "command": "quarantineRejectedRecords",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func search(sessionId: UInt64, text: String, includeArchived: Bool) throws -> [VaultItemView] {
        guard case let .items(payload) = try send([
            "command": "search",
            "session_id": sessionId,
            "text": text,
            "include_archived": includeArchived
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.items
    }

    func listAuthorizedCredentialIds(sessionId: UInt64) throws -> Set<String> {
        guard case let .authorizedCredentialIds(payload) = try send([
            "command": "listAuthorizedCredentialIds",
            "session_id": sessionId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return Set(payload.credentialIds)
    }

    func appsToolsPendingRequests() throws -> AppsToolsPendingRequestQueue {
        guard case let .appsToolsPendingRequests(payload) = try send([
            "command": "appsToolsPendingRequests"
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.queue
    }

    func denyAppsToolsPendingRequest(
        requestSource: String,
        requestId: String
    ) throws -> AppsToolsPendingRequestDecision {
        try appsToolsPendingRequestDecisionResponse([
            "command": "appsToolsDenyPendingRequest",
            "request_source": requestSource,
            "request_id": requestId
        ])
    }

    func approveAppsToolsPairing(
        requestId: String,
        label: String
    ) throws -> AppsToolsPendingRequestDecision {
        try appsToolsPendingRequestDecisionResponse([
            "command": "appsToolsApprovePairing",
            "request_id": requestId,
            "label": label
        ])
    }

    func approveAppsToolsPendingUnlock(
        sessionId: UInt64,
        requestId: String
    ) throws -> AppsToolsPendingRequestDecision {
        try appsToolsPendingRequestDecisionResponse([
            "command": "appsToolsApprovePendingUnlock",
            "session_id": sessionId,
            "request_id": requestId
        ])
    }

    func reviewAppsToolsPendingCredential(
        sessionId: UInt64,
        requestId: String
    ) throws -> AppsToolsCredentialReview {
        guard case let .appsToolsCredentialReview(payload) = try send([
            "command": "appsToolsReviewPendingCredential",
            "session_id": sessionId,
            "request_id": requestId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.review
    }

    func allowAppsToolsPendingRequestOnce(
        sessionId: UInt64,
        requestId: String,
        credentialId: String?,
        secretFieldId: String?
    ) throws -> AppsToolsPendingRequestDecision {
        try appsToolsPendingRequestDecisionResponse([
            "command": "appsToolsAllowOnce",
            "session_id": sessionId,
            "request_id": requestId,
            "credential_id": credentialId as Any,
            "secret_field_id": secretFieldId as Any
        ])
    }

    func configureAppsToolsLongTermAccess(
        sessionId: UInt64,
        requestId: String,
        credentialId: String?,
        secretFieldId: String?,
        confirmationPolicy: AppsToolsConfirmationPolicy
    ) throws -> AppsToolsPendingRequestDecision {
        try appsToolsPendingRequestDecisionResponse([
            "command": "appsToolsConfigureLongTermAccess",
            "session_id": sessionId,
            "request_id": requestId,
            "credential_id": credentialId as Any,
            "secret_field_id": secretFieldId as Any,
            "confirmation_policy": confirmationPolicy.rawValue
        ])
    }

    func appsToolsSnapshot(sessionId: UInt64) throws -> AppsToolsSnapshot {
        try appsToolsSnapshotResponse([
            "command": "appsToolsSnapshot",
            "session_id": sessionId
        ])
    }

    func appsToolsConsumerDetail(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsConsumerDetail {
        guard case let .appsToolsConsumerDetail(payload) = try send([
            "command": "appsToolsConsumerDetail",
            "session_id": sessionId,
            "consumer_id": consumerId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.detail
    }

    func appsToolsUsageProfileSetup(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsUsageProfileSetup {
        guard case let .appsToolsUsageProfileSetup(payload) = try send([
            "command": "appsToolsUsageProfileSetup",
            "session_id": sessionId,
            "consumer_id": consumerId
        ]), payload.setup.consumerId == consumerId else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.setup
    }

    func createAppsToolsUsageProfile(
        sessionId: UInt64,
        consumerId: String,
        draft: AppsToolsUsageProfileDraft
    ) throws -> AppsToolsUsageProfile {
        guard case let .appsToolsUsageProfileCreated(payload) = try send([
            "command": "createAppsToolsUsageProfile",
            "session_id": sessionId,
            "consumer_id": consumerId,
            "label": draft.label,
            "template_id": draft.templateId,
            "technical_name": draft.technicalName as Any
        ]), payload.consumerId == consumerId else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.profile
    }

    func removeAppsToolsUsageProfile(
        sessionId: UInt64,
        consumerId: String,
        usageProfileId: String
    ) throws -> Bool {
        guard case let .appsToolsUsageProfileRemoved(payload) = try send([
            "command": "removeAppsToolsUsageProfile",
            "session_id": sessionId,
            "consumer_id": consumerId,
            "usage_profile_id": usageProfileId
        ]), payload.consumerId == consumerId,
            payload.usageProfileId == usageProfileId
        else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.removed
    }

    func setAppsToolsPaused(sessionId: UInt64, paused: Bool) throws -> AppsToolsSnapshot {
        try appsToolsSnapshotResponse([
            "command": "setAppsToolsPaused",
            "session_id": sessionId,
            "paused": paused
        ])
    }

    func revokeAppsToolsField(
        sessionId: UInt64,
        consumerId: String,
        field: AppsToolsFieldReference
    ) throws -> AppsToolsSnapshot {
        try appsToolsSnapshotResponse([
            "command": "revokeAppsToolsField",
            "session_id": sessionId,
            "consumer_id": consumerId,
            "vault_id": field.vaultId,
            "credential_id": field.credentialId,
            "secret_field_id": field.secretFieldId
        ])
    }

    func revokeAppsToolsConsumer(
        sessionId: UInt64,
        consumerId: String
    ) throws -> AppsToolsSnapshot {
        try appsToolsSnapshotResponse([
            "command": "revokeAppsToolsConsumer",
            "session_id": sessionId,
            "consumer_id": consumerId
        ])
    }

    func createCredentialFromTemplate(
        sessionId: UInt64,
        form: TemplateCredentialForm
    ) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "createCredentialFromTemplate",
            "session_id": sessionId,
            "template_id": form.template.rawValue,
            "title": form.title,
            "secret": form.secret,
            "expiry": form.template.supportsExpiry ? form.expiry.nilIfEmpty as Any : NSNull(),
            "notes": form.notes.nilIfEmpty as Any,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func updateCredential(
        sessionId: UInt64,
        credentialId: String,
        form: CredentialEditorForm
    ) throws -> [VaultItemView] {
        guard let expectedRevision = form.revision else {
            throw CoreBridgeError.commandFailed("Credential revision is required")
        }
        let fields: [[String: Any]] = form.fields.map { field in
            var value: [String: Any] = [
                "role": field.normalizedRole
            ]
            if let label = field.normalizedLabel {
                value["label"] = label
            }
            switch field.fieldType {
            case .text:
                value["value_type"] = "text"
                value["text"] = field.text
            case .existingSecret:
                value["value_type"] = "existingSecret"
                value["secret_field_id"] = field.secretFieldId ?? ""
                if !field.secretInput.isEmpty {
                    value["replacement"] = field.secretInput
                }
            case .newSecret:
                value["value_type"] = "newSecret"
                value["secret_kind"] = field.secretKind
                value["secret"] = field.secretInput
            }
            return value
        }
        return try itemsResponse([
            "command": "updateCredential",
            "session_id": sessionId,
            "credential_id": credentialId,
            "expected_revision": expectedRevision,
            "title": form.normalizedTitle,
            "template_id": form.templateId ?? NSNull(),
            "fields": fields,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func duplicateCredential(
        sessionId: UInt64,
        credentialId: String,
        expectedRevision: String,
        title: String
    ) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "duplicateCredential",
            "session_id": sessionId,
            "credential_id": credentialId,
            "expected_revision": expectedRevision,
            "title": title
        ])
    }

    func getCredential(sessionId: UInt64, credentialId: String) throws -> CredentialDetail {
        guard case let .credentialDetail(payload) = try send([
            "command": "getCredential",
            "session_id": sessionId,
            "credential_id": credentialId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.detail
    }

    func getCredentialSecretField(
        sessionId: UInt64,
        credentialId: String,
        secretFieldId: String
    ) throws -> String {
        guard case let .secret(payload) = try send([
            "command": "getCredentialSecretField",
            "session_id": sessionId,
            "credential_id": credentialId,
            "secret_field_id": secretFieldId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.value
    }

    func createLogin(sessionId: UInt64, form: LoginForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "createLogin",
            "session_id": sessionId,
            "title": form.title,
            "username": form.username.nilIfEmpty as Any,
            "password": form.password.nilIfEmpty as Any,
            "url": form.url.nilIfEmpty as Any,
            "urls": form.urls,
            "notes": form.notes.nilIfEmpty as Any,
            "totp_secret": form.totpSecretForSave,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func updateLogin(sessionId: UInt64, itemId: String, form: LoginForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "updateLogin",
            "session_id": sessionId,
            "item_id": itemId,
            "title": form.title,
            "username": form.username.nilIfEmpty as Any,
            "password": form.passwordForUpdate as Any,
            "url": form.url.nilIfEmpty as Any,
            "urls": form.urls,
            "notes": form.notes.nilIfEmpty as Any,
            "totp_secret": form.totpSecretForSave,
            "expected_revision": form.revision as Any,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func getLogin(sessionId: UInt64, itemId: String) throws -> LoginDetail {
        guard case let .loginDetail(detail) = try send([
            "command": "getLogin",
            "session_id": sessionId,
            "item_id": itemId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return detail
    }

    func createSecureNote(sessionId: UInt64, form: SecureNoteForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "createSecureNote",
            "session_id": sessionId,
            "title": form.title,
            "body": form.body,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func updateSecureNote(sessionId: UInt64, itemId: String, form: SecureNoteForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "updateSecureNote",
            "session_id": sessionId,
            "item_id": itemId,
            "title": form.title,
            "body": form.body,
            "expected_revision": form.revision as Any,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func getSecureNote(sessionId: UInt64, itemId: String) throws -> SecureNoteDetail {
        guard case let .secureNoteDetail(detail) = try send([
            "command": "getSecureNote",
            "session_id": sessionId,
            "item_id": itemId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return detail
    }

    func createCreditCard(sessionId: UInt64, form: CreditCardForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "createCreditCard",
            "session_id": sessionId,
            "title": form.title,
            "cardholder_name": form.cardholderName.nilIfEmpty as Any,
            "number": form.number.nilIfEmpty as Any,
            "expiry_month": form.expiryMonthValue as Any,
            "expiry_year": form.expiryYearValue as Any,
            "verification_code": form.verificationCode.nilIfEmpty as Any,
            "notes": form.notes.nilIfEmpty as Any,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func updateCreditCard(sessionId: UInt64, itemId: String, form: CreditCardForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "updateCreditCard",
            "session_id": sessionId,
            "item_id": itemId,
            "title": form.title,
            "cardholder_name": form.cardholderName.nilIfEmpty as Any,
            "number": form.numberForUpdate as Any,
            "expiry_month": form.expiryMonthValue as Any,
            "expiry_year": form.expiryYearValue as Any,
            "verification_code": form.verificationCodeForUpdate as Any,
            "notes": form.notes.nilIfEmpty as Any,
            "expected_revision": form.revision as Any,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func getCreditCard(sessionId: UInt64, itemId: String) throws -> CreditCardDetail {
        guard case let .creditCardDetail(detail) = try send([
            "command": "getCreditCard",
            "session_id": sessionId,
            "item_id": itemId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return detail
    }

    func getCreditCardField(sessionId: UInt64, itemId: String, field: String) throws -> String {
        guard case let .secret(payload) = try send([
            "command": "getCreditCardField",
            "session_id": sessionId,
            "item_id": itemId,
            "field": field
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.value
    }

    func createSoftwareLicense(sessionId: UInt64, form: SoftwareLicenseForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "createSoftwareLicense",
            "session_id": sessionId,
            "title": form.title,
            "product": form.product.nilIfEmpty as Any,
            "license_key": form.licenseKey.nilIfEmpty as Any,
            "licensed_to": form.licensedTo.nilIfEmpty as Any,
            "notes": form.notes.nilIfEmpty as Any,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func updateSoftwareLicense(sessionId: UInt64, itemId: String, form: SoftwareLicenseForm) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "updateSoftwareLicense",
            "session_id": sessionId,
            "item_id": itemId,
            "title": form.title,
            "product": form.product.nilIfEmpty as Any,
            "license_key": form.licenseKeyForUpdate as Any,
            "licensed_to": form.licensedTo.nilIfEmpty as Any,
            "notes": form.notes.nilIfEmpty as Any,
            "expected_revision": form.revision as Any,
            "tags": form.tags,
            "favorite": form.favorite
        ])
    }

    func getSoftwareLicense(sessionId: UInt64, itemId: String) throws -> SoftwareLicenseDetail {
        guard case let .softwareLicenseDetail(detail) = try send([
            "command": "getSoftwareLicense",
            "session_id": sessionId,
            "item_id": itemId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return detail
    }

    func getSoftwareLicenseField(sessionId: UInt64, itemId: String, field: String) throws -> String {
        guard case let .secret(payload) = try send([
            "command": "getSoftwareLicenseField",
            "session_id": sessionId,
            "item_id": itemId,
            "field": field
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.value
    }

    func getLoginField(sessionId: UInt64, itemId: String, field: String) throws -> String {
        guard case let .secret(payload) = try send([
            "command": "getLoginField",
            "session_id": sessionId,
            "item_id": itemId,
            "field": field
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.value
    }

    func archiveItem(sessionId: UInt64, itemId: String, expectedRevision: String?) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "archiveItem",
            "session_id": sessionId,
            "item_id": itemId,
            "expected_revision": expectedRevision as Any
        ])
    }

    func restoreItem(sessionId: UInt64, itemId: String) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "restoreItem",
            "session_id": sessionId,
            "item_id": itemId
        ])
    }

    func deleteItem(sessionId: UInt64, itemId: String, expectedRevision: String?) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "deleteItem",
            "session_id": sessionId,
            "item_id": itemId,
            "expected_revision": expectedRevision as Any
        ])
    }

    func resolveConflict(sessionId: UInt64, conflictId: String) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "resolveConflict",
            "session_id": sessionId,
            "conflict_id": conflictId
        ])
    }

    func getConflictCandidates(sessionId: UInt64, conflictId: String) throws -> [ConflictCandidateView] {
        guard case let .conflictCandidates(payload) = try send([
            "command": "getConflictCandidates",
            "session_id": sessionId,
            "conflict_id": conflictId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.candidates
    }

    func resolveConflictCandidate(sessionId: UInt64, conflictId: String, revision: String) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "resolveConflictCandidate",
            "session_id": sessionId,
            "conflict_id": conflictId,
            "revision": revision
        ])
    }

    func resolveConflictMerge(sessionId: UInt64, conflictId: String, baseRevision: String, fieldSelections: [ConflictMergeFieldSelection]) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "resolveConflictMerge",
            "session_id": sessionId,
            "conflict_id": conflictId,
            "base_revision": baseRevision,
            "field_selections": fieldSelections.map(\.commandPayload)
        ])
    }

    func setFavorite(sessionId: UInt64, itemId: String, expectedRevision: String?, favorite: Bool) throws -> [VaultItemView] {
        try itemsResponse([
            "command": "setFavorite",
            "session_id": sessionId,
            "item_id": itemId,
            "expected_revision": expectedRevision as Any,
            "favorite": favorite
        ])
    }

    func totpCode(sessionId: UInt64, itemId: String) throws -> TotpPayload {
        guard case let .totp(payload) = try send([
            "command": "totpCode",
            "session_id": sessionId,
            "item_id": itemId
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func previewImport(sessionId: UInt64, sourcePath: String, sourceFormat: String) throws -> ImportPreviewPayload {
        try importPreviewResponse([
            "command": "previewImport",
            "session_id": sessionId,
            "source_path": sourcePath,
            "source_format": sourceFormat
        ])
    }

    func commitImport(sessionId: UInt64, sourcePath: String, sourceFormat: String, keepDuplicates: Bool) throws -> ImportPreviewPayload {
        try importPreviewResponse([
            "command": "commitImport",
            "session_id": sessionId,
            "source_path": sourcePath,
            "source_format": sourceFormat,
            "keep_duplicates": keepDuplicates
        ])
    }

    func exportItems(
        sessionId: UInt64,
        destinationPath: String,
        exportFormat: String,
        currentPassword: String
    ) throws -> ExportResultPayload {
        guard case let .exportResult(payload) = try send([
            "command": "exportItems",
            "session_id": sessionId,
            "destination_path": destinationPath,
            "export_format": exportFormat,
            "current_password": currentPassword
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func backupVault(sessionId: UInt64, destinationPath: String) throws -> BackupResultPayload {
        guard case let .backupResult(payload) = try send([
            "command": "backupVault",
            "session_id": sessionId,
            "destination_path": destinationPath
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    func restoreVaultBackup(sourcePath: String, destinationPath: String) throws -> RestoreBackupResultPayload {
        guard case let .restoreBackupResult(payload) = try send([
            "command": "restoreVaultBackup",
            "source_path": sourcePath,
            "destination_path": destinationPath
        ]) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    private func itemsResponse(_ command: [String: Any]) throws -> [VaultItemView] {
        guard case let .items(payload) = try send(command) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.items
    }

    private func appsToolsSnapshotResponse(_ command: [String: Any]) throws -> AppsToolsSnapshot {
        guard case let .appsToolsSnapshot(payload) = try send(command) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.snapshot
    }

    private func appsToolsPendingRequestDecisionResponse(
        _ command: [String: Any]
    ) throws -> AppsToolsPendingRequestDecision {
        guard case let .appsToolsPendingRequestDecision(payload) = try send(command) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload.decision
    }

    private func importPreviewResponse(_ command: [String: Any]) throws -> ImportPreviewPayload {
        guard case let .importPreview(payload) = try send(command) else {
            throw CoreBridgeError.unexpectedResponse
        }
        return payload
    }

    private func send(_ command: [String: Any]) throws -> CorePayload {
        guard let commandFunction, let freeFunction else {
            throw CoreBridgeError.unavailable(status)
        }
        let cleaned = command.compactMapValues { value -> Any? in
            if value is NSNull { return nil }
            return value
        }
        let data = try JSONSerialization.data(withJSONObject: cleaned)
        guard let json = String(data: data, encoding: .utf8) else {
            throw CoreBridgeError.invalidJSON
        }

        return try json.withCString { pointer in
            guard let responsePointer = commandFunction(pointer) else {
                throw CoreBridgeError.emptyResponse
            }
            defer { freeFunction(responsePointer) }
            let response = String(cString: responsePointer)
            let responseData = Data(response.utf8)
            let decoded = try JSONDecoder().decode(CoreResponse.self, from: responseData)
            if decoded.ok, let payload = decoded.payload {
                return payload
            }
            throw CoreBridgeError.commandFailed(decoded.error ?? "unknown core error")
        }
    }

    private static var developmentLibraryOverridesEnabled: Bool {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }

    static func libraryCandidates(
        privateFrameworksPath: String?,
        bundlePath: String,
        environment: [String: String],
        currentDirectoryPath: String,
        includeDevelopmentOverrides: Bool
    ) -> [String] {
        var candidates: [String] = []
        if includeDevelopmentOverrides,
           let env = environment["PSW_FFI_LIBRARY"],
           !env.isEmpty {
            candidates.append(env)
        }
        if let frameworksPath = privateFrameworksPath {
            candidates.append("\(frameworksPath)/libpsw_ffi.dylib")
        }
        let bundleCandidate = "\(bundlePath)/Contents/Frameworks/libpsw_ffi.dylib"
        if !candidates.contains(bundleCandidate) {
            candidates.append(bundleCandidate)
        }
        if includeDevelopmentOverrides {
            candidates.append("\(currentDirectoryPath)/target/debug/libpsw_ffi.dylib")
            candidates.append("\(currentDirectoryPath)/../../target/debug/libpsw_ffi.dylib")
            candidates.append("\(currentDirectoryPath)/../../../target/debug/libpsw_ffi.dylib")
        }
        return candidates
    }
}

enum CoreBridgeError: LocalizedError {
    case unavailable(String)
    case commandFailed(String)
    case emptyResponse
    case invalidJSON
    case unexpectedResponse

    var errorDescription: String? {
        switch self {
        case let .unavailable(status):
            return status
        case let .commandFailed(message):
            return message
        case .emptyResponse:
            return "Rust core returned no response"
        case .invalidJSON:
            return "Command JSON could not be encoded"
        case .unexpectedResponse:
            return "Rust core returned an unexpected response"
        }
    }
}

struct CoreResponse: Decodable {
    let ok: Bool
    let error: String?
    let payload: CorePayload?
}

enum CorePayload: Decodable {
    case unit
    case version(VersionPayload)
    case vault(VaultPayload)
    case unlocked(UnlockedPayload)
    case items(ItemsPayload)
    case authorizedCredentialIds(AuthorizedCredentialIdsPayload)
    case appsToolsPendingRequests(AppsToolsPendingRequestQueuePayload)
    case appsToolsPendingRequestDecision(AppsToolsPendingRequestDecisionPayload)
    case appsToolsCredentialReview(AppsToolsCredentialReviewPayload)
    case appsToolsSnapshot(AppsToolsSnapshotPayload)
    case appsToolsConsumerDetail(AppsToolsConsumerDetailPayload)
    case appsToolsUsageProfileSetup(AppsToolsUsageProfileSetupPayload)
    case appsToolsUsageProfileCreated(AppsToolsUsageProfileCreatedPayload)
    case appsToolsUsageProfileRemoved(AppsToolsUsageProfileRemovedPayload)
    case passwordHealth(PasswordHealthPayload)
    case syncRefreshReport(SyncRefreshPayload)
    case syncQuarantineReport(SyncQuarantinePayload)
    case loginDetail(LoginDetail)
    case secureNoteDetail(SecureNoteDetail)
    case creditCardDetail(CreditCardDetail)
    case softwareLicenseDetail(SoftwareLicenseDetail)
    case credentialDetail(CredentialDetailPayload)
    case secret(SecretPayload)
    case totp(TotpPayload)
    case importPreview(ImportPreviewPayload)
    case exportResult(ExportResultPayload)
    case backupResult(BackupResultPayload)
    case restoreBackupResult(RestoreBackupResultPayload)
    case recoveryStatus(RecoveryStatusPayload)
    case recoveryKit(RecoveryKitPayload)
    case recoveryConfirmed(RecoveryConfirmationPayload)
    case conflictCandidates(ConflictCandidatesPayload)

    enum CodingKeys: CodingKey {
        case type
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "unit":
            self = .unit
        case "version":
            self = .version(try VersionPayload(from: decoder))
        case "vault":
            self = .vault(try VaultPayload(from: decoder))
        case "unlocked":
            self = .unlocked(try UnlockedPayload(from: decoder))
        case "items":
            self = .items(try ItemsPayload(from: decoder))
        case "authorizedCredentialIds":
            self = .authorizedCredentialIds(try AuthorizedCredentialIdsPayload(from: decoder))
        case "appsToolsPendingRequests":
            self = .appsToolsPendingRequests(
                try AppsToolsPendingRequestQueuePayload(from: decoder)
            )
        case "appsToolsPendingRequestDecision":
            self = .appsToolsPendingRequestDecision(
                try AppsToolsPendingRequestDecisionPayload(from: decoder)
            )
        case "appsToolsCredentialReview":
            self = .appsToolsCredentialReview(
                try AppsToolsCredentialReviewPayload(from: decoder)
            )
        case "appsToolsSnapshot":
            self = .appsToolsSnapshot(try AppsToolsSnapshotPayload(from: decoder))
        case "appsToolsConsumerDetail":
            self = .appsToolsConsumerDetail(try AppsToolsConsumerDetailPayload(from: decoder))
        case "appsToolsUsageProfileSetup":
            self = .appsToolsUsageProfileSetup(
                try AppsToolsUsageProfileSetupPayload(from: decoder)
            )
        case "appsToolsUsageProfileCreated":
            self = .appsToolsUsageProfileCreated(
                try AppsToolsUsageProfileCreatedPayload(from: decoder)
            )
        case "appsToolsUsageProfileRemoved":
            self = .appsToolsUsageProfileRemoved(
                try AppsToolsUsageProfileRemovedPayload(from: decoder)
            )
        case "passwordHealth":
            self = .passwordHealth(try PasswordHealthPayload(from: decoder))
        case "syncRefreshReport":
            self = .syncRefreshReport(try SyncRefreshPayload(from: decoder))
        case "syncQuarantineReport":
            self = .syncQuarantineReport(try SyncQuarantinePayload(from: decoder))
        case "loginDetail":
            self = .loginDetail(try LoginDetail(from: decoder))
        case "secureNoteDetail":
            self = .secureNoteDetail(try SecureNoteDetail(from: decoder))
        case "creditCardDetail":
            self = .creditCardDetail(try CreditCardDetail(from: decoder))
        case "softwareLicenseDetail":
            self = .softwareLicenseDetail(try SoftwareLicenseDetail(from: decoder))
        case "credentialDetail":
            self = .credentialDetail(try CredentialDetailPayload(from: decoder))
        case "secret":
            self = .secret(try SecretPayload(from: decoder))
        case "totp":
            self = .totp(try TotpPayload(from: decoder))
        case "importPreview":
            self = .importPreview(try ImportPreviewPayload(from: decoder))
        case "exportResult":
            self = .exportResult(try ExportResultPayload(from: decoder))
        case "backupResult":
            self = .backupResult(try BackupResultPayload(from: decoder))
        case "restoreBackupResult":
            self = .restoreBackupResult(try RestoreBackupResultPayload(from: decoder))
        case "recoveryStatus":
            self = .recoveryStatus(try RecoveryStatusPayload(from: decoder))
        case "recoveryKit":
            self = .recoveryKit(try RecoveryKitPayload(from: decoder))
        case "recoveryConfirmed":
            self = .recoveryConfirmed(try RecoveryConfirmationPayload(from: decoder))
        case "conflictCandidates":
            self = .conflictCandidates(try ConflictCandidatesPayload(from: decoder))
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "Unknown payload type")
        }
    }
}

struct VersionPayload: Decodable {
    let version: String
}

struct VaultPayload: Decodable {
    let displayName: String?
    let vaultFormatVersion: UInt32
    let recordFormatVersion: UInt32

    enum CodingKeys: String, CodingKey {
        case displayName = "display_name"
        case vaultFormatVersion = "vault_format_version"
        case recordFormatVersion = "record_format_version"
    }
}

struct UnlockedPayload: Decodable {
    let sessionId: UInt64
    let items: [VaultItemView]
    let appsToolsVaultPathConflict: Bool

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case items
        case appsToolsVaultPathConflict = "apps_tools_vault_path_conflict"
    }

    init(
        sessionId: UInt64,
        items: [VaultItemView],
        appsToolsVaultPathConflict: Bool = false
    ) {
        self.sessionId = sessionId
        self.items = items
        self.appsToolsVaultPathConflict = appsToolsVaultPathConflict
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sessionId = try container.decode(UInt64.self, forKey: .sessionId)
        items = try container.decode([VaultItemView].self, forKey: .items)
        appsToolsVaultPathConflict = try container.decodeIfPresent(
            Bool.self,
            forKey: .appsToolsVaultPathConflict
        ) ?? false
    }
}

struct ItemsPayload: Decodable {
    let items: [VaultItemView]
}

struct AuthorizedCredentialIdsPayload: Decodable, Equatable {
    let credentialIds: [String]

    enum CodingKeys: String, CodingKey {
        case credentialIds = "credential_ids"
    }
}

struct AppsToolsPendingRequestQueuePayload: Decodable, Equatable {
    let queue: AppsToolsPendingRequestQueue
}

struct AppsToolsPendingRequestDecisionPayload: Decodable, Equatable {
    let decision: AppsToolsPendingRequestDecision
}

struct AppsToolsPendingRequestDecision: Decodable, Equatable {
    let action: String
    let status: String
    let useGrantId: String?
    let accessRuleId: String?

    enum CodingKeys: String, CodingKey {
        case action
        case status
        case useGrantId = "use_grant_id"
        case accessRuleId = "access_rule_id"
    }
}

struct AppsToolsCredentialReviewPayload: Decodable, Equatable {
    let review: AppsToolsCredentialReview
}

struct AppsToolsCredentialReview: Decodable, Equatable {
    let requestId: String
    let requestDescription: String
    let capability: String
    let capabilityVersion: UInt16
    let truncated: Bool
    let candidates: [AppsToolsCredentialCandidate]

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case requestDescription = "request_description"
        case capability
        case capabilityVersion = "capability_version"
        case truncated
        case candidates
    }
}

struct AppsToolsCredentialCandidate: Decodable, Equatable, Identifiable {
    let credentialId: String
    let title: String
    let templateId: String?
    let tags: [String]
    let favorite: Bool
    let secretFields: [AppsToolsCredentialFieldCandidate]

    var id: String { credentialId }

    enum CodingKeys: String, CodingKey {
        case credentialId = "credential_id"
        case title
        case templateId = "template_id"
        case tags
        case favorite
        case secretFields = "secret_fields"
    }
}

struct AppsToolsCredentialFieldCandidate: Decodable, Equatable, Identifiable {
    let secretFieldId: String
    let role: String
    let label: String?
    let kind: String

    var id: String { secretFieldId }

    enum CodingKeys: String, CodingKey {
        case secretFieldId = "secret_field_id"
        case role
        case label
        case kind
    }
}

struct AppsToolsCredentialSelection: Equatable, Hashable {
    let credentialId: String
    let secretFieldId: String
}

enum AppsToolsConfirmationPolicy: String, CaseIterable, Identifiable {
    case everyUse = "every-use"
    case oncePerUnlockSession = "once-per-unlock-session"
    case automaticWhileUnlocked = "automatic-while-unlocked"

    var id: String { rawValue }
}

struct AppsToolsPendingRequestQueue: Decodable, Equatable {
    let pendingCount: Int
    let requests: [AppsToolsPendingRequest]

    static let empty = AppsToolsPendingRequestQueue(
        pendingCount: 0,
        requests: []
    )

    enum CodingKeys: String, CodingKey {
        case pendingCount = "pending_count"
        case requests
    }
}

struct AppsToolsPendingRequest: Decodable, Equatable, Identifiable {
    let requestSource: String
    let requestId: String
    let kind: String
    let consumerId: String?
    let consumerLabel: String?
    let identity: AppsToolsConsumerIdentity?
    let pairingComparisonCode: String?
    let pairingKeyFingerprint: String?
    let vaultId: String?
    let credentialId: String?
    let secretFieldId: String?
    let capability: String?
    let capabilityVersion: UInt16?
    let requestDescription: String?
    let createdAtMilliseconds: Int64?
    let expiresAtMilliseconds: Int64?
    let remainingMilliseconds: UInt64?

    var id: String { "\(requestSource):\(requestId)" }

    enum CodingKeys: String, CodingKey {
        case requestSource = "request_source"
        case requestId = "request_id"
        case kind
        case consumerId = "consumer_id"
        case consumerLabel = "consumer_label"
        case identity
        case pairingComparisonCode = "pairing_comparison_code"
        case pairingKeyFingerprint = "pairing_key_fingerprint"
        case vaultId = "vault_id"
        case credentialId = "credential_id"
        case secretFieldId = "secret_field_id"
        case capability
        case capabilityVersion = "capability_version"
        case requestDescription = "request_description"
        case createdAtMilliseconds = "created_at_ms"
        case expiresAtMilliseconds = "expires_at_ms"
        case remainingMilliseconds = "remaining_ms"
    }
}

struct AppsToolsSnapshotPayload: Decodable, Equatable {
    let snapshot: AppsToolsSnapshot
}

struct AppsToolsConsumerDetailPayload: Decodable, Equatable {
    let detail: AppsToolsConsumerDetail
}

struct AppsToolsUsageProfileSetupPayload: Decodable, Equatable {
    let setup: AppsToolsUsageProfileSetup
}

struct AppsToolsUsageProfileCreatedPayload: Decodable, Equatable {
    let consumerId: String
    let profile: AppsToolsUsageProfile

    enum CodingKeys: String, CodingKey {
        case consumerId = "consumer_id"
        case profile
    }
}

struct AppsToolsUsageProfileRemovedPayload: Decodable, Equatable {
    let consumerId: String
    let usageProfileId: String
    let removed: Bool

    enum CodingKeys: String, CodingKey {
        case consumerId = "consumer_id"
        case usageProfileId = "usage_profile_id"
        case removed
    }
}

struct AppsToolsSnapshot: Decodable, Equatable {
    let paused: Bool
    let authorizedCredentialIds: [String]
    let consumers: [AppsToolsConsumerSummary]

    static let empty = AppsToolsSnapshot(
        paused: false,
        authorizedCredentialIds: [],
        consumers: []
    )

    enum CodingKeys: String, CodingKey {
        case paused
        case authorizedCredentialIds = "authorized_credential_ids"
        case consumers
    }
}

struct AppsToolsConsumerIdentity: Decodable, Equatable {
    let executableName: String?
    let bundleIdentifier: String?
    let teamIdentifier: String?
    let codeSigningEvidence: String
    let codeSignatureFingerprint: String?

    enum CodingKeys: String, CodingKey {
        case executableName = "executable_name"
        case bundleIdentifier = "bundle_identifier"
        case teamIdentifier = "team_identifier"
        case codeSigningEvidence = "code_signing_evidence"
        case codeSignatureFingerprint = "code_signature_fingerprint"
    }
}

struct AppsToolsConsumerSummary: Decodable, Equatable, Identifiable {
    let consumerId: String
    let label: String
    let identity: AppsToolsConsumerIdentity
    let accessRuleCount: Int
    let usageProfileCount: Int
    let createdAtMilliseconds: Int64

    var id: String { consumerId }

    enum CodingKeys: String, CodingKey {
        case consumerId = "consumer_id"
        case label
        case identity
        case accessRuleCount = "access_rule_count"
        case usageProfileCount = "usage_profile_count"
        case createdAtMilliseconds = "created_at_ms"
    }
}

struct AppsToolsFieldReference: Decodable, Equatable {
    let vaultId: String
    let credentialId: String
    let secretFieldId: String
    let currentVault: Bool
    let credentialTitle: String?
    let fieldLabel: String?
    let secretKind: String?

    enum CodingKeys: String, CodingKey {
        case vaultId = "vault_id"
        case credentialId = "credential_id"
        case secretFieldId = "secret_field_id"
        case currentVault = "current_vault"
        case credentialTitle = "credential_title"
        case fieldLabel = "field_label"
        case secretKind = "secret_kind"
    }
}

struct AppsToolsFieldGrant: Decodable, Equatable, Identifiable {
    let accessRuleId: String
    let field: AppsToolsFieldReference
    let capability: String
    let capabilityVersion: UInt16
    let confirmationPolicy: String
    let lifetime: String
    let expiresAtMilliseconds: Int64?
    let createdAtMilliseconds: Int64
    let active: Bool

    var id: String { accessRuleId }

    enum CodingKeys: String, CodingKey {
        case accessRuleId = "access_rule_id"
        case field
        case capability
        case capabilityVersion = "capability_version"
        case confirmationPolicy = "confirmation_policy"
        case lifetime
        case expiresAtMilliseconds = "expires_at_ms"
        case createdAtMilliseconds = "created_at_ms"
        case active
    }
}

struct AppsToolsUsagePlacement: Decodable, Equatable {
    let kind: String
    let variableName: String?
    let appendNewline: Bool?
    let referenceVariableName: String?
    let renderDevFdPath: Bool?
    let headerName: String?

    enum CodingKeys: String, CodingKey {
        case kind
        case variableName = "variable_name"
        case appendNewline = "append_newline"
        case referenceVariableName = "reference_variable_name"
        case renderDevFdPath = "render_dev_fd_path"
        case headerName = "header_name"
    }
}

struct AppsToolsUsageProfile: Decodable, Equatable, Identifiable {
    let usageProfileId: String
    let label: String
    let capability: String
    let capabilityVersion: UInt16
    let placement: AppsToolsUsagePlacement
    let createdAtMilliseconds: Int64

    var id: String { usageProfileId }

    enum CodingKeys: String, CodingKey {
        case usageProfileId = "usage_profile_id"
        case label
        case capability
        case capabilityVersion = "capability_version"
        case placement
        case createdAtMilliseconds = "created_at_ms"
    }
}

struct AppsToolsUsageProfileTemplate: Decodable, Equatable, Identifiable {
    let templateId: String
    let capability: String
    let capabilityVersion: UInt16
    let technicalField: String
    let suggestedValue: String?

    var id: String { templateId }

    enum CodingKeys: String, CodingKey {
        case templateId = "template_id"
        case capability
        case capabilityVersion = "capability_version"
        case technicalField = "technical_field"
        case suggestedValue = "suggested_value"
    }
}

struct AppsToolsUsageProfileRecommendation: Decodable, Equatable {
    let recommendationId: String
    let templateId: String
    let technicalName: String

    enum CodingKeys: String, CodingKey {
        case recommendationId = "recommendation_id"
        case templateId = "template_id"
        case technicalName = "technical_name"
    }
}

struct AppsToolsUsageProfileSetup: Decodable, Equatable {
    let consumerId: String
    let templates: [AppsToolsUsageProfileTemplate]
    let recommendation: AppsToolsUsageProfileRecommendation?

    enum CodingKeys: String, CodingKey {
        case consumerId = "consumer_id"
        case templates
        case recommendation
    }

    func template(_ templateId: String) -> AppsToolsUsageProfileTemplate? {
        templates.first { $0.templateId == templateId }
    }
}

struct AppsToolsUsageProfileDraft: Equatable {
    let label: String
    let templateId: String
    let technicalName: String?
}

struct AppsToolsAuditEvent: Decodable, Equatable, Identifiable {
    let auditEventId: String
    let occurredAtMilliseconds: Int64
    let kind: String
    let field: AppsToolsFieldReference?
    let capability: String?
    let capabilityVersion: UInt16?
    let decision: String
    let confirmationMethod: String

    var id: String { auditEventId }

    enum CodingKeys: String, CodingKey {
        case auditEventId = "audit_event_id"
        case occurredAtMilliseconds = "occurred_at_ms"
        case kind
        case field
        case capability
        case capabilityVersion = "capability_version"
        case decision
        case confirmationMethod = "confirmation_method"
    }
}

struct AppsToolsConsumerDetail: Decodable, Equatable {
    let consumer: AppsToolsConsumerSummary
    let fieldGrants: [AppsToolsFieldGrant]
    let usageProfiles: [AppsToolsUsageProfile]
    let recentAuditEvents: [AppsToolsAuditEvent]

    enum CodingKeys: String, CodingKey {
        case consumer
        case fieldGrants = "field_grants"
        case usageProfiles = "usage_profiles"
        case recentAuditEvents = "recent_audit_events"
    }
}

struct CredentialDetailPayload: Decodable, Equatable {
    let detail: CredentialDetail
}

struct PasswordHealthPayload: Decodable, Equatable {
    let checkedLoginPasswords: Int
    let weakPasswords: Int
    let reusedPasswords: Int
    let issues: [PasswordHealthIssue]

    init(
        checkedLoginPasswords: Int,
        weakPasswords: Int,
        reusedPasswords: Int,
        issues: [PasswordHealthIssue]
    ) {
        self.checkedLoginPasswords = checkedLoginPasswords
        self.weakPasswords = weakPasswords
        self.reusedPasswords = reusedPasswords
        self.issues = issues
    }

    enum CodingKeys: String, CodingKey {
        case checkedLoginPasswords = "checked_login_passwords"
        case weakPasswords = "weak_passwords"
        case reusedPasswords = "reused_passwords"
        case issues
    }
}

struct PasswordHealthIssue: Decodable, Equatable, Identifiable {
    let itemId: String
    let title: String
    let kind: PasswordHealthIssueKind
    let reuseGroupSize: Int?

    var id: String {
        "\(itemId):\(kind.rawValue)"
    }

    init(
        itemId: String,
        title: String,
        kind: PasswordHealthIssueKind,
        reuseGroupSize: Int? = nil
    ) {
        self.itemId = itemId
        self.title = title
        self.kind = kind
        self.reuseGroupSize = reuseGroupSize
    }

    enum CodingKeys: String, CodingKey {
        case itemId = "item_id"
        case title
        case kind
        case reuseGroupSize = "reuse_group_size"
    }
}

enum PasswordHealthIssueKind: String, Decodable, Equatable {
    case weakPassword
    case reusedPassword
}

struct SyncRefreshPayload: Decodable, Equatable {
    let loadedItems: Int
    let appliedTombstones: Int
    let detectedConflicts: Int
    let rejectedRecords: Int
    let rejectedItemRecords: Int
    let rejectedTombstoneRecords: Int
    let rejectedRecordFiles: [SyncRejectedRecordFile]
    let items: [VaultItemView]

    init(
        loadedItems: Int,
        appliedTombstones: Int,
        detectedConflicts: Int,
        rejectedRecords: Int,
        rejectedItemRecords: Int = 0,
        rejectedTombstoneRecords: Int = 0,
        rejectedRecordFiles: [SyncRejectedRecordFile] = [],
        items: [VaultItemView]
    ) {
        self.loadedItems = loadedItems
        self.appliedTombstones = appliedTombstones
        self.detectedConflicts = detectedConflicts
        self.rejectedRecords = rejectedRecords
        self.rejectedItemRecords = rejectedItemRecords
        self.rejectedTombstoneRecords = rejectedTombstoneRecords
        self.rejectedRecordFiles = rejectedRecordFiles
        self.items = items
    }

    enum CodingKeys: String, CodingKey {
        case loadedItems = "loaded_items"
        case appliedTombstones = "applied_tombstones"
        case detectedConflicts = "detected_conflicts"
        case rejectedRecords = "rejected_records"
        case rejectedItemRecords = "rejected_item_records"
        case rejectedTombstoneRecords = "rejected_tombstone_records"
        case rejectedRecordFiles = "rejected_record_files"
        case items
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        loadedItems = try container.decode(Int.self, forKey: .loadedItems)
        appliedTombstones = try container.decode(Int.self, forKey: .appliedTombstones)
        detectedConflicts = try container.decode(Int.self, forKey: .detectedConflicts)
        rejectedRecords = try container.decode(Int.self, forKey: .rejectedRecords)
        rejectedItemRecords = try container.decodeIfPresent(Int.self, forKey: .rejectedItemRecords) ?? 0
        rejectedTombstoneRecords = try container.decodeIfPresent(Int.self, forKey: .rejectedTombstoneRecords) ?? 0
        rejectedRecordFiles = try container.decodeIfPresent([SyncRejectedRecordFile].self, forKey: .rejectedRecordFiles) ?? []
        items = try container.decode([VaultItemView].self, forKey: .items)
    }
}

struct SyncRejectedRecordFile: Decodable, Equatable {
    let kind: String
    let fileName: String

    enum CodingKeys: String, CodingKey {
        case kind
        case fileName = "file_name"
    }
}

struct SyncQuarantinePayload: Decodable, Equatable {
    let movedRecords: Int
    let movedItemRecords: Int
    let movedTombstoneRecords: Int

    enum CodingKeys: String, CodingKey {
        case movedRecords = "moved_records"
        case movedItemRecords = "moved_item_records"
        case movedTombstoneRecords = "moved_tombstone_records"
    }
}

struct SecretPayload: Decodable {
    let value: String
}

struct TotpPayload: Decodable {
    let code: String
    let remainingSeconds: UInt64

    enum CodingKeys: String, CodingKey {
        case code
        case remainingSeconds = "remaining_seconds"
    }
}

struct ImportPreviewPayload: Decodable, Equatable {
    let importableRecords: Int
    let skippedRecords: Int
    let duplicateRecords: Int
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case importableRecords = "importable_records"
        case skippedRecords = "skipped_records"
        case duplicateRecords = "duplicate_records"
        case warnings
    }
}

struct ExportResultPayload: Decodable, Equatable {
    let exportedRecords: Int
    let skippedRecords: Int
    let omissions: [ExportOmissionPayload]
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case exportedRecords = "exported_records"
        case skippedRecords = "skipped_records"
        case omissions
        case warnings
    }

    init(
        exportedRecords: Int,
        skippedRecords: Int,
        warnings: [String],
        omissions: [ExportOmissionPayload] = []
    ) {
        self.exportedRecords = exportedRecords
        self.skippedRecords = skippedRecords
        self.omissions = omissions
        self.warnings = warnings
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        exportedRecords = try container.decode(Int.self, forKey: .exportedRecords)
        skippedRecords = try container.decode(Int.self, forKey: .skippedRecords)
        omissions = try container.decodeIfPresent(
            [ExportOmissionPayload].self,
            forKey: .omissions
        ) ?? []
        warnings = try container.decode([String].self, forKey: .warnings)
    }
}

struct ExportOmissionPayload: Decodable, Equatable {
    let reason: String
    let count: Int
}

struct BackupResultPayload: Decodable, Equatable {
    let copiedItemFiles: Int
    let copiedAttachmentFiles: Int
    let copiedTombstoneFiles: Int

    enum CodingKeys: String, CodingKey {
        case copiedItemFiles = "copied_item_files"
        case copiedAttachmentFiles = "copied_attachment_files"
        case copiedTombstoneFiles = "copied_tombstone_files"
    }
}

struct RestoreBackupResultPayload: Decodable, Equatable {
    let copiedItemFiles: Int
    let copiedAttachmentFiles: Int
    let copiedTombstoneFiles: Int

    enum CodingKeys: String, CodingKey {
        case copiedItemFiles = "copied_item_files"
        case copiedAttachmentFiles = "copied_attachment_files"
        case copiedTombstoneFiles = "copied_tombstone_files"
    }
}

struct RecoveryStatusPayload: Decodable, Equatable {
    let hasRecoveryEnvelope: Bool
    let recoveryKeyId: String?

    init(hasRecoveryEnvelope: Bool, recoveryKeyId: String?) {
        self.hasRecoveryEnvelope = hasRecoveryEnvelope
        self.recoveryKeyId = recoveryKeyId
    }

    enum CodingKeys: String, CodingKey {
        case hasRecoveryEnvelope = "has_recovery_envelope"
        case recoveryKeyId = "recovery_key_id"
    }
}

enum RecoveryWorkflowKind: String, Decodable, Equatable {
    case setup
    case rotation
}

struct RecoveryKitPayload: Decodable, Equatable, Identifiable {
    let workflowId: UInt64
    let workflowKind: RecoveryWorkflowKind
    let vaultId: String
    let recoveryKeyId: String
    let generatedAtUnixSeconds: UInt64
    let canonicalCode: String
    let groupedCode: String
    let qrPayload: String
    let verificationGroups: [String]

    var id: UInt64 {
        workflowId
    }

    init(
        workflowId: UInt64,
        workflowKind: RecoveryWorkflowKind,
        vaultId: String,
        recoveryKeyId: String,
        generatedAtUnixSeconds: UInt64,
        canonicalCode: String,
        groupedCode: String,
        qrPayload: String,
        verificationGroups: [String]
    ) {
        self.workflowId = workflowId
        self.workflowKind = workflowKind
        self.vaultId = vaultId
        self.recoveryKeyId = recoveryKeyId
        self.generatedAtUnixSeconds = generatedAtUnixSeconds
        self.canonicalCode = canonicalCode
        self.groupedCode = groupedCode
        self.qrPayload = qrPayload
        self.verificationGroups = verificationGroups
    }

    enum CodingKeys: String, CodingKey {
        case workflowId = "workflow_id"
        case workflowKind = "workflow_kind"
        case vaultId = "vault_id"
        case recoveryKeyId = "recovery_key_id"
        case generatedAtUnixSeconds = "generated_at_unix_seconds"
        case canonicalCode = "canonical_code"
        case groupedCode = "grouped_code"
        case qrPayload = "qr_payload"
        case verificationGroups = "verification_groups"
    }
}

struct RecoveryConfirmationPayload: Decodable, Equatable {
    let workflowKind: RecoveryWorkflowKind
    let recoveryKeyId: String

    enum CodingKeys: String, CodingKey {
        case workflowKind = "workflow_kind"
        case recoveryKeyId = "recovery_key_id"
    }
}

struct ConflictCandidatesPayload: Decodable, Equatable {
    let candidates: [ConflictCandidateView]
}

extension String {
    var nilIfEmpty: String? {
        let value = trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}
