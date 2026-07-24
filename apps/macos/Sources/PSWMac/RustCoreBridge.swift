import Darwin
import Foundation

protocol CoreService {
    var isAvailable: Bool { get }
    var status: String { get }

    func createVault(path: String, displayName: String?, password: String) throws
    func openVault(path: String) throws
    func unlock(path: String, password: String) throws -> UnlockedPayload
    func unlockWithLocalMaterial(path: String, localMaterial: String) throws -> UnlockedPayload
    func localUnlockMaterial(sessionId: UInt64) throws -> String
    func changeMasterPassword(sessionId: UInt64, currentPassword: String, newPassword: String) throws
    func lock(sessionId: UInt64) throws
    func listItems(sessionId: UInt64) throws -> [VaultItemView]
    func passwordHealth(sessionId: UInt64) throws -> PasswordHealthPayload
    func refreshFromDisk(sessionId: UInt64) throws -> SyncRefreshPayload
    func quarantineRejectedRecords(sessionId: UInt64) throws -> SyncQuarantinePayload
    func search(sessionId: UInt64, text: String, includeArchived: Bool) throws -> [VaultItemView]
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
    func exportItems(sessionId: UInt64, destinationPath: String, exportFormat: String) throws -> ExportResultPayload
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
        let candidates = RustCoreBridge.libraryCandidates()
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

    func exportItems(sessionId: UInt64, destinationPath: String, exportFormat: String) throws -> ExportResultPayload {
        guard case let .exportResult(payload) = try send([
            "command": "exportItems",
            "session_id": sessionId,
            "destination_path": destinationPath,
            "export_format": exportFormat
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

    private static func libraryCandidates() -> [String] {
        var candidates: [String] = []
        if let env = ProcessInfo.processInfo.environment["PSW_FFI_LIBRARY"], !env.isEmpty {
            candidates.append(env)
        }
        if let frameworksPath = Bundle.main.privateFrameworksPath {
            candidates.append("\(frameworksPath)/libpsw_ffi.dylib")
        }
        candidates.append("\(Bundle.main.bundlePath)/Contents/Frameworks/libpsw_ffi.dylib")
        let cwd = FileManager.default.currentDirectoryPath
        candidates.append("\(cwd)/target/debug/libpsw_ffi.dylib")
        candidates.append("\(cwd)/../../target/debug/libpsw_ffi.dylib")
        candidates.append("\(cwd)/../../../target/debug/libpsw_ffi.dylib")
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
    case passwordHealth(PasswordHealthPayload)
    case syncRefreshReport(SyncRefreshPayload)
    case syncQuarantineReport(SyncQuarantinePayload)
    case loginDetail(LoginDetail)
    case secureNoteDetail(SecureNoteDetail)
    case creditCardDetail(CreditCardDetail)
    case softwareLicenseDetail(SoftwareLicenseDetail)
    case secret(SecretPayload)
    case totp(TotpPayload)
    case importPreview(ImportPreviewPayload)
    case exportResult(ExportResultPayload)
    case backupResult(BackupResultPayload)
    case restoreBackupResult(RestoreBackupResultPayload)
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

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case items
    }
}

struct ItemsPayload: Decodable {
    let items: [VaultItemView]
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
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case exportedRecords = "exported_records"
        case skippedRecords = "skipped_records"
        case warnings
    }
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

struct ConflictCandidatesPayload: Decodable, Equatable {
    let candidates: [ConflictCandidateView]
}

extension String {
    var nilIfEmpty: String? {
        let value = trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}
