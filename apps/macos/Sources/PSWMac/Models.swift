import Foundation

enum VaultSyncProvider: String, Equatable {
    case iCloudDrive = "iCloud Drive"
    case dropbox = "Dropbox"
    case oneDrive = "OneDrive"
    case googleDrive = "Google Drive"
    case syncthing = "Syncthing"

    var displayName: String { rawValue }
}

struct VaultSyncLocationHint: Equatable {
    let provider: VaultSyncProvider?

    var isLikelySynced: Bool {
        provider != nil
    }

    static func classify(url: URL?) -> VaultSyncLocationHint {
        guard let url else {
            return VaultSyncLocationHint(provider: nil)
        }

        let components = url.standardizedFileURL.pathComponents.map { component in
            component.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        let collapsedComponents = components.map { component in
            component.replacingOccurrences(of: " ", with: "")
        }
        let path = components.joined(separator: "/")
        let collapsedPath = collapsedComponents.joined(separator: "/")

        if path.contains("/library/mobile documents/")
            || collapsedPath.contains("com~apple~clouddocs")
            || components.contains("icloud drive")
        {
            return VaultSyncLocationHint(provider: .iCloudDrive)
        }

        if components.contains(where: { $0 == "dropbox" || $0.hasPrefix("dropbox ") }) {
            return VaultSyncLocationHint(provider: .dropbox)
        }

        if collapsedComponents.contains(where: { $0 == "onedrive" || $0.hasPrefix("onedrive-") }) {
            return VaultSyncLocationHint(provider: .oneDrive)
        }

        if collapsedPath.contains("googledrive")
            || components.contains("google drive")
            || components.contains("my drive")
        {
            return VaultSyncLocationHint(provider: .googleDrive)
        }

        if components.contains(where: { $0 == "syncthing" || $0.hasPrefix("syncthing ") }) {
            return VaultSyncLocationHint(provider: .syncthing)
        }

        return VaultSyncLocationHint(provider: nil)
    }
}

enum VaultRequiredPathKind: String, Equatable {
    case file
    case directory
}

struct VaultRequiredPathCheck: Equatable, Identifiable {
    let label: String
    let kind: VaultRequiredPathKind
    let exists: Bool
    let hasExpectedKind: Bool

    var id: String { label }

    var isReady: Bool {
        exists && hasExpectedKind
    }
}

enum VaultSyncReadinessStatus: String, Equatable {
    case completeLikelySynced
    case completeLocalOrUnknown
    case incomplete
}

struct VaultSyncReadiness: Equatable {
    let locationHint: VaultSyncLocationHint
    let requiredPaths: [VaultRequiredPathCheck]
    let localUnlockEnvelopePresent: Bool

    var status: VaultSyncReadinessStatus {
        guard requiredStructureComplete else { return .incomplete }
        return locationHint.isLikelySynced ? .completeLikelySynced : .completeLocalOrUnknown
    }

    var requiredStructureComplete: Bool {
        requiredPaths.allSatisfy(\.isReady)
    }

    var missingOrInvalidRequiredPathLabels: [String] {
        requiredPaths
            .filter { !$0.isReady }
            .map(\.label)
    }

    static func inspect(url: URL?, fileManager: FileManager = .default) -> VaultSyncReadiness? {
        guard let url else { return nil }

        let requiredDefinitions: [(String, VaultRequiredPathKind)] = [
            ("vault.json", .file),
            ("keys.enc", .file),
            ("items/", .directory),
            ("attachments/", .directory),
            ("tombstones/", .directory)
        ]
        let requiredPaths = requiredDefinitions.map { label, kind in
            let childName = label.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            let childURL = url.appendingPathComponent(childName, isDirectory: kind == .directory)
            var isDirectory: ObjCBool = false
            let exists = fileManager.fileExists(atPath: childURL.path, isDirectory: &isDirectory)
            let hasExpectedKind = exists && (kind == .directory ? isDirectory.boolValue : !isDirectory.boolValue)
            return VaultRequiredPathCheck(
                label: label,
                kind: kind,
                exists: exists,
                hasExpectedKind: hasExpectedKind
            )
        }
        let localUnlockURL = url.appendingPathComponent("local_unlock.enc", isDirectory: false)
        var isDirectory: ObjCBool = false
        let localUnlockEnvelopePresent = fileManager.fileExists(
            atPath: localUnlockURL.path,
            isDirectory: &isDirectory
        ) && !isDirectory.boolValue

        return VaultSyncReadiness(
            locationHint: VaultSyncLocationHint.classify(url: url),
            requiredPaths: requiredPaths,
            localUnlockEnvelopePresent: localUnlockEnvelopePresent
        )
    }
}

enum SavedSecretRevealField: Hashable {
    case loginPassword
    case loginTotpSecret
    case creditCardNumber
    case creditCardVerificationCode
    case softwareLicenseKey
    case credential(String)
}

struct SavedSecretRevealKey: Hashable {
    let itemId: String
    let field: SavedSecretRevealField
}

struct SavedSecretRevealCache: Equatable {
    private(set) var values: [SavedSecretRevealKey: String] = [:]

    mutating func reveal(_ value: String, for key: SavedSecretRevealKey) {
        values[key] = value
    }

    mutating func hide(_ key: SavedSecretRevealKey) {
        values[key] = nil
    }

    mutating func clear(itemId: String) {
        values = values.filter { $0.key.itemId != itemId }
    }

    mutating func clearAll() {
        values.removeAll()
    }

    func value(for key: SavedSecretRevealKey) -> String? {
        values[key]
    }

    func isRevealed(_ key: SavedSecretRevealKey) -> Bool {
        values[key] != nil
    }
}

struct StaleSaveReview: Equatable {
    let itemId: String
    let itemTitle: String
    let itemType: String
    let rows: [StaleSaveReviewRow]

    var hasVisibleRows: Bool {
        !rows.isEmpty
    }
}

struct StaleSaveReviewRow: Equatable, Identifiable {
    let fieldLabel: String
    let currentValue: String?
    let draftValue: String?
    let redacted: Bool

    var id: String { fieldLabel }
}

struct VaultItemView: Identifiable, Decodable, Equatable {
    let id: String
    let revision: String
    let title: String
    let itemType: String
    let templateId: String?
    let secretKinds: [String]
    let status: String
    let conflictId: String?
    let favorite: Bool
    let tags: [String]

    init(
        id: String,
        revision: String = "rev_test",
        title: String,
        itemType: String,
        templateId: String? = nil,
        secretKinds: [String] = [],
        status: String,
        conflictId: String? = nil,
        favorite: Bool,
        tags: [String]
    ) {
        self.id = id
        self.revision = revision
        self.title = title
        self.itemType = itemType
        self.templateId = templateId
        self.secretKinds = secretKinds
        self.status = status
        self.conflictId = conflictId
        self.favorite = favorite
        self.tags = tags
    }

    enum CodingKeys: String, CodingKey {
        case id
        case revision
        case title
        case itemType = "item_type"
        case templateId = "template_id"
        case secretKinds = "secret_kinds"
        case status
        case conflictId = "conflict_id"
        case favorite
        case tags
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        revision = try container.decode(String.self, forKey: .revision)
        title = try container.decode(String.self, forKey: .title)
        itemType = try container.decode(String.self, forKey: .itemType)
        templateId = try container.decodeIfPresent(String.self, forKey: .templateId)
        secretKinds = try container.decodeIfPresent([String].self, forKey: .secretKinds) ?? []
        status = try container.decode(String.self, forKey: .status)
        conflictId = try container.decodeIfPresent(String.self, forKey: .conflictId)
        favorite = try container.decode(Bool.self, forKey: .favorite)
        tags = try container.decode([String].self, forKey: .tags)
    }

    var isConflicted: Bool {
        status == "conflicted" && conflictId != nil
    }

    var isArchived: Bool {
        status == "archived"
    }

    var isLogin: Bool {
        credentialTemplateKind == .login || itemType == "login"
    }

    var isSecureNote: Bool {
        credentialTemplateKind == .secureNote || itemType == "secure note"
    }

    var isCreditCard: Bool {
        credentialTemplateKind == .creditCard || itemType == "credit card"
    }

    var isSoftwareLicense: Bool {
        credentialTemplateKind == .softwareLicense || itemType == "software license"
    }

    var credentialTemplateKind: CredentialTemplateKind? {
        guard let templateId else { return nil }
        return CredentialTemplateKind(rawValue: templateId)
    }

    var isTemplateCredential: Bool {
        credentialTemplateKind?.usesTemplateCredentialForm == true
    }
}

struct LoginDetail: Decodable, Equatable {
    let id: String
    var revision: String
    var title: String
    var username: String?
    var url: String?
    var urls: [String]
    var notes: String?
    var totpSecret: String?
    var favorite: Bool
    var tags: [String]
    var status: String

    init(
        id: String,
        revision: String,
        title: String,
        username: String?,
        url: String?,
        urls: [String]? = nil,
        notes: String?,
        totpSecret: String?,
        favorite: Bool,
        tags: [String],
        status: String
    ) {
        self.id = id
        self.revision = revision
        self.title = title
        self.username = username
        self.url = url
        self.urls = urls ?? url.map { [$0] } ?? []
        self.notes = notes
        self.totpSecret = totpSecret
        self.favorite = favorite
        self.tags = tags
        self.status = status
    }

    enum CodingKeys: String, CodingKey {
        case id
        case revision
        case title
        case username
        case url
        case urls
        case notes
        case totpSecret = "totp_secret"
        case favorite
        case tags
        case status
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let id = try container.decode(String.self, forKey: .id)
        let revision = try container.decode(String.self, forKey: .revision)
        let title = try container.decode(String.self, forKey: .title)
        let username = try container.decodeIfPresent(String.self, forKey: .username)
        let url = try container.decodeIfPresent(String.self, forKey: .url)
        let urls = try container.decodeIfPresent([String].self, forKey: .urls)
        let notes = try container.decodeIfPresent(String.self, forKey: .notes)
        let totpSecret = try container.decodeIfPresent(String.self, forKey: .totpSecret)
        let favorite = try container.decode(Bool.self, forKey: .favorite)
        let tags = try container.decode([String].self, forKey: .tags)
        let status = try container.decode(String.self, forKey: .status)
        self.init(
            id: id,
            revision: revision,
            title: title,
            username: username,
            url: url,
            urls: urls,
            notes: notes,
            totpSecret: totpSecret,
            favorite: favorite,
            tags: tags,
            status: status
        )
    }
}

struct LoginForm: Equatable {
    var revision: String?
    var title: String = ""
    var username: String = ""
    var password: String = ""
    var urlsText: String = ""
    var notes: String = ""
    var totpSecret: String = ""
    var tagsText: String = ""
    var favorite = false
    var clearPasswordOnSave = false

    init() {}

    init(detail: LoginDetail) {
        revision = detail.revision
        title = detail.title
        username = detail.username ?? ""
        urlsText = detail.urls.joined(separator: "\n")
        notes = detail.notes ?? ""
        totpSecret = detail.totpSecret ?? ""
        tagsText = detail.tags.joined(separator: ", ")
        favorite = detail.favorite
    }

    var url: String {
        get { urls.first ?? "" }
        set { urlsText = newValue }
    }

    var urls: [String] {
        Self.normalizedURLs(from: urlsText)
    }

    static func normalizedURLs(from text: String) -> [String] {
        text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    var tags: [String] {
        var seen = Set<String>()
        return tagsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { tag in
                guard !tag.isEmpty else { return false }
                return seen.insert(tag.lowercased()).inserted
            }
    }

    var normalizedTitle: String {
        title.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var totpSecretForSave: String {
        totpSecret.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var passwordForUpdate: String? {
        if let password = password.nilIfEmpty {
            return password
        }
        return clearPasswordOnSave ? "" : nil
    }

    var isValidForSave: Bool {
        !normalizedTitle.isEmpty
    }
}

struct SecureNoteDetail: Decodable, Equatable {
    let id: String
    var revision: String
    var title: String
    var body: String
    var favorite: Bool
    var tags: [String]
    var status: String
}

struct SecureNoteForm: Equatable {
    var revision: String?
    var title: String = ""
    var body: String = ""
    var tagsText: String = ""
    var favorite = false

    init() {}

    init(detail: SecureNoteDetail) {
        revision = detail.revision
        title = detail.title
        body = detail.body
        tagsText = detail.tags.joined(separator: ", ")
        favorite = detail.favorite
    }

    var tags: [String] {
        var seen = Set<String>()
        return tagsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { tag in
                guard !tag.isEmpty else { return false }
                return seen.insert(tag.lowercased()).inserted
            }
    }

    var normalizedTitle: String {
        title.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var isValidForSave: Bool {
        !normalizedTitle.isEmpty
    }
}

struct TemplateCredentialForm: Equatable {
    var template: CredentialTemplateKind = .apiToken
    var title: String = ""
    var secret: String = ""
    var expiry: String = ""
    var notes: String = ""
    var tagsText: String = ""
    var favorite = false

    var tags: [String] {
        deduplicatedTags(from: tagsText)
    }

    var normalizedTitle: String {
        title.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var isValidForSave: Bool {
        template.usesTemplateCredentialForm
            && !normalizedTitle.isEmpty
            && !secret.isEmpty
    }
}

struct CredentialDetail: Decodable, Equatable {
    let id: String
    let revision: String
    let title: String
    let templateId: String?
    let fields: [CredentialDetailField]
    let favorite: Bool
    let tags: [String]
    let status: String

    enum CodingKeys: String, CodingKey {
        case id
        case revision
        case title
        case templateId = "template_id"
        case fields
        case favorite
        case tags
        case status
    }

    var textFields: [CredentialDetailField.TextField] {
        fields.compactMap(\.textField)
    }

    var secretFields: [CredentialDetailField.SecretField] {
        fields.compactMap(\.secretField)
    }
}

enum CredentialDetailField: Decodable, Equatable {
    struct TextField: Equatable, Identifiable {
        let role: String
        let label: String?
        let text: String

        var id: String { "text:\(role):\(label ?? "")" }
    }

    struct SecretField: Equatable, Identifiable {
        let role: String
        let label: String?
        let secretFieldId: String
        let secretKind: String
        let hasValue: Bool

        var id: String { secretFieldId }
    }

    case text(TextField)
    case secret(SecretField)

    private enum CodingKeys: String, CodingKey {
        case valueType = "value_type"
        case role
        case label
        case text
        case secretFieldId = "secret_field_id"
        case secretKind = "secret_kind"
        case hasValue = "has_value"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .valueType) {
        case "text":
            self = .text(TextField(
                role: try container.decode(String.self, forKey: .role),
                label: try container.decodeIfPresent(String.self, forKey: .label),
                text: try container.decode(String.self, forKey: .text)
            ))
        case "secret":
            self = .secret(SecretField(
                role: try container.decode(String.self, forKey: .role),
                label: try container.decodeIfPresent(String.self, forKey: .label),
                secretFieldId: try container.decode(String.self, forKey: .secretFieldId),
                secretKind: try container.decode(String.self, forKey: .secretKind),
                hasValue: try container.decode(Bool.self, forKey: .hasValue)
            ))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .valueType,
                in: container,
                debugDescription: "Unknown credential field value type"
            )
        }
    }

    var textField: TextField? {
        guard case let .text(field) = self else { return nil }
        return field
    }

    var secretField: SecretField? {
        guard case let .secret(field) = self else { return nil }
        return field
    }
}

struct CreditCardDetail: Decodable, Equatable {
    let id: String
    var revision: String
    var title: String
    var cardholderName: String?
    var expiryMonth: Int?
    var expiryYear: Int?
    var notes: String?
    var favorite: Bool
    var tags: [String]
    var status: String

    enum CodingKeys: String, CodingKey {
        case id
        case revision
        case title
        case cardholderName = "cardholder_name"
        case expiryMonth = "expiry_month"
        case expiryYear = "expiry_year"
        case notes
        case favorite
        case tags
        case status
    }
}

struct CreditCardForm: Equatable {
    var revision: String?
    var title: String = ""
    var cardholderName: String = ""
    var number: String = ""
    var expiryMonth: String = ""
    var expiryYear: String = ""
    var verificationCode: String = ""
    var notes: String = ""
    var tagsText: String = ""
    var favorite = false
    var clearNumberOnSave = false
    var clearVerificationCodeOnSave = false

    init() {}

    init(detail: CreditCardDetail) {
        revision = detail.revision
        title = detail.title
        cardholderName = detail.cardholderName ?? ""
        expiryMonth = detail.expiryMonth.map { String(format: "%02d", $0) } ?? ""
        expiryYear = detail.expiryYear.map(String.init) ?? ""
        notes = detail.notes ?? ""
        tagsText = detail.tags.joined(separator: ", ")
        favorite = detail.favorite
    }

    var tags: [String] {
        deduplicatedTags(from: tagsText)
    }

    var normalizedTitle: String {
        title.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var expiryMonthValue: Int? {
        Int(expiryMonth.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    var expiryYearValue: Int? {
        Int(expiryYear.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    var numberForUpdate: String? {
        if let number = number.nilIfEmpty {
            return number
        }
        return clearNumberOnSave ? "" : nil
    }

    var verificationCodeForUpdate: String? {
        if let verificationCode = verificationCode.nilIfEmpty {
            return verificationCode
        }
        return clearVerificationCodeOnSave ? "" : nil
    }

    var isValidForSave: Bool {
        !normalizedTitle.isEmpty
    }
}

struct SoftwareLicenseDetail: Decodable, Equatable {
    let id: String
    var revision: String
    var title: String
    var product: String?
    var licensedTo: String?
    var notes: String?
    var favorite: Bool
    var tags: [String]
    var status: String

    enum CodingKeys: String, CodingKey {
        case id
        case revision
        case title
        case product
        case licensedTo = "licensed_to"
        case notes
        case favorite
        case tags
        case status
    }
}

struct SoftwareLicenseForm: Equatable {
    var revision: String?
    var title: String = ""
    var product: String = ""
    var licenseKey: String = ""
    var licensedTo: String = ""
    var notes: String = ""
    var tagsText: String = ""
    var favorite = false
    var clearLicenseKeyOnSave = false

    init() {}

    init(detail: SoftwareLicenseDetail) {
        revision = detail.revision
        title = detail.title
        product = detail.product ?? ""
        licensedTo = detail.licensedTo ?? ""
        notes = detail.notes ?? ""
        tagsText = detail.tags.joined(separator: ", ")
        favorite = detail.favorite
    }

    var tags: [String] {
        deduplicatedTags(from: tagsText)
    }

    var normalizedTitle: String {
        title.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var licenseKeyForUpdate: String? {
        if let licenseKey = licenseKey.nilIfEmpty {
            return licenseKey
        }
        return clearLicenseKeyOnSave ? "" : nil
    }

    var isValidForSave: Bool {
        !normalizedTitle.isEmpty
    }
}

private func deduplicatedTags(from tagsText: String) -> [String] {
    var seen = Set<String>()
    return tagsText
        .split(separator: ",")
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { tag in
            guard !tag.isEmpty else { return false }
            return seen.insert(tag.lowercased()).inserted
        }
}

struct ConflictCandidateView: Identifiable, Equatable {
    let itemId: String
    let revision: String
    let title: String
    let itemType: String
    let status: String
    let favorite: Bool
    let tags: [String]
    let comparisonFields: [ConflictCandidateField]
    let changedFields: [String]
    let preview: String?
    let templateId: String?
    let credentialFields: [ConflictCandidateCredentialField]
    let fieldShapeChanged: Bool
    let supportsSafeFieldMerge: Bool

    var id: String { revision }

    init(
        itemId: String,
        revision: String,
        title: String,
        itemType: String,
        status: String,
        favorite: Bool,
        tags: [String],
        comparisonFields: [ConflictCandidateField],
        changedFields: [String],
        preview: String?,
        templateId: String? = nil,
        credentialFields: [ConflictCandidateCredentialField] = [],
        fieldShapeChanged: Bool = false,
        supportsSafeFieldMerge: Bool = true
    ) {
        self.itemId = itemId
        self.revision = revision
        self.title = title
        self.itemType = itemType
        self.status = status
        self.favorite = favorite
        self.tags = tags
        self.comparisonFields = comparisonFields
        self.changedFields = changedFields
        self.preview = preview
        self.templateId = templateId
        self.credentialFields = credentialFields
        self.fieldShapeChanged = fieldShapeChanged
        self.supportsSafeFieldMerge = supportsSafeFieldMerge
    }

    enum CodingKeys: String, CodingKey {
        case itemId = "item_id"
        case revision
        case title
        case itemType = "item_type"
        case status
        case favorite
        case tags
        case comparisonFields = "comparison_fields"
        case changedFields = "changed_fields"
        case preview
        case templateId = "template_id"
        case credentialFields = "credential_fields"
        case fieldShapeChanged = "field_shape_changed"
        case supportsSafeFieldMerge = "supports_safe_field_merge"
    }
}

extension ConflictCandidateView: Decodable {
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            itemId: try container.decode(String.self, forKey: .itemId),
            revision: try container.decode(String.self, forKey: .revision),
            title: try container.decode(String.self, forKey: .title),
            itemType: try container.decode(String.self, forKey: .itemType),
            status: try container.decode(String.self, forKey: .status),
            favorite: try container.decode(Bool.self, forKey: .favorite),
            tags: try container.decode([String].self, forKey: .tags),
            comparisonFields: try container.decode([ConflictCandidateField].self, forKey: .comparisonFields),
            changedFields: try container.decode([String].self, forKey: .changedFields),
            preview: try container.decodeIfPresent(String.self, forKey: .preview),
            templateId: try container.decodeIfPresent(String.self, forKey: .templateId),
            credentialFields: try container.decodeIfPresent(
                [ConflictCandidateCredentialField].self,
                forKey: .credentialFields
            ) ?? [],
            fieldShapeChanged: try container.decodeIfPresent(Bool.self, forKey: .fieldShapeChanged) ?? false,
            supportsSafeFieldMerge: try container.decodeIfPresent(
                Bool.self,
                forKey: .supportsSafeFieldMerge
            ) ?? true
        )
    }
}

struct ConflictCandidateField: Decodable, Equatable {
    let label: String
    let value: String?
    let redacted: Bool
}

enum ConflictCandidateCredentialField: Decodable, Equatable, Identifiable {
    struct TextField: Equatable {
        let index: Int
        let role: String
        let label: String?
        let text: String
        let changed: Bool
    }

    struct SecretField: Equatable {
        let index: Int
        let role: String
        let label: String?
        let secretFieldId: String
        let secretKind: String
        let hasValue: Bool
        let changed: Bool
    }

    case text(TextField)
    case secret(SecretField)

    var id: String {
        switch self {
        case let .text(field):
            return "text:\(field.index)"
        case let .secret(field):
            return field.secretFieldId
        }
    }

    var changed: Bool {
        switch self {
        case let .text(field):
            return field.changed
        case let .secret(field):
            return field.changed
        }
    }

    private enum CodingKeys: String, CodingKey {
        case valueType = "value_type"
        case index
        case role
        case label
        case text
        case secretFieldId = "secret_field_id"
        case secretKind = "secret_kind"
        case hasValue = "has_value"
        case changed
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(String.self, forKey: .valueType) {
        case "text":
            self = .text(TextField(
                index: try container.decode(Int.self, forKey: .index),
                role: try container.decode(String.self, forKey: .role),
                label: try container.decodeIfPresent(String.self, forKey: .label),
                text: try container.decode(String.self, forKey: .text),
                changed: try container.decode(Bool.self, forKey: .changed)
            ))
        case "secret":
            self = .secret(SecretField(
                index: try container.decode(Int.self, forKey: .index),
                role: try container.decode(String.self, forKey: .role),
                label: try container.decodeIfPresent(String.self, forKey: .label),
                secretFieldId: try container.decode(String.self, forKey: .secretFieldId),
                secretKind: try container.decode(String.self, forKey: .secretKind),
                hasValue: try container.decode(Bool.self, forKey: .hasValue),
                changed: try container.decode(Bool.self, forKey: .changed)
            ))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .valueType,
                in: container,
                debugDescription: "Unknown conflict credential field value type"
            )
        }
    }
}

struct ConflictMergeFieldSelection: Encodable, Equatable {
    let fieldLabel: String
    let revision: String

    enum CodingKeys: String, CodingKey {
        case fieldLabel = "field_label"
        case revision
    }

    var commandPayload: [String: String] {
        [
            "field_label": fieldLabel,
            "revision": revision
        ]
    }
}
