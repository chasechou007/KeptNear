import Foundation

enum CredentialEditorFieldType: Equatable {
    case text
    case existingSecret
    case newSecret
}

enum CredentialSecretKind: String, CaseIterable, Identifiable {
    case password
    case apiToken = "api-token"
    case apiKey = "api-key"
    case totpSeed = "totp-seed"
    case privateKey = "private-key"
    case certificate
    case genericSecret = "generic-secret"

    var id: String { rawValue }
}

struct CredentialEditorField: Equatable, Identifiable {
    let id: UUID
    var fieldType: CredentialEditorFieldType
    var role: String
    var label: String
    var text: String
    var secretFieldId: String?
    var secretKind: String
    var secretInput: String
    var hasSavedSecret: Bool

    init(
        id: UUID = UUID(),
        fieldType: CredentialEditorFieldType,
        role: String,
        label: String = "",
        text: String = "",
        secretFieldId: String? = nil,
        secretKind: String = CredentialSecretKind.genericSecret.rawValue,
        secretInput: String = "",
        hasSavedSecret: Bool = false
    ) {
        self.id = id
        self.fieldType = fieldType
        self.role = role
        self.label = label
        self.text = text
        self.secretFieldId = secretFieldId
        self.secretKind = secretKind
        self.secretInput = secretInput
        self.hasSavedSecret = hasSavedSecret
    }

    static func text(role: String = "text") -> CredentialEditorField {
        CredentialEditorField(fieldType: .text, role: role)
    }

    static func newSecret(role: String = "secret") -> CredentialEditorField {
        CredentialEditorField(fieldType: .newSecret, role: role)
    }

    var normalizedRole: String {
        role.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var normalizedLabel: String? {
        let value = label.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    var isSecret: Bool {
        fieldType != .text
    }

    var isValidForSave: Bool {
        guard !normalizedRole.isEmpty else { return false }
        if fieldType == .newSecret {
            return !secretInput.isEmpty && CredentialSecretKind(rawValue: secretKind) != nil
        }
        if fieldType == .existingSecret {
            return secretFieldId?.isEmpty == false
        }
        return true
    }
}

struct CredentialEditorForm: Equatable {
    var revision: String?
    var title: String = ""
    var templateId: String?
    var fields: [CredentialEditorField] = []
    var tagsText: String = ""
    var favorite = false

    init() {}

    init(detail: CredentialDetail) {
        revision = detail.revision
        title = detail.title
        templateId = detail.templateId
        fields = detail.fields.map { field in
            switch field {
            case let .text(field):
                return CredentialEditorField(
                    fieldType: .text,
                    role: field.role,
                    label: field.label ?? "",
                    text: field.text
                )
            case let .secret(field):
                return CredentialEditorField(
                    fieldType: .existingSecret,
                    role: field.role,
                    label: field.label ?? "",
                    secretFieldId: field.secretFieldId,
                    secretKind: field.secretKind,
                    hasSavedSecret: field.hasValue
                )
            }
        }
        tagsText = detail.tags.joined(separator: ", ")
        favorite = detail.favorite
    }

    var normalizedTitle: String {
        title.trimmingCharacters(in: .whitespacesAndNewlines)
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

    var isValidForSave: Bool {
        !normalizedTitle.isEmpty
            && fields.allSatisfy(\.isValidForSave)
            && Set(fields.compactMap(\.secretFieldId)).count
                == fields.compactMap(\.secretFieldId).count
    }

    mutating func addTextField() {
        fields.append(.text())
    }

    mutating func addSecretField() {
        fields.append(.newSecret())
    }

    mutating func removeField(id: UUID) {
        fields.removeAll { $0.id == id }
    }

    mutating func moveField(id: UUID, offset: Int) {
        guard let source = fields.firstIndex(where: { $0.id == id }) else { return }
        let destination = source + offset
        guard fields.indices.contains(destination) else { return }
        fields.swapAt(source, destination)
    }
}
