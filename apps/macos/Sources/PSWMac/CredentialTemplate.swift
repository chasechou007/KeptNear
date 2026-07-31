import Foundation

enum CredentialTemplateKind: String, CaseIterable, Identifiable {
    case login
    case apiToken = "api-token"
    case apiKey = "api-key"
    case sshKey = "ssh-key"
    case certificate
    case secureNote = "secure-note"
    case custom
    case creditCard = "credit-card"
    case softwareLicense = "software-license"

    static let requiredTemplates: [CredentialTemplateKind] = [
        .login,
        .apiToken,
        .apiKey,
        .sshKey,
        .certificate,
        .secureNote,
        .custom
    ]

    static let credentialTemplates: [CredentialTemplateKind] = [
        .login,
        .apiToken,
        .apiKey,
        .sshKey,
        .certificate,
        .custom
    ]

    static let personalRecordTemplates: [CredentialTemplateKind] = [
        .secureNote,
        .creditCard,
        .softwareLicense
    ]

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
        case .apiToken, .apiKey, .sshKey, .certificate, .custom:
            return .templateCredential
        }
    }

    var systemImage: String {
        switch self {
        case .login:
            return "person.badge.key"
        case .apiToken:
            return "ticket"
        case .apiKey:
            return "key.horizontal"
        case .sshKey:
            return "terminal"
        case .certificate:
            return "checkmark.seal"
        case .secureNote:
            return "note.text"
        case .custom:
            return "slider.horizontal.3"
        case .creditCard:
            return "creditcard"
        case .softwareLicense:
            return "shippingbox"
        }
    }

    var usesTemplateCredentialForm: Bool {
        switch self {
        case .apiToken, .apiKey, .sshKey, .certificate, .custom:
            return true
        case .login, .secureNote, .creditCard, .softwareLicense:
            return false
        }
    }

    var supportsExpiry: Bool {
        self == .apiToken || self == .apiKey || self == .certificate
    }

    var primarySecretKind: String? {
        switch self {
        case .apiToken:
            return "api-token"
        case .apiKey:
            return "api-key"
        case .sshKey:
            return "private-key"
        case .certificate:
            return "certificate"
        case .custom:
            return "generic-secret"
        case .login, .secureNote, .creditCard, .softwareLicense:
            return nil
        }
    }
}
