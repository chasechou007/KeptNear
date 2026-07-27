import Foundation

enum VaultDetailMode: Equatable {
    case empty
    case readOnly
    case editing
    case creating

    init(hasSelection: Bool, isEditing: Bool, isCreating: Bool) {
        if isCreating {
            self = .creating
        } else if hasSelection, isEditing {
            self = .editing
        } else if hasSelection {
            self = .readOnly
        } else {
            self = .empty
        }
    }
}

struct VaultItemDetailModel: Equatable {
    struct Login: Equatable {
        let username: String?
        let urls: [String]
        let notes: String?
        let hasTotpSecret: Bool
    }

    struct SecureNote: Equatable {
        let body: String
    }

    struct CreditCard: Equatable {
        let cardholderName: String?
        let expiration: String?
        let notes: String?
    }

    struct SoftwareLicense: Equatable {
        let product: String?
        let licensedTo: String?
        let notes: String?
    }

    enum Content: Equatable {
        case login(Login)
        case secureNote(SecureNote)
        case creditCard(CreditCard)
        case softwareLicense(SoftwareLicense)
    }

    let item: VaultItemView
    let content: Content

    init?(
        item: VaultItemView,
        login: LoginDetail?,
        secureNote: SecureNoteDetail?,
        creditCard: CreditCardDetail?,
        softwareLicense: SoftwareLicenseDetail?
    ) {
        if item.isLogin, let login, login.id == item.id {
            content = .login(Login(
                username: login.username,
                urls: login.urls,
                notes: login.notes,
                hasTotpSecret: Self.hasContent(login.totpSecret)
            ))
        } else if item.isSecureNote, let secureNote, secureNote.id == item.id {
            content = .secureNote(SecureNote(body: secureNote.body))
        } else if item.isCreditCard, let creditCard, creditCard.id == item.id {
            content = .creditCard(CreditCard(
                cardholderName: creditCard.cardholderName,
                expiration: Self.expiration(month: creditCard.expiryMonth, year: creditCard.expiryYear),
                notes: creditCard.notes
            ))
        } else if item.isSoftwareLicense, let softwareLicense, softwareLicense.id == item.id {
            content = .softwareLicense(SoftwareLicense(
                product: softwareLicense.product,
                licensedTo: softwareLicense.licensedTo,
                notes: softwareLicense.notes
            ))
        } else {
            return nil
        }

        self.item = item
    }

    private static func hasContent(_ value: String?) -> Bool {
        value?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }

    private static func expiration(month: Int?, year: Int?) -> String? {
        let values = [
            month.map { String(format: "%02d", $0) },
            year.map(String.init)
        ].compactMap { $0 }
        return values.isEmpty ? nil : values.joined(separator: " / ")
    }
}

enum VaultItemDetailCopyAction: Equatable {
    case username
    case password
    case totp
    case url(String)
    case secureNoteBody
    case cardNumber
    case cardVerificationCode
    case licenseKey
}

enum VaultItemDetailMoreAction: Equatable {
    case toggleFavorite
    case duplicate
    case resolveConflict
    case restoreArchive
    case archive
    case delete
}

struct VaultItemDetailCapabilities: Equatable {
    let canEdit: Bool
    let canCopyLoginFields: Bool
    let canCopyTotp: Bool
    let canOpenURL: Bool
    let canCopySecureNoteBody: Bool
    let canCopyCreditCardFields: Bool
    let canCopySoftwareLicenseFields: Bool
    let canRevealSecrets: Bool
    let canToggleFavorite: Bool
    let canDuplicate: Bool
    let canResolveConflict: Bool
    let canRestoreArchive: Bool
    let canArchive: Bool
    let canDelete: Bool

    func canCopy(_ action: VaultItemDetailCopyAction) -> Bool {
        switch action {
        case .username, .password, .url:
            return canCopyLoginFields
        case .totp:
            return canCopyTotp
        case .secureNoteBody:
            return canCopySecureNoteBody
        case .cardNumber, .cardVerificationCode:
            return canCopyCreditCardFields
        case .licenseKey:
            return canCopySoftwareLicenseFields
        }
    }
}

struct VaultItemDetailActions {
    let edit: () -> Void
    let copy: (VaultItemDetailCopyAction) -> Void
    let openURL: (String) -> Void
    let revealedSecret: (SavedSecretRevealField) -> String?
    let revealSecret: (SavedSecretRevealField) -> Void
    let hideSecret: (SavedSecretRevealField) -> Void
    let performMoreAction: (VaultItemDetailMoreAction) -> Void
}
