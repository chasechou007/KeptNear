import Foundation

enum ItemEditorKind: Equatable, CaseIterable {
    case login
    case secureNote
    case creditCard
    case softwareLicense
}

struct EditorDraftState: Equatable {
    var login: LoginForm = LoginForm()
    var baselineLogin: LoginForm = LoginForm()
    var secureNote: SecureNoteForm = SecureNoteForm()
    var baselineSecureNote: SecureNoteForm = SecureNoteForm()
    var creditCard: CreditCardForm = CreditCardForm()
    var baselineCreditCard: CreditCardForm = CreditCardForm()
    var softwareLicense: SoftwareLicenseForm = SoftwareLicenseForm()
    var baselineSoftwareLicense: SoftwareLicenseForm = SoftwareLicenseForm()

    func hasUnsavedChanges(isUnlocked: Bool, activeKind: ItemEditorKind) -> Bool {
        guard isUnlocked else { return false }
        switch activeKind {
        case .login:
            return login != baselineLogin
        case .secureNote:
            return secureNote != baselineSecureNote
        case .creditCard:
            return creditCard != baselineCreditCard
        case .softwareLicense:
            return softwareLicense != baselineSoftwareLicense
        }
    }
}
