import SwiftUI

enum DestructiveAction: Equatable {
    case archive
    case delete
}

enum ItemListRowAction: String, CaseIterable, Identifiable, Equatable {
    case copyUsername
    case copyPassword
    case copyTotp
    case openURL
    case copyBody
    case copyCardNumber
    case copyVerificationCode
    case copyLicenseKey
    case favorite
    case duplicate
    case resolveConflict
    case restoreArchive
    case archive
    case delete

    var id: String { rawValue }

    var isDestructive: Bool {
        self == .archive || self == .delete
    }

    var destructiveAction: DestructiveAction? {
        switch self {
        case .archive:
            return .archive
        case .delete:
            return .delete
        default:
            return nil
        }
    }

    var buttonRole: ButtonRole? {
        self == .delete ? .destructive : nil
    }

    static func actions(for item: VaultItemView) -> [ItemListRowAction] {
        if item.isConflicted {
            return [.resolveConflict]
        }

        var actions = itemTypeActions(for: item)
        actions.append(.favorite)
        actions.append(.duplicate)
        actions.append(item.isArchived ? .restoreArchive : .archive)
        actions.append(.delete)
        return actions
    }

    func title(text: AppText, item: VaultItemView) -> String {
        switch self {
        case .copyUsername:
            return text.copyUsername
        case .copyPassword:
            return text.copyPassword
        case .copyTotp:
            return text.copyTotp
        case .openURL:
            return text.openURL
        case .copyBody:
            return text.copyBody
        case .copyCardNumber:
            return text.copyCardNumber
        case .copyVerificationCode:
            return text.copyVerificationCode
        case .copyLicenseKey:
            return text.copyLicenseKey
        case .favorite:
            return item.favorite ? text.unfavorite : text.favorite
        case .duplicate:
            return text.duplicate
        case .resolveConflict:
            return text.resolveConflict
        case .restoreArchive:
            return text.restore
        case .archive:
            return text.archive
        case .delete:
            return text.delete
        }
    }

    func systemImage(item: VaultItemView) -> String {
        switch self {
        case .copyUsername:
            return "person.crop.circle"
        case .copyPassword:
            return "key"
        case .copyTotp:
            return "timer"
        case .openURL:
            return "safari"
        case .copyBody:
            return "doc.on.doc"
        case .copyCardNumber:
            return "creditcard"
        case .copyVerificationCode:
            return "number"
        case .copyLicenseKey:
            return "seal"
        case .favorite:
            return item.favorite ? "star.slash" : "star"
        case .duplicate:
            return "plus.square.on.square"
        case .resolveConflict:
            return "checkmark.seal"
        case .restoreArchive:
            return "arrow.uturn.backward"
        case .archive:
            return "archivebox"
        case .delete:
            return "trash"
        }
    }

    private static func itemTypeActions(for item: VaultItemView) -> [ItemListRowAction] {
        if item.isLogin {
            return [.copyUsername, .copyPassword, .copyTotp, .openURL]
        }
        if item.isSecureNote {
            return [.copyBody]
        }
        if item.isCreditCard {
            return [.copyCardNumber, .copyVerificationCode]
        }
        if item.isSoftwareLicense {
            return [.copyLicenseKey]
        }
        return []
    }
}
