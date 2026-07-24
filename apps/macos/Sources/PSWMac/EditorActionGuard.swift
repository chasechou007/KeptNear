import Foundation

enum EditorGuardedAction: Equatable {
    case editorNavigation
    case createVault
    case manualSyncRefresh
    case importCommit
    case backupVault
    case restoreBackup
    case copyVaultToSyncLocation
    case syncRecovery
    case destructiveItemMutation
}

struct EditorActionGuard: Equatable {
    static func shouldConfirmDiscard(
        before action: EditorGuardedAction,
        drafts: EditorDraftState,
        isUnlocked: Bool,
        activeKind: ItemEditorKind
    ) -> Bool {
        switch action {
        case .editorNavigation, .createVault, .manualSyncRefresh, .importCommit, .backupVault, .restoreBackup, .copyVaultToSyncLocation, .syncRecovery, .destructiveItemMutation:
            return drafts.hasUnsavedChanges(isUnlocked: isUnlocked, activeKind: activeKind)
        }
    }
}
