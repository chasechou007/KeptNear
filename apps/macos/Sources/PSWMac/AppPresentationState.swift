enum AppPresentationState: Equatable {
    case welcome
    case locked
    case unlocked

    init(hasSelectedVault: Bool, isUnlocked: Bool) {
        guard hasSelectedVault else {
            self = .welcome
            return
        }

        self = isUnlocked ? .unlocked : .locked
    }
}
