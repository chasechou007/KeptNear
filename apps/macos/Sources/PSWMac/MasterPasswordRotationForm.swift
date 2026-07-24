import Foundation

struct MasterPasswordRotationForm: Equatable {
    var currentPassword = ""
    var newPassword = ""
    var confirmation = ""

    var isEmpty: Bool {
        currentPassword.isEmpty && newPassword.isEmpty && confirmation.isEmpty
    }

    mutating func clear() {
        currentPassword = ""
        newPassword = ""
        confirmation = ""
    }
}
