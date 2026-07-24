import SwiftUI

struct MasterPasswordStrengthView: View {
    let password: String
    let text: AppText

    private var strength: MasterPasswordStrength {
        MasterPasswordStrength.evaluate(password)
    }

    var body: some View {
        if strength.level != .empty {
            VStack(alignment: .leading, spacing: 4) {
                Label(text.masterPasswordStrengthLabel(strength), systemImage: "shield.lefthalf.filled")
                    .font(.caption)
                    .foregroundStyle(tint)
                ProgressView(
                    value: Double(strength.level.rawValue),
                    total: Double(MasterPasswordStrengthLevel.veryStrong.rawValue)
                )
                .tint(tint)
                Text(text.masterPasswordStrengthHint(strength))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var tint: Color {
        switch strength.level {
        case .empty:
            return .secondary
        case .weak:
            return .red
        case .fair:
            return .orange
        case .strong:
            return .blue
        case .veryStrong:
            return .green
        }
    }
}
