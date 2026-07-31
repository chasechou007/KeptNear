import SwiftUI

enum AppsToolsCompatibilityDisclosurePolicy {
    static func requiresDisclosure(capability: String?) -> Bool {
        capability == "process.run"
    }
}

struct AppsToolsCompatibilityDisclosure: View {
    let text: AppText
    var compact = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .frame(width: 18)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text(text.processCompatibilityTitle)
                    .font(compact ? .caption.weight(.semibold) : .callout.weight(.semibold))
                Text(text.processCompatibilityDisclosure)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(compact ? 10 : 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.09))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .accessibilityElement(children: .combine)
    }
}
