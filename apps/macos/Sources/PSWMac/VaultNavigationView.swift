import SwiftUI

struct VaultNavigationList: View {
    let text: AppText
    let counts: VaultNavigationCounts
    let hasPasswordHealthResult: Bool
    @Binding var selection: VaultNavigationDestination?

    var body: some View {
        List(selection: $selection) {
            Section {
                navigationRow(
                    text.allItems,
                    systemImage: "square.grid.2x2",
                    count: counts.allItems,
                    destination: .allItems
                )
                navigationRow(
                    text.favoritesFilter,
                    systemImage: "star",
                    count: counts.favorites,
                    destination: .favorites
                )
                navigationRow(
                    text.security,
                    systemImage: "checkmark.shield",
                    count: hasPasswordHealthResult ? counts.security : nil,
                    destination: .security,
                    emphasized: counts.security > 0
                )
                navigationRow(
                    text.conflictsFilter,
                    systemImage: "arrow.triangle.2.circlepath",
                    count: counts.conflicts,
                    destination: .conflicts,
                    emphasized: counts.conflicts > 0
                )
                navigationRow(
                    text.archive,
                    systemImage: "archivebox",
                    count: counts.archived,
                    destination: .archive
                )
            }

            if !counts.itemTypes.isEmpty {
                Section(text.categories) {
                    ForEach(counts.itemTypes) { itemType in
                        navigationRow(
                            text.itemTypeName(itemType.value),
                            systemImage: Self.itemTypeIcon(itemType.value),
                            count: itemType.count,
                            destination: .itemType(itemType.value)
                        )
                    }
                }
            }

            if !counts.tags.isEmpty {
                Section(text.tags) {
                    ForEach(counts.tags) { tag in
                        navigationRow(
                            tag.value,
                            systemImage: "tag",
                            count: tag.count,
                            destination: .tag(tag.value)
                        )
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    private func navigationRow(
        _ title: String,
        systemImage: String,
        count: Int?,
        destination: VaultNavigationDestination,
        emphasized: Bool = false
    ) -> some View {
        HStack(spacing: 9) {
            Image(systemName: systemImage)
                .foregroundStyle(emphasized ? Color.orange : Color.secondary)
                .frame(width: 17)
            Text(title)
                .lineLimit(1)
            Spacer(minLength: 8)
            if let count {
                Text("\(count)")
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundStyle(emphasized ? Color.orange : Color.secondary)
            }
        }
        .contentShape(Rectangle())
        .tag(destination)
    }

    static func itemTypeIcon(_ itemType: String) -> String {
        switch itemType.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "login":
            return "person.crop.circle"
        case "secure note":
            return "note.text"
        case "credit card":
            return "creditcard"
        case "software license":
            return "shippingbox"
        default:
            return "doc"
        }
    }
}

struct VaultItemSummaryRow: View {
    let item: VaultItemView
    let text: AppText

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(iconColor.opacity(0.12))
                Image(systemName: VaultNavigationList.itemTypeIcon(item.itemType))
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(iconColor)
            }
            .frame(width: 30, height: 30)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                    .fontWeight(.medium)
                    .lineLimit(1)
                Text(rowSubtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 6)

            if item.favorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundStyle(.yellow)
                    .accessibilityLabel(text.favoritesFilter)
            }
        }
        .frame(minHeight: 38)
        .contentShape(Rectangle())
    }

    private var iconColor: Color {
        item.isConflicted ? .orange : .accentColor
    }

    private var rowSubtitle: String {
        let itemType = text.itemTypeName(item.itemType)
        guard item.status != "active" else { return itemType }
        let status = text.itemStatus(item.status)
        return status.isEmpty ? itemType : "\(itemType), \(status)"
    }
}
