import SwiftUI

struct VaultNavigationList: View {
    let text: AppText
    let counts: VaultNavigationCounts
    let hasPasswordHealthResult: Bool
    let pendingRequestCount: Int
    @Binding var selection: VaultNavigationDestination?

    var body: some View {
        List(selection: $selection) {
            Section(text.browse) {
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
            }

            Section {
                navigationRow(
                    text.appsAndTools,
                    systemImage: "cpu",
                    count: pendingRequestCount > 0 ? nil : counts.appsToolsAuthorized,
                    destination: .appsAndTools,
                    attentionCount: pendingRequestCount
                )
            }

            Section(text.smartViews) {
                navigationRow(
                    text.loginsSmartView,
                    systemImage: "person.badge.key",
                    count: counts.logins,
                    destination: .smartView(.logins)
                )
                navigationRow(
                    text.developerCredentialsSmartView,
                    systemImage: "chevron.left.forwardslash.chevron.right",
                    count: counts.developerCredentials,
                    destination: .smartView(.developerCredentials)
                )
                navigationRow(
                    text.keysAndCertificatesSmartView,
                    systemImage: "key.horizontal",
                    count: counts.keysAndCertificates,
                    destination: .smartView(.keysAndCertificates)
                )
            }

            if !counts.itemTypes.isEmpty {
                Section(text.itemTypes) {
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

            Section(text.securityAndMaintenance) {
                navigationRow(
                    text.security,
                    systemImage: "checkmark.shield",
                    count: hasPasswordHealthResult ? counts.security : nil,
                    destination: .security,
                    emphasized: counts.security > 0
                )
                navigationRow(
                    text.conflictsFilter,
                    systemImage: "exclamationmark.triangle",
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
        emphasized: Bool = false,
        attentionCount: Int = 0
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
            if attentionCount > 0 {
                Text(attentionCount > 99 ? "99+" : "\(attentionCount)")
                    .font(.caption2)
                    .fontWeight(.semibold)
                    .monospacedDigit()
                    .foregroundStyle(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.red, in: Capsule())
            }
        }
        .contentShape(Rectangle())
        .tag(destination)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(title)
        .accessibilityValue(
            attentionCount > 0
                ? text.pendingRequestCount(attentionCount)
                : count.map { text.itemCount($0) } ?? ""
        )
    }

    static func itemTypeIcon(_ itemType: String) -> String {
        switch itemType.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "login":
            return "person.crop.circle"
        case "api token":
            return "ticket"
        case "api key":
            return "key.horizontal"
        case "ssh key":
            return "terminal"
        case "certificate":
            return "checkmark.seal"
        case "custom":
            return "slider.horizontal.3"
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
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(iconColor)
            }
            .frame(width: 34, height: 34)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                    .fontWeight(.medium)
                    .lineLimit(1)
                Text(Self.subtitle(for: item, text: text))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 6)

            if item.isConflicted {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .accessibilityLabel(text.conflictsFilter)
            }

            if item.favorite {
                Image(systemName: "star.fill")
                    .font(.caption)
                    .foregroundStyle(.yellow)
                    .accessibilityLabel(text.favoritesFilter)
            }
        }
        .frame(minHeight: 56)
        .contentShape(Rectangle())
    }

    private var iconColor: Color {
        item.isConflicted ? .orange : .accentColor
    }

    static func subtitle(for item: VaultItemView, text: AppText) -> String {
        let itemType = text.itemTypeName(item.itemType)
        if item.status != "active" {
            let status = text.itemStatus(item.status)
            return status.isEmpty ? itemType : "\(itemType) · \(status)"
        }

        let tags = item.tags
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .prefix(2)

        return ([itemType] + tags).joined(separator: " · ")
    }
}

enum VaultSidebarStatusKind {
    case ready
    case attention
    case waiting

    var systemImage: String {
        switch self {
        case .ready:
            return "checkmark.circle.fill"
        case .attention:
            return "exclamationmark.triangle.fill"
        case .waiting:
            return "pause.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .ready:
            return KeptNearBrand.primary
        case .attention:
            return .orange
        case .waiting:
            return .secondary
        }
    }
}

struct VaultSidebarFooter: View {
    let title: String
    let detail: String
    let kind: VaultSidebarStatusKind
    let refreshLabel: String
    let isRefreshDisabled: Bool
    let showStatus: () -> Void
    let refresh: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Button(action: showStatus) {
                HStack(spacing: 8) {
                    Image(systemName: kind.systemImage)
                        .foregroundStyle(kind.color)
                        .accessibilityHidden(true)

                    VStack(alignment: .leading, spacing: 1) {
                        Text(title)
                            .font(.caption)
                            .fontWeight(.medium)
                            .lineLimit(1)
                        Text(detail)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(title)

            Spacer(minLength: 4)

            Button(action: refresh) {
                Label(refreshLabel, systemImage: "arrow.clockwise")
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help(refreshLabel)
            .disabled(isRefreshDisabled)
        }
        .padding(.horizontal, 12)
        .frame(minHeight: 48)
        .accessibilityElement(children: .contain)
    }
}
