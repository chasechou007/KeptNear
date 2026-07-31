import Foundation

enum VaultSmartView: String, CaseIterable, Hashable, Identifiable {
    case logins
    case developerCredentials
    case keysAndCertificates
    case appsToolsAuthorized

    var id: String { rawValue }
}

enum VaultNavigationDestination: Hashable {
    case allItems
    case favorites
    case appsAndTools
    case smartView(VaultSmartView)
    case security
    case conflicts
    case archive
    case itemType(String)
    case tag(String)

    var isItemDestination: Bool {
        self != .security && self != .appsAndTools
    }
}

struct VaultNavigationCount: Equatable, Identifiable {
    let value: String
    let count: Int

    var id: String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}

struct VaultNavigationCounts: Equatable {
    private static let preferredItemTypeOrder = [
        "login",
        "secure note",
        "credit card",
        "software license"
    ]

    let allItems: Int
    let favorites: Int
    let logins: Int
    let developerCredentials: Int
    let keysAndCertificates: Int
    let appsToolsAuthorized: Int
    let security: Int
    let conflicts: Int
    let archived: Int
    let itemTypes: [VaultNavigationCount]
    let tags: [VaultNavigationCount]

    static let empty = VaultNavigationCounts(
        items: [],
        passwordHealth: nil,
        authorizedCredentialIds: []
    )

    init(
        items: [VaultItemView],
        passwordHealth: PasswordHealthPayload?,
        authorizedCredentialIds: Set<String> = []
    ) {
        let activeItems = items.filter { !$0.isArchived }
        allItems = activeItems.count
        favorites = activeItems.filter(\.favorite).count
        logins = activeItems.filter {
            $0.appears(in: .logins, authorizedCredentialIds: authorizedCredentialIds)
        }.count
        developerCredentials = activeItems.filter {
            $0.appears(in: .developerCredentials, authorizedCredentialIds: authorizedCredentialIds)
        }.count
        keysAndCertificates = activeItems.filter {
            $0.appears(in: .keysAndCertificates, authorizedCredentialIds: authorizedCredentialIds)
        }.count
        appsToolsAuthorized = activeItems.filter {
            $0.appears(in: .appsToolsAuthorized, authorizedCredentialIds: authorizedCredentialIds)
        }.count
        conflicts = activeItems.filter(\.isConflicted).count
        archived = items.filter(\.isArchived).count
        security = Set(passwordHealth?.issues.map(\.itemId) ?? []).count
        itemTypes = Self.counts(
            values: activeItems.map(\.itemType),
            preferredOrder: Self.preferredItemTypeOrder
        )
        tags = Self.counts(values: activeItems.flatMap(\.tags))
    }

    func count(for destination: VaultNavigationDestination) -> Int {
        switch destination {
        case .allItems:
            return allItems
        case .favorites:
            return favorites
        case .appsAndTools:
            return appsToolsAuthorized
        case let .smartView(smartView):
            switch smartView {
            case .logins:
                return logins
            case .developerCredentials:
                return developerCredentials
            case .keysAndCertificates:
                return keysAndCertificates
            case .appsToolsAuthorized:
                return appsToolsAuthorized
            }
        case .security:
            return security
        case .conflicts:
            return conflicts
        case .archive:
            return archived
        case let .itemType(itemType):
            return Self.count(itemType, in: itemTypes)
        case let .tag(tag):
            return Self.count(tag, in: tags)
        }
    }

    private static func counts(
        values: [String],
        preferredOrder: [String] = []
    ) -> [VaultNavigationCount] {
        var displayValues: [String: String] = [:]
        var counts: [String: Int] = [:]

        for value in values {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let normalized = trimmed.lowercased()
            displayValues[normalized] = displayValues[normalized] ?? trimmed
            counts[normalized, default: 0] += 1
        }

        return counts.compactMap { normalized, count in
            displayValues[normalized].map { VaultNavigationCount(value: $0, count: count) }
        }
        .sorted { lhs, rhs in
            let lhsNormalized = lhs.value.lowercased()
            let rhsNormalized = rhs.value.lowercased()
            let lhsIndex = preferredOrder.firstIndex(of: lhsNormalized)
            let rhsIndex = preferredOrder.firstIndex(of: rhsNormalized)
            switch (lhsIndex, rhsIndex) {
            case let (lhsIndex?, rhsIndex?):
                return lhsIndex < rhsIndex
            case (_?, nil):
                return true
            case (nil, _?):
                return false
            case (nil, nil):
                return lhs.value.localizedCaseInsensitiveCompare(rhs.value) == .orderedAscending
            }
        }
    }

    private static func count(
        _ value: String,
        in counts: [VaultNavigationCount]
    ) -> Int {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return counts.first { $0.id == normalized }?.count ?? 0
    }
}

extension VaultItemView {
    func appears(
        in smartView: VaultSmartView,
        authorizedCredentialIds: Set<String>
    ) -> Bool {
        let normalizedSecretKinds = Set(secretKinds.map(Self.normalizeSmartViewValue))
        let normalizedItemType = Self.normalizeSmartViewValue(itemType)
        switch smartView {
        case .logins:
            return normalizedSecretKinds.contains("password")
                || credentialTemplateKind == .login
                || normalizedItemType == "login"
        case .developerCredentials:
            return !normalizedSecretKinds.isDisjoint(with: [
                "api-token",
                "api-key",
                "private-key",
                "certificate"
            ])
                || credentialTemplateKind.map {
                    [.apiToken, .apiKey, .sshKey, .certificate].contains($0)
                } == true
                || ["api token", "api key", "ssh key", "certificate"].contains(normalizedItemType)
        case .keysAndCertificates:
            return !normalizedSecretKinds.isDisjoint(with: ["private-key", "certificate"])
                || credentialTemplateKind.map {
                    [.sshKey, .certificate].contains($0)
                } == true
                || ["ssh key", "certificate"].contains(normalizedItemType)
        case .appsToolsAuthorized:
            return authorizedCredentialIds.contains(id)
        }
    }

    private static func normalizeSmartViewValue(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
