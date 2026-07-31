import SwiftUI

struct VaultItemListPane<ContextMenuContent: View>: View {
    let text: AppText
    let destination: VaultNavigationDestination
    let items: [VaultItemView]
    let navigationCounts: VaultNavigationCounts
    @Binding var selection: String?
    @Binding var searchText: String
    let searchFocus: FocusState<Bool>.Binding
    let hasActiveListFilters: Bool
    let statusMessage: String
    let statusIsError: Bool
    let serviceIsAvailable: Bool
    let search: () -> Void
    let clearFilters: () -> Void
    let createItem: () -> Void
    let navigate: (VaultNavigationDestination) -> Void
    private let contextMenuContent: (VaultItemView) -> ContextMenuContent

    init(
        text: AppText,
        destination: VaultNavigationDestination,
        items: [VaultItemView],
        navigationCounts: VaultNavigationCounts,
        selection: Binding<String?>,
        searchText: Binding<String>,
        searchFocus: FocusState<Bool>.Binding,
        hasActiveListFilters: Bool,
        statusMessage: String,
        statusIsError: Bool,
        serviceIsAvailable: Bool,
        search: @escaping () -> Void,
        clearFilters: @escaping () -> Void,
        createItem: @escaping () -> Void,
        navigate: @escaping (VaultNavigationDestination) -> Void,
        @ViewBuilder contextMenuContent: @escaping (VaultItemView) -> ContextMenuContent
    ) {
        self.text = text
        self.destination = destination
        self.items = items
        self.navigationCounts = navigationCounts
        _selection = selection
        _searchText = searchText
        self.searchFocus = searchFocus
        self.hasActiveListFilters = hasActiveListFilters
        self.statusMessage = statusMessage
        self.statusIsError = statusIsError
        self.serviceIsAvailable = serviceIsAvailable
        self.search = search
        self.clearFilters = clearFilters
        self.createItem = createItem
        self.navigate = navigate
        self.contextMenuContent = contextMenuContent
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if items.isEmpty {
                emptyState
            } else {
                List(selection: $selection) {
                    ForEach(items) { item in
                        VaultItemSummaryRow(item: item, text: text)
                            .tag(item.id)
                            .contextMenu {
                                contextMenuContent(item)
                            }
                    }
                }
                .listStyle(.inset)
            }

            Divider()
            statusBar
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(text.navigationTitle(destination))
                    .font(.headline)
                    .lineLimit(1)
                Spacer()
                Text(text.itemCount(items.count))
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            HStack(spacing: 7) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField(text.search, text: $searchText)
                    .textFieldStyle(.plain)
                    .focused(searchFocus)
                    .onSubmit(search)
                    .onChange(of: searchText) { _ in search() }
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                        search()
                    } label: {
                        Label(text.clearFilters, systemImage: "xmark.circle.fill")
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .help(text.clearFilters)
                }
            }
            .padding(.horizontal, 9)
            .frame(height: 30)
            .background(
                Color.secondary.opacity(0.09),
                in: RoundedRectangle(cornerRadius: 6, style: .continuous)
            )

            if showsCollectionFilters {
                collectionFilters
            }
        }
        .padding(12)
    }

    private var collectionFilters: some View {
        HStack(spacing: 8) {
            typeMenu

            if !navigationCounts.tags.isEmpty {
                tagMenu
            }

            Spacer(minLength: 4)

            if selectedType != nil || selectedTag != nil {
                Button {
                    clearFilters()
                } label: {
                    Label(text.clearFilters, systemImage: "xmark.circle")
                }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .help(text.clearFilters)
            }
        }
        .controlSize(.small)
    }

    private var typeMenu: some View {
        Menu {
            Button {
                if selectedType != nil {
                    navigate(.allItems)
                }
            } label: {
                Label(text.allTypes, systemImage: selectedType == nil ? "checkmark" : "square.stack.3d.up")
            }

            if !navigationCounts.itemTypes.isEmpty {
                Divider()
            }

            ForEach(navigationCounts.itemTypes) { itemType in
                Button {
                    navigate(.itemType(itemType.value))
                } label: {
                    Label(
                        "\(text.itemTypeName(itemType.value)) (\(itemType.count))",
                        systemImage: selectedType == itemType.value
                            ? "checkmark"
                            : VaultNavigationList.itemTypeIcon(itemType.value)
                    )
                }
            }
        } label: {
            Label(
                selectedType.map(text.itemTypeName) ?? text.allTypes,
                systemImage: "square.stack.3d.up"
            )
        }
        .help(text.allTypes)
    }

    private var tagMenu: some View {
        Menu {
            Button {
                if selectedTag != nil {
                    navigate(.allItems)
                }
            } label: {
                Label(text.allTags, systemImage: selectedTag == nil ? "checkmark" : "tag")
            }

            Divider()

            ForEach(navigationCounts.tags) { tag in
                Button {
                    navigate(.tag(tag.value))
                } label: {
                    Label(
                        "\(tag.value) (\(tag.count))",
                        systemImage: selectedTag == tag.value ? "checkmark" : "tag"
                    )
                }
            }
        } label: {
            Label(selectedTag ?? text.allTags, systemImage: "tag")
        }
        .help(text.allTags)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: hasActiveListFilters ? "line.3.horizontal.decrease.circle" : "key")
                .font(.system(size: 30))
                .foregroundStyle(.secondary)
            Text(hasActiveListFilters ? text.noMatchingItemsTitle : text.emptyVaultTitle)
                .font(.headline)
                .multilineTextAlignment(.center)
            Text(hasActiveListFilters ? text.noMatchingItemsSubtitle : text.emptyVaultSubtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if hasActiveListFilters {
                Button {
                    clearFilters()
                } label: {
                    Label(text.clearFilters, systemImage: "xmark.circle")
                }
            } else {
                Button {
                    createItem()
                } label: {
                    Label(text.newItem, systemImage: "plus")
                }
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var statusBar: some View {
        HStack(spacing: 7) {
            Image(systemName: statusIcon)
                .foregroundStyle(statusColor)
                .accessibilityHidden(true)
            Text(statusMessage)
                .font(.caption)
                .foregroundStyle(statusColor)
                .lineLimit(1)
            Spacer()
        }
        .padding(.horizontal, 10)
        .frame(height: 30)
        .accessibilityElement(children: .combine)
    }

    private var selectedType: String? {
        guard case let .itemType(itemType) = destination else { return nil }
        return itemType
    }

    private var selectedTag: String? {
        guard case let .tag(tag) = destination else { return nil }
        return tag
    }

    private var showsCollectionFilters: Bool {
        switch destination {
        case .allItems, .itemType, .tag:
            return true
        case .favorites, .appsAndTools, .smartView, .security, .conflicts, .archive:
            return false
        }
    }

    private var statusIcon: String {
        if statusIsError {
            return "exclamationmark.circle.fill"
        }
        return serviceIsAvailable ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
    }

    private var statusColor: Color {
        if statusIsError {
            return .red
        }
        return serviceIsAvailable ? .secondary : .orange
    }
}
