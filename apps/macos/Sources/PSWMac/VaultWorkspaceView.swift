import SwiftUI

enum VaultWorkspaceLayout {
    static let sidebarMinimum: CGFloat = 200
    static let sidebarIdeal: CGFloat = 220
    static let sidebarMaximum: CGFloat = 260

    static let itemListMinimum: CGFloat = 300
    static let itemListIdeal: CGFloat = 340
    static let itemListMaximum: CGFloat = 400

    static let detailMinimum: CGFloat = 480
    static let detailIdeal: CGFloat = 640
    static let detailMaximum: CGFloat = 1_000
    static let detailContentMaximum: CGFloat = 780
}

struct VaultWorkspaceView<Sidebar: View, ItemList: View, Detail: View>: View {
    private let sidebar: Sidebar
    private let itemList: ItemList
    private let detail: Detail

    init(
        @ViewBuilder sidebar: () -> Sidebar,
        @ViewBuilder itemList: () -> ItemList,
        @ViewBuilder detail: () -> Detail
    ) {
        self.sidebar = sidebar()
        self.itemList = itemList()
        self.detail = detail()
    }

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(
                    min: VaultWorkspaceLayout.sidebarMinimum,
                    ideal: VaultWorkspaceLayout.sidebarIdeal,
                    max: VaultWorkspaceLayout.sidebarMaximum
                )
        } content: {
            itemList
                .navigationSplitViewColumnWidth(
                    min: VaultWorkspaceLayout.itemListMinimum,
                    ideal: VaultWorkspaceLayout.itemListIdeal,
                    max: VaultWorkspaceLayout.itemListMaximum
                )
        } detail: {
            detail
                .frame(
                    maxWidth: VaultWorkspaceLayout.detailContentMaximum,
                    maxHeight: .infinity
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .navigationSplitViewColumnWidth(
                    min: VaultWorkspaceLayout.detailMinimum,
                    ideal: VaultWorkspaceLayout.detailIdeal,
                    max: VaultWorkspaceLayout.detailMaximum
                )
        }
        .navigationSplitViewStyle(.balanced)
    }
}
