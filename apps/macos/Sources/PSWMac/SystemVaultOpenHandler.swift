import Foundation

@MainActor
struct SystemVaultOpenHandler {
    static func openFirstVault(from urls: [URL], store: VaultStore) -> Bool {
        guard let vaultURL = urls.first(where: isSupportedVaultURL) else {
            store.statusMessage = "Unsupported vault file"
            return false
        }

        return store.openVault(url: vaultURL)
    }

    static func isSupportedVaultURL(_ url: URL) -> Bool {
        url.pathExtension.lowercased() == "pswvault"
    }
}
