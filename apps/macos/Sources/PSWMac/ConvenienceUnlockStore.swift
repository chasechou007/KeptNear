import Foundation
import Security

protocol ConvenienceUnlockStoring {
    func containsMaterial(for vaultURL: URL) -> Bool
    func loadMaterial(for vaultURL: URL) throws -> String?
    func saveMaterial(_ material: String, for vaultURL: URL) throws
    func deleteMaterial(for vaultURL: URL) throws
    func deleteLegacyPasswordMaterial(for vaultURL: URL) throws -> Int
}

final class KeychainConvenienceUnlockStore: ConvenienceUnlockStoring {
    private let currentService = "psw-local-vault.local-unlock-material.v1"
    private let legacyPasswordServices = [
        "psw-local-vault.master-password.v1",
        "psw-local-vault.convenience-unlock.v1",
        "psw-local-vault.keychain-unlock.v1"
    ]

    func containsMaterial(for vaultURL: URL) -> Bool {
        var query = keychainQuery(for: vaultURL, service: currentService)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    func loadMaterial(for vaultURL: URL) throws -> String? {
        var query = keychainQuery(for: vaultURL, service: currentService)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw ConvenienceUnlockError.keychain(status)
        }
        guard let data = result as? Data, let material = String(data: data, encoding: .utf8) else {
            throw ConvenienceUnlockError.invalidData
        }
        return material
    }

    func saveMaterial(_ material: String, for vaultURL: URL) throws {
        try deleteMaterial(for: vaultURL)

        var item = keychainQuery(for: vaultURL, service: currentService)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        item[kSecValueData as String] = Data(material.utf8)

        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ConvenienceUnlockError.keychain(status)
        }
    }

    func deleteMaterial(for vaultURL: URL) throws {
        let status = SecItemDelete(keychainQuery(for: vaultURL, service: currentService) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ConvenienceUnlockError.keychain(status)
        }
    }

    func deleteLegacyPasswordMaterial(for vaultURL: URL) throws -> Int {
        var removed = 0
        for service in legacyPasswordServices {
            let status = SecItemDelete(keychainQuery(for: vaultURL, service: service) as CFDictionary)
            if status == errSecSuccess {
                removed += 1
            } else if status != errSecItemNotFound {
                throw ConvenienceUnlockError.keychain(status)
            }
        }
        return removed
    }

    private func keychainQuery(for vaultURL: URL, service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultURL.standardizedFileURL.path
        ]
    }
}

enum ConvenienceUnlockError: LocalizedError {
    case keychain(OSStatus)
    case invalidData
    case unavailable

    var errorDescription: String? {
        switch self {
        case let .keychain(status):
            return "Keychain operation failed with status \(status)"
        case .invalidData:
            return "Keychain unlock data is invalid"
        case .unavailable:
            return "No Keychain unlock data is available for this vault"
        }
    }
}
