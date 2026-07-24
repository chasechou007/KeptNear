import Foundation

struct SyncDiagnosticsSnapshot: Equatable {
    let loadedItems: Int
    let appliedTombstones: Int
    let detectedConflicts: Int
    let rejectedRecords: Int
    let rejectedItemRecords: Int
    let rejectedTombstoneRecords: Int
}

struct SyncReadinessDiagnosticsSnapshot: Equatable {
    let status: VaultSyncReadinessStatus
    let requiredStructureComplete: Bool
    let missingOrInvalidRequiredPathLabels: [String]
    let likelyProviderName: String?
    let localUnlockEnvelopePresent: Bool
}

struct DiagnosticsSnapshot: Equatable {
    let appName: String
    let appVersion: String
    let appBuild: String
    let coreAvailable: Bool
    let coreStatus: String
    let vaultSelected: Bool
    let vaultName: String?
    let unlocked: Bool
    let itemCount: Int
    let plaintextImportCleanupPending: Bool
    let plaintextExportCleanupPending: Bool
    let convenienceUnlockAvailable: Bool
    let syncReadiness: SyncReadinessDiagnosticsSnapshot?
    let sync: SyncDiagnosticsSnapshot?
    let syncRefreshDeferredByUnsavedEdits: Bool
    let clipboardTimeoutSeconds: Int
    let autoLockSeconds: Int
    let language: AppLanguage
}

enum DiagnosticsFormatter {
    static func report(for snapshot: DiagnosticsSnapshot) -> String {
        var lines = [
            "\(KeptNearBrand.name) Diagnostics",
            "App name: \(snapshot.appName)",
            "App version: \(snapshot.appVersion)",
            "App build: \(snapshot.appBuild)",
            "Core available: \(yesNo(snapshot.coreAvailable))",
            "Core status: \(snapshot.coreStatus)",
            "Vault selected: \(yesNo(snapshot.vaultSelected))",
            "Vault name: \(snapshot.vaultName ?? "none")",
            "Vault unlocked: \(yesNo(snapshot.unlocked))",
            "Item count: \(snapshot.itemCount)",
            "Plaintext import cleanup pending: \(yesNo(snapshot.plaintextImportCleanupPending))",
            "Plaintext export cleanup pending: \(yesNo(snapshot.plaintextExportCleanupPending))",
            "Convenience unlock available: \(yesNo(snapshot.convenienceUnlockAvailable))",
            "Clipboard clear seconds: \(snapshot.clipboardTimeoutSeconds)",
            "Auto-lock seconds: \(snapshot.autoLockSeconds)",
            "Language: \(snapshot.language.rawValue)"
        ]

        if let readiness = snapshot.syncReadiness {
            lines.append(contentsOf: [
                "Sync readiness: \(readiness.status.rawValue)",
                "Sync required structure complete: \(yesNo(readiness.requiredStructureComplete))",
                "Sync likely provider: \(readiness.likelyProviderName ?? "local-or-unknown")",
                "Sync local unlock envelope present: \(yesNo(readiness.localUnlockEnvelopePresent))"
            ])
            if readiness.missingOrInvalidRequiredPathLabels.isEmpty {
                lines.append("Sync missing required paths: none")
            } else {
                lines.append("Sync missing required paths: \(readiness.missingOrInvalidRequiredPathLabels.joined(separator: ", "))")
            }
        } else {
            lines.append("Sync readiness: no vault")
        }

        if let sync = snapshot.sync {
            lines.append(contentsOf: [
                "Sync loaded items: \(sync.loadedItems)",
                "Sync applied tombstones: \(sync.appliedTombstones)",
                "Sync detected conflicts: \(sync.detectedConflicts)",
                "Sync rejected records: \(sync.rejectedRecords)",
                "Sync rejected item records: \(sync.rejectedItemRecords)",
                "Sync rejected tombstone records: \(sync.rejectedTombstoneRecords)"
            ])
        } else {
            lines.append("Sync report: none")
        }
        lines.append("Sync refresh deferred by unsaved edits: \(yesNo(snapshot.syncRefreshDeferredByUnsavedEdits))")

        lines.append("Secret fields included: no")
        return lines.joined(separator: "\n")
    }

    private static func yesNo(_ value: Bool) -> String {
        value ? "yes" : "no"
    }
}
