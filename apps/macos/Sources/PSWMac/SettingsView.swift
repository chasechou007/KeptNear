import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var store: VaultStore
    @AppStorage(AppLanguage.storageKey) private var languageRaw = AppLanguage.english.rawValue
    @State private var masterPasswordRotationForm = MasterPasswordRotationForm()

    private var text: AppText {
        AppText(languageRaw)
    }

    var body: some View {
        TabView {
            Form {
                Picker(text.languageLabel, selection: $languageRaw) {
                    ForEach(AppLanguage.allCases) { language in
                        Text(language.displayName).tag(language.rawValue)
                    }
                }
                .pickerStyle(.radioGroup)

                Text(text.languageHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 300, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(20)
            .tabItem {
                Label(text.settingsGeneral, systemImage: "gearshape")
            }
            Form {
                TrustBoundarySummaryView(text: text)

                Divider()

                Picker(text.clipboard, selection: $store.clipboardTimeout) {
                    ForEach(VaultStore.supportedClipboardTimeouts, id: \.self) { seconds in
                        Text(text.durationOption(seconds)).tag(seconds)
                    }
                }
                .pickerStyle(.radioGroup)

                Text(text.clipboardPreferenceHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 300, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)

                Divider()

                Picker(text.autoLock, selection: $store.autoLockSeconds) {
                    ForEach(VaultStore.supportedAutoLockDurations, id: \.self) { seconds in
                        Text(text.durationOption(seconds)).tag(seconds)
                    }
                }
                .pickerStyle(.radioGroup)

                Text(text.autoLockPreferenceHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 300, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)

                Divider()

                Text(text.masterPasswordRotationHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 300, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)

                SecureField(text.currentMasterPassword, text: $masterPasswordRotationForm.currentPassword)
                SecureField(text.newMasterPassword, text: $masterPasswordRotationForm.newPassword)
                MasterPasswordStrengthView(password: masterPasswordRotationForm.newPassword, text: text)
                SecureField(text.confirmNewMasterPassword, text: $masterPasswordRotationForm.confirmation)

                Button {
                    if store.changeMasterPassword(
                        currentPassword: masterPasswordRotationForm.currentPassword,
                        newPassword: masterPasswordRotationForm.newPassword,
                        confirmation: masterPasswordRotationForm.confirmation
                    ) {
                        masterPasswordRotationForm.clear()
                    }
                } label: {
                    Label(text.changeMasterPassword, systemImage: "key")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!store.isUnlocked || store.isBusy)

                Divider()

                Text(text.cleanupLegacyKeychainHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 300, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)

                Button {
                    store.cleanupLegacyKeychainPasswords()
                } label: {
                    Label(text.cleanupLegacyKeychain, systemImage: "trash")
                }
                .buttonStyle(.bordered)
                .disabled(store.vaultURL == nil || store.isBusy)
            }
            .padding(20)
            .tabItem {
                Label(text.security, systemImage: "lock.shield")
            }
            Form {
                Text(text.diagnosticsHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 300, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)

                Button {
                    store.copyDiagnostics(languageRaw: languageRaw)
                } label: {
                    Label(text.copyDiagnostics, systemImage: "doc.on.doc")
                }
                .buttonStyle(.borderedProminent)

                if store.statusMessage == "Diagnostics copied" {
                    Text(text.diagnosticsCopied)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(20)
            .tabItem {
                Label(text.diagnostics, systemImage: "wrench.and.screwdriver")
            }
        }
        .frame(width: 520, height: 500)
        .onChange(of: store.isUnlocked) { isUnlocked in
            if !isUnlocked {
                masterPasswordRotationForm.clear()
            }
        }
        .onDisappear {
            masterPasswordRotationForm.clear()
        }
    }
}

private struct TrustBoundarySummaryView: View {
    let text: AppText

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(text.trustBoundaryTitle)
                .font(.headline)

            TrustBoundaryRow(
                systemImage: "externaldrive",
                title: text.trustBoundaryLocalVaultTitle,
                message: text.trustBoundaryLocalVaultMessage
            )
            TrustBoundaryRow(
                systemImage: "arrow.triangle.2.circlepath",
                title: text.trustBoundarySyncTitle,
                message: text.trustBoundarySyncMessage
            )
            TrustBoundaryRow(
                systemImage: "doc.text",
                title: text.trustBoundaryDiagnosticsTitle,
                message: text.trustBoundaryDiagnosticsMessage
            )
            TrustBoundaryRow(
                systemImage: "exclamationmark.triangle",
                title: text.trustBoundaryFormatTitle,
                message: text.trustBoundaryFormatMessage
            )
        }
    }
}

private struct TrustBoundaryRow: View {
    let systemImage: String
    let title: String
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: systemImage)
                .font(.body)
                .foregroundStyle(.secondary)
                .frame(width: 22)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
