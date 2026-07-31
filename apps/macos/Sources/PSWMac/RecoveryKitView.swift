import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct RecoveryKitView: View {
    @EnvironmentObject private var store: VaultStore
    @AppStorage(AppLanguage.storageKey) private var languageRaw = AppLanguage.english.rawValue
    @State private var confirmationCode = ""

    let kit: RecoveryKitPayload

    private var text: AppText {
        AppText(languageRaw)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: kit.workflowKind == .rotation ? "arrow.triangle.2.circlepath" : "key.viewfinder")
                    .font(.system(size: 28))
                    .foregroundStyle(.tint)
                    .frame(width: 36, height: 36)

                VStack(alignment: .leading, spacing: 5) {
                    Text(kit.workflowKind == .rotation ? text.rotateRecoveryKey : text.recoveryKitTitle)
                        .font(.title2)
                        .fontWeight(.semibold)
                    Text(text.recoveryKitAuthorityWarning)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Divider()

            if store.recoveryKitHasExternalCopy {
                confirmationView
            } else {
                materialView
            }

            Divider()

            HStack {
                Button {
                    store.deferRecoveryKit()
                    confirmationCode = ""
                } label: {
                    Label(text.doLater, systemImage: "clock")
                }
                .buttonStyle(.bordered)

                Spacer()

                if store.recoveryKitHasExternalCopy {
                    Button {
                        if store.confirmRecoveryKit(recoveryCode: confirmationCode) {
                            confirmationCode = ""
                        }
                    } label: {
                        Label(text.confirmRecoveryKit, systemImage: "checkmark.shield")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(confirmationCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || store.isBusy)
                } else {
                    Button {
                        printRecoveryKit()
                    } label: {
                        Label(text.printRecoveryKit, systemImage: "printer")
                    }
                    .buttonStyle(.bordered)
                    .disabled(store.isBusy)

                    Button {
                        chooseRecoveryKitDestination()
                    } label: {
                        Label(text.saveRecoveryKit, systemImage: "square.and.arrow.down")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(store.isBusy)
                }
            }

            if !store.statusMessage.isEmpty {
                Text(text.statusMessage(store.statusMessage))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(28)
        .frame(width: 650)
        .interactiveDismissDisabled()
        .onDisappear {
            confirmationCode = ""
        }
    }

    private var materialView: some View {
        HStack(alignment: .top, spacing: 28) {
            if let qrImage = RecoveryKitQRCode.image(payload: kit.qrPayload, scale: 8) {
                Image(nsImage: qrImage)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 190, height: 190)
                    .accessibilityLabel(text.recoveryKitQRCode)
            }

            VStack(alignment: .leading, spacing: 14) {
                Text(text.recoveryCode)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Text(kit.groupedCode)
                    .font(.system(.body, design: .monospaced, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel(text.recoveryCode)

                LabeledContent(text.vaultIdentifier, value: kit.vaultId)
                    .font(.caption)
                LabeledContent(text.recoveryKeyIdentifier, value: kit.recoveryKeyId)
                    .font(.caption)
                LabeledContent(text.generatedAt, value: generatedAt)
                    .font(.caption)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var confirmationView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(text.verifyRecoveryKitTitle, systemImage: "checkmark.shield")
                .font(.headline)

            Text(text.verifyRecoveryKitMessage)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            SecureField(text.recoveryCode, text: $confirmationCode)
                .textContentType(.oneTimeCode)

            Text(text.recoveryKitSourceHidden)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var generatedAt: String {
        let formatter = DateFormatter()
        formatter.locale = text.locale
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(
            from: Date(timeIntervalSince1970: TimeInterval(kit.generatedAtUnixSeconds))
        )
    }

    private var documentCopy: RecoveryKitDocumentCopy {
        RecoveryKitDocumentCopy(
            title: text.recoveryKitTitle,
            authorityWarningTitle: text.recoveryKitAuthorityWarningTitle,
            authorityWarningMessage: text.recoveryKitAuthorityWarning,
            recoveryCodeLabel: text.recoveryCode,
            vaultIdLabel: text.vaultIdentifier,
            recoveryKeyIdLabel: text.recoveryKeyIdentifier,
            generatedLabel: text.generatedAt,
            offlineStorageMessage: text.recoveryKitOfflineStorageMessage
        )
    }

    private func chooseRecoveryKitDestination() {
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.allowedContentTypes = [.pdf]
        panel.nameFieldStringValue = "KeptNear-Recovery-Kit.pdf"
        if panel.runModal() == .OK, let url = panel.url {
            _ = store.saveRecoveryKit(destinationURL: url, copy: documentCopy)
        }
    }

    private func printRecoveryKit() {
        _ = store.printRecoveryKit(copy: documentCopy)
    }
}
