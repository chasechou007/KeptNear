import SwiftUI

struct WelcomeView: View {
    let text: AppText
    let recentVaultName: String?
    let openVault: () -> Void
    let createVault: () -> Void
    let openRecentVault: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 72) {
            identity
                .frame(maxWidth: 510, alignment: .leading)

            actions
                .frame(width: 370)
        }
        .padding(.horizontal, 72)
        .padding(.vertical, 56)
        .frame(maxWidth: 1_120, maxHeight: .infinity)
        .frame(maxWidth: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var identity: some View {
        VStack(alignment: .leading, spacing: 22) {
            KeptNearMark()
                .frame(width: 48, height: 48)
                .accessibilityLabel(KeptNearBrand.name)

            Text(text.welcomeHeadline)
                .font(.system(size: 42, weight: .bold, design: .rounded))
                .foregroundStyle(KeptNearBrand.graphite)
                .fixedSize(horizontal: false, vertical: true)

            Text(text.welcomeMessage)
                .font(.title3)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 18) {
                welcomePrinciple(text.encryptedVault, systemImage: "lock.shield")
                welcomePrinciple(text.filesStayWithYou, systemImage: "externaldrive")
                welcomePrinciple(text.localFirst, systemImage: "network.slash")
            }
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(text.welcomeActionsTitle)
                .font(.title3)
                .fontWeight(.semibold)

            Text(text.welcomeActionsMessage)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button(action: openVault) {
                Label(text.openExistingVault, systemImage: "folder")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)

            Button(action: createVault) {
                Label(text.newVault, systemImage: "plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)

            if let recentVaultName {
                Divider()

                Button(action: openRecentVault) {
                    HStack(spacing: 10) {
                        Image(systemName: "clock.arrow.circlepath")
                        VStack(alignment: .leading, spacing: 2) {
                            Text(text.openRecentVault)
                            Text(recentVaultName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Spacer()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(text.openRecentVault)
            }

            Divider()

            Label(text.welcomeSyncMessage, systemImage: "checkmark.shield")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(Color.primary.opacity(0.10))
        }
    }

    private func welcomePrinciple(_ title: String, systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.caption)
            .foregroundStyle(KeptNearBrand.primary)
            .lineLimit(1)
    }
}
