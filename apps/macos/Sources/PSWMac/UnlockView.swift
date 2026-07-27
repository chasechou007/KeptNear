import SwiftUI

struct UnlockView: View {
    let text: AppText
    let vaultName: String
    let vaultLocation: String
    @Binding var password: String
    @Binding var rememberInKeychain: Bool
    let convenienceUnlockAvailable: Bool
    let statusMessage: String
    let statusIsError: Bool
    let unlock: () -> Void
    let unlockWithKeychain: () -> Void
    let revealInFinder: () -> Void
    let recoverForgottenPassword: () -> Void

    @FocusState private var passwordFocused: Bool

    var body: some View {
        VStack(spacing: 22) {
            KeptNearMark()
                .frame(width: 56, height: 56)
                .accessibilityLabel(KeptNearBrand.name)

            VStack(spacing: 7) {
                Text(text.unlockVaultNamed(vaultName))
                    .font(.title)
                    .fontWeight(.semibold)

                Label(vaultLocation, systemImage: "folder")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            VStack(alignment: .leading, spacing: 14) {
                Text(text.masterPassword)
                    .font(.callout)
                    .fontWeight(.medium)

                SecureField(text.masterPassword, text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($passwordFocused)
                    .onSubmit(unlock)

                Toggle(text.enableKeychainUnlock, isOn: $rememberInKeychain)
                    .toggleStyle(.checkbox)
                    .disabled(password.isEmpty)

                Button(action: unlock) {
                    Label(text.unlock, systemImage: "lock.open")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(password.isEmpty)

                if convenienceUnlockAvailable {
                    Button(action: unlockWithKeychain) {
                        Label(text.unlockWithKeychain, systemImage: "key.viewfinder")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                }

                if !statusMessage.isEmpty {
                    Label(
                        statusMessage,
                        systemImage: statusIsError ? "exclamationmark.circle.fill" : "info.circle"
                    )
                    .font(.caption)
                    .foregroundStyle(statusIsError ? Color.red : Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel(statusMessage)
                }
            }
            .padding(22)
            .frame(width: 390)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(Color.primary.opacity(0.10))
            }

            HStack(spacing: 18) {
                Button(action: recoverForgottenPassword) {
                    Label(text.forgotMasterPassword, systemImage: "questionmark.circle")
                }
                Button(action: revealInFinder) {
                    Label(text.revealInFinder, systemImage: "folder")
                }
            }
            .buttonStyle(.plain)
            .foregroundStyle(KeptNearBrand.primary)
        }
        .padding(48)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear {
            DispatchQueue.main.async {
                passwordFocused = true
            }
        }
    }
}
