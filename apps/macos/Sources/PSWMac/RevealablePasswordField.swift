import SwiftUI

struct RevealablePasswordField: View {
    let title: String
    @Binding var text: String
    @Binding var isRevealed: Bool
    let appText: AppText

    var body: some View {
        HStack(spacing: 8) {
            Group {
                if isRevealed {
                    TextField(title, text: $text)
                } else {
                    SecureField(title, text: $text)
                }
            }

            Button {
                isRevealed.toggle()
            } label: {
                Label(
                    isRevealed ? appText.hide : appText.reveal,
                    systemImage: isRevealed ? "eye.slash" : "eye"
                )
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help(isRevealed ? appText.hide : appText.reveal)
        }
    }
}
