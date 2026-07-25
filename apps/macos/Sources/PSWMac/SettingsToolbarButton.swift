import AppKit
import SwiftUI

struct SettingsToolbarButton: View {
    let text: AppText

    @ViewBuilder
    var body: some View {
        if #available(macOS 14.0, *) {
            SettingsLink {
                label
            }
            .help(text.settings)
        } else {
            Button {
                _ = NSApp.sendAction(
                    Selector(("showSettingsWindow:")),
                    to: nil,
                    from: nil
                )
            } label: {
                label
            }
            .help(text.settings)
        }
    }

    private var label: some View {
        Label(text.settings, systemImage: "gearshape")
    }
}
