import AppKit
import Foundation

protocol ClipboardManaging {
    func copy(_ value: String, clearAfter seconds: TimeInterval)
    func clearManagedSecret()
}

protocol PasteboardStoring {
    @discardableResult
    func clearContents() -> Int
    @discardableResult
    func setString(_ string: String, forType dataType: NSPasteboard.PasteboardType) -> Bool
    func string(forType dataType: NSPasteboard.PasteboardType) -> String?
}

extension NSPasteboard: PasteboardStoring {}

final class ClipboardManager: ClipboardManaging {
    private let pasteboard: PasteboardStoring
    private var token = UUID()
    private var managedSecret: String?

    init(pasteboard: PasteboardStoring = NSPasteboard.general) {
        self.pasteboard = pasteboard
    }

    func copy(_ value: String, clearAfter seconds: TimeInterval) {
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)

        let currentToken = UUID()
        token = currentToken
        managedSecret = value
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { [weak self] in
            guard let self, self.token == currentToken else { return }
            if pasteboard.string(forType: .string) == value {
                pasteboard.clearContents()
            }
            self.managedSecret = nil
        }
    }

    func clearManagedSecret() {
        let currentSecret = managedSecret
        token = UUID()
        managedSecret = nil

        if let currentSecret, pasteboard.string(forType: .string) == currentSecret {
            pasteboard.clearContents()
        }
    }
}
