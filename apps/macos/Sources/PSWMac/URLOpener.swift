import AppKit
import Foundation

protocol URLOpening {
    func open(_ url: URL)
}

struct MacURLOpener: URLOpening {
    func open(_ url: URL) {
        NSWorkspace.shared.open(url)
    }
}
