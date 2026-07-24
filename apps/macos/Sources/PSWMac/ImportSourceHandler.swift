import AppKit
import Foundation

protocol ImportSourceHandling {
    func revealInFinder(_ url: URL)
    func moveToTrash(_ url: URL) throws
}

struct MacImportSourceHandler: ImportSourceHandling {
    func revealInFinder(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    func moveToTrash(_ url: URL) throws {
        var resultingURL: NSURL?
        try FileManager.default.trashItem(at: url, resultingItemURL: &resultingURL)
    }
}
