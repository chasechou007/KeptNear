import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var openVaultHandler: (([URL]) -> Bool)?
    private var terminationHandler: (() -> Void)?
    private var lastWindowCloseHandler: (() -> Void)?
    private var pendingOpenURLs: [[URL]] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        let urls = filenames.map { URL(fileURLWithPath: $0) }
        let handled = handleOpenURLs(urls)
        sender.reply(toOpenOrPrint: handled ? .success : .failure)
    }

    func applicationWillTerminate(_ notification: Notification) {
        terminationHandler?()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        lastWindowCloseHandler?()
        return false
    }

    func installOpenVaultHandler(_ handler: @escaping ([URL]) -> Bool) {
        openVaultHandler = handler

        let pending = pendingOpenURLs
        pendingOpenURLs.removeAll()
        for urls in pending {
            _ = handler(urls)
        }
    }

    func installTerminationHandler(_ handler: @escaping () -> Void) {
        terminationHandler = handler
    }

    func installLastWindowCloseHandler(_ handler: @escaping () -> Void) {
        lastWindowCloseHandler = handler
    }

    @discardableResult
    private func handleOpenURLs(_ urls: [URL]) -> Bool {
        guard let openVaultHandler else {
            pendingOpenURLs.append(urls)
            return true
        }
        return openVaultHandler(urls)
    }
}

@main
struct PSWMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @AppStorage(AppLanguage.storageKey) private var languageRaw = AppLanguage.english.rawValue
    @StateObject private var store = VaultStore(service: RustCoreBridge.default)

    private var text: AppText {
        AppText(languageRaw)
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(store)
                .tint(KeptNearBrand.primary)
                .frame(minWidth: 980, minHeight: 640)
                .onAppear {
                    appDelegate.installOpenVaultHandler { urls in
                        SystemVaultOpenHandler.openFirstVault(from: urls, store: store)
                    }
                    appDelegate.installTerminationHandler {
                        store.lock()
                    }
                    appDelegate.installLastWindowCloseHandler {
                        store.lock()
                    }
                }
                .onOpenURL { url in
                    _ = SystemVaultOpenHandler.openFirstVault(from: [url], store: store)
                }
        }
        .commands {
            PSWMacCommands(text: text)
        }

        Settings {
            SettingsView()
                .environmentObject(store)
                .tint(KeptNearBrand.primary)
        }
    }
}
