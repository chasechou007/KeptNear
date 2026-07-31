import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var openVaultHandler: (([URL]) -> Bool)?
    private var terminationHandler: (() -> Void)?
    private var lastWindowCloseHandler: (() -> Void)?
    private var pendingOpenURLs: [[URL]] = []
    private var menuBarLanguageRaw = AppLanguage.english.rawValue
    private var menuRefreshObserverTokens: [NSObjectProtocol] = []
    private var menuRefreshScheduled = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        installMenuRefreshObservers()
    }

    // SwiftUI can rebuild standard menus after scene updates, so reapply titles last.
    func applicationDidUpdate(_ notification: Notification) {
        refreshMenuBarLanguage()
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

    func updateMenuBarLanguage(_ languageRaw: String) {
        menuBarLanguageRaw = languageRaw
        refreshMenuBarLanguage()
        DispatchQueue.main.async { [weak self] in
            self?.refreshMenuBarLanguage()
        }
    }

    private func refreshMenuBarLanguage() {
        MenuBarLocalization.apply(using: AppText(menuBarLanguageRaw))
    }

    private func installMenuRefreshObservers() {
        guard menuRefreshObserverTokens.isEmpty else { return }

        let center = NotificationCenter.default
        let notificationNames: [Notification.Name] = [
            NSMenu.didAddItemNotification,
            NSMenu.didRemoveItemNotification,
            NSMenu.didChangeItemNotification
        ]
        menuRefreshObserverTokens = notificationNames.map { name in
            center.addObserver(
                forName: name,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                Task { @MainActor [weak self] in
                    self?.scheduleMenuBarRefresh()
                }
            }
        }
    }

    private func scheduleMenuBarRefresh() {
        guard !menuRefreshScheduled else { return }
        menuRefreshScheduled = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            menuRefreshScheduled = false
            refreshMenuBarLanguage()
        }
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
                .environment(\.locale, text.locale)
                .tint(KeptNearBrand.primary)
                .frame(minWidth: 1_040, minHeight: 680)
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
                    appDelegate.updateMenuBarLanguage(languageRaw)
                }
                .onChange(of: languageRaw) { newValue in
                    appDelegate.updateMenuBarLanguage(newValue)
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
                .environment(\.locale, text.locale)
                .tint(KeptNearBrand.primary)
        }
    }
}
