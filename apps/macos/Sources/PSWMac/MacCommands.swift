import AppKit
import SwiftUI

enum MenuBarLocalization {
    enum Kind: CaseIterable, Equatable {
        case file
        case edit
        case view
        case window
        case help
        case item
        case vault
    }

    private static let knownTitles: [Kind: Set<String>] = [
        .file: ["File", "文件", "ファイル"],
        .edit: ["Edit", "编辑", "編集"],
        .view: ["View", "显示", "表示"],
        .window: ["Window", "窗口", "ウインドウ"],
        .help: ["Help", "帮助", "ヘルプ"],
        .item: ["Item", "项目", "アイテム"],
        .vault: ["Vault", "密码库", "保管庫"]
    ]

    static func kind(forTitle title: String) -> Kind? {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        for (kind, titles) in knownTitles where titles.contains(trimmed) {
            return kind
        }
        return nil
    }

    static func localizedTitle(for kind: Kind, text: AppText) -> String {
        switch kind {
        case .file:
            return text.fileMenu
        case .edit:
            return text.editMenu
        case .view:
            return text.viewMenu
        case .window:
            return text.windowMenu
        case .help:
            return text.helpMenu
        case .item:
            return text.itemMenu
        case .vault:
            return text.vaultMenu
        }
    }

    static func apply(using text: AppText) {
        guard let mainMenu = NSApp.mainMenu else { return }
        for item in mainMenu.items {
            guard let kind = kind(forTitle: item.title) else { continue }
            let localized = localizedTitle(for: kind, text: text)
            if item.title != localized {
                item.title = localized
            }
            if item.submenu?.title != localized {
                item.submenu?.title = localized
            }
        }
    }
}

enum PSWMacCommand: CaseIterable {
    case newItem
    case saveCurrentEditor
    case focusSearch
    case copyUsername
    case copyPassword
    case copyTotp
    case copySecureNoteBody
    case copyCardNumber
    case copyCardVerificationCode
    case copyLicenseKey
    case refreshSync
    case lockVault
}

struct PSWMacCommandAvailability: Equatable {
    var canCreateNewItem: Bool
    var canSaveCurrentEditor: Bool
    var canFocusSearch: Bool
    var canCopyUsername: Bool
    var canCopyPassword: Bool
    var canCopyTotp: Bool
    var canCopySecureNoteBody: Bool
    var canCopyCardNumber: Bool
    var canCopyCardVerificationCode: Bool
    var canCopyLicenseKey: Bool
    var canRefreshSync: Bool
    var canLockVault: Bool

    init(
        isUnlocked: Bool,
        canSaveCurrentEditor: Bool,
        canCopyUsername: Bool = false,
        canCopyPassword: Bool = false,
        canCopyTotp: Bool = false,
        canCopySecureNoteBody: Bool = false,
        canCopyCardNumber: Bool = false,
        canCopyCardVerificationCode: Bool = false,
        canCopyLicenseKey: Bool = false
    ) {
        self.canCreateNewItem = isUnlocked
        self.canSaveCurrentEditor = isUnlocked && canSaveCurrentEditor
        self.canFocusSearch = isUnlocked
        self.canCopyUsername = isUnlocked && canCopyUsername
        self.canCopyPassword = isUnlocked && canCopyPassword
        self.canCopyTotp = isUnlocked && canCopyTotp
        self.canCopySecureNoteBody = isUnlocked && canCopySecureNoteBody
        self.canCopyCardNumber = isUnlocked && canCopyCardNumber
        self.canCopyCardVerificationCode = isUnlocked && canCopyCardVerificationCode
        self.canCopyLicenseKey = isUnlocked && canCopyLicenseKey
        self.canRefreshSync = isUnlocked
        self.canLockVault = isUnlocked
    }

    func isEnabled(_ command: PSWMacCommand) -> Bool {
        switch command {
        case .newItem:
            return canCreateNewItem
        case .saveCurrentEditor:
            return canSaveCurrentEditor
        case .focusSearch:
            return canFocusSearch
        case .copyUsername:
            return canCopyUsername
        case .copyPassword:
            return canCopyPassword
        case .copyTotp:
            return canCopyTotp
        case .copySecureNoteBody:
            return canCopySecureNoteBody
        case .copyCardNumber:
            return canCopyCardNumber
        case .copyCardVerificationCode:
            return canCopyCardVerificationCode
        case .copyLicenseKey:
            return canCopyLicenseKey
        case .refreshSync:
            return canRefreshSync
        case .lockVault:
            return canLockVault
        }
    }
}

struct PSWMacCommandHandler {
    var availability: PSWMacCommandAvailability
    var createNewItem: () -> Void
    var saveCurrentEditor: () -> Void
    var focusSearch: () -> Void
    var copyUsername: () -> Void
    var copyPassword: () -> Void
    var copyTotp: () -> Void
    var copySecureNoteBody: () -> Void
    var copyCardNumber: () -> Void
    var copyCardVerificationCode: () -> Void
    var copyLicenseKey: () -> Void
    var refreshSync: () -> Void
    var lockVault: () -> Void

    func perform(_ command: PSWMacCommand) {
        guard availability.isEnabled(command) else { return }

        switch command {
        case .newItem:
            createNewItem()
        case .saveCurrentEditor:
            saveCurrentEditor()
        case .focusSearch:
            focusSearch()
        case .copyUsername:
            copyUsername()
        case .copyPassword:
            copyPassword()
        case .copyTotp:
            copyTotp()
        case .copySecureNoteBody:
            copySecureNoteBody()
        case .copyCardNumber:
            copyCardNumber()
        case .copyCardVerificationCode:
            copyCardVerificationCode()
        case .copyLicenseKey:
            copyLicenseKey()
        case .refreshSync:
            refreshSync()
        case .lockVault:
            lockVault()
        }
    }
}

private struct PSWMacCommandHandlerKey: FocusedValueKey {
    typealias Value = PSWMacCommandHandler
}

extension FocusedValues {
    var pswMacCommandHandler: PSWMacCommandHandler? {
        get { self[PSWMacCommandHandlerKey.self] }
        set { self[PSWMacCommandHandlerKey.self] = newValue }
    }
}

struct PSWMacCommands: Commands {
    @FocusedValue(\.pswMacCommandHandler) private var commandHandler

    let text: AppText

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button(text.newItem) {
                commandHandler?.perform(.newItem)
            }
            .keyboardShortcut("n", modifiers: [.command])
            .disabled(!isEnabled(.newItem))
        }

        CommandGroup(after: .saveItem) {
            Button(text.saveItem) {
                commandHandler?.perform(.saveCurrentEditor)
            }
            .keyboardShortcut("s", modifiers: [.command])
            .disabled(!isEnabled(.saveCurrentEditor))
        }

        CommandGroup(after: .textEditing) {
            Button(text.focusSearch) {
                commandHandler?.perform(.focusSearch)
            }
            .keyboardShortcut("f", modifiers: [.command])
            .disabled(!isEnabled(.focusSearch))
        }

        CommandMenu(text.itemMenu) {
            Button(text.copyUsername) {
                commandHandler?.perform(.copyUsername)
            }
            .keyboardShortcut("u", modifiers: [.command, .option])
            .disabled(!isEnabled(.copyUsername))

            Button(text.copyPassword) {
                commandHandler?.perform(.copyPassword)
            }
            .keyboardShortcut("p", modifiers: [.command, .option])
            .disabled(!isEnabled(.copyPassword))

            Button(text.copyTotp) {
                commandHandler?.perform(.copyTotp)
            }
            .keyboardShortcut("t", modifiers: [.command, .option])
            .disabled(!isEnabled(.copyTotp))

            Divider()

            Button(text.copyBody) {
                commandHandler?.perform(.copySecureNoteBody)
            }
            .keyboardShortcut("b", modifiers: [.command, .option])
            .disabled(!isEnabled(.copySecureNoteBody))

            Button(text.copyCardNumber) {
                commandHandler?.perform(.copyCardNumber)
            }
            .keyboardShortcut("c", modifiers: [.command, .option])
            .disabled(!isEnabled(.copyCardNumber))

            Button(text.copyVerificationCode) {
                commandHandler?.perform(.copyCardVerificationCode)
            }
            .keyboardShortcut("v", modifiers: [.command, .option])
            .disabled(!isEnabled(.copyCardVerificationCode))

            Button(text.copyLicenseKey) {
                commandHandler?.perform(.copyLicenseKey)
            }
            .keyboardShortcut("k", modifiers: [.command, .option])
            .disabled(!isEnabled(.copyLicenseKey))
        }

        CommandMenu(text.vaultMenu) {
            Button(text.syncRefresh) {
                commandHandler?.perform(.refreshSync)
            }
            .keyboardShortcut("r", modifiers: [.command, .shift])
            .disabled(!isEnabled(.refreshSync))

            Divider()

            Button(text.lockVault) {
                commandHandler?.perform(.lockVault)
            }
            .keyboardShortcut("l", modifiers: [.command, .shift])
            .disabled(!isEnabled(.lockVault))
        }
    }

    private func isEnabled(_ command: PSWMacCommand) -> Bool {
        commandHandler?.availability.isEnabled(command) == true
    }
}
