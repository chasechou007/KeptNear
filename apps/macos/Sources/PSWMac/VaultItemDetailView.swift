import Foundation
import SwiftUI

struct VaultItemDetailView: View {
    let text: AppText
    let model: VaultItemDetailModel
    let capabilities: VaultItemDetailCapabilities
    let actions: VaultItemDetailActions

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header

                if model.item.isConflicted {
                    statusCallout(
                        text.detailConflictMessage,
                        systemImage: "exclamationmark.triangle.fill",
                        color: .orange
                    )
                } else if model.item.isArchived {
                    statusCallout(
                        text.detailArchivedMessage,
                        systemImage: "archivebox.fill",
                        color: .secondary
                    )
                }

                detailContent

                Text("\(text.revision) \(model.item.revision.prefix(10))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 24)
            }
            .padding(.horizontal, 28)
            .padding(.top, 36)
            .padding(.bottom, 48)
            .frame(maxWidth: VaultWorkspaceLayout.detailContentMaximum)
            .frame(maxWidth: .infinity, alignment: .top)
        }
    }

    private var header: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center, spacing: 14) {
                itemIdentity
                Spacer(minLength: 16)
                headerActions
            }

            VStack(alignment: .leading, spacing: 14) {
                itemIdentity
                HStack {
                    Spacer()
                    headerActions
                }
            }
        }
        .padding(.bottom, 28)
    }

    private var itemIdentity: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(itemIconColor.opacity(0.13))
                Image(systemName: VaultNavigationList.itemTypeIcon(model.item.itemType))
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(itemIconColor)
            }
            .frame(width: 50, height: 50)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text(model.item.title)
                        .font(.title2)
                        .fontWeight(.semibold)
                        .lineLimit(2)

                    if model.item.favorite {
                        Image(systemName: "star.fill")
                            .font(.caption)
                            .foregroundStyle(.yellow)
                            .accessibilityLabel(text.favoritesFilter)
                    }
                }

                Text(itemSubtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }

    private var headerActions: some View {
        HStack(spacing: 7) {
            Button {
                actions.copy(primaryCopyAction)
            } label: {
                Label(primaryCopyLabel, systemImage: "doc.on.doc")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .disabled(!capabilities.canCopy(primaryCopyAction))

            Button(action: actions.edit) {
                Label(text.editItem, systemImage: "pencil")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(!capabilities.canEdit)

            moreMenu
        }
    }

    private var moreMenu: some View {
        Menu {
            Button {
                actions.performMoreAction(.toggleFavorite)
            } label: {
                Label(
                    model.item.favorite ? text.unfavorite : text.favorite,
                    systemImage: model.item.favorite ? "star.slash" : "star"
                )
            }
            .disabled(!capabilities.canToggleFavorite)

            Button {
                actions.performMoreAction(.duplicate)
            } label: {
                Label(text.duplicate, systemImage: "plus.square.on.square")
            }
            .disabled(!capabilities.canDuplicate)

            if model.item.isConflicted {
                Button {
                    actions.performMoreAction(.resolveConflict)
                } label: {
                    Label(text.resolveConflict, systemImage: "checkmark.seal")
                }
                .disabled(!capabilities.canResolveConflict)
            }

            if model.item.isArchived {
                Button {
                    actions.performMoreAction(.restoreArchive)
                } label: {
                    Label(text.restore, systemImage: "arrow.uturn.backward")
                }
                .disabled(!capabilities.canRestoreArchive)
            }

            Divider()

            Button {
                actions.performMoreAction(.archive)
            } label: {
                Label(text.archive, systemImage: "archivebox")
            }
            .disabled(!capabilities.canArchive)

            Button(role: .destructive) {
                actions.performMoreAction(.delete)
            } label: {
                Label(text.delete, systemImage: "trash")
            }
            .disabled(!capabilities.canDelete)
        } label: {
            Label(text.more, systemImage: "ellipsis.circle")
                .labelStyle(.iconOnly)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help(text.more)
        .accessibilityLabel(text.more)
    }

    @ViewBuilder
    private var detailContent: some View {
        switch model.content {
        case let .login(login):
            loginContent(login)
        case let .credential(credential):
            credentialContent(credential)
        case let .secureNote(note):
            secureNoteContent(note)
        case let .creditCard(card):
            creditCardContent(card)
        case let .softwareLicense(license):
            softwareLicenseContent(license)
        }
    }

    private func credentialContent(_ credential: VaultItemDetailModel.Credential) -> some View {
        VStack(alignment: .leading, spacing: 22) {
            if !credential.secretFields.isEmpty {
                VaultDetailSection(title: text.protectedFields) {
                    ForEach(Array(credential.secretFields.enumerated()), id: \.element.id) { index, field in
                        if index > 0 {
                            Divider()
                        }
                        secretRow(
                            label: text.credentialFieldName(role: field.role, label: field.label),
                            field: .credential(field.secretFieldId),
                            copyAction: .credentialSecret(field.secretFieldId),
                            copyLabel: text.copySecret
                        )
                    }
                }
            }

            if !credential.textFields.isEmpty {
                VaultDetailSection(title: text.otherDetails) {
                    ForEach(Array(credential.textFields.enumerated()), id: \.offset) { index, field in
                        if index > 0 {
                            Divider()
                        }
                        VaultDetailFieldRow(
                            label: text.credentialFieldName(role: field.role, label: field.label),
                            value: displayValue(field.text),
                            multiline: true
                        ) {
                            EmptyView()
                        }
                    }
                }
            }

            metadataSection(tags: model.item.tags, notes: nil)
        }
    }

    private func loginContent(_ login: VaultItemDetailModel.Login) -> some View {
        VStack(alignment: .leading, spacing: 22) {
            VaultDetailSection(title: text.account) {
                VaultDetailFieldRow(
                    label: text.username,
                    value: displayValue(login.username)
                ) {
                    copyButton(.username, label: text.copyUsername)
                }

                Divider()

                secretRow(
                    label: text.password,
                    field: .loginPassword,
                    copyAction: .password,
                    copyLabel: text.copyPassword
                )

                if login.hasTotpSecret {
                    Divider()

                    secretRow(
                        label: text.totpSecret,
                        field: .loginTotpSecret,
                        copyAction: .totp,
                        copyLabel: text.copyTotp
                    )
                }
            }

            if !login.urls.isEmpty {
                VaultDetailSection(title: text.websites) {
                    ForEach(Array(login.urls.enumerated()), id: \.offset) { index, url in
                        if index > 0 {
                            Divider()
                        }

                        VaultDetailFieldRow(label: text.url, value: url) {
                            HStack(spacing: 2) {
                                copyButton(.url(url), label: text.copyURL)
                                iconButton(
                                    label: text.openURL,
                                    systemImage: "arrow.up.right.square",
                                    disabled: !capabilities.canOpenURL
                                ) {
                                    actions.openURL(url)
                                }
                            }
                        }
                    }
                }
            }

            metadataSection(tags: model.item.tags, notes: login.notes)
        }
    }

    private func secureNoteContent(_ note: VaultItemDetailModel.SecureNote) -> some View {
        VStack(alignment: .leading, spacing: 22) {
            VaultDetailSection(title: text.content) {
                VaultDetailTextBlock(value: displayValue(note.body)) {
                    copyButton(.secureNoteBody, label: text.copyBody)
                }
            }

            metadataSection(tags: model.item.tags, notes: nil)
        }
    }

    private func creditCardContent(_ card: VaultItemDetailModel.CreditCard) -> some View {
        VStack(alignment: .leading, spacing: 22) {
            VaultDetailSection(title: text.cardDetails) {
                VaultDetailFieldRow(
                    label: text.cardholderName,
                    value: displayValue(card.cardholderName)
                ) {
                    EmptyView()
                }

                Divider()

                VaultDetailFieldRow(
                    label: text.expiration,
                    value: displayValue(card.expiration)
                ) {
                    EmptyView()
                }
            }

            VaultDetailSection(title: text.protectedFields) {
                secretRow(
                    label: text.cardNumber,
                    field: .creditCardNumber,
                    copyAction: .cardNumber,
                    copyLabel: text.copyCardNumber
                )

                Divider()

                secretRow(
                    label: text.verificationCode,
                    field: .creditCardVerificationCode,
                    copyAction: .cardVerificationCode,
                    copyLabel: text.copyVerificationCode
                )
            }

            metadataSection(tags: model.item.tags, notes: card.notes)
        }
    }

    private func softwareLicenseContent(_ license: VaultItemDetailModel.SoftwareLicense) -> some View {
        VStack(alignment: .leading, spacing: 22) {
            VaultDetailSection(title: text.licenseDetails) {
                VaultDetailFieldRow(
                    label: text.product,
                    value: displayValue(license.product)
                ) {
                    EmptyView()
                }

                Divider()

                VaultDetailFieldRow(
                    label: text.licensedTo,
                    value: displayValue(license.licensedTo)
                ) {
                    EmptyView()
                }

                Divider()

                secretRow(
                    label: text.licenseKey,
                    field: .softwareLicenseKey,
                    copyAction: .licenseKey,
                    copyLabel: text.copyLicenseKey
                )
            }

            metadataSection(tags: model.item.tags, notes: license.notes)
        }
    }

    @ViewBuilder
    private func metadataSection(tags: [String], notes: String?) -> some View {
        let hasNotes = notes?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
        if !tags.isEmpty || hasNotes {
            VaultDetailSection(title: text.otherDetails) {
                if !tags.isEmpty {
                    VaultDetailFieldRow(
                        label: text.tags,
                        value: tags.joined(separator: "  /  "),
                        multiline: true
                    ) {
                        EmptyView()
                    }
                }

                if !tags.isEmpty, hasNotes {
                    Divider()
                }

                if hasNotes {
                    VaultDetailFieldRow(
                        label: text.notes,
                        value: notes ?? "",
                        multiline: true
                    ) {
                        EmptyView()
                    }
                }
            }
        }
    }

    private func secretRow(
        label: String,
        field: SavedSecretRevealField,
        copyAction: VaultItemDetailCopyAction,
        copyLabel: String
    ) -> some View {
        let revealedValue = actions.revealedSecret(field)
        return VaultDetailFieldRow(
            label: label,
            value: revealedValue ?? text.redactedValue,
            monospaced: true,
            secondaryValue: revealedValue == nil
        ) {
            HStack(spacing: 2) {
                iconButton(
                    label: revealedValue == nil ? text.reveal : text.hide,
                    systemImage: revealedValue == nil ? "eye" : "eye.slash",
                    disabled: revealedValue == nil && !capabilities.canRevealSecrets
                ) {
                    if revealedValue == nil {
                        actions.revealSecret(field)
                    } else {
                        actions.hideSecret(field)
                    }
                }
                copyButton(copyAction, label: copyLabel)
            }
        }
    }

    private func copyButton(
        _ action: VaultItemDetailCopyAction,
        label: String
    ) -> some View {
        iconButton(
            label: label,
            systemImage: "doc.on.doc",
            disabled: !capabilities.canCopy(action)
        ) {
            actions.copy(action)
        }
    }

    private func iconButton(
        label: String,
        systemImage: String,
        disabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Label(label, systemImage: systemImage)
                .labelStyle(.iconOnly)
        }
        .buttonStyle(.borderless)
        .frame(width: 28, height: 28)
        .contentShape(Rectangle())
        .help(label)
        .accessibilityLabel(label)
        .disabled(disabled)
    }

    private func statusCallout(
        _ message: String,
        systemImage: String,
        color: Color
    ) -> some View {
        Label(message, systemImage: systemImage)
            .font(.caption)
            .foregroundStyle(color)
            .padding(.horizontal, 12)
            .frame(minHeight: 38)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(0.09), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .padding(.bottom, 22)
    }

    private var itemIconColor: Color {
        model.item.isConflicted ? .orange : KeptNearBrand.primary
    }

    private var itemSubtitle: String {
        let typeName = text.itemTypeName(model.item.itemType)
        guard model.item.status != "active" else { return typeName }
        return "\(typeName) / \(text.itemStatus(model.item.status))"
    }

    private var primaryCopyAction: VaultItemDetailCopyAction {
        switch model.content {
        case .login:
            return .password
        case let .credential(credential):
            return .credentialSecret(credential.secretFields.first?.secretFieldId ?? "")
        case .secureNote:
            return .secureNoteBody
        case .creditCard:
            return .cardNumber
        case .softwareLicense:
            return .licenseKey
        }
    }

    private var primaryCopyLabel: String {
        switch primaryCopyAction {
        case .username:
            return text.copyUsername
        case .password:
            return text.copyPassword
        case .totp:
            return text.copyTotp
        case .url:
            return text.copyURL
        case .secureNoteBody:
            return text.copyBody
        case .cardNumber:
            return text.copyCardNumber
        case .cardVerificationCode:
            return text.copyVerificationCode
        case .licenseKey:
            return text.copyLicenseKey
        case .credentialSecret:
            return text.copySecret
        }
    }

    private func displayValue(_ value: String?) -> String {
        guard let value else { return text.notSet }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? text.notSet : value
    }
}

private struct VaultDetailSection<Content: View>: View {
    let title: String
    private let content: Content

    init(title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundStyle(.secondary)
                .padding(.leading, 4)

            VStack(spacing: 0) {
                content
            }
            .background(
                Color.secondary.opacity(0.045),
                in: RoundedRectangle(cornerRadius: 6, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .stroke(Color.secondary.opacity(0.14), lineWidth: 1)
            }
        }
    }
}

private struct VaultDetailFieldRow<Actions: View>: View {
    let label: String
    let value: String
    var monospaced = false
    var multiline = false
    var secondaryValue = false
    private let actions: Actions

    init(
        label: String,
        value: String,
        monospaced: Bool = false,
        multiline: Bool = false,
        secondaryValue: Bool = false,
        @ViewBuilder actions: () -> Actions
    ) {
        self.label = label
        self.value = value
        self.monospaced = monospaced
        self.multiline = multiline
        self.secondaryValue = secondaryValue
        self.actions = actions()
    }

    var body: some View {
        HStack(alignment: multiline ? .top : .center, spacing: 12) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(minWidth: 92, idealWidth: 108, maxWidth: 124, alignment: .leading)

            valueText
                .frame(maxWidth: .infinity, alignment: .leading)

            actions
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, multiline ? 13 : 9)
        .frame(minHeight: 50)
    }

    @ViewBuilder
    private var valueText: some View {
        let base = Text(value)
            .font(monospaced ? .system(.body, design: .monospaced) : .body)
            .textSelection(.enabled)

        if secondaryValue {
            base
                .foregroundStyle(.secondary)
                .lineLimit(multiline ? nil : 1)
        } else {
            base
                .lineLimit(multiline ? nil : 1)
        }
    }
}

private struct VaultDetailTextBlock<Actions: View>: View {
    let value: String
    private let actions: Actions

    init(value: String, @ViewBuilder actions: () -> Actions) {
        self.value = value
        self.actions = actions()
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(value)
                .lineSpacing(3)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)

            actions
                .fixedSize()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
