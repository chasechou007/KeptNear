import SwiftUI

struct CredentialFieldEditorView: View {
    @Binding var form: CredentialEditorForm

    let text: AppText
    let canSave: Bool
    let save: () -> Void
    let cancel: () -> Void
    let createNew: () -> Void

    @State private var revealedSecretInputs: Set<UUID> = []

    var body: some View {
        Form {
            Section {
                TextField(text.title, text: $form.title)
                TextField(text.tags, text: $form.tagsText)
                Toggle(text.favorite, isOn: $form.favorite)
                    .toggleStyle(.checkbox)
            }

            Section(text.credentialFields) {
                if form.fields.isEmpty {
                    Text(text.noCredentialFields)
                        .foregroundStyle(.secondary)
                }
                ForEach($form.fields) { $field in
                    fieldRow(field: $field)
                }
                Menu {
                    Button {
                        form.addTextField()
                    } label: {
                        Label(text.addTextField, systemImage: "textformat")
                    }
                    Button {
                        form.addSecretField()
                    } label: {
                        Label(text.addSecretField, systemImage: "key")
                    }
                } label: {
                    Label(text.addField, systemImage: "plus")
                }
            }

            Section {
                HStack {
                    Button(action: save) {
                        Label(text.save, systemImage: "checkmark")
                    }
                    .disabled(!canSave || !form.isValidForSave)
                    Button(action: cancel) {
                        Label(text.cancel, systemImage: "xmark")
                    }
                    .keyboardShortcut(.cancelAction)
                    Button(action: createNew) {
                        Label(text.newItem, systemImage: "plus")
                    }
                    Spacer()
                }
            }
        }
        .formStyle(.grouped)
        .padding(16)
    }

    @ViewBuilder
    private func fieldRow(field: Binding<CredentialEditorField>) -> some View {
        let fieldId = field.wrappedValue.id
        let fieldName = text.credentialFieldAccessibilityName(
            role: field.wrappedValue.role,
            label: field.wrappedValue.label,
            secretKind: field.wrappedValue.secretKind
        )
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                TextField(text.fieldRole, text: field.role)
                    .accessibilityLabel(
                        text.credentialFieldAction(text.fieldRole, fieldName: fieldName)
                    )
                TextField(text.fieldLabel, text: field.label)
                    .accessibilityLabel(
                        text.credentialFieldAction(text.fieldLabel, fieldName: fieldName)
                    )
                fieldOrderButton(
                    systemImage: "arrow.up",
                    help: text.credentialFieldAction(text.moveFieldUp, fieldName: fieldName),
                    disabled: form.fields.first?.id == fieldId
                ) {
                    form.moveField(id: fieldId, offset: -1)
                }
                fieldOrderButton(
                    systemImage: "arrow.down",
                    help: text.credentialFieldAction(text.moveFieldDown, fieldName: fieldName),
                    disabled: form.fields.last?.id == fieldId
                ) {
                    form.moveField(id: fieldId, offset: 1)
                }
                Button(role: .destructive) {
                    revealedSecretInputs.remove(fieldId)
                    form.removeField(id: fieldId)
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help(text.credentialFieldAction(text.removeField, fieldName: fieldName))
                .accessibilityLabel(
                    text.credentialFieldAction(text.removeField, fieldName: fieldName)
                )
            }

            switch field.wrappedValue.fieldType {
            case .text:
                TextField(text.fieldValue, text: field.text, axis: .vertical)
                    .lineLimit(1...6)
                    .accessibilityLabel(
                        text.credentialFieldAction(text.fieldValue, fieldName: fieldName)
                    )
            case .existingSecret:
                HStack(spacing: 8) {
                    Label(
                        text.credentialSecretKindName(field.wrappedValue.secretKind),
                        systemImage: "lock"
                    )
                    .foregroundStyle(.secondary)
                    secretInput(field: field, fieldName: fieldName)
                }
                if field.wrappedValue.secretInput.isEmpty {
                    Text(text.savedSecretUnchanged)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            case .newSecret:
                Picker(text.secretKind, selection: field.secretKind) {
                    ForEach(CredentialSecretKind.allCases) { kind in
                        Text(text.credentialSecretKindName(kind.rawValue))
                            .tag(kind.rawValue)
                    }
                }
                .pickerStyle(.menu)
                .accessibilityLabel(
                    text.credentialFieldAction(text.secretKind, fieldName: fieldName)
                )
                secretInput(field: field, fieldName: fieldName)
            }
        }
        .padding(.vertical, 6)
    }

    @ViewBuilder
    private func secretInput(
        field: Binding<CredentialEditorField>,
        fieldName: String
    ) -> some View {
        let fieldId = field.wrappedValue.id
        let revealAction = revealedSecretInputs.contains(fieldId)
            ? text.hide
            : text.reveal
        let revealLabel = text.credentialFieldAction(revealAction, fieldName: fieldName)
        let inputLabel = text.credentialFieldAction(
            text.replacementSecret,
            fieldName: fieldName
        )
        HStack(spacing: 6) {
            if revealedSecretInputs.contains(fieldId) {
                TextField(text.replacementSecret, text: field.secretInput)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(inputLabel)
            } else {
                SecureField(text.replacementSecret, text: field.secretInput)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(inputLabel)
            }
            Button {
                if revealedSecretInputs.contains(fieldId) {
                    revealedSecretInputs.remove(fieldId)
                } else {
                    revealedSecretInputs.insert(fieldId)
                }
            } label: {
                Image(systemName: revealedSecretInputs.contains(fieldId) ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(revealLabel)
            .accessibilityLabel(revealLabel)
        }
    }

    private func fieldOrderButton(
        systemImage: String,
        help: String,
        disabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Image(systemName: systemImage)
        }
        .buttonStyle(.borderless)
        .disabled(disabled)
        .help(help)
        .accessibilityLabel(help)
    }
}
