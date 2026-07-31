import SwiftUI

struct PendingRequestsToolbarButton: View {
    let text: AppText
    let pendingCount: Int
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack(alignment: .topTrailing) {
                Image(systemName: pendingCount > 0 ? "bell.badge.fill" : "bell")
                    .frame(width: 24, height: 22)

                if pendingCount > 0 {
                    Text(pendingCount > 99 ? "99+" : "\(pendingCount)")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 4)
                        .frame(minWidth: 15, minHeight: 15)
                        .background(Color.red, in: Capsule())
                        .offset(x: 8, y: -6)
                }
            }
            .frame(width: 32, height: 24)
        }
        .help(text.reviewPendingRequests)
        .accessibilityLabel(
            pendingCount > 0
                ? "\(text.reviewPendingRequests), \(text.pendingRequestCount(pendingCount))"
                : text.reviewPendingRequests
        )
    }
}

struct AppsToolsPendingRequestsView: View {
    @Environment(\.dismiss) private var dismiss

    let text: AppText
    @ObservedObject var store: VaultStore
    @State private var presentedAction: PendingRequestPresentation?

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if store.appsToolsPendingRequestActionFailed {
                actionError
                Divider()
            }

            if !store.appsToolsPendingRequestsAvailable {
                unavailableState
            } else if store.appsToolsPendingRequests.requests.isEmpty {
                emptyState
            } else {
                requestList
            }
        }
        .frame(minWidth: 640, idealWidth: 700, minHeight: 460, idealHeight: 560)
        .sheet(item: $presentedAction) { presentation in
            presentedActionView(presentation)
        }
        .onDisappear {
            store.clearAppsToolsPendingRequestActionError()
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "bell.badge")
                .font(.title2)
                .foregroundStyle(.secondary)
                .frame(width: 28, height: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(text.pendingRequests)
                    .font(.title2)
                    .fontWeight(.semibold)
                Text(text.pendingRequestCount(store.appsToolsPendingRequests.pendingCount))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button(action: store.refreshAppsToolsPendingRequests) {
                Label(text.refreshAppsToolsAccess, systemImage: "arrow.clockwise")
            }
            .labelStyle(.iconOnly)
            .help(text.refreshAppsToolsAccess)

            Button {
                dismiss()
            } label: {
                Label(text.close, systemImage: "xmark")
            }
            .labelStyle(.iconOnly)
            .help(text.close)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
    }

    private var requestList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(
                    Array(store.appsToolsPendingRequests.requests.enumerated()),
                    id: \.element.id
                ) { index, request in
                    if index > 0 {
                        Divider()
                            .padding(.leading, 58)
                    }
                    requestRow(request)
                }
            }
            .padding(.horizontal, 20)
        }
    }

    private func requestRow(_ request: AppsToolsPendingRequest) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: requestIcon(request.kind))
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(requestColor(request.kind))
                .frame(width: 30, height: 30)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 7) {
                HStack(alignment: .firstTextBaseline) {
                    Text(text.pendingRequestKind(request.kind))
                        .font(.headline)
                    Spacer(minLength: 12)
                    if let expiry = expiryText(request) {
                        Text(expiry)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Text(text.pendingRequestConsumer(request))
                    .foregroundStyle(.secondary)

                if let description = request.requestDescription {
                    detailRow(text.requestDescription, description)
                }
                if let code = request.pairingComparisonCode {
                    detailRow(text.comparisonCode, code, monospaced: true)
                }
                if let fingerprint = request.pairingKeyFingerprint {
                    detailRow(text.pairingKeyFingerprint, fingerprint, monospaced: true)
                }
                if let capability = request.capability,
                   let version = request.capabilityVersion
                {
                    detailRow(
                        text.requestedCapability,
                        text.capabilityLabel(capability, version: version)
                    )
                }

                if AppsToolsCompatibilityDisclosurePolicy.requiresDisclosure(
                    capability: request.capability
                ) {
                    AppsToolsCompatibilityDisclosure(text: text, compact: true)
                }

                requestActions(request)
            }
        }
        .padding(.vertical, 14)
    }

    @ViewBuilder
    private func requestActions(_ request: AppsToolsPendingRequest) -> some View {
        let processingAnotherRequest = store.appsToolsPendingRequestActionInFlightId != nil
            && store.appsToolsPendingRequestActionInFlightId != request.id

        HStack(spacing: 10) {
            Button(role: .destructive) {
                _ = store.denyAppsToolsPendingRequest(request)
            } label: {
                Label(text.deny, systemImage: "xmark")
            }
            .disabled(processingAnotherRequest)

            Spacer(minLength: 10)

            switch request.kind {
            case "pairing":
                Button {
                    store.clearAppsToolsPendingRequestActionError()
                    presentedAction = .pairing(request)
                } label: {
                    Label(text.pairConsumer, systemImage: "link.badge.plus")
                }
                .buttonStyle(.borderedProminent)
                .disabled(processingAnotherRequest)
            case "unlock":
                Button {
                    _ = store.approveAppsToolsPendingUnlock(request)
                } label: {
                    Label(text.approveUnlock, systemImage: "lock.open")
                }
                .buttonStyle(.borderedProminent)
                .disabled(processingAnotherRequest || !store.isUnlocked)
            case "access":
                accessRequestActions(request, processingAnotherRequest: processingAnotherRequest)
            case "credential-access":
                credentialRequestActions(
                    request,
                    processingAnotherRequest: processingAnotherRequest
                )
            default:
                EmptyView()
            }
        }

        if request.kind != "pairing",
           !store.isUnlocked
        {
            Label(text.unlockToRespond, systemImage: "lock")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func accessRequestActions(
        _ request: AppsToolsPendingRequest,
        processingAnotherRequest: Bool
    ) -> some View {
        Group {
            Button {
                _ = store.allowAppsToolsPendingRequestOnce(request)
            } label: {
                Label(text.allowOnce, systemImage: "1.circle")
            }
            .disabled(processingAnotherRequest || !store.isUnlocked)

            Button {
                store.clearAppsToolsPendingRequestActionError()
                presentedAction = .longTerm(request)
            } label: {
                Label(text.configureLongTermAccess, systemImage: "slider.horizontal.3")
            }
            .buttonStyle(.borderedProminent)
            .disabled(processingAnotherRequest || !store.isUnlocked)
        }
    }

    private func credentialRequestActions(
        _ request: AppsToolsPendingRequest,
        processingAnotherRequest: Bool
    ) -> some View {
        Group {
            Button {
                store.clearAppsToolsPendingRequestActionError()
                presentedAction = .credential(request, intent: .allowOnce)
            } label: {
                Label(text.allowOnce, systemImage: "1.circle")
            }
            .disabled(processingAnotherRequest || !store.isUnlocked)

            Button {
                store.clearAppsToolsPendingRequestActionError()
                presentedAction = .credential(request, intent: .configureLongTerm)
            } label: {
                Label(text.configureLongTermAccess, systemImage: "slider.horizontal.3")
            }
            .buttonStyle(.borderedProminent)
            .disabled(processingAnotherRequest || !store.isUnlocked)
        }
    }

    private func detailRow(
        _ label: String,
        _ value: String,
        monospaced: Bool = false
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 130, alignment: .leading)
            Text(value)
                .font(monospaced ? .caption.monospaced() : .caption)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var unavailableState: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 30))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(text.pendingRequestsUnavailable)
                .font(.headline)
            Button(action: store.refreshAppsToolsPendingRequests) {
                Label(text.tryAgain, systemImage: "arrow.clockwise")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(text.noPendingRequests)
                .font(.headline)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var actionError: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.circle.fill")
                .foregroundStyle(.red)
                .accessibilityHidden(true)
            Text(text.requestActionFailed)
                .font(.callout)
                .foregroundStyle(.red)
            Spacer()
            Button {
                store.clearAppsToolsPendingRequestActionError()
            } label: {
                Label(text.close, systemImage: "xmark")
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help(text.close)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private func presentedActionView(_ presentation: PendingRequestPresentation) -> some View {
        switch presentation {
        case let .pairing(request):
            PairingRequestDecisionView(text: text, store: store, request: request)
        case let .credential(request, intent):
            CredentialRequestDecisionView(
                text: text,
                store: store,
                request: request,
                intent: intent
            )
        case let .longTerm(request):
            LongTermAccessDecisionView(
                text: text,
                store: store,
                request: request,
                selectedCredential: nil
            )
        }
    }

    private func expiryText(_ request: AppsToolsPendingRequest) -> String? {
        if let milliseconds = request.expiresAtMilliseconds {
            return "\(text.expires) \(text.formattedDateTime(milliseconds))"
        }
        if let remaining = request.remainingMilliseconds {
            let minutes = max(1, Int((remaining + 59_999) / 60_000))
            return text.pendingRequestExpiresIn(minutes)
        }
        return nil
    }

    private func requestIcon(_ kind: String) -> String {
        switch kind {
        case "pairing":
            return "link.badge.plus"
        case "unlock":
            return "lock.open"
        case "access":
            return "key.horizontal"
        case "credential-access":
            return "magnifyingglass"
        default:
            return "checkmark.shield"
        }
    }

    private func requestColor(_ kind: String) -> Color {
        kind == "pairing" ? .blue : .orange
    }
}

private enum PendingRequestAccessIntent: Equatable {
    case allowOnce
    case configureLongTerm
}

private enum PendingRequestPresentation: Identifiable {
    case pairing(AppsToolsPendingRequest)
    case credential(AppsToolsPendingRequest, intent: PendingRequestAccessIntent)
    case longTerm(AppsToolsPendingRequest)

    var id: String {
        switch self {
        case let .pairing(request):
            return "\(request.id):pairing"
        case let .credential(request, intent):
            return "\(request.id):credential:\(String(describing: intent))"
        case let .longTerm(request):
            return "\(request.id):long-term"
        }
    }
}

private struct SelectedCredentialField {
    let selection: AppsToolsCredentialSelection
    let credentialTitle: String
    let fieldName: String
}

private struct PairingRequestDecisionView: View {
    @Environment(\.dismiss) private var dismiss

    let text: AppText
    @ObservedObject var store: VaultStore
    let request: AppsToolsPendingRequest
    @State private var label = ""

    var body: some View {
        VStack(spacing: 0) {
            decisionHeader(text.pairConsumer, systemImage: "link.badge.plus")
            Divider()

            Form {
                TextField(text.consumerName, text: $label)
                if let code = request.pairingComparisonCode {
                    LabeledContent(text.comparisonCode) {
                        Text(code)
                            .font(.body.monospaced())
                            .textSelection(.enabled)
                    }
                }
                if let fingerprint = request.pairingKeyFingerprint {
                    LabeledContent(text.pairingKeyFingerprint) {
                        Text(fingerprint)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
            .formStyle(.grouped)

            if store.appsToolsPendingRequestActionFailed {
                requestActionError(text)
            }

            decisionFooter(
                text: text,
                primaryTitle: text.pairConsumer,
                primarySystemImage: "link.badge.plus",
                primaryDisabled: label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                cancel: { dismiss() },
                primary: {
                    if store.approveAppsToolsPairing(request, label: label) {
                        dismiss()
                    }
                }
            )
        }
        .frame(width: 540, height: 390)
        .onAppear {
            label = text.pendingRequestConsumer(request)
            store.clearAppsToolsPendingRequestActionError()
        }
    }
}

private struct CredentialRequestDecisionView: View {
    @Environment(\.dismiss) private var dismiss

    let text: AppText
    @ObservedObject var store: VaultStore
    let request: AppsToolsPendingRequest
    let intent: PendingRequestAccessIntent
    @State private var review: AppsToolsCredentialReview?
    @State private var selectedCredential: SelectedCredentialField?
    @State private var configuringLongTerm = false

    var body: some View {
        if configuringLongTerm, let selectedCredential {
            LongTermAccessDecisionContent(
                text: text,
                store: store,
                request: request,
                selectedCredential: selectedCredential,
                back: { configuringLongTerm = false },
                cancel: { dismiss() },
                completed: { dismiss() }
            )
            .frame(width: 600, height: 470)
        } else {
            credentialSelection
                .frame(width: 600, height: 520)
                .onAppear(perform: loadReview)
        }
    }

    private var credentialSelection: some View {
        VStack(spacing: 0) {
            decisionHeader(text.chooseCredential, systemImage: "key.horizontal")
            Divider()

            if AppsToolsCompatibilityDisclosurePolicy.requiresDisclosure(
                capability: request.capability
            ) {
                AppsToolsCompatibilityDisclosure(text: text, compact: true)
                    .padding(.horizontal, 20)
                    .padding(.top, 12)
            }

            Group {
                if let review, review.candidates.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 30))
                            .foregroundStyle(.secondary)
                            .accessibilityHidden(true)
                        Text(text.noMatchingCredentials)
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let review {
                    List {
                        ForEach(review.candidates) { candidate in
                            Section {
                                ForEach(candidate.secretFields) { field in
                                    credentialFieldButton(candidate: candidate, field: field)
                                }
                            } header: {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(candidate.title)
                                    if !candidate.tags.isEmpty {
                                        Text(candidate.tags.joined(separator: ", "))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                    .listStyle(.inset)
                } else if store.appsToolsPendingRequestActionFailed {
                    requestActionError(text)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ProgressView()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }

            if review?.truncated == true {
                Text(text.matchingResultsTruncated)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
            }

            if store.appsToolsPendingRequestActionFailed, review != nil {
                requestActionError(text)
            }

            decisionFooter(
                text: text,
                primaryTitle: intent == .allowOnce
                    ? text.allowOnce
                    : text.configureLongTermAccess,
                primarySystemImage: intent == .allowOnce
                    ? "1.circle"
                    : "slider.horizontal.3",
                primaryDisabled: selectedCredential == nil,
                cancel: { dismiss() },
                primary: continueWithSelection
            )
        }
    }

    private func credentialFieldButton(
        candidate: AppsToolsCredentialCandidate,
        field: AppsToolsCredentialFieldCandidate
    ) -> some View {
        let selection = AppsToolsCredentialSelection(
            credentialId: candidate.credentialId,
            secretFieldId: field.secretFieldId
        )
        let selected = selectedCredential?.selection == selection
        let fieldName = field.label?.nilIfEmpty
            ?? text.credentialSecretKindName(field.kind)

        return Button {
            selectedCredential = SelectedCredentialField(
                selection: selection,
                credentialTitle: candidate.title,
                fieldName: fieldName
            )
        } label: {
            HStack(spacing: 10) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected ? Color.accentColor : Color.secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(fieldName)
                    Text(text.credentialSecretKindName(field.kind))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(
            text.credentialSelectionAccessibilityLabel(
                credentialTitle: candidate.title,
                fieldName: fieldName,
                secretKind: text.credentialSecretKindName(field.kind)
            )
        )
        .accessibilityValue(selected ? text.selected : text.notSelected)
    }

    private func loadReview() {
        guard review == nil else { return }
        store.clearAppsToolsPendingRequestActionError()
        review = store.reviewAppsToolsPendingCredential(request)
    }

    private func continueWithSelection() {
        guard let selectedCredential else { return }
        switch intent {
        case .allowOnce:
            if store.allowAppsToolsPendingRequestOnce(
                request,
                selection: selectedCredential.selection
            ) {
                dismiss()
            }
        case .configureLongTerm:
            configuringLongTerm = true
        }
    }
}

private struct LongTermAccessDecisionView: View {
    @Environment(\.dismiss) private var dismiss

    let text: AppText
    @ObservedObject var store: VaultStore
    let request: AppsToolsPendingRequest
    let selectedCredential: SelectedCredentialField?

    var body: some View {
        LongTermAccessDecisionContent(
            text: text,
            store: store,
            request: request,
            selectedCredential: selectedCredential,
            back: nil,
            cancel: { dismiss() },
            completed: { dismiss() }
        )
        .frame(width: 600, height: 470)
        .onAppear {
            store.clearAppsToolsPendingRequestActionError()
        }
    }
}

private struct LongTermAccessDecisionContent: View {
    let text: AppText
    @ObservedObject var store: VaultStore
    let request: AppsToolsPendingRequest
    let selectedCredential: SelectedCredentialField?
    let back: (() -> Void)?
    let cancel: () -> Void
    let completed: () -> Void
    @State private var policy = AppsToolsConfirmationPolicy.everyUse

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                if let back {
                    Button(action: back) {
                        Label(text.chooseCredential, systemImage: "chevron.left")
                    }
                    .labelStyle(.iconOnly)
                    .help(text.chooseCredential)
                }
                Image(systemName: "slider.horizontal.3")
                    .font(.title2)
                    .foregroundStyle(.secondary)
                    .frame(width: 28, height: 28)
                    .accessibilityHidden(true)
                Text(text.configureLongTermAccess)
                    .font(.title2)
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)

            Divider()

            Form {
                if let selectedCredential {
                    LabeledContent(text.chooseCredential) {
                        Text(selectedCredential.credentialTitle)
                    }
                    LabeledContent(text.chooseSecretField) {
                        Text(selectedCredential.fieldName)
                    }
                } else if let description = request.requestDescription {
                    LabeledContent(text.requestDescription) {
                        Text(description)
                            .multilineTextAlignment(.trailing)
                    }
                }

                Picker(text.confirmationPolicyTitle, selection: $policy) {
                    ForEach(AppsToolsConfirmationPolicy.allCases) { candidate in
                        Text(text.confirmationPolicy(candidate.rawValue))
                            .tag(candidate)
                    }
                }
                .pickerStyle(.radioGroup)

                Text(text.confirmationPolicyDetail(policy))
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if AppsToolsCompatibilityDisclosurePolicy.requiresDisclosure(
                    capability: request.capability
                ) {
                    AppsToolsCompatibilityDisclosure(text: text)
                }
            }
            .formStyle(.grouped)

            if store.appsToolsPendingRequestActionFailed {
                requestActionError(text)
            }

            decisionFooter(
                text: text,
                primaryTitle: text.saveAccess,
                primarySystemImage: "checkmark.shield",
                primaryDisabled: false,
                cancel: cancel,
                primary: {
                    if store.configureAppsToolsLongTermAccess(
                        request,
                        selection: selectedCredential?.selection,
                        confirmationPolicy: policy
                    ) {
                        completed()
                    }
                }
            )
        }
    }
}

private func decisionHeader(_ title: String, systemImage: String) -> some View {
    HStack(spacing: 12) {
        Image(systemName: systemImage)
            .font(.title2)
            .foregroundStyle(.secondary)
            .frame(width: 28, height: 28)
            .accessibilityHidden(true)
        Text(title)
            .font(.title2)
            .fontWeight(.semibold)
        Spacer()
    }
    .padding(.horizontal, 20)
    .padding(.vertical, 16)
}

private func decisionFooter(
    text: AppText,
    primaryTitle: String,
    primarySystemImage: String,
    primaryDisabled: Bool,
    cancel: @escaping () -> Void,
    primary: @escaping () -> Void
) -> some View {
    HStack(spacing: 10) {
        Spacer()
        Button(text.cancel, action: cancel)
            .keyboardShortcut(.cancelAction)
        Button(action: primary) {
            Label(primaryTitle, systemImage: primarySystemImage)
        }
        .buttonStyle(.borderedProminent)
        .keyboardShortcut(.defaultAction)
        .disabled(primaryDisabled)
    }
    .padding(.horizontal, 20)
    .padding(.vertical, 14)
}

private func requestActionError(_ text: AppText) -> some View {
    Label(text.requestActionFailed, systemImage: "exclamationmark.circle.fill")
        .font(.callout)
        .foregroundStyle(.red)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
}
