import SwiftUI

struct AppsToolsNavigationPane: View {
    let text: AppText
    let snapshot: AppsToolsSnapshot
    let selectedConsumerId: String?
    let inventoryAvailable: Bool
    let pendingRequestCount: Int
    let pendingRequestsAvailable: Bool
    let isBusy: Bool
    let refresh: () -> Void
    let showPendingRequests: () -> Void
    let showAuthorizedItems: () -> Void
    let selectConsumer: (String) -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Label(text.appsAndTools, systemImage: "cpu")
                    .font(.headline)
                Spacer()
                Button(action: refresh) {
                    Label(text.refreshAppsToolsAccess, systemImage: "arrow.clockwise")
                }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .disabled(isBusy)
                .help(text.refreshAppsToolsAccess)
            }
            .padding(12)

            Divider()

            List {
                Section(text.pendingRequests) {
                    Button(action: showPendingRequests) {
                        HStack(spacing: 9) {
                            Image(
                                systemName: pendingRequestCount > 0
                                    ? "bell.badge.fill"
                                    : "bell"
                            )
                            .foregroundStyle(
                                !pendingRequestsAvailable
                                    ? Color.orange
                                    : pendingRequestCount > 0
                                        ? Color.red
                                        : Color.secondary
                            )
                            .frame(width: 17)
                            Text(
                                pendingRequestsAvailable
                                    ? pendingRequestCount > 0
                                        ? text.pendingRequestCount(pendingRequestCount)
                                        : text.noPendingRequests
                                    : text.pendingRequestsUnavailable
                            )
                            .lineLimit(2)
                            Spacer(minLength: 8)
                            Image(systemName: "chevron.right")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(text.pendingRequests)
                    .accessibilityValue(
                        pendingRequestsAvailable
                            ? pendingRequestCount > 0
                                ? text.pendingRequestCount(pendingRequestCount)
                                : text.noPendingRequests
                            : text.pendingRequestsUnavailable
                    )
                }

                Section(text.appsToolsOverview) {
                    statusRow

                    Button(action: showAuthorizedItems) {
                        HStack(spacing: 9) {
                            Image(systemName: "checkmark.shield")
                                .foregroundStyle(.secondary)
                                .frame(width: 17)
                            Text(text.authorizedItems)
                            Spacer(minLength: 8)
                            Text("\(snapshot.authorizedCredentialIds.count)")
                                .font(.caption)
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(!inventoryAvailable)
                    .accessibilityLabel(text.authorizedItems)
                    .accessibilityValue(
                        inventoryAvailable
                            ? text.itemCount(snapshot.authorizedCredentialIds.count)
                            : text.authorizationDataUnavailable
                    )
                }

                Section(text.consumers) {
                    if inventoryAvailable, snapshot.consumers.isEmpty {
                        Text(text.noPairedConsumers)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.vertical, 6)
                    } else {
                        ForEach(snapshot.consumers) { consumer in
                            Button {
                                selectConsumer(consumer.consumerId)
                            } label: {
                                consumerRow(consumer)
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(consumer.label)
                            .accessibilityValue(text.consumerAccessibilityValue(consumer))
                            .listRowBackground(
                                selectedConsumerId == consumer.consumerId
                                    ? Color.accentColor.opacity(0.12)
                                    : Color.clear
                            )
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    private var statusRow: some View {
        HStack(spacing: 9) {
            Image(
                systemName: !inventoryAvailable
                    ? "exclamationmark.triangle.fill"
                    : snapshot.paused
                        ? "pause.circle.fill"
                        : "checkmark.circle.fill"
            )
            .foregroundStyle(
                !inventoryAvailable
                    ? Color.orange
                    : snapshot.paused
                        ? Color.orange
                        : Color.green
            )
            .frame(width: 17)
            Text(text.machineAccess)
            Spacer(minLength: 8)
            Text(
                !inventoryAvailable
                    ? text.authorizationDataUnavailable
                    : snapshot.paused
                        ? text.paused
                        : text.active
            )
            .font(.caption)
            .foregroundStyle(
                !inventoryAvailable || snapshot.paused ? Color.orange : Color.secondary
            )
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text.machineAccess)
        .accessibilityValue(
            !inventoryAvailable
                ? text.authorizationDataUnavailable
                : snapshot.paused
                    ? text.paused
                    : text.active
        )
    }

    private func consumerRow(_ consumer: AppsToolsConsumerSummary) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "terminal")
                .foregroundStyle(.secondary)
                .frame(width: 20)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text(consumer.label)
                    .lineLimit(1)
                Text(text.consumerIdentitySummary(consumer.identity))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            Text("\(consumer.accessRuleCount)")
                .font(.caption)
                .monospacedDigit()
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}

struct AppsToolsDetailView: View {
    let text: AppText
    let snapshot: AppsToolsSnapshot
    let detail: AppsToolsConsumerDetail?
    let usageProfileSetup: AppsToolsUsageProfileSetup?
    let usageProfileActionFailed: Bool
    let inventoryAvailable: Bool
    let isBusy: Bool
    let refresh: () -> Void
    let setPaused: (Bool) -> Void
    let revokeField: (AppsToolsFieldGrant) -> Void
    let createUsageProfile: (AppsToolsUsageProfileDraft) -> Bool
    let removeUsageProfile: (AppsToolsUsageProfile) -> Void
    let revokeConsumer: () -> Void

    @State private var confirmation: AppsToolsConfirmation?
    @State private var showsUsageProfileSetup = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if !inventoryAvailable {
                unavailableState
            } else if let detail {
                consumerDetail(detail)
            } else {
                emptyState
            }
        }
        .alert(item: $confirmation) { confirmation in
            switch confirmation {
            case let .field(grant):
                return Alert(
                    title: Text(text.revokeFieldAccess),
                    message: Text(
                        text.revokeFieldAccessMessage(
                            grant.field,
                            capability: grant.capability
                        )
                    ),
                    primaryButton: .destructive(Text(text.revoke)) {
                        revokeField(grant)
                    },
                    secondaryButton: .cancel(Text(text.cancel))
                )
            case let .consumer(label):
                return Alert(
                    title: Text(text.unpairConsumer),
                    message: Text(text.unpairConsumerMessage(label)),
                    primaryButton: .destructive(Text(text.unpair)) {
                        revokeConsumer()
                    },
                    secondaryButton: .cancel(Text(text.cancel))
                )
            case let .usageProfile(profile):
                return Alert(
                    title: Text(text.removeUsageProfile),
                    message: Text(text.removeUsageProfileMessage(profile.label)),
                    primaryButton: .destructive(Text(text.delete)) {
                        removeUsageProfile(profile)
                    },
                    secondaryButton: .cancel(Text(text.cancel))
                )
            }
        }
        .sheet(isPresented: $showsUsageProfileSetup) {
            if let detail, let usageProfileSetup {
                UsageProfileSetupView(
                    text: text,
                    consumer: detail.consumer,
                    setup: usageProfileSetup,
                    isBusy: isBusy,
                    actionFailed: usageProfileActionFailed,
                    save: createUsageProfile
                )
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: detail == nil ? "cpu" : "terminal")
                .font(.title2)
                .foregroundStyle(.secondary)
                .frame(width: 28, height: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(detail?.consumer.label ?? text.appsAndTools)
                    .font(.title2)
                    .fontWeight(.semibold)
                    .lineLimit(1)
                Text(
                    inventoryAvailable
                        ? snapshot.paused
                            ? text.machineAccessPaused
                            : text.machineAccessActive
                        : text.authorizationDataUnavailable
                )
                .font(.caption)
                .foregroundStyle(
                    inventoryAvailable && !snapshot.paused ? Color.secondary : Color.orange
                )
            }

            Spacer()

            Toggle(
                text.pauseAppsToolsAccess,
                isOn: Binding(
                    get: { snapshot.paused },
                    set: setPaused
                )
            )
            .toggleStyle(.switch)
            .disabled(!inventoryAvailable || isBusy)
            .accessibilityLabel(text.pauseAppsToolsAccess)
            .accessibilityValue(snapshot.paused ? text.paused : text.active)
            .help(snapshot.paused ? text.machineAccessPaused : text.machineAccessActive)

            Button(action: refresh) {
                Label(text.refreshAppsToolsAccess, systemImage: "arrow.clockwise")
            }
            .labelStyle(.iconOnly)
            .disabled(isBusy)
            .help(text.refreshAppsToolsAccess)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
    }

    private var unavailableState: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 32))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(text.authorizationDataUnavailable)
                .font(.headline)
            Button(action: refresh) {
                Label(text.tryAgain, systemImage: "arrow.clockwise")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "terminal")
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(text.noPairedConsumers)
                .font(.headline)
            Text(text.authorizedItemsCount(snapshot.authorizedCredentialIds.count))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func consumerDetail(_ detail: AppsToolsConsumerDetail) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                detailSection(text.identityEvidence) {
                    identityRows(detail.consumer)
                }

                detailSection(
                    text.fieldAccess,
                    count: detail.fieldGrants.count
                ) {
                    if detail.fieldGrants.isEmpty {
                        emptySection(text.noFieldAccess)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(detail.fieldGrants.enumerated()), id: \.element.id) {
                                index,
                                grant in
                                if index > 0 {
                                    Divider()
                                        .padding(.vertical, 12)
                                }
                                fieldGrantRow(grant)
                            }
                        }
                    }
                }

                detailSection(
                    text.usageProfiles,
                    count: detail.usageProfiles.count
                ) {
                    HStack {
                        if usageProfileActionFailed {
                            Label(
                                text.usageProfileActionFailed,
                                systemImage: "exclamationmark.circle"
                            )
                            .font(.caption)
                            .foregroundStyle(.red)
                        } else if usageProfileSetup == nil {
                            Text(text.usageProfileSetupUnavailable)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        Spacer(minLength: 12)

                        Button {
                            showsUsageProfileSetup = true
                        } label: {
                            Label(text.addUsageProfile, systemImage: "plus")
                        }
                        .disabled(usageProfileSetup == nil || isBusy)
                        .accessibilityLabel(text.addUsageProfile)
                    }

                    if detail.usageProfiles.isEmpty {
                        emptySection(text.noUsageProfiles)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(detail.usageProfiles.enumerated()), id: \.element.id) {
                                index,
                                profile in
                                if index > 0 {
                                    Divider()
                                        .padding(.vertical, 12)
                                }
                                usageProfileRow(profile)
                            }
                        }
                    }
                }

                detailSection(
                    text.recentActivity,
                    count: detail.recentAuditEvents.count
                ) {
                    if detail.recentAuditEvents.isEmpty {
                        emptySection(text.noRecentActivity)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(detail.recentAuditEvents.enumerated()), id: \.element.id) {
                                index,
                                event in
                                if index > 0 {
                                    Divider()
                                        .padding(.vertical, 10)
                                }
                                auditEventRow(event)
                            }
                        }
                    }
                }

                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    Text(text.revocationDeliveryLimit)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    Button(role: .destructive) {
                        confirmation = .consumer(detail.consumer.label)
                    } label: {
                        Label(text.unpairConsumer, systemImage: "person.crop.circle.badge.minus")
                    }
                    .disabled(isBusy)
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func identityRows(_ consumer: AppsToolsConsumerSummary) -> some View {
        VStack(spacing: 10) {
            valueRow(text.executable, consumer.identity.executableName ?? text.notAvailable)
            valueRow(text.bundleIdentifier, consumer.identity.bundleIdentifier ?? text.notAvailable)
            valueRow(text.teamIdentifier, consumer.identity.teamIdentifier ?? text.notAvailable)
            valueRow(
                text.codeSigning,
                text.codeSigningEvidence(consumer.identity.codeSigningEvidence)
            )
            if let fingerprint = consumer.identity.codeSignatureFingerprint {
                valueRow(text.signatureFingerprint, fingerprint, monospaced: true)
            }
            valueRow(
                text.pairedAt,
                text.formattedDateTime(consumer.createdAtMilliseconds)
            )
        }
    }

    private func fieldGrantRow(_ grant: AppsToolsFieldGrant) -> some View {
        let credentialTitle = grant.field.credentialTitle ?? text.unknownCredential
        let fieldName = grant.field.fieldLabel ?? text.unknownSecretField
        let revokeLabel = text.credentialFieldAction(
            text.revokeFieldAccess,
            fieldName: "\(credentialTitle) · \(fieldName)"
        )

        return HStack(alignment: .top, spacing: 14) {
            Image(systemName: grant.active ? "key.horizontal.fill" : "key.slash")
                .foregroundStyle(grant.active ? Color.accentColor : Color.secondary)
                .frame(width: 22)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 6) {
                Text(credentialTitle)
                    .font(.headline)
                Text(fieldName)
                    .foregroundStyle(.secondary)

                if !grant.active {
                    Text(text.inactive)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }

                HStack(spacing: 12) {
                    Label(
                        text.capabilityLabel(grant.capability, version: grant.capabilityVersion),
                        systemImage: "bolt.horizontal"
                    )
                    Label(
                        text.confirmationPolicy(grant.confirmationPolicy),
                        systemImage: "checkmark.shield"
                    )
                    Label(
                        text.ruleLifetime(grant),
                        systemImage: "clock"
                    )
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)

                if !grant.field.currentVault {
                    Text(text.otherVault)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            Spacer(minLength: 12)

            Button(role: .destructive) {
                confirmation = .field(grant)
            } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .disabled(isBusy)
            .help(revokeLabel)
            .accessibilityLabel(revokeLabel)
        }
    }

    private func usageProfileRow(_ profile: AppsToolsUsageProfile) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "slider.horizontal.3")
                .foregroundStyle(.secondary)
                .frame(width: 22)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 5) {
                Text(profile.label)
                    .font(.headline)
                Text(text.usagePlacement(profile.placement))
                    .foregroundStyle(.secondary)
                Text(text.capabilityLabel(profile.capability, version: profile.capabilityVersion))
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if AppsToolsCompatibilityDisclosurePolicy.requiresDisclosure(
                    capability: profile.capability
                ) {
                    AppsToolsCompatibilityDisclosure(text: text, compact: true)
                        .padding(.top, 3)
                }
            }

            Spacer(minLength: 12)

            Button(role: .destructive) {
                confirmation = .usageProfile(profile)
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .disabled(isBusy)
            .help(text.removeUsageProfile)
            .accessibilityLabel("\(text.removeUsageProfile): \(profile.label)")
        }
    }

    private func auditEventRow(_ event: AppsToolsAuditEvent) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: auditDecisionIcon(event.decision))
                .foregroundStyle(auditDecisionColor(event.decision))
                .frame(width: 22)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(text.auditEvent(event.kind, decision: event.decision))
                if let field = event.field {
                    Text(
                        [
                            field.credentialTitle,
                            field.fieldLabel
                        ]
                        .compactMap { $0 }
                        .joined(separator: " · ")
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                HStack(spacing: 8) {
                    Text(text.formattedDateTime(event.occurredAtMilliseconds))
                    Text(text.confirmationMethod(event.confirmationMethod))
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
    }

    private func detailSection<Content: View>(
        _ title: String,
        count: Int? = nil,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(title)
                    .font(.headline)
                if let count {
                    Text("\(count)")
                        .font(.caption)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            }
            content()
        }
    }

    private func emptySection(_ title: String) -> some View {
        Text(title)
            .font(.callout)
            .foregroundStyle(.secondary)
            .padding(.vertical, 4)
    }

    private func valueRow(
        _ label: String,
        _ value: String,
        monospaced: Bool = false
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 20) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .leading)
            Text(value)
                .font(monospaced ? .body.monospaced() : .body)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
    }

    private func auditDecisionIcon(_ decision: String) -> String {
        switch decision {
        case "allowed", "resumed":
            return "checkmark.circle.fill"
        case "denied", "failed":
            return "xmark.circle.fill"
        case "revoked":
            return "minus.circle.fill"
        case "paused":
            return "pause.circle.fill"
        default:
            return "clock.fill"
        }
    }

    private func auditDecisionColor(_ decision: String) -> Color {
        switch decision {
        case "allowed", "resumed":
            return .green
        case "denied", "failed", "revoked":
            return .red
        case "paused":
            return .orange
        default:
            return .secondary
        }
    }
}

private enum AppsToolsConfirmation: Identifiable {
    case field(AppsToolsFieldGrant)
    case consumer(String)
    case usageProfile(AppsToolsUsageProfile)

    var id: String {
        switch self {
        case let .field(grant):
            return "field:\(grant.id)"
        case let .consumer(label):
            return "consumer:\(label)"
        case let .usageProfile(profile):
            return "usage-profile:\(profile.id)"
        }
    }
}
