import SwiftUI

struct UsageProfileSetupView: View {
    let text: AppText
    let consumer: AppsToolsConsumerSummary
    let setup: AppsToolsUsageProfileSetup
    let isBusy: Bool
    let actionFailed: Bool
    let save: (AppsToolsUsageProfileDraft) -> Bool

    @Environment(\.dismiss) private var dismiss
    @State private var destination: UsageProfileDestination
    @State private var webAuthentication: UsageProfileWebAuthentication
    @State private var profileName: String
    @State private var technicalName: String
    @State private var advancedSettingsExpanded = false

    init(
        text: AppText,
        consumer: AppsToolsConsumerSummary,
        setup: AppsToolsUsageProfileSetup,
        isBusy: Bool,
        actionFailed: Bool,
        save: @escaping (AppsToolsUsageProfileDraft) -> Bool
    ) {
        self.text = text
        self.consumer = consumer
        self.setup = setup
        self.isBusy = isBusy
        self.actionFailed = actionFailed
        self.save = save

        let recommendation = setup.recommendation
        let recommendedTemplateId = recommendation?.templateId
        _destination = State(
            initialValue: recommendedTemplateId == "cli-environment-variable"
                ? .commandLine
                : .webApi
        )
        _webAuthentication = State(
            initialValue: recommendedTemplateId == "http-api-key-header"
                ? .apiKey
                : .bearer
        )
        _profileName = State(
            initialValue: recommendation.map {
                text.usageProfileRecommendationName(
                    $0.recommendationId,
                    fallback: consumer.label
                )
            } ?? consumer.label
        )
        _technicalName = State(
            initialValue: recommendation?.technicalName
                ?? setup.template("http-api-key-header")?.suggestedValue
                ?? ""
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(text.usageProfileSetupTitle)
                    .font(.title2)
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 18)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if let recommendation = setup.recommendation {
                        recommendationView(recommendation)
                    }

                    setupSection(text.usageProfileName) {
                        TextField(text.usageProfileName, text: $profileName)
                            .textFieldStyle(.roundedBorder)
                    }

                    setupSection(text.usageDestination) {
                        Picker(text.usageDestination, selection: $destination) {
                            ForEach(UsageProfileDestination.allCases) { destination in
                                Text(destination.label(text)).tag(destination)
                            }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .onChange(of: destination) { _ in
                            resetTechnicalNameForSelection()
                        }

                        if destination == .webApi {
                            Picker(text.webApiAuthentication, selection: $webAuthentication) {
                                ForEach(UsageProfileWebAuthentication.allCases) { authentication in
                                    Text(authentication.label(text)).tag(authentication)
                                }
                            }
                            .pickerStyle(.radioGroup)
                            .onChange(of: webAuthentication) { _ in
                                resetTechnicalNameForSelection()
                            }
                        }
                    }

                    DisclosureGroup(
                        text.advancedSettings,
                        isExpanded: $advancedSettingsExpanded
                    ) {
                        VStack(alignment: .leading, spacing: 12) {
                            Label(
                                text.usagePlacement(selectedPlacement),
                                systemImage: "arrow.right.square"
                            )
                            .foregroundStyle(.secondary)

                            Label(
                                text.capabilityLabel(
                                    selectedTemplate?.capability ?? "",
                                    version: selectedTemplate?.capabilityVersion ?? 1
                                ),
                                systemImage: "bolt.horizontal"
                            )
                            .foregroundStyle(.secondary)

                            if selectedTemplate?.technicalField == "environment-variable-name" {
                                TextField(text.environmentVariableName, text: $technicalName)
                                    .textFieldStyle(.roundedBorder)
                                    .accessibilityLabel(text.environmentVariableName)
                            } else if selectedTemplate?.technicalField == "http-header-name" {
                                TextField(text.httpHeaderName, text: $technicalName)
                                    .textFieldStyle(.roundedBorder)
                                    .accessibilityLabel(text.httpHeaderName)
                            }
                        }
                        .padding(.top, 10)
                    }

                    if requiresTechnicalName, normalizedTechnicalName == nil {
                        Label(text.technicalNameRequired, systemImage: "info.circle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }

                    if destination == .commandLine {
                        AppsToolsCompatibilityDisclosure(text: text)
                    }

                    Label(text.usageProfileNoSecretNotice, systemImage: "lock.shield")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    if actionFailed {
                        Label(text.usageProfileActionFailed, systemImage: "exclamationmark.circle")
                            .font(.callout)
                            .foregroundStyle(.red)
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider()

            HStack(spacing: 10) {
                Spacer()
                Button(text.cancel) {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Button {
                    let draft = AppsToolsUsageProfileDraft(
                        label: profileName.trimmingCharacters(in: .whitespacesAndNewlines),
                        templateId: selectedTemplateId,
                        technicalName: normalizedTechnicalName
                    )
                    if save(draft) {
                        dismiss()
                    }
                } label: {
                    Label(text.saveUsageProfile, systemImage: "checkmark")
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave || isBusy)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 14)
        }
        .frame(minWidth: 520, idealWidth: 560, minHeight: 500, idealHeight: 560)
    }

    private func recommendationView(
        _ recommendation: AppsToolsUsageProfileRecommendation
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "sparkles")
                .foregroundStyle(Color.accentColor)
                .frame(width: 22)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 5) {
                Text(text.automaticRecommendation)
                    .font(.headline)
                Text(
                    text.usageProfileRecommendation(
                        recommendation.recommendationId,
                        toolName: consumer.label
                    )
                )
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 16)

            Button(text.useRecommendation) {
                applyRecommendation(recommendation)
            }
            .disabled(isBusy)
        }
        .padding(14)
        .background(Color.accentColor.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func setupSection<Content: View>(
        _ title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.headline)
            content()
        }
    }

    private var selectedTemplateId: String {
        switch destination {
        case .commandLine:
            return "cli-environment-variable"
        case .webApi:
            return webAuthentication == .bearer
                ? "http-bearer-authorization"
                : "http-api-key-header"
        }
    }

    private var selectedTemplate: AppsToolsUsageProfileTemplate? {
        setup.template(selectedTemplateId)
    }

    private var requiresTechnicalName: Bool {
        switch selectedTemplate?.technicalField {
        case "environment-variable-name", "http-header-name":
            return true
        default:
            return false
        }
    }

    private var normalizedTechnicalName: String? {
        guard requiresTechnicalName else { return nil }
        let value = technicalName.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    private var canSave: Bool {
        !profileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && selectedTemplate != nil
            && (!requiresTechnicalName || normalizedTechnicalName != nil)
    }

    private var selectedPlacement: AppsToolsUsagePlacement {
        switch selectedTemplateId {
        case "cli-environment-variable":
            return AppsToolsUsagePlacement(
                kind: "process-environment",
                variableName: normalizedTechnicalName,
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: nil
            )
        case "http-api-key-header":
            return AppsToolsUsagePlacement(
                kind: "http-header",
                variableName: nil,
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: normalizedTechnicalName
            )
        default:
            return AppsToolsUsagePlacement(
                kind: "http-bearer-authorization",
                variableName: nil,
                appendNewline: nil,
                referenceVariableName: nil,
                renderDevFdPath: nil,
                headerName: nil
            )
        }
    }

    private func resetTechnicalNameForSelection() {
        if destination == .commandLine {
            technicalName = setup.recommendation?.templateId == selectedTemplateId
                ? setup.recommendation?.technicalName ?? ""
                : ""
            return
        }
        technicalName = webAuthentication == .apiKey
            ? setup.template("http-api-key-header")?.suggestedValue ?? ""
            : ""
    }

    private func applyRecommendation(
        _ recommendation: AppsToolsUsageProfileRecommendation
    ) {
        switch recommendation.templateId {
        case "cli-environment-variable":
            destination = .commandLine
        case "http-api-key-header":
            destination = .webApi
            webAuthentication = .apiKey
        default:
            destination = .webApi
            webAuthentication = .bearer
        }
        profileName = text.usageProfileRecommendationName(
            recommendation.recommendationId,
            fallback: consumer.label
        )
        technicalName = recommendation.technicalName
    }
}

private enum UsageProfileDestination: String, CaseIterable, Identifiable {
    case commandLine
    case webApi

    var id: String { rawValue }

    func label(_ text: AppText) -> String {
        switch self {
        case .commandLine:
            return text.commandLineTool
        case .webApi:
            return text.webApi
        }
    }
}

private enum UsageProfileWebAuthentication: String, CaseIterable, Identifiable {
    case bearer
    case apiKey

    var id: String { rawValue }

    func label(_ text: AppText) -> String {
        switch self {
        case .bearer:
            return text.bearerToken
        case .apiKey:
            return text.apiKeyHeader
        }
    }
}
