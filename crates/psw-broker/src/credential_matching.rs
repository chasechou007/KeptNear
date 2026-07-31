use std::fmt::{Debug, Display, Formatter};

use psw_core::{CredentialId, CredentialSummary, SecretFieldId, SecretFieldKind, VaultId};
use zeroize::Zeroize;

use crate::access_rule::{validate_capability, BrokerAccessRuleError};
use crate::credential_search::{BrokerCredentialMetadata, BrokerCredentialSearchManager};
use crate::protocol::BrokerErrorCode;
use crate::state_model::{
    AuthorizationTarget, Capability, CapabilityName, ConsumerId, CredentialFieldScope,
    VaultSessionId,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};

/// Maximum UTF-8 byte length accepted for a new credential request description.
pub const MAX_CREDENTIAL_REQUEST_DESCRIPTION_BYTES: usize = 256;

/// Maximum number of matching credentials shown in one human review.
pub const MAX_HUMAN_CREDENTIAL_CANDIDATES: usize = 50;

struct BrokerCredentialRequestDescription {
    display: String,
    normalized: String,
}

impl BrokerCredentialRequestDescription {
    fn new(mut text: String) -> Result<Self, BrokerCredentialMatchingError> {
        if validate_credential_request_description(&text).is_err() {
            text.zeroize();
            return Err(BrokerCredentialMatchingError::InvalidDescription);
        }
        let trimmed = text.trim();
        let display = trimmed.to_owned();
        let normalized = display.to_lowercase();
        text.zeroize();
        Ok(Self {
            display,
            normalized,
        })
    }

    fn duplicate(&self) -> Self {
        Self {
            display: self.display.clone(),
            normalized: self.normalized.clone(),
        }
    }
}

pub(crate) fn validate_credential_request_description(
    text: &str,
) -> Result<(), BrokerCredentialMatchingError> {
    let trimmed = text.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_CREDENTIAL_REQUEST_DESCRIPTION_BYTES
        || trimmed.chars().any(is_unsafe_request_character)
    {
        Err(BrokerCredentialMatchingError::InvalidDescription)
    } else {
        Ok(())
    }
}

impl Debug for BrokerCredentialRequestDescription {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerCredentialRequestDescription(<redacted>)")
    }
}

impl Drop for BrokerCredentialRequestDescription {
    fn drop(&mut self) {
        self.display.zeroize();
        self.normalized.zeroize();
    }
}

/// A paired Consumer's bounded description of a credential it cannot yet see.
///
/// Constructing this value does not admit the request, read a Vault, or expose
/// candidate metadata.
pub struct BrokerNewCredentialRequest {
    consumer_id: ConsumerId,
    vault_id: VaultId,
    capability: Capability,
    description: BrokerCredentialRequestDescription,
}

impl BrokerNewCredentialRequest {
    /// Builds one bounded request for a supported field-scoped capability.
    pub fn new(
        consumer_id: ConsumerId,
        vault_id: VaultId,
        capability: Capability,
        description: String,
    ) -> Result<Self, BrokerCredentialMatchingError> {
        let description = BrokerCredentialRequestDescription::new(description)?;
        validate_request_capability(capability)?;
        Ok(Self {
            consumer_id,
            vault_id,
            capability,
            description,
        })
    }
}

impl Debug for BrokerNewCredentialRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerNewCredentialRequest")
            .field("capability", &self.capability)
            .field("description", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A machine request admitted for later review without any candidate metadata.
///
/// This process-local value deliberately has no candidate accessor and no
/// serialization contract. Task 5.8 adds stable asynchronous request state.
pub struct BrokerAdmittedCredentialRequest {
    request: BrokerNewCredentialRequest,
}

impl BrokerAdmittedCredentialRequest {
    /// Returns the paired Consumer that submitted the request.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.request.consumer_id
    }

    /// Returns the requested stable Vault identity.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.request.vault_id
    }

    /// Returns the requested field-scoped capability.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.request.capability
    }

    pub(crate) fn normalized_description(&self) -> &str {
        &self.request.description.normalized
    }

    pub(crate) fn display_description(&self) -> &str {
        &self.request.description.display
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            request: BrokerNewCredentialRequest {
                consumer_id: self.request.consumer_id,
                vault_id: self.request.vault_id,
                capability: self.request.capability,
                description: self.request.description.duplicate(),
            },
        }
    }
}

impl Debug for BrokerAdmittedCredentialRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerAdmittedCredentialRequest")
            .field("capability", &self.request.capability)
            .field("candidate_metadata", &"<unavailable>")
            .finish_non_exhaustive()
    }
}

/// One capability-compatible Secret Field shown only to the local human.
#[derive(Eq, PartialEq)]
pub struct BrokerHumanSecretFieldCandidate {
    secret_field_id: SecretFieldId,
    role: String,
    label: Option<String>,
    kind: SecretFieldKind,
}

impl BrokerHumanSecretFieldCandidate {
    /// Returns the immutable Secret Field identity.
    #[must_use]
    pub const fn secret_field_id(&self) -> SecretFieldId {
        self.secret_field_id
    }

    /// Returns the provider-neutral field role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the optional user-visible field label.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns the authenticated Secret Field kind.
    #[must_use]
    pub const fn kind(&self) -> SecretFieldKind {
        self.kind
    }
}

impl Debug for BrokerHumanSecretFieldCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHumanSecretFieldCandidate")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerHumanSecretFieldCandidate {
    fn drop(&mut self) {
        self.role.zeroize();
        if let Some(label) = &mut self.label {
            label.zeroize();
        }
    }
}

/// One matched Credential shown only in the trusted local human control plane.
#[derive(Eq, PartialEq)]
pub struct BrokerHumanCredentialCandidate {
    vault_id: VaultId,
    credential_id: CredentialId,
    title: String,
    template_id: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    secret_fields: Vec<BrokerHumanSecretFieldCandidate>,
}

impl BrokerHumanCredentialCandidate {
    /// Returns the immutable Vault identity.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the immutable Credential identity.
    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// Returns the user-visible Credential title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the optional presentation template identity.
    #[must_use]
    pub fn template_id(&self) -> Option<&str> {
        self.template_id.as_deref()
    }

    /// Returns user-managed tags used only for local disambiguation.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Returns whether the Credential is marked as a favorite.
    #[must_use]
    pub const fn favorite(&self) -> bool {
        self.favorite
    }

    /// Returns only fields compatible with the requested capability.
    #[must_use]
    pub fn secret_fields(&self) -> &[BrokerHumanSecretFieldCandidate] {
        &self.secret_fields
    }
}

impl Debug for BrokerHumanCredentialCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHumanCredentialCandidate")
            .field("field_count", &self.secret_fields.len())
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerHumanCredentialCandidate {
    fn drop(&mut self) {
        self.title.zeroize();
        if let Some(template_id) = &mut self.template_id {
            template_id.zeroize();
        }
        for tag in &mut self.tags {
            tag.zeroize();
        }
    }
}

/// Human-only review containing matched candidates for one admitted request.
///
/// This value is not serializable and must never be returned by a Consumer
/// protocol handler.
pub struct BrokerHumanCredentialReview {
    consumer_id: ConsumerId,
    vault_id: VaultId,
    vault_session_id: VaultSessionId,
    capability: Capability,
    description: BrokerCredentialRequestDescription,
    candidates: Vec<BrokerHumanCredentialCandidate>,
    truncated: bool,
}

impl BrokerHumanCredentialReview {
    /// Returns the paired Consumer awaiting a local decision.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the Vault being reviewed.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the requested capability.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the bounded Consumer description for local human presentation.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description.display
    }

    /// Returns matched candidates visible only to the local human.
    #[must_use]
    pub fn candidates(&self) -> &[BrokerHumanCredentialCandidate] {
        &self.candidates
    }

    /// Returns whether additional matching candidates were omitted by the cap.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) const fn vault_session_id(&self) -> VaultSessionId {
        self.vault_session_id
    }
}

impl Debug for BrokerHumanCredentialReview {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHumanCredentialReview")
            .field("capability", &self.capability)
            .field("description", &"<redacted>")
            .field("candidate_count", &self.candidates.len())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// Exact Credential and Secret Field selected by the local human.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BrokerCredentialCandidateSelection {
    credential_id: CredentialId,
    secret_field_id: SecretFieldId,
}

impl BrokerCredentialCandidateSelection {
    /// Creates an exact selection from identities supplied by the local UI.
    #[must_use]
    pub const fn new(credential_id: CredentialId, secret_field_id: SecretFieldId) -> Self {
        Self {
            credential_id,
            secret_field_id,
        }
    }

    /// Returns the selected Credential identity.
    #[must_use]
    pub const fn credential_id(self) -> CredentialId {
        self.credential_id
    }

    /// Returns the selected Secret Field identity.
    #[must_use]
    pub const fn secret_field_id(self) -> SecretFieldId {
        self.secret_field_id
    }
}

impl Debug for BrokerCredentialCandidateSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerCredentialCandidateSelection(<redacted>)")
    }
}

/// Human-approved exact scope and minimum metadata safe to reveal afterward.
pub struct BrokerApprovedCredentialSelection {
    target: AuthorizationTarget,
    secret_kind: SecretFieldKind,
    metadata: BrokerCredentialMetadata,
}

impl BrokerApprovedCredentialSelection {
    /// Returns the exact Consumer, field, and capability authorization target.
    #[must_use]
    pub const fn target(&self) -> AuthorizationTarget {
        self.target
    }

    /// Returns the authenticated kind of the selected Secret Field.
    #[must_use]
    pub const fn secret_kind(&self) -> SecretFieldKind {
        self.secret_kind
    }

    /// Returns the minimum selected metadata that may be shown after approval.
    #[must_use]
    pub const fn metadata(&self) -> &BrokerCredentialMetadata {
        &self.metadata
    }
}

impl Debug for BrokerApprovedCredentialSelection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerApprovedCredentialSelection")
            .field("secret_kind", &self.secret_kind)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// Sanitized failure while matching a new credential request.
#[derive(Debug)]
pub enum BrokerCredentialMatchingError {
    /// The request description is empty, unbounded, or unsafe to display.
    InvalidDescription,
    /// The requested capability is not a supported field-scoped version.
    UnsupportedCapability,
    /// The requesting Consumer is not paired or was removed.
    ConsumerUnavailable,
    /// The selected Credential or field was not part of the human review.
    CandidateUnavailable,
    /// The reviewed Credential changed before the human decision committed.
    ReviewStale,
    /// Authenticated encrypted device state could not be read.
    DeviceState(DeviceStateError),
}

impl BrokerCredentialMatchingError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(&self) -> BrokerErrorCode {
        match self {
            Self::InvalidDescription => BrokerErrorCode::InvalidRequest,
            Self::UnsupportedCapability => BrokerErrorCode::UnsupportedCapability,
            Self::ConsumerUnavailable => BrokerErrorCode::ConsumerRevoked,
            Self::CandidateUnavailable | Self::ReviewStale => BrokerErrorCode::AccessDenied,
            Self::DeviceState(_) => BrokerErrorCode::OperationFailed,
        }
    }
}

impl Display for BrokerCredentialMatchingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDescription => {
                formatter.write_str("credential request description is invalid")
            }
            Self::UnsupportedCapability => {
                formatter.write_str("credential request capability is unsupported")
            }
            Self::ConsumerUnavailable => {
                formatter.write_str("credential request Consumer is unavailable")
            }
            Self::CandidateUnavailable => {
                formatter.write_str("credential request selection is unavailable")
            }
            Self::ReviewStale => formatter.write_str("credential request review is stale"),
            Self::DeviceState(source) => {
                write!(formatter, "credential request state failed: {source}")
            }
        }
    }
}

impl std::error::Error for BrokerCredentialMatchingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::InvalidDescription
            | Self::UnsupportedCapability
            | Self::ConsumerUnavailable
            | Self::CandidateUnavailable
            | Self::ReviewStale => None,
        }
    }
}

pub(crate) struct BrokerCredentialMatchingManager;

impl BrokerCredentialMatchingManager {
    pub(crate) fn admit(
        state: &DeviceStateStore,
        request: BrokerNewCredentialRequest,
    ) -> Result<BrokerAdmittedCredentialRequest, BrokerCredentialMatchingError> {
        Self::require_consumer(state, request.consumer_id)?;
        Ok(BrokerAdmittedCredentialRequest { request })
    }

    pub(crate) fn require_consumer(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
    ) -> Result<(), BrokerCredentialMatchingError> {
        if state
            .consumer(consumer_id)
            .map_err(BrokerCredentialMatchingError::DeviceState)?
            .is_none()
        {
            return Err(BrokerCredentialMatchingError::ConsumerUnavailable);
        }
        Ok(())
    }

    pub(crate) fn review(
        admitted: BrokerAdmittedCredentialRequest,
        vault_session_id: VaultSessionId,
        summaries: Vec<CredentialSummary>,
    ) -> BrokerHumanCredentialReview {
        let request = admitted.request;
        let mut candidates = summaries
            .into_iter()
            .filter(|summary| summary.vault_id == request.vault_id)
            .filter_map(|summary| {
                candidate_from_summary(summary, request.consumer_id, request.capability)
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.title
                .cmp(&right.title)
                .then_with(|| left.credential_id.cmp(&right.credential_id))
        });
        let truncated = candidates.len() > MAX_HUMAN_CREDENTIAL_CANDIDATES;
        candidates.truncate(MAX_HUMAN_CREDENTIAL_CANDIDATES);
        BrokerHumanCredentialReview {
            consumer_id: request.consumer_id,
            vault_id: request.vault_id,
            vault_session_id,
            capability: request.capability,
            description: request.description,
            candidates,
            truncated,
        }
    }

    pub(crate) fn approve(
        review: BrokerHumanCredentialReview,
        selection: BrokerCredentialCandidateSelection,
        summary: Option<CredentialSummary>,
    ) -> Result<BrokerApprovedCredentialSelection, BrokerCredentialMatchingError> {
        let reviewed = review
            .candidates
            .iter()
            .find(|candidate| candidate.credential_id == selection.credential_id)
            .ok_or(BrokerCredentialMatchingError::CandidateUnavailable)?;
        let reviewed_field = reviewed
            .secret_fields
            .iter()
            .find(|field| field.secret_field_id == selection.secret_field_id)
            .ok_or(BrokerCredentialMatchingError::CandidateUnavailable)?;
        let summary = summary.ok_or(BrokerCredentialMatchingError::ReviewStale)?;
        let latest = candidate_from_summary(summary.clone(), review.consumer_id, review.capability)
            .ok_or(BrokerCredentialMatchingError::ReviewStale)?;
        if latest != *reviewed {
            return Err(BrokerCredentialMatchingError::ReviewStale);
        }

        let target = AuthorizationTarget::new(
            review.consumer_id,
            CredentialFieldScope::new(
                review.vault_id,
                selection.credential_id,
                selection.secret_field_id,
            ),
            review.capability,
        );
        validate_capability(target, reviewed_field.kind).map_err(map_access_rule_error)?;
        let metadata = BrokerCredentialSearchManager::project_exact(
            target.field_scope(),
            reviewed_field.kind,
            Some(summary),
        )
        .map_err(|_| BrokerCredentialMatchingError::ReviewStale)?
        .ok_or(BrokerCredentialMatchingError::ReviewStale)?;
        Ok(BrokerApprovedCredentialSelection {
            target,
            secret_kind: reviewed_field.kind,
            metadata,
        })
    }
}

fn validate_request_capability(
    capability: Capability,
) -> Result<(), BrokerCredentialMatchingError> {
    if capability.version() != 1
        || !matches!(
            capability.name(),
            CapabilityName::CredentialSearch
                | CapabilityName::HttpRequest
                | CapabilityName::ProcessRun
        )
    {
        return Err(BrokerCredentialMatchingError::UnsupportedCapability);
    }
    Ok(())
}

fn candidate_from_summary(
    mut summary: CredentialSummary,
    consumer_id: ConsumerId,
    capability: Capability,
) -> Option<BrokerHumanCredentialCandidate> {
    let mut compatible_fields = Vec::new();
    for mut field in summary.secret_fields.drain(..) {
        let target = AuthorizationTarget::new(
            consumer_id,
            CredentialFieldScope::new(
                summary.vault_id,
                summary.credential_id,
                field.secret_field_id,
            ),
            capability,
        );
        if validate_capability(target, field.kind).is_ok() {
            compatible_fields.push(BrokerHumanSecretFieldCandidate {
                secret_field_id: field.secret_field_id,
                role: std::mem::take(&mut field.role),
                label: field.label.take(),
                kind: field.kind,
            });
        }
        field.role.zeroize();
        if let Some(label) = &mut field.label {
            label.zeroize();
        }
    }
    if compatible_fields.is_empty() {
        zeroize_summary_metadata(&mut summary);
        return None;
    }
    Some(BrokerHumanCredentialCandidate {
        vault_id: summary.vault_id,
        credential_id: summary.credential_id,
        title: std::mem::take(&mut summary.title),
        template_id: summary.template_id.take(),
        tags: std::mem::take(&mut summary.tags),
        favorite: summary.favorite,
        secret_fields: compatible_fields,
    })
}

fn zeroize_summary_metadata(summary: &mut CredentialSummary) {
    summary.title.zeroize();
    if let Some(template_id) = &mut summary.template_id {
        template_id.zeroize();
    }
    for tag in &mut summary.tags {
        tag.zeroize();
    }
    for field in &mut summary.secret_fields {
        field.role.zeroize();
        if let Some(label) = &mut field.label {
            label.zeroize();
        }
    }
}

fn is_unsafe_request_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn map_access_rule_error(error: BrokerAccessRuleError) -> BrokerCredentialMatchingError {
    match error {
        BrokerAccessRuleError::UnsupportedCapability
        | BrokerAccessRuleError::IncompatibleSecretKind => {
            BrokerCredentialMatchingError::ReviewStale
        }
        BrokerAccessRuleError::ConsumerUnavailable => {
            BrokerCredentialMatchingError::ConsumerUnavailable
        }
        BrokerAccessRuleError::DeviceState(source) => {
            BrokerCredentialMatchingError::DeviceState(source)
        }
        BrokerAccessRuleError::InvalidLifetime | BrokerAccessRuleError::ConflictingRule => {
            BrokerCredentialMatchingError::ReviewStale
        }
    }
}

#[cfg(test)]
mod tests {
    use psw_core::SecretFieldSummary;

    use super::*;

    fn summary(
        vault_id: VaultId,
        title: &str,
        template_id: Option<&str>,
        tags: &[&str],
        fields: Vec<SecretFieldSummary>,
    ) -> CredentialSummary {
        CredentialSummary {
            vault_id,
            credential_id: CredentialId::generate(),
            title: title.to_owned(),
            template_id: template_id.map(str::to_owned),
            secret_fields: fields,
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            favorite: false,
        }
    }

    fn field(role: &str, label: Option<&str>, kind: SecretFieldKind) -> SecretFieldSummary {
        SecretFieldSummary {
            secret_field_id: SecretFieldId::generate(),
            role: role.to_owned(),
            label: label.map(str::to_owned),
            kind,
        }
    }

    fn admitted(
        consumer_id: ConsumerId,
        vault_id: VaultId,
        capability: CapabilityName,
        description: &str,
    ) -> BrokerAdmittedCredentialRequest {
        BrokerAdmittedCredentialRequest {
            request: BrokerNewCredentialRequest::new(
                consumer_id,
                vault_id,
                Capability::v1(capability),
                description.to_owned(),
            )
            .expect("request"),
        }
    }

    #[test]
    fn request_description_is_bounded_display_safe_and_debug_redacted() {
        let consumer_id = ConsumerId::generate();
        let vault_id = VaultId::generate();
        let request = BrokerNewCredentialRequest::new(
            consumer_id,
            vault_id,
            Capability::v1(CapabilityName::HttpRequest),
            "  GitHub release token  ".to_owned(),
        )
        .expect("request");
        let debug = format!("{request:?}");
        assert!(!debug.contains("GitHub"));
        assert!(!debug.contains(&consumer_id.to_string()));
        assert!(!debug.contains(&vault_id.to_string()));

        for invalid in [
            String::new(),
            "line\nbreak".to_owned(),
            "spoof \u{202e} token".to_owned(),
            "x".repeat(MAX_CREDENTIAL_REQUEST_DESCRIPTION_BYTES + 1),
        ] {
            assert!(matches!(
                BrokerNewCredentialRequest::new(
                    consumer_id,
                    vault_id,
                    Capability::v1(CapabilityName::HttpRequest),
                    invalid,
                ),
                Err(BrokerCredentialMatchingError::InvalidDescription)
            ));
        }
    }

    #[test]
    fn human_review_keeps_only_capability_compatible_fields() {
        let consumer_id = ConsumerId::generate();
        let vault_id = VaultId::generate();
        let matching = summary(
            vault_id,
            "Deployment",
            Some("service"),
            &["github", "production"],
            vec![
                field("token", Some("Release token"), SecretFieldKind::ApiToken),
                field("ssh", Some("Deploy key"), SecretFieldKind::PrivateKey),
            ],
        );
        let review = BrokerCredentialMatchingManager::review(
            admitted(consumer_id, vault_id, CapabilityName::HttpRequest, "github"),
            VaultSessionId::generate(),
            vec![matching],
        );

        assert_eq!(review.description(), "github");
        assert_eq!(review.candidates().len(), 1);
        let candidate = &review.candidates()[0];
        assert_eq!(candidate.title(), "Deployment");
        assert_eq!(candidate.tags(), &["github", "production"]);
        assert_eq!(candidate.secret_fields().len(), 1);
        assert_eq!(
            candidate.secret_fields()[0].kind(),
            SecretFieldKind::ApiToken
        );
        let debug = format!("{review:?}");
        assert!(!debug.contains("github"));
        assert!(!debug.contains("Deployment"));
        assert!(!debug.contains("Release token"));
    }

    #[test]
    fn human_review_caps_candidate_count_without_returning_a_vault_catalog() {
        let consumer_id = ConsumerId::generate();
        let vault_id = VaultId::generate();
        let summaries = (0..=MAX_HUMAN_CREDENTIAL_CANDIDATES)
            .map(|index| {
                summary(
                    vault_id,
                    &format!("Service {index:02}"),
                    None,
                    &["shared-match"],
                    vec![field("token", None, SecretFieldKind::ApiToken)],
                )
            })
            .collect();
        let review = BrokerCredentialMatchingManager::review(
            admitted(
                consumer_id,
                vault_id,
                CapabilityName::CredentialSearch,
                "shared-match",
            ),
            VaultSessionId::generate(),
            summaries,
        );
        assert_eq!(review.candidates().len(), MAX_HUMAN_CREDENTIAL_CANDIDATES);
        assert!(review.truncated());
    }

    #[test]
    fn approval_returns_only_the_selected_exact_scope_and_minimum_metadata() {
        let consumer_id = ConsumerId::generate();
        let vault_id = VaultId::generate();
        let summary = summary(
            vault_id,
            "GitHub production",
            Some("private-template"),
            &["private-tag"],
            vec![
                field("token", Some("API token"), SecretFieldKind::ApiToken),
                field(
                    "password",
                    Some("Unselected password"),
                    SecretFieldKind::Password,
                ),
            ],
        );
        let credential_id = summary.credential_id;
        let selected_field_id = summary.secret_fields[0].secret_field_id;
        let review = BrokerCredentialMatchingManager::review(
            admitted(consumer_id, vault_id, CapabilityName::HttpRequest, "github"),
            VaultSessionId::generate(),
            vec![summary.clone()],
        );
        let approved = BrokerCredentialMatchingManager::approve(
            review,
            BrokerCredentialCandidateSelection::new(credential_id, selected_field_id),
            Some(summary),
        )
        .expect("approval");

        assert_eq!(approved.target().consumer_id(), consumer_id);
        assert_eq!(approved.target().field_scope().vault_id(), vault_id);
        assert_eq!(
            approved.target().field_scope().credential_id(),
            credential_id
        );
        assert_eq!(
            approved.target().field_scope().secret_field_id(),
            selected_field_id
        );
        assert_eq!(approved.secret_kind(), SecretFieldKind::ApiToken);
        assert_eq!(approved.metadata().title(), "GitHub production");
        assert_eq!(
            approved.metadata().authorized_field().label(),
            Some("API token")
        );
    }

    #[test]
    fn unavailable_or_changed_selection_fails_closed() {
        let consumer_id = ConsumerId::generate();
        let vault_id = VaultId::generate();
        let summary = summary(
            vault_id,
            "Original title",
            None,
            &["match"],
            vec![field("token", None, SecretFieldKind::ApiToken)],
        );
        let credential_id = summary.credential_id;
        let field_id = summary.secret_fields[0].secret_field_id;
        let review = BrokerCredentialMatchingManager::review(
            admitted(consumer_id, vault_id, CapabilityName::HttpRequest, "match"),
            VaultSessionId::generate(),
            vec![summary.clone()],
        );
        assert!(matches!(
            BrokerCredentialMatchingManager::approve(
                review,
                BrokerCredentialCandidateSelection::new(
                    CredentialId::generate(),
                    SecretFieldId::generate(),
                ),
                Some(summary.clone()),
            ),
            Err(BrokerCredentialMatchingError::CandidateUnavailable)
        ));

        let review = BrokerCredentialMatchingManager::review(
            admitted(consumer_id, vault_id, CapabilityName::HttpRequest, "match"),
            VaultSessionId::generate(),
            vec![summary.clone()],
        );
        let mut changed = summary;
        changed.title = "Changed title".to_owned();
        assert!(matches!(
            BrokerCredentialMatchingManager::approve(
                review,
                BrokerCredentialCandidateSelection::new(credential_id, field_id),
                Some(changed),
            ),
            Err(BrokerCredentialMatchingError::ReviewStale)
        ));
    }
}
