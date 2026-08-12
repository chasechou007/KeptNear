use std::collections::VecDeque;
use std::fmt::{Debug, Display, Formatter};
use std::time::Instant;

use psw_core::{SecretBytes, VaultId};

use crate::{
    bundled_usage_profile_templates, recommend_bundled_usage_profile, ApprovalRequestId,
    BrokerAppsToolsSnapshot, BrokerAuditClearConfirmation, BrokerAuditClearSummary,
    BrokerAuditCursor, BrokerAuditExport, BrokerAuditFilter, BrokerAuditPage,
    BrokerConsumerAuditSummary, BrokerConsumerDetail, BrokerConsumerIdentityEvidence,
    BrokerConsumerSummary, BrokerCredentialCandidateSelection, BrokerFieldGrantSummary,
    BrokerGrantInvalidationSummary, BrokerHumanCredentialCandidate, BrokerHumanCredentialReview,
    BrokerInstanceId, BrokerPairingUserApproval, BrokerPendingRequest, BrokerPendingRequestId,
    BrokerPendingRequestKind, BrokerReadinessProjection, BrokerRevocationSummary, BrokerRuntime,
    BrokerRuntimeError, BrokerUsageProfileSummary, BrokerVaultSessionSnapshot,
    BundledUsageProfileRecommendation, BundledUsageProfileTemplate, Capability, ConfirmationPolicy,
    ConsumerEvidenceFingerprint, ConsumerId, ControllerAuthenticationChallenge,
    ControllerAuthenticationCompletion, ControllerAuthenticationConnection,
    ControllerAuthenticationError, ControllerAuthenticationMode, ControllerAuthenticationProof,
    ControllerAuthenticationService, ControllerAuthorityError, ControllerAuthorityManager,
    ControllerBootstrapMode, ControllerChallengeRequest, ControllerId, ControllerKeyStore,
    ControllerSessionId, CredentialFieldScope, CredentialId, HumanControlAuditConfirmationId,
    HumanControlFailureCode, HumanControlOperation, HumanControlProtocolFailure,
    HumanControlProtocolVersion, HumanControlRequiredAction, HumanControlVersionOffer,
    PackagedComponent, PairingComparisonCode, PairingRequestId, RuleLifetime, SecretFieldId,
    SecretFieldKind, StateTimestamp, UsageProfile, UsageProfileDefinition, UsageProfileId,
    UseGrantId, CONTROLLER_ROLE, HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE,
    HUMAN_CONTROL_CONTROLLER_LEASE_TTL, HUMAN_CONTROL_DENY_DECISION, HUMAN_CONTROL_SCHEMA_ID,
    HUMAN_CONTROL_SHUTDOWN_REASON, MAX_HUMAN_CONTROL_AUDIT_CLEAR_CONFIRMATIONS,
    MAX_HUMAN_CONTROL_AUDIT_EVENTS, MAX_HUMAN_CONTROL_COLLECTION_ITEMS,
    MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
};

const MAX_HUMAN_CONTROL_AUDIT_EXPORT_BYTES: usize = MAX_HUMAN_CONTROL_RESPONSE_LENGTH / 2;
const MAX_HUMAN_CONTROL_CREDENTIAL_REVIEW_BYTES: usize = MAX_HUMAN_CONTROL_RESPONSE_LENGTH / 2;
const MAX_HUMAN_CONTROL_METADATA_TEXT_BYTES: usize = 1_024;
const HUMAN_CONTROL_CREDENTIAL_CANDIDATE_OVERHEAD_BYTES: usize = 512;
const HUMAN_CONTROL_SECRET_FIELD_OVERHEAD_BYTES: usize = 192;
const HUMAN_CONTROL_TAG_OVERHEAD_BYTES: usize = 32;

const HUMAN_CONTROL_DISPATCH_OPERATIONS: [HumanControlOperation; 29] = [
    HumanControlOperation::Hello,
    HumanControlOperation::ControllerChallenge,
    HumanControlOperation::ControllerAuthenticate,
    HumanControlOperation::ControllerLeaseRenew,
    HumanControlOperation::ReadinessGet,
    HumanControlOperation::MachineAccessPauseSet,
    HumanControlOperation::VaultUnlock,
    HumanControlOperation::VaultLock,
    HumanControlOperation::PendingList,
    HumanControlOperation::PendingDeny,
    HumanControlOperation::PairingApprove,
    HumanControlOperation::UnlockApprove,
    HumanControlOperation::CredentialReview,
    HumanControlOperation::CredentialAllowOnce,
    HumanControlOperation::CredentialAuthorize,
    HumanControlOperation::AuthorizationSnapshot,
    HumanControlOperation::ConsumerDetail,
    HumanControlOperation::UsageProfileCatalog,
    HumanControlOperation::UsageProfileCreate,
    HumanControlOperation::UsageProfileRemove,
    HumanControlOperation::FieldAccessRevoke,
    HumanControlOperation::GrantRevoke,
    HumanControlOperation::ConsumerRevoke,
    HumanControlOperation::AllAccessRevoke,
    HumanControlOperation::AuditList,
    HumanControlOperation::AuditClear,
    HumanControlOperation::AuditExport,
    HumanControlOperation::RepairPrepare,
    HumanControlOperation::Shutdown,
];

/// The only secret-bearing value accepted by the human-control dispatcher.
pub enum HumanControlVaultUnlockCredential {
    /// User-entered Vault master password.
    MasterPassword(SecretBytes),
    /// Approved device-local convenience-unlock material.
    LocalMaterial(SecretBytes),
}

impl Debug for HumanControlVaultUnlockCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HumanControlVaultUnlockCredential(<redacted>)")
    }
}

/// Closed typed request catalog for human-control protocol version 1.
pub enum HumanControlRequest {
    /// Negotiate one supported version.
    Hello(HumanControlVersionOffer),
    /// Request a fresh controller challenge.
    ControllerChallenge(ControllerChallengeRequest),
    /// Submit one single-use controller proof.
    ControllerAuthenticate(ControllerAuthenticationProof),
    /// Confirm the current connection lease remains active.
    ControllerLeaseRenew {
        /// Exact authenticated controller session being renewed.
        controller_session_id: ControllerSessionId,
        /// Exact running Broker process instance being renewed.
        broker_instance_id: BrokerInstanceId,
    },
    /// Read Broker service readiness.
    ReadinessGet,
    /// Persist Machine Access Pause independently from service health.
    MachineAccessPauseSet {
        /// Requested persisted pause state.
        paused: bool,
    },
    /// Unlock one already-tracked machine Vault.
    VaultUnlock {
        /// Stable identity of the already-tracked Vault.
        vault_id: VaultId,
        /// Exactly one zeroizing unlock credential.
        credential: HumanControlVaultUnlockCredential,
    },
    /// Lock one machine Vault and invalidate its grants.
    VaultLock {
        /// Stable identity of the tracked Vault.
        vault_id: VaultId,
    },
    /// List pending decisions without private request descriptions.
    PendingList,
    /// Deny one exact pending decision.
    PendingDeny {
        /// Stable pending decision identity.
        request_id: BrokerPendingRequestId,
        /// Fixed denial decision retained from the closed wire body.
        decision: String,
    },
    /// Approve one exact Consumer pairing.
    PairingApprove {
        /// Process-local pairing request identity.
        request_id: PairingRequestId,
        /// Explicit local user approval and bounded label.
        approval: BrokerPairingUserApproval,
    },
    /// Approve one pending unlock after the machine Vault is unlocked.
    UnlockApprove {
        /// Persisted unlock approval identity.
        request_id: ApprovalRequestId,
        /// Exact Vault identity shown to the human controller.
        vault_id: VaultId,
    },
    /// Review credential candidates without returning the Consumer description.
    CredentialReview {
        /// Persisted credential-access approval identity.
        request_id: ApprovalRequestId,
    },
    /// Approve one exact request once.
    CredentialAllowOnce {
        /// Persisted field or credential-access approval identity.
        request_id: ApprovalRequestId,
        /// Exact Credential and Secret Field submitted by the controller.
        selection: BrokerCredentialCandidateSelection,
    },
    /// Create one exact Access Rule.
    CredentialAuthorize {
        /// Persisted field or credential-access approval identity.
        request_id: ApprovalRequestId,
        /// Exact Credential and Secret Field submitted by the controller.
        selection: BrokerCredentialCandidateSelection,
        /// Human-selected confirmation policy for the Access Rule.
        confirmation_policy: ConfirmationPolicy,
        /// Human-selected persistent or absolute expiry boundary.
        rule_lifetime: RuleLifetime,
        /// Exact capability shown to the human controller.
        capability: Capability,
    },
    /// Read one Vault's secret-free authorization summary.
    AuthorizationSnapshot {
        /// Stable Vault identity used to scope the inventory.
        vault_id: VaultId,
    },
    /// Read one Consumer's management detail.
    ConsumerDetail {
        /// Stable paired Consumer identity.
        consumer_id: ConsumerId,
    },
    /// Read provider-neutral Usage Profile templates.
    UsageProfileCatalog {
        /// Stable paired Consumer identity.
        consumer_id: ConsumerId,
        /// Optional bounded executable basename for offline recommendation.
        executable_name_hint: Option<String>,
    },
    /// Create one declarative Consumer-owned Usage Profile.
    UsageProfileCreate {
        /// Stable paired Consumer identity.
        consumer_id: ConsumerId,
        /// Human-readable local profile label.
        label: String,
        /// Declarative capability-compatible placement definition.
        definition: UsageProfileDefinition,
    },
    /// Remove one declarative Usage Profile.
    UsageProfileRemove {
        /// Stable paired Consumer identity.
        consumer_id: ConsumerId,
        /// Stable Consumer-owned Usage Profile identity.
        usage_profile_id: UsageProfileId,
    },
    /// Revoke one exact Consumer and Secret Field boundary.
    FieldAccessRevoke {
        /// Stable paired Consumer identity.
        consumer_id: ConsumerId,
        /// Exact Vault, Credential, and Secret Field scope.
        field_scope: CredentialFieldScope,
    },
    /// Revoke one exact Consumer-owned Use Grant.
    GrantRevoke {
        /// Stable paired Consumer identity.
        consumer_id: ConsumerId,
        /// Stable Consumer-owned Use Grant identity.
        use_grant_id: UseGrantId,
    },
    /// Unpair one Consumer and revoke its future authorization.
    ConsumerRevoke {
        /// Stable paired Consumer identity.
        consumer_id: ConsumerId,
        /// Fixed destructive revocation scope retained from the wire body.
        scope: String,
    },
    /// Revoke every Consumer authorization without changing human Vault data.
    AllAccessRevoke,
    /// Read one bounded audit page.
    AuditList {
        /// Exact non-secret audit selection.
        filter: BrokerAuditFilter,
        /// Optional newest-first continuation position.
        cursor: Option<BrokerAuditCursor>,
        /// Bounded maximum event count.
        limit: usize,
    },
    /// Clear one explicitly confirmed audit selection.
    AuditClear {
        /// Exact non-secret audit selection.
        filter: BrokerAuditFilter,
        /// Exact identity issued with the confirmed audit selection.
        confirmation_id: HumanControlAuditConfirmationId,
    },
    /// Export one bounded non-secret audit document.
    AuditExport {
        /// Exact non-secret audit selection.
        filter: BrokerAuditFilter,
        /// Bounded maximum exported event count.
        limit: usize,
    },
    /// Quiesce process state before App-managed repair.
    RepairPrepare {
        /// Exact component the controller expects to quiesce.
        expected_component: PackagedComponent,
        /// Exact human-control protocol expected by the repair client.
        expected_protocol: HumanControlProtocolVersion,
    },
    /// Gracefully stop process-owned sessions and grants.
    Shutdown {
        /// Fixed shutdown reason retained from the wire body.
        reason: String,
    },
}

impl HumanControlRequest {
    /// Returns the exact frozen operation represented by this request variant.
    #[must_use]
    pub const fn operation(&self) -> HumanControlOperation {
        match self {
            Self::Hello(_) => HumanControlOperation::Hello,
            Self::ControllerChallenge(_) => HumanControlOperation::ControllerChallenge,
            Self::ControllerAuthenticate(_) => HumanControlOperation::ControllerAuthenticate,
            Self::ControllerLeaseRenew { .. } => HumanControlOperation::ControllerLeaseRenew,
            Self::ReadinessGet => HumanControlOperation::ReadinessGet,
            Self::MachineAccessPauseSet { .. } => HumanControlOperation::MachineAccessPauseSet,
            Self::VaultUnlock { .. } => HumanControlOperation::VaultUnlock,
            Self::VaultLock { .. } => HumanControlOperation::VaultLock,
            Self::PendingList => HumanControlOperation::PendingList,
            Self::PendingDeny { .. } => HumanControlOperation::PendingDeny,
            Self::PairingApprove { .. } => HumanControlOperation::PairingApprove,
            Self::UnlockApprove { .. } => HumanControlOperation::UnlockApprove,
            Self::CredentialReview { .. } => HumanControlOperation::CredentialReview,
            Self::CredentialAllowOnce { .. } => HumanControlOperation::CredentialAllowOnce,
            Self::CredentialAuthorize { .. } => HumanControlOperation::CredentialAuthorize,
            Self::AuthorizationSnapshot { .. } => HumanControlOperation::AuthorizationSnapshot,
            Self::ConsumerDetail { .. } => HumanControlOperation::ConsumerDetail,
            Self::UsageProfileCatalog { .. } => HumanControlOperation::UsageProfileCatalog,
            Self::UsageProfileCreate { .. } => HumanControlOperation::UsageProfileCreate,
            Self::UsageProfileRemove { .. } => HumanControlOperation::UsageProfileRemove,
            Self::FieldAccessRevoke { .. } => HumanControlOperation::FieldAccessRevoke,
            Self::GrantRevoke { .. } => HumanControlOperation::GrantRevoke,
            Self::ConsumerRevoke { .. } => HumanControlOperation::ConsumerRevoke,
            Self::AllAccessRevoke => HumanControlOperation::AllAccessRevoke,
            Self::AuditList { .. } => HumanControlOperation::AuditList,
            Self::AuditClear { .. } => HumanControlOperation::AuditClear,
            Self::AuditExport { .. } => HumanControlOperation::AuditExport,
            Self::RepairPrepare { .. } => HumanControlOperation::RepairPrepare,
            Self::Shutdown { .. } => HumanControlOperation::Shutdown,
        }
    }
}

impl Debug for HumanControlRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanControlRequest")
            .field("operation", &self.operation())
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Pending-decision projection that deliberately excludes request descriptions.
#[derive(Clone, Eq, PartialEq)]
pub struct HumanControlPendingRequest {
    /// Stable pending identity.
    pub request_id: BrokerPendingRequestId,
    /// Fixed decision kind.
    pub kind: BrokerPendingRequestKind,
    /// Stable paired Consumer identity when allocated.
    pub consumer_id: Option<ConsumerId>,
    /// Bounded path-free operating-system evidence for pairing verification.
    pub identity_evidence: Option<BrokerConsumerIdentityEvidence>,
    /// Human comparison code shared with the requesting Consumer.
    pub pairing_comparison_code: Option<PairingComparisonCode>,
    /// Short fingerprint of the proposed Consumer pairing key.
    pub pairing_key_fingerprint: Option<ConsumerEvidenceFingerprint>,
    /// Remaining process-local pairing lifetime in milliseconds.
    pub pairing_remaining_millis: Option<u64>,
    /// Stable Vault identity when applicable.
    pub vault_id: Option<VaultId>,
    /// Exact field scope when the request already names one.
    pub field_scope: Option<CredentialFieldScope>,
    /// Requested capability metadata without an operation payload.
    pub capability: Option<Capability>,
    /// Creation time for persisted approvals.
    pub created_at: Option<StateTimestamp>,
    /// Exclusive expiry for persisted approvals.
    pub expires_at: Option<StateTimestamp>,
}

impl From<&BrokerPendingRequest> for HumanControlPendingRequest {
    fn from(request: &BrokerPendingRequest) -> Self {
        Self {
            request_id: request.request_id(),
            kind: request.kind(),
            consumer_id: request.consumer_id(),
            identity_evidence: request.identity_evidence().cloned(),
            pairing_comparison_code: request.pairing_comparison_code(),
            pairing_key_fingerprint: request.pairing_key_fingerprint(),
            pairing_remaining_millis: request
                .remaining()
                .map(|remaining| u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
            vault_id: request.vault_id(),
            field_scope: request.field_scope(),
            capability: request.capability(),
            created_at: request.created_at(),
            expires_at: request.expires_at(),
        }
    }
}

impl Debug for HumanControlPendingRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanControlPendingRequest")
            .field("request_id", &self.request_id)
            .field("kind", &self.kind)
            .field("consumer_id", &self.consumer_id)
            .field("has_identity_evidence", &self.identity_evidence.is_some())
            .field(
                "has_pairing_verification",
                &self.pairing_comparison_code.is_some(),
            )
            .field("vault_id", &self.vault_id)
            .field("field_scope", &self.field_scope)
            .field("capability", &self.capability)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// One secret-field candidate containing metadata but never its value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlSecretFieldCandidate {
    /// Stable Secret Field identity.
    pub secret_field_id: SecretFieldId,
    /// Provider-neutral role.
    pub role: String,
    /// Optional local presentation label.
    pub label: Option<String>,
    /// Authenticated field kind.
    pub kind: SecretFieldKind,
}

/// One human-visible Credential candidate without any Secret Field value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlCredentialCandidate {
    /// Stable Vault identity.
    pub vault_id: VaultId,
    /// Stable Credential identity.
    pub credential_id: CredentialId,
    /// Local presentation title.
    pub title: String,
    /// Optional open template identity.
    pub template_id: Option<String>,
    /// Local disambiguation tags.
    pub tags: Vec<String>,
    /// Favorite presentation state.
    pub favorite: bool,
    /// Capability-compatible fields without values.
    pub secret_fields: Vec<HumanControlSecretFieldCandidate>,
}

/// Human credential review without the Consumer-supplied private description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlCredentialReview {
    /// Stable paired Consumer identity.
    pub consumer_id: ConsumerId,
    /// Stable Vault identity.
    pub vault_id: VaultId,
    /// Requested capability.
    pub capability: Capability,
    /// Bounded metadata-only candidate list.
    pub candidates: Vec<HumanControlCredentialCandidate>,
    /// Whether candidate metadata or additional candidates were omitted.
    pub truncated: bool,
}

impl From<&BrokerHumanCredentialReview> for HumanControlCredentialReview {
    fn from(review: &BrokerHumanCredentialReview) -> Self {
        let mut remaining_bytes = MAX_HUMAN_CONTROL_CREDENTIAL_REVIEW_BYTES;
        let mut candidates = Vec::new();
        let mut truncated = review.truncated();

        for candidate in review.candidates() {
            let Some(projection) = project_credential_candidate(candidate, remaining_bytes) else {
                truncated = true;
                break;
            };
            remaining_bytes = remaining_bytes.saturating_sub(projection.estimated_bytes);
            truncated |= projection.truncated;
            candidates.push(projection.candidate);
        }

        Self {
            consumer_id: review.consumer_id(),
            vault_id: review.vault_id(),
            capability: review.capability(),
            candidates,
            truncated,
        }
    }
}

struct ProjectedCredentialCandidate {
    candidate: HumanControlCredentialCandidate,
    estimated_bytes: usize,
    truncated: bool,
}

fn project_credential_candidate(
    candidate: &BrokerHumanCredentialCandidate,
    budget: usize,
) -> Option<ProjectedCredentialCandidate> {
    let (title, title_truncated) = bounded_metadata_text(candidate.title());
    let (template_id, template_truncated) = match candidate.template_id() {
        Some(template_id) => {
            let (template_id, truncated) = bounded_metadata_text(template_id);
            (Some(template_id), truncated)
        }
        None => (None, false),
    };
    let mut estimated_bytes = HUMAN_CONTROL_CREDENTIAL_CANDIDATE_OVERHEAD_BYTES
        .saturating_add(metadata_wire_budget(&title))
        .saturating_add(
            template_id
                .as_ref()
                .map_or(0, |value| metadata_wire_budget(value)),
        );
    if estimated_bytes > budget {
        return None;
    }

    let mut truncated = title_truncated || template_truncated;
    let mut secret_fields = Vec::new();
    for field in candidate.secret_fields() {
        let (role, role_truncated) = bounded_metadata_text(field.role());
        let (label, label_truncated) = match field.label() {
            Some(label) => {
                let (label, was_truncated) = bounded_metadata_text(label);
                (Some(label), was_truncated)
            }
            None => (None, false),
        };
        let field_bytes = HUMAN_CONTROL_SECRET_FIELD_OVERHEAD_BYTES
            .saturating_add(metadata_wire_budget(&role))
            .saturating_add(
                label
                    .as_ref()
                    .map_or(0, |value| metadata_wire_budget(value)),
            );
        if estimated_bytes.saturating_add(field_bytes) > budget {
            truncated = true;
            break;
        }
        estimated_bytes += field_bytes;
        truncated |= role_truncated || label_truncated;
        secret_fields.push(HumanControlSecretFieldCandidate {
            secret_field_id: field.secret_field_id(),
            role,
            label,
            kind: field.kind(),
        });
    }

    let mut tags = Vec::new();
    for tag in candidate.tags() {
        let (tag, tag_truncated) = bounded_metadata_text(tag);
        let tag_bytes = HUMAN_CONTROL_TAG_OVERHEAD_BYTES.saturating_add(metadata_wire_budget(&tag));
        if estimated_bytes.saturating_add(tag_bytes) > budget {
            truncated = true;
            break;
        }
        estimated_bytes += tag_bytes;
        truncated |= tag_truncated;
        tags.push(tag);
    }

    Some(ProjectedCredentialCandidate {
        candidate: HumanControlCredentialCandidate {
            vault_id: candidate.vault_id(),
            credential_id: candidate.credential_id(),
            title,
            template_id,
            tags,
            favorite: candidate.favorite(),
            secret_fields,
        },
        estimated_bytes,
        truncated,
    })
}

fn bounded_metadata_text(value: &str) -> (String, bool) {
    if value.len() <= MAX_HUMAN_CONTROL_METADATA_TEXT_BYTES {
        return (value.to_owned(), false);
    }
    let mut end = MAX_HUMAN_CONTROL_METADATA_TEXT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

const fn metadata_wire_budget(value: &str) -> usize {
    // JSON-style control-character escaping can expand one UTF-8 byte to six bytes.
    value.len().saturating_mul(6)
}

/// Provider-neutral offline Usage Profile catalog for one existing Consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlUsageProfileCatalog {
    /// Stable Consumer identity.
    pub consumer_id: ConsumerId,
    /// Complete immutable template catalog.
    pub templates: Vec<BundledUsageProfileTemplate>,
    /// Optional exact offline recommendation.
    pub recommendation: Option<BundledUsageProfileRecommendation>,
}

/// Bounded audit page plus one Broker-issued clear token for its exact selection.
#[derive(Debug)]
pub struct HumanControlAuditPage {
    page: BrokerAuditPage,
    clear_confirmation_id: HumanControlAuditConfirmationId,
}

impl HumanControlAuditPage {
    /// Returns the newest-first audit page.
    #[must_use]
    pub const fn page(&self) -> &BrokerAuditPage {
        &self.page
    }

    /// Returns the single-use token bound to the list request's exact filter.
    #[must_use]
    pub const fn clear_confirmation_id(&self) -> HumanControlAuditConfirmationId {
        self.clear_confirmation_id
    }
}

/// Bounded Vault authorization inventory for one human-control response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlAuthorizationSnapshot {
    /// Persisted machine-access pause state.
    pub paused: bool,
    /// Stable authorized Credential identities, capped at the protocol limit.
    pub authorized_credential_ids: Vec<CredentialId>,
    /// Paired Consumer summaries, capped at the protocol limit.
    pub consumers: Vec<BrokerConsumerSummary>,
    /// Whether additional Credential identities were omitted.
    pub authorized_credentials_truncated: bool,
    /// Whether additional Consumers were omitted.
    pub consumers_truncated: bool,
}

impl From<BrokerAppsToolsSnapshot> for HumanControlAuthorizationSnapshot {
    fn from(snapshot: BrokerAppsToolsSnapshot) -> Self {
        Self {
            paused: snapshot.paused(),
            authorized_credentials_truncated: snapshot.authorized_credential_ids().len()
                > MAX_HUMAN_CONTROL_COLLECTION_ITEMS,
            authorized_credential_ids: snapshot
                .authorized_credential_ids()
                .iter()
                .copied()
                .take(MAX_HUMAN_CONTROL_COLLECTION_ITEMS)
                .collect(),
            consumers_truncated: snapshot.consumers().len() > MAX_HUMAN_CONTROL_COLLECTION_ITEMS,
            consumers: snapshot
                .consumers()
                .iter()
                .take(MAX_HUMAN_CONTROL_COLLECTION_ITEMS)
                .cloned()
                .collect(),
        }
    }
}

/// Bounded management detail for one paired Consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlConsumerDetail {
    /// Stable Consumer identity and bounded presentation evidence.
    pub consumer: BrokerConsumerSummary,
    /// Field grants capped at the protocol collection limit.
    pub field_grants: Vec<BrokerFieldGrantSummary>,
    /// Usage Profiles capped at the protocol collection limit.
    pub usage_profiles: Vec<BrokerUsageProfileSummary>,
    /// Existing bounded recent audit projection.
    pub recent_audit_events: Vec<BrokerConsumerAuditSummary>,
    /// Whether additional field grants were omitted.
    pub field_grants_truncated: bool,
    /// Whether additional Usage Profiles were omitted.
    pub usage_profiles_truncated: bool,
}

impl From<BrokerConsumerDetail> for HumanControlConsumerDetail {
    fn from(detail: BrokerConsumerDetail) -> Self {
        Self {
            consumer: detail.consumer().clone(),
            field_grants_truncated: detail.field_grants().len()
                > MAX_HUMAN_CONTROL_COLLECTION_ITEMS,
            field_grants: detail
                .field_grants()
                .iter()
                .take(MAX_HUMAN_CONTROL_COLLECTION_ITEMS)
                .cloned()
                .collect(),
            usage_profiles_truncated: detail.usage_profiles().len()
                > MAX_HUMAN_CONTROL_COLLECTION_ITEMS,
            usage_profiles: detail
                .usage_profiles()
                .iter()
                .take(MAX_HUMAN_CONTROL_COLLECTION_ITEMS)
                .cloned()
                .collect(),
            recent_audit_events: detail.recent_audit_events().to_vec(),
        }
    }
}

/// Closed secret-free response catalog for human-control protocol version 1.
#[derive(Debug)]
pub enum HumanControlResponse {
    /// Negotiated protocol and exact operation catalog.
    Hello {
        /// Highest mutually supported protocol version.
        protocol: HumanControlProtocolVersion,
        /// Exact frozen operation schema identity.
        schema: &'static str,
        /// Ephemeral Broker process identity.
        broker_instance_id: BrokerInstanceId,
        /// Complete operations available in the selected version.
        operations: Vec<HumanControlOperation>,
    },
    /// Fresh authentication challenge.
    ControllerChallenge(ControllerAuthenticationChallenge),
    /// Authenticated controller/session identity.
    ControllerAuthenticated {
        /// Stable public controller identity.
        controller_id: ControllerId,
        /// Ephemeral authenticated connection session.
        session_id: ControllerSessionId,
        /// Relative lease window advertised to the client in milliseconds.
        lease_duration_millis: u64,
    },
    /// Current bounded connection lease remains active.
    ControllerLease {
        /// Ephemeral authenticated connection session.
        session_id: ControllerSessionId,
        /// Renewed relative lease window advertised to the client in milliseconds.
        lease_duration_millis: u64,
    },
    /// Authenticated path-free service readiness.
    Readiness(BrokerReadinessProjection),
    /// Persisted pause state independent of service health.
    PauseState {
        /// Persisted pause value after the transition.
        paused: bool,
    },
    /// Stable machine Vault lock state.
    VaultState(BrokerVaultSessionSnapshot),
    /// Pending decisions without private request input.
    PendingQueue(Vec<HumanControlPendingRequest>),
    /// Fixed successful decision receipt.
    DecisionReceipt {
        /// Whether the accepted decision changed durable or process state.
        changed: bool,
    },
    /// Human-only credential metadata without values or request description.
    CredentialReview(HumanControlCredentialReview),
    /// Vault-scoped authorization summary.
    AuthorizationSnapshot(HumanControlAuthorizationSnapshot),
    /// Consumer management detail.
    ConsumerDetail(HumanControlConsumerDetail),
    /// Offline Usage Profile catalog.
    UsageProfileCatalog(HumanControlUsageProfileCatalog),
    /// Created Usage Profile metadata.
    UsageProfile(UsageProfile),
    /// Fixed idempotent removal receipt.
    RemovalReceipt {
        /// Whether an exact owned record existed and was removed.
        removed: bool,
    },
    /// Fixed revocation counts.
    RevocationSummary(BrokerRevocationSummary),
    /// Bounded audit page.
    AuditPage(HumanControlAuditPage),
    /// Fixed audit clear counts.
    AuditClearSummary(BrokerAuditClearSummary),
    /// Versioned non-secret audit export.
    AuditExport(BrokerAuditExport),
    /// Quiesced state ready for App-managed repair.
    RepairReadiness(BrokerGrantInvalidationSummary),
    /// Graceful shutdown receipt.
    ShutdownReceipt(BrokerGrantInvalidationSummary),
}

/// Connection authentication phase separate from every Consumer session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlConnectionPhase {
    /// No protocol has been negotiated.
    AwaitingHello,
    /// Version selected; controller proof is required.
    Negotiated(HumanControlProtocolVersion),
    /// Dedicated human controller authenticated.
    Authenticated {
        /// Public controller identity.
        controller_id: ControllerId,
        /// Ephemeral connection session.
        session_id: ControllerSessionId,
    },
    /// Connection is no longer usable.
    Closed,
}

/// Mutable state for one human-control connection.
pub struct HumanControlConnectionState {
    phase: HumanControlConnectionPhase,
    authentication: ControllerAuthenticationConnection,
    audit_clear_confirmations: VecDeque<BrokerAuditClearConfirmation>,
    lease_expires_at: Option<Instant>,
}

impl HumanControlConnectionState {
    /// Returns the current fixed phase without exposing authentication material.
    #[must_use]
    pub const fn phase(&self) -> HumanControlConnectionPhase {
        self.phase
    }

    /// Consumes any challenge and permanently closes this connection state.
    pub fn close(&mut self) {
        self.authentication.consume_outstanding();
        self.audit_clear_confirmations.clear();
        self.lease_expires_at = None;
        self.phase = HumanControlConnectionPhase::Closed;
    }
}

impl Debug for HumanControlConnectionState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanControlConnectionState")
            .field("phase", &self.phase)
            .finish()
    }
}

/// Fixed dispatcher failure with no nested runtime or request detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanControlDispatchError {
    failure: HumanControlProtocolFailure,
}

impl HumanControlDispatchError {
    /// Returns the fixed protocol failure safe to send to the App.
    #[must_use]
    pub const fn failure(self) -> HumanControlProtocolFailure {
        self.failure
    }

    fn new(failure: HumanControlProtocolFailure) -> Self {
        Self { failure }
    }

    fn code(code: HumanControlFailureCode) -> Self {
        Self::new(HumanControlProtocolFailure::new(code, false, None))
    }
}

impl Display for HumanControlDispatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("human-control request failed")
    }
}

impl std::error::Error for HumanControlDispatchError {}

/// Versioned dispatcher for the dedicated App human-control channel.
pub struct HumanControlDispatcher<S> {
    broker_instance_id: BrokerInstanceId,
    authentication: ControllerAuthenticationService,
    authority: ControllerAuthorityManager<S>,
}

impl<S> HumanControlDispatcher<S>
where
    S: ControllerKeyStore,
{
    /// Creates a dispatcher around one restricted controller-key store.
    pub fn new(broker_instance_id: BrokerInstanceId, key_store: S) -> Self {
        Self {
            broker_instance_id,
            authentication: ControllerAuthenticationService::new(broker_instance_id),
            authority: ControllerAuthorityManager::new(key_store),
        }
    }

    /// Creates an unauthenticated connection that accepts only `hello` first.
    #[must_use]
    pub fn connection(&self) -> HumanControlConnectionState {
        HumanControlConnectionState {
            phase: HumanControlConnectionPhase::AwaitingHello,
            authentication: self.authentication.connection(),
            audit_clear_confirmations: VecDeque::new(),
            lease_expires_at: None,
        }
    }

    /// Prepares Controller authority only after trusted App enablement approval.
    ///
    /// This method is deliberately outside the Human Control wire catalog. The
    /// future activation-qualified App flow must verify its artifact and obtain
    /// explicit local approval before calling it.
    pub fn prepare_controller_authority_after_explicit_enable(
        &self,
        runtime: &BrokerRuntime,
    ) -> Result<ControllerBootstrapMode, HumanControlDispatchError> {
        let record = runtime
            .controller_authority_record()
            .map_err(map_runtime_error)?;
        self.authority
            .prepare_for_explicit_enable(record)
            .map(|prepared| prepared.mode())
            .map_err(map_authority_error)
    }

    /// Dispatches exactly one typed request through negotiation and controller auth.
    pub fn dispatch(
        &self,
        runtime: &mut BrokerRuntime,
        state: &mut HumanControlConnectionState,
        request: HumanControlRequest,
        now: Instant,
        observed_at: StateTimestamp,
    ) -> Result<HumanControlResponse, HumanControlDispatchError> {
        match request {
            HumanControlRequest::Hello(offer) => self.hello(state, offer),
            HumanControlRequest::ControllerChallenge(request) => {
                self.controller_challenge(runtime, state, request, now)
            }
            HumanControlRequest::ControllerAuthenticate(proof) => {
                self.controller_authenticate(runtime, state, proof, now, observed_at)
            }
            request => {
                let HumanControlConnectionPhase::Authenticated { session_id, .. } = state.phase
                else {
                    return Err(HumanControlDispatchError::new(
                        HumanControlProtocolFailure::new(
                            if matches!(state.phase, HumanControlConnectionPhase::AwaitingHello) {
                                HumanControlFailureCode::NegotiationRequired
                            } else {
                                HumanControlFailureCode::AuthenticationRequired
                            },
                            false,
                            Some(
                                if matches!(state.phase, HumanControlConnectionPhase::AwaitingHello)
                                {
                                    HumanControlRequiredAction::SendHello
                                } else {
                                    HumanControlRequiredAction::AuthenticateController
                                },
                            ),
                        ),
                    ));
                };
                if !connection_lease_is_live(state, now) {
                    state.close();
                    return Err(HumanControlDispatchError::new(
                        HumanControlProtocolFailure::new(
                            HumanControlFailureCode::AuthenticationRequired,
                            false,
                            Some(HumanControlRequiredAction::Reauthenticate),
                        ),
                    ));
                }
                self.dispatch_authenticated(runtime, state, request, session_id, now, observed_at)
            }
        }
    }

    fn hello(
        &self,
        state: &mut HumanControlConnectionState,
        offer: HumanControlVersionOffer,
    ) -> Result<HumanControlResponse, HumanControlDispatchError> {
        if state.phase != HumanControlConnectionPhase::AwaitingHello {
            state.close();
            return Err(HumanControlDispatchError::code(
                HumanControlFailureCode::InvalidRequest,
            ));
        }
        let Some(protocol) = offer.negotiate_current() else {
            state.close();
            return Err(HumanControlDispatchError::new(
                HumanControlProtocolFailure::new(
                    HumanControlFailureCode::ProtocolIncompatible,
                    false,
                    Some(HumanControlRequiredAction::UpdateComponent),
                ),
            ));
        };
        if offer.role() != CONTROLLER_ROLE
            || !offer
                .schema_ids()
                .iter()
                .any(|schema_id| schema_id == HUMAN_CONTROL_SCHEMA_ID)
        {
            state.close();
            return Err(HumanControlDispatchError::new(
                HumanControlProtocolFailure::new(
                    HumanControlFailureCode::ProtocolIncompatible,
                    false,
                    Some(HumanControlRequiredAction::UpdateComponent),
                ),
            ));
        }
        state.phase = HumanControlConnectionPhase::Negotiated(protocol);
        Ok(HumanControlResponse::Hello {
            protocol,
            schema: HUMAN_CONTROL_SCHEMA_ID,
            broker_instance_id: self.broker_instance_id,
            operations: HUMAN_CONTROL_DISPATCH_OPERATIONS.to_vec(),
        })
    }

    fn controller_challenge(
        &self,
        runtime: &BrokerRuntime,
        state: &mut HumanControlConnectionState,
        request: ControllerChallengeRequest,
        now: Instant,
    ) -> Result<HumanControlResponse, HumanControlDispatchError> {
        let HumanControlConnectionPhase::Negotiated(protocol) = state.phase else {
            return Err(HumanControlDispatchError::code(
                HumanControlFailureCode::NegotiationRequired,
            ));
        };
        state
            .authentication
            .check_challenge_budget(request.controller_id(), now)
            .map_err(map_authentication_error)?;
        let record = runtime
            .controller_authority_record()
            .map_err(map_runtime_error)?;
        let prepared = self
            .authority
            .prepare_for_challenge(record)
            .map_err(map_authority_error)?;
        let expected_mode = match prepared.mode() {
            ControllerBootstrapMode::BootstrapNew | ControllerBootstrapMode::ResumeBootstrap => {
                ControllerAuthenticationMode::Bootstrap
            }
            ControllerBootstrapMode::AuthenticateExisting => {
                ControllerAuthenticationMode::Authenticate
            }
        };
        if request.controller_id() != prepared.key().controller_id() {
            return Err(map_authentication_error(
                state
                    .authentication
                    .reject_challenge(request.controller_id(), now),
            ));
        }
        let challenge = state
            .authentication
            .challenge(
                request,
                expected_mode,
                protocol,
                prepared.key().public_key(),
                record,
                now,
            )
            .map_err(map_authentication_error)?;
        Ok(HumanControlResponse::ControllerChallenge(challenge))
    }

    fn controller_authenticate(
        &self,
        runtime: &BrokerRuntime,
        state: &mut HumanControlConnectionState,
        proof: ControllerAuthenticationProof,
        now: Instant,
        approved_at: StateTimestamp,
    ) -> Result<HumanControlResponse, HumanControlDispatchError> {
        if !matches!(state.phase, HumanControlConnectionPhase::Negotiated(_)) {
            return Err(HumanControlDispatchError::code(
                HumanControlFailureCode::NegotiationRequired,
            ));
        }
        let completion = state
            .authentication
            .complete(proof, now, approved_at)
            .map_err(map_authentication_error)?;
        let (controller_id, session_id) = match completion {
            ControllerAuthenticationCompletion::Bootstrap { record, session_id } => {
                runtime
                    .insert_controller_authority_record(record)
                    .map_err(map_runtime_error)?;
                (record.controller_id(), session_id)
            }
            ControllerAuthenticationCompletion::Authenticated {
                controller_id,
                session_id,
            } => (controller_id, session_id),
        };
        state.phase = HumanControlConnectionPhase::Authenticated {
            controller_id,
            session_id,
        };
        state.lease_expires_at = lease_deadline(now);
        if state.lease_expires_at.is_none() {
            state.close();
            return Err(HumanControlDispatchError::code(
                HumanControlFailureCode::OperationFailed,
            ));
        }
        Ok(HumanControlResponse::ControllerAuthenticated {
            controller_id,
            session_id,
            lease_duration_millis: controller_lease_duration_millis(),
        })
    }

    fn dispatch_authenticated(
        &self,
        runtime: &mut BrokerRuntime,
        state: &mut HumanControlConnectionState,
        request: HumanControlRequest,
        session_id: ControllerSessionId,
        now: Instant,
        observed_at: StateTimestamp,
    ) -> Result<HumanControlResponse, HumanControlDispatchError> {
        match request {
            HumanControlRequest::ControllerLeaseRenew {
                controller_session_id,
                broker_instance_id,
            } => {
                validate_controller_lease(
                    session_id,
                    self.broker_instance_id,
                    controller_session_id,
                    broker_instance_id,
                )?;
                state.lease_expires_at = lease_deadline(now);
                if state.lease_expires_at.is_none() {
                    state.close();
                    return Err(HumanControlDispatchError::code(
                        HumanControlFailureCode::OperationFailed,
                    ));
                }
                Ok(HumanControlResponse::ControllerLease {
                    session_id,
                    lease_duration_millis: controller_lease_duration_millis(),
                })
            }
            HumanControlRequest::ReadinessGet => runtime
                .readiness_projection()
                .map(HumanControlResponse::Readiness)
                .map_err(map_runtime_error),
            HumanControlRequest::MachineAccessPauseSet { paused } => {
                runtime
                    .set_machine_access_paused(paused, observed_at)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::PauseState { paused })
            }
            HumanControlRequest::VaultUnlock {
                vault_id,
                credential,
            } => {
                let result = match credential {
                    HumanControlVaultUnlockCredential::MasterPassword(secret) => runtime
                        .process()
                        .vault_sessions()
                        .unlock_with_master_password(vault_id, secret),
                    HumanControlVaultUnlockCredential::LocalMaterial(secret) => runtime
                        .process()
                        .vault_sessions()
                        .unlock_with_local_material(vault_id, secret),
                };
                result.map(HumanControlResponse::VaultState).map_err(|_| {
                    HumanControlDispatchError::code(HumanControlFailureCode::UnlockFailed)
                })
            }
            HumanControlRequest::VaultLock { vault_id } => {
                runtime
                    .lock_vault_for_human(vault_id)
                    .map_err(map_runtime_error)?;
                runtime
                    .process()
                    .vault_sessions()
                    .snapshot(vault_id)
                    .map(HumanControlResponse::VaultState)
                    .map_err(|_| {
                        HumanControlDispatchError::code(HumanControlFailureCode::RequestUnavailable)
                    })
            }
            HumanControlRequest::PendingList => {
                let queue = runtime
                    .pending_requests_for_human()
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::PendingQueue(
                    queue
                        .requests()
                        .iter()
                        .take(pending_projection_limit(queue.pending_count()))
                        .map(HumanControlPendingRequest::from)
                        .collect(),
                ))
            }
            HumanControlRequest::PendingDeny {
                request_id,
                decision,
            } => {
                validate_pending_deny_decision(&decision)?;
                runtime
                    .deny_pending_request(request_id, observed_at)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::DecisionReceipt { changed: true })
            }
            HumanControlRequest::PairingApprove {
                request_id,
                approval,
            } => {
                runtime
                    .approve_pairing(request_id, approval)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::DecisionReceipt { changed: true })
            }
            HumanControlRequest::UnlockApprove {
                request_id,
                vault_id,
            } => {
                runtime
                    .approve_pending_unlock(request_id, vault_id, observed_at)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::DecisionReceipt { changed: true })
            }
            HumanControlRequest::CredentialReview { request_id } => {
                let review = runtime
                    .review_pending_new_credential_for_current_session(request_id, observed_at)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::CredentialReview(
                    HumanControlCredentialReview::from(&review),
                ))
            }
            HumanControlRequest::CredentialAllowOnce {
                request_id,
                selection,
            } => {
                runtime
                    .allow_once_pending_request(request_id, Some(selection), observed_at)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::DecisionReceipt { changed: true })
            }
            HumanControlRequest::CredentialAuthorize {
                request_id,
                selection,
                confirmation_policy,
                rule_lifetime,
                capability,
            } => {
                let created = runtime
                    .configure_pending_request_access_rule(
                        request_id,
                        Some(selection),
                        capability,
                        confirmation_policy,
                        rule_lifetime,
                        observed_at,
                    )
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::DecisionReceipt {
                    changed: created.newly_created(),
                })
            }
            HumanControlRequest::AuthorizationSnapshot { vault_id } => runtime
                .apps_tools_snapshot(vault_id)
                .map(HumanControlAuthorizationSnapshot::from)
                .map(HumanControlResponse::AuthorizationSnapshot)
                .map_err(map_runtime_error),
            HumanControlRequest::ConsumerDetail { consumer_id } => runtime
                .apps_tools_consumer_detail(consumer_id)
                .map(HumanControlConsumerDetail::from)
                .map(HumanControlResponse::ConsumerDetail)
                .map_err(map_runtime_error),
            HumanControlRequest::UsageProfileCatalog {
                consumer_id,
                executable_name_hint,
            } => {
                runtime
                    .apps_tools_consumer_detail(consumer_id)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::UsageProfileCatalog(
                    HumanControlUsageProfileCatalog {
                        consumer_id,
                        templates: bundled_usage_profile_templates().to_vec(),
                        recommendation: recommend_bundled_usage_profile(
                            executable_name_hint.as_deref(),
                        ),
                    },
                ))
            }
            HumanControlRequest::UsageProfileCreate {
                consumer_id,
                label,
                definition,
            } => runtime
                .create_usage_profile(consumer_id, label, definition)
                .map(HumanControlResponse::UsageProfile)
                .map_err(map_runtime_error),
            HumanControlRequest::UsageProfileRemove {
                consumer_id,
                usage_profile_id,
            } => runtime
                .remove_usage_profile(consumer_id, usage_profile_id)
                .map(|removed| HumanControlResponse::RemovalReceipt { removed })
                .map_err(map_runtime_error),
            HumanControlRequest::FieldAccessRevoke {
                consumer_id,
                field_scope,
            } => runtime
                .revoke_consumer_field_access(consumer_id, field_scope)
                .map(HumanControlResponse::RevocationSummary)
                .map_err(map_runtime_error),
            HumanControlRequest::GrantRevoke {
                consumer_id,
                use_grant_id,
            } => runtime
                .revoke_use_grant_for_human(consumer_id, use_grant_id)
                .map(grant_revoke_response)
                .map_err(map_runtime_error),
            HumanControlRequest::ConsumerRevoke { consumer_id, scope } => {
                validate_fixed_value(&scope, HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE)?;
                runtime
                    .revoke_consumer_access(consumer_id)
                    .map(HumanControlResponse::RevocationSummary)
                    .map_err(map_runtime_error)
            }
            HumanControlRequest::AllAccessRevoke => runtime
                .revoke_all_apps_and_tools_access()
                .map(HumanControlResponse::RevocationSummary)
                .map_err(map_runtime_error),
            HumanControlRequest::AuditList {
                filter,
                cursor,
                limit,
            } => {
                validate_human_control_audit_limit(limit)?;
                let page = runtime
                    .view_audit_at(filter, cursor, limit, observed_at)
                    .map_err(map_runtime_error)?;
                let confirmation =
                    BrokerAuditClearConfirmation::for_human_control_selection(filter);
                let clear_confirmation_id = confirmation.confirmation_id();
                retain_audit_clear_confirmation(&mut state.audit_clear_confirmations, confirmation);
                Ok(HumanControlResponse::AuditPage(HumanControlAuditPage {
                    page,
                    clear_confirmation_id,
                }))
            }
            HumanControlRequest::AuditClear {
                filter,
                confirmation_id,
            } => {
                let confirmation = take_audit_clear_confirmation(
                    &mut state.audit_clear_confirmations,
                    confirmation_id,
                )?;
                validate_audit_clear_confirmation(&confirmation, confirmation_id, filter)?;
                runtime
                    .clear_audit(filter, confirmation)
                    .map(HumanControlResponse::AuditClearSummary)
                    .map_err(map_runtime_error)
            }
            HumanControlRequest::AuditExport { filter, limit } => {
                validate_human_control_audit_limit(limit)?;
                runtime
                    .export_human_control_audit_json_at(
                        filter,
                        observed_at,
                        limit,
                        MAX_HUMAN_CONTROL_AUDIT_EXPORT_BYTES,
                    )
                    .map(HumanControlResponse::AuditExport)
                    .map_err(map_runtime_error)
            }
            HumanControlRequest::RepairPrepare {
                expected_component,
                expected_protocol,
            } => {
                validate_repair_target(expected_component, expected_protocol)?;
                let summary = runtime
                    .shutdown_at(observed_at)
                    .map_err(map_runtime_error)?;
                state.close();
                Ok(HumanControlResponse::RepairReadiness(summary))
            }
            HumanControlRequest::Shutdown { reason } => {
                validate_fixed_value(&reason, HUMAN_CONTROL_SHUTDOWN_REASON)?;
                let summary = runtime
                    .shutdown_at(observed_at)
                    .map_err(map_runtime_error)?;
                state.close();
                Ok(HumanControlResponse::ShutdownReceipt(summary))
            }
            HumanControlRequest::Hello(_)
            | HumanControlRequest::ControllerChallenge(_)
            | HumanControlRequest::ControllerAuthenticate(_) => Err(
                HumanControlDispatchError::code(HumanControlFailureCode::InvalidRequest),
            ),
        }
    }
}

fn validate_repair_target(
    expected_component: PackagedComponent,
    expected_protocol: HumanControlProtocolVersion,
) -> Result<(), HumanControlDispatchError> {
    if expected_component != PackagedComponent::Broker
        || expected_protocol != HumanControlProtocolVersion::current()
    {
        return Err(HumanControlDispatchError::new(
            HumanControlProtocolFailure::new(
                HumanControlFailureCode::ProtocolIncompatible,
                false,
                Some(HumanControlRequiredAction::UpdateComponent),
            ),
        ));
    }
    Ok(())
}

fn validate_pending_deny_decision(decision: &str) -> Result<(), HumanControlDispatchError> {
    validate_fixed_value(decision, HUMAN_CONTROL_DENY_DECISION)
}

fn validate_fixed_value(value: &str, expected: &str) -> Result<(), HumanControlDispatchError> {
    if value == expected {
        Ok(())
    } else {
        Err(HumanControlDispatchError::code(
            HumanControlFailureCode::InvalidRequest,
        ))
    }
}

fn validate_controller_lease(
    authenticated_session_id: ControllerSessionId,
    running_broker_instance_id: BrokerInstanceId,
    requested_session_id: ControllerSessionId,
    requested_broker_instance_id: BrokerInstanceId,
) -> Result<(), HumanControlDispatchError> {
    if authenticated_session_id == requested_session_id
        && running_broker_instance_id == requested_broker_instance_id
    {
        Ok(())
    } else {
        Err(HumanControlDispatchError::code(
            HumanControlFailureCode::InvalidRequest,
        ))
    }
}

fn lease_deadline(now: Instant) -> Option<Instant> {
    now.checked_add(HUMAN_CONTROL_CONTROLLER_LEASE_TTL)
}

fn controller_lease_duration_millis() -> u64 {
    u64::try_from(HUMAN_CONTROL_CONTROLLER_LEASE_TTL.as_millis())
        .expect("human-control lease duration fits u64 milliseconds")
}

fn connection_lease_is_live(state: &HumanControlConnectionState, now: Instant) -> bool {
    state
        .lease_expires_at
        .is_some_and(|expires_at| now < expires_at)
}

fn validate_audit_clear_confirmation(
    confirmation: &BrokerAuditClearConfirmation,
    confirmation_id: HumanControlAuditConfirmationId,
    filter: BrokerAuditFilter,
) -> Result<(), HumanControlDispatchError> {
    if confirmation.matches(confirmation_id, filter) {
        Ok(())
    } else {
        Err(HumanControlDispatchError::code(
            HumanControlFailureCode::InvalidRequest,
        ))
    }
}

fn retain_audit_clear_confirmation(
    confirmations: &mut VecDeque<BrokerAuditClearConfirmation>,
    confirmation: BrokerAuditClearConfirmation,
) {
    if confirmations.len() == MAX_HUMAN_CONTROL_AUDIT_CLEAR_CONFIRMATIONS {
        confirmations.pop_front();
    }
    confirmations.push_back(confirmation);
}

fn take_audit_clear_confirmation(
    confirmations: &mut VecDeque<BrokerAuditClearConfirmation>,
    confirmation_id: HumanControlAuditConfirmationId,
) -> Result<BrokerAuditClearConfirmation, HumanControlDispatchError> {
    let index = confirmations
        .iter()
        .position(|confirmation| confirmation.confirmation_id() == confirmation_id)
        .ok_or_else(|| HumanControlDispatchError::code(HumanControlFailureCode::InvalidRequest))?;
    confirmations
        .remove(index)
        .ok_or_else(|| HumanControlDispatchError::code(HumanControlFailureCode::InvalidRequest))
}

fn grant_revoke_response(removed: bool) -> HumanControlResponse {
    HumanControlResponse::RevocationSummary(BrokerRevocationSummary::for_use_grant(removed))
}

const fn pending_projection_limit(pending_count: usize) -> usize {
    if pending_count > MAX_HUMAN_CONTROL_COLLECTION_ITEMS {
        MAX_HUMAN_CONTROL_COLLECTION_ITEMS
    } else {
        pending_count
    }
}

fn validate_human_control_audit_limit(limit: usize) -> Result<(), HumanControlDispatchError> {
    if limit == 0 || limit > MAX_HUMAN_CONTROL_AUDIT_EVENTS {
        Err(HumanControlDispatchError::code(
            HumanControlFailureCode::InvalidRequest,
        ))
    } else {
        Ok(())
    }
}

fn map_authentication_error(error: ControllerAuthenticationError) -> HumanControlDispatchError {
    HumanControlDispatchError::new(error.protocol_failure())
}

fn map_authority_error(error: ControllerAuthorityError) -> HumanControlDispatchError {
    let code = match error {
        ControllerAuthorityError::RemovalPending
        | ControllerAuthorityError::IncompleteAuthority => {
            HumanControlFailureCode::ControllerUnavailable
        }
        ControllerAuthorityError::CreationVerificationFailed
        | ControllerAuthorityError::RemovalNotStarted
        | ControllerAuthorityError::RemovalVerificationFailed
        | ControllerAuthorityError::Store { .. } => HumanControlFailureCode::OperationFailed,
    };
    HumanControlDispatchError::code(code)
}

fn map_runtime_error(error: BrokerRuntimeError) -> HumanControlDispatchError {
    let code = match error {
        BrokerRuntimeError::Approval(_)
        | BrokerRuntimeError::HumanControl(_)
        | BrokerRuntimeError::Pairing(_)
        | BrokerRuntimeError::UsageProfile(_) => HumanControlFailureCode::RequestUnavailable,
        BrokerRuntimeError::VaultSession(_) => HumanControlFailureCode::VaultLocked,
        BrokerRuntimeError::LocalData(_) => HumanControlFailureCode::ProtectedStateUnavailable,
        BrokerRuntimeError::MachineAccess(_) => HumanControlFailureCode::Conflict,
        _ => HumanControlFailureCode::OperationFailed,
    };
    HumanControlDispatchError::code(code)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{
        BrokerRevocationKind, ControllerKeyStoreError, ControllerSigningKey, DeviceKeyStore,
        DeviceKeyStoreError, DevicePaths, DeviceRootKey, HumanControlAuthenticationRequirement,
        HumanControlProtocolVersionRange, HumanControlRequestSecretClass,
        HumanControlResultSecrecy, CONTROLLER_ROLE, HUMAN_CONTROL_OPERATION_CONTRACTS,
        MAX_CONTROLLER_FAILURES_PER_IDENTITY,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct MemoryDeviceKeyStore {
        bytes: RefCell<Option<Vec<u8>>>,
    }

    impl DeviceKeyStore for MemoryDeviceKeyStore {
        fn load(&self) -> Result<Option<DeviceRootKey>, DeviceKeyStoreError> {
            self.bytes
                .borrow()
                .as_ref()
                .map(|bytes| DeviceRootKey::from_stored_bytes(bytes.clone()))
                .transpose()
        }

        fn create_new(&self, key: &DeviceRootKey) -> Result<(), DeviceKeyStoreError> {
            let mut bytes = self.bytes.borrow_mut();
            if bytes.is_some() {
                return Err(DeviceKeyStoreError::AlreadyExists);
            }
            *bytes = Some(key.expose().to_vec());
            Ok(())
        }

        fn delete(&self) -> Result<bool, DeviceKeyStoreError> {
            Ok(self.bytes.borrow_mut().take().is_some())
        }
    }

    struct MemoryControllerKeyStore {
        seed: RefCell<Option<Vec<u8>>>,
        marker: Cell<bool>,
        loads: Rc<Cell<usize>>,
    }

    impl MemoryControllerKeyStore {
        fn empty() -> Self {
            Self {
                seed: RefCell::new(None),
                marker: Cell::new(false),
                loads: Rc::new(Cell::new(0)),
            }
        }

        fn seeded(byte: u8) -> Self {
            Self {
                seed: RefCell::new(Some(vec![byte; 32])),
                marker: Cell::new(false),
                loads: Rc::new(Cell::new(0)),
            }
        }

        fn seeded_with_load_counter(byte: u8) -> (Self, Rc<Cell<usize>>) {
            let store = Self::seeded(byte);
            let loads = Rc::clone(&store.loads);
            (store, loads)
        }
    }

    impl ControllerKeyStore for MemoryControllerKeyStore {
        fn load_seed(&self) -> Result<Option<ControllerSigningKey>, ControllerKeyStoreError> {
            self.loads.set(self.loads.get() + 1);
            self.seed
                .borrow()
                .as_ref()
                .map(|seed| ControllerSigningKey::from_stored_bytes(seed.clone()))
                .transpose()
        }

        fn create_seed(&self, key: &ControllerSigningKey) -> Result<(), ControllerKeyStoreError> {
            let mut seed = self.seed.borrow_mut();
            if seed.is_some() {
                return Err(ControllerKeyStoreError::AlreadyExists);
            }
            *seed = Some(key.expose_seed().to_vec());
            Ok(())
        }

        fn delete_seed(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(self.seed.borrow_mut().take().is_some())
        }

        fn removal_pending(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(self.marker.get())
        }

        fn create_removal_marker(&self) -> Result<(), ControllerKeyStoreError> {
            if self.marker.replace(true) {
                return Err(ControllerKeyStoreError::AlreadyExists);
            }
            Ok(())
        }

        fn delete_removal_marker(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(self.marker.replace(false))
        }
    }

    fn timestamp(value: i64) -> StateTimestamp {
        StateTimestamp::from_unix_millis(value).expect("timestamp")
    }

    fn runtime(label: &str) -> (std::path::PathBuf, BrokerRuntime) {
        let unique = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "keptnear-human-dispatch-{label}-{}-{nanos}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let paths = DevicePaths::prepare_for_test_home(&home).expect("paths");
        let runtime = BrokerRuntime::open_or_initialize_with_paths_at(
            paths,
            MemoryDeviceKeyStore::default(),
            timestamp(100),
        )
        .expect("runtime");
        (home, runtime)
    }

    fn hello() -> HumanControlRequest {
        HumanControlRequest::Hello(
            HumanControlVersionOffer::new(
                CONTROLLER_ROLE,
                [HumanControlProtocolVersionRange::new(1, 0, 0).expect("range")],
                [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
            )
            .expect("offer"),
        )
    }

    #[test]
    fn request_enum_and_frozen_catalog_cover_the_same_closed_operations() {
        let source = include_str!("human_control_dispatcher.rs");
        let catalog = HUMAN_CONTROL_OPERATION_CONTRACTS
            .iter()
            .map(|contract| contract.operation())
            .collect::<Vec<_>>();
        assert_eq!(HUMAN_CONTROL_DISPATCH_OPERATIONS.to_vec(), catalog);
        assert_eq!(
            HUMAN_CONTROL_DISPATCH_OPERATIONS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            29
        );
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [
            concat!("credential", ".search"),
            concat!("access", ".request"),
            concat!("http", ".request"),
            concat!("process", ".run"),
            concat!("secret", "-get"),
        ] {
            assert!(!production.contains(&format!("\"{forbidden}\"")));
        }
        assert!(matches!(
            grant_revoke_response(true),
            HumanControlResponse::RevocationSummary(summary)
                if summary.kind() == BrokerRevocationKind::UseGrant
                    && summary.use_grants_removed() == 1
        ));
        assert_eq!(pending_projection_limit(320), 256);
        let expires_at = timestamp(10_000);
        assert!(matches!(
            HumanControlRequest::CredentialAuthorize {
                request_id: ApprovalRequestId::generate(),
                selection: BrokerCredentialCandidateSelection::new(
                    CredentialId::generate(),
                    SecretFieldId::generate(),
                ),
                confirmation_policy: ConfirmationPolicy::EveryUse,
                rule_lifetime: RuleLifetime::Until(expires_at),
                capability: Capability::v1(crate::CapabilityName::HttpRequest),
            },
            HumanControlRequest::CredentialAuthorize {
                rule_lifetime: RuleLifetime::Until(actual),
                ..
            } if actual == expires_at
        ));
        assert!(validate_human_control_audit_limit(256).is_ok());
        assert!(validate_pending_deny_decision(HUMAN_CONTROL_DENY_DECISION).is_ok());
        assert!(validate_fixed_value(
            HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE,
            HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE,
        )
        .is_ok());
        assert!(
            validate_fixed_value(HUMAN_CONTROL_SHUTDOWN_REASON, HUMAN_CONTROL_SHUTDOWN_REASON,)
                .is_ok()
        );
        assert_eq!(
            validate_pending_deny_decision("approve")
                .expect_err("reject contradictory decision")
                .failure()
                .code(),
            HumanControlFailureCode::InvalidRequest
        );
        let session_id = ControllerSessionId::generate();
        let broker_instance_id = BrokerInstanceId::generate();
        assert!(validate_controller_lease(
            session_id,
            broker_instance_id,
            session_id,
            broker_instance_id,
        )
        .is_ok());
        assert!(validate_controller_lease(
            session_id,
            broker_instance_id,
            ControllerSessionId::generate(),
            broker_instance_id,
        )
        .is_err());
        let filter = BrokerAuditFilter::all();
        let confirmation = BrokerAuditClearConfirmation::after_user_confirmation(filter);
        assert!(validate_audit_clear_confirmation(
            &confirmation,
            confirmation.confirmation_id(),
            filter,
        )
        .is_ok());
        assert!(validate_audit_clear_confirmation(
            &confirmation,
            HumanControlAuditConfirmationId::generate(),
            filter,
        )
        .is_err());
        assert_eq!(
            validate_human_control_audit_limit(257)
                .expect_err("reject oversized audit page")
                .failure()
                .code(),
            HumanControlFailureCode::InvalidRequest
        );
    }

    #[test]
    fn metadata_text_bounds_preserve_utf8_and_reserve_escape_expansion() {
        let source = "\u{754c}".repeat(MAX_HUMAN_CONTROL_METADATA_TEXT_BYTES);
        let (bounded, truncated) = bounded_metadata_text(&source);
        assert!(truncated);
        assert!(bounded.len() <= MAX_HUMAN_CONTROL_METADATA_TEXT_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(metadata_wire_budget("\0"), 6);
        assert_eq!(
            metadata_wire_budget(&bounded),
            bounded.len().saturating_mul(6)
        );
    }

    #[test]
    fn audit_clear_confirmation_queue_is_bounded_single_use_and_connection_local() {
        let mut confirmations = VecDeque::new();
        let first =
            BrokerAuditClearConfirmation::for_human_control_selection(BrokerAuditFilter::all());
        let first_id = first.confirmation_id();
        retain_audit_clear_confirmation(&mut confirmations, first);
        for _ in 0..MAX_HUMAN_CONTROL_AUDIT_CLEAR_CONFIRMATIONS {
            retain_audit_clear_confirmation(
                &mut confirmations,
                BrokerAuditClearConfirmation::for_human_control_selection(BrokerAuditFilter::all()),
            );
        }
        assert_eq!(
            confirmations.len(),
            MAX_HUMAN_CONTROL_AUDIT_CLEAR_CONFIRMATIONS
        );
        assert!(take_audit_clear_confirmation(&mut confirmations, first_id).is_err());

        let retained =
            BrokerAuditClearConfirmation::for_human_control_selection(BrokerAuditFilter::all());
        let retained_id = retained.confirmation_id();
        retain_audit_clear_confirmation(&mut confirmations, retained);
        assert!(take_audit_clear_confirmation(&mut confirmations, retained_id).is_ok());
        assert!(take_audit_clear_confirmation(&mut confirmations, retained_id).is_err());

        let dispatcher = HumanControlDispatcher::new(
            BrokerInstanceId::generate(),
            MemoryControllerKeyStore::empty(),
        );
        let mut connection = dispatcher.connection();
        retain_audit_clear_confirmation(
            &mut connection.audit_clear_confirmations,
            BrokerAuditClearConfirmation::for_human_control_selection(BrokerAuditFilter::all()),
        );
        connection.close();
        assert!(connection.audit_clear_confirmations.is_empty());
    }

    #[test]
    fn negotiation_rejects_wrong_role_or_schema_before_challenge_state() {
        let (home, mut runtime) = runtime("negotiation-bindings");
        let dispatcher = HumanControlDispatcher::new(
            runtime.process().broker_instance_id(),
            MemoryControllerKeyStore::seeded(0x31),
        );
        for (role, schema) in [
            ("consumer", HUMAN_CONTROL_SCHEMA_ID),
            (CONTROLLER_ROLE, "keptnear.human-control.schema.future"),
        ] {
            let mut state = dispatcher.connection();
            let request = HumanControlRequest::Hello(
                HumanControlVersionOffer::new(
                    role,
                    [HumanControlProtocolVersionRange::new(1, 0, 0).expect("range")],
                    [schema.to_owned()],
                )
                .expect("structurally bounded offer"),
            );
            let error = dispatcher
                .dispatch(
                    &mut runtime,
                    &mut state,
                    request,
                    Instant::now(),
                    timestamp(101),
                )
                .expect_err("incompatible identity");
            assert_eq!(
                error.failure().code(),
                HumanControlFailureCode::ProtocolIncompatible
            );
            assert_eq!(state.phase(), HumanControlConnectionPhase::Closed);
        }
        runtime.shutdown_at(timestamp(102)).expect("shutdown");
        drop(runtime);
        fs::remove_dir_all(home).expect("cleanup");
    }

    #[test]
    fn unauthenticated_challenge_cannot_create_controller_authority() {
        let (home, mut runtime) = runtime("challenge-no-create");
        let dispatcher = HumanControlDispatcher::new(
            runtime.process().broker_instance_id(),
            MemoryControllerKeyStore::empty(),
        );
        let mut state = dispatcher.connection();
        let now = Instant::now();
        dispatcher
            .dispatch(&mut runtime, &mut state, hello(), now, timestamp(101))
            .expect("hello");
        let untrusted_key =
            ControllerSigningKey::from_stored_bytes(vec![0x32; 32]).expect("request key");
        let request = ControllerChallengeRequest::new(
            untrusted_key.controller_id(),
            crate::ControllerNonce::from_bytes([0x33; 32]),
        );
        let error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerChallenge(request),
                now,
                timestamp(102),
            )
            .expect_err("authority was not explicitly prepared");
        assert_eq!(
            error.failure().code(),
            HumanControlFailureCode::ControllerUnavailable
        );
        assert_eq!(
            dispatcher
                .prepare_controller_authority_after_explicit_enable(&runtime)
                .expect("trusted explicit preparation"),
            ControllerBootstrapMode::BootstrapNew
        );
        runtime.shutdown_at(timestamp(103)).expect("shutdown");
        drop(runtime);
        fs::remove_dir_all(home).expect("cleanup");
    }

    #[test]
    fn repair_target_must_match_before_runtime_quiescence() {
        assert!(validate_repair_target(
            PackagedComponent::Broker,
            HumanControlProtocolVersion::current()
        )
        .is_ok());
        for (component, protocol) in [
            (
                PackagedComponent::MacOsApp,
                HumanControlProtocolVersion::current(),
            ),
            (
                PackagedComponent::Broker,
                HumanControlProtocolVersion::new(2, 0).expect("future protocol"),
            ),
        ] {
            let error = validate_repair_target(component, protocol).expect_err("mismatch");
            assert_eq!(
                error.failure().code(),
                HumanControlFailureCode::ProtocolIncompatible
            );
            assert_eq!(
                error.failure().required_action(),
                Some(HumanControlRequiredAction::UpdateComponent)
            );
        }
    }

    #[test]
    fn only_unlock_request_accepts_secret_and_every_result_is_secret_free() {
        for contract in HUMAN_CONTROL_OPERATION_CONTRACTS {
            assert_eq!(
                contract.result_secrecy(),
                HumanControlResultSecrecy::SecretFree
            );
            if contract.operation() == HumanControlOperation::VaultUnlock {
                assert_eq!(
                    contract.request_secret_class(),
                    HumanControlRequestSecretClass::VaultUnlockCredential
                );
            } else if !matches!(
                contract.authentication(),
                HumanControlAuthenticationRequirement::Negotiated
            ) {
                assert_ne!(
                    contract.request_secret_class(),
                    HumanControlRequestSecretClass::VaultUnlockCredential
                );
            }
        }
        let marker = "seeded-private-request-marker";
        let request = HumanControlRequest::UsageProfileCatalog {
            consumer_id: ConsumerId::generate(),
            executable_name_hint: Some(marker.to_owned()),
        };
        assert!(!format!("{request:?}").contains(marker));
        let unlock = HumanControlVaultUnlockCredential::MasterPassword(SecretBytes::new(
            b"seeded-secret-marker".to_vec(),
        ));
        assert!(!format!("{unlock:?}").contains("seeded-secret-marker"));
    }

    #[test]
    fn pending_projection_does_not_have_a_private_request_description_field() {
        let source = include_str!("human_control_dispatcher.rs");
        let projection = source
            .split("pub struct HumanControlPendingRequest")
            .nth(1)
            .expect("pending projection")
            .split("impl From")
            .next()
            .expect("projection body");
        assert!(!projection.contains("description"));
        for required in [
            "identity_evidence",
            "pairing_comparison_code",
            "pairing_key_fingerprint",
            "pairing_remaining_millis",
        ] {
            assert!(projection.contains(required));
        }
        let review = source
            .split("pub struct HumanControlCredentialReview")
            .nth(1)
            .expect("review projection")
            .split("impl From")
            .next()
            .expect("review body");
        assert!(!review.contains("description"));
    }

    #[test]
    fn real_runtime_requires_controller_proof_then_dispatches_secret_free_management() {
        let (home, mut runtime) = runtime("authenticated");
        let seed = ControllerSigningKey::from_stored_bytes(vec![0x71; 32]).expect("seed");
        let dispatcher = HumanControlDispatcher::new(
            runtime.process().broker_instance_id(),
            MemoryControllerKeyStore::seeded(0x71),
        );
        let mut state = dispatcher.connection();
        let now = Instant::now();

        let error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ReadinessGet,
                now,
                timestamp(110),
            )
            .expect_err("hello required");
        assert_eq!(
            error.failure().code(),
            HumanControlFailureCode::NegotiationRequired
        );
        assert!(matches!(
            dispatcher.dispatch(&mut runtime, &mut state, hello(), now, timestamp(111)),
            Ok(HumanControlResponse::Hello { .. })
        ));

        let challenge_request = ControllerChallengeRequest::new(
            seed.controller_id(),
            crate::ControllerNonce::from_bytes([0x73; 32]),
        );
        let challenge = match dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerChallenge(challenge_request),
                now,
                timestamp(112),
            )
            .expect("challenge")
        {
            HumanControlResponse::ControllerChallenge(challenge) => challenge,
            other => panic!("unexpected response {other:?}"),
        };
        let authenticated = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerAuthenticate(challenge.prove(&seed)),
                now,
                timestamp(113),
            )
            .expect("authenticate");
        let (controller_id, session_id) = match authenticated {
            HumanControlResponse::ControllerAuthenticated {
                controller_id,
                session_id,
                lease_duration_millis,
            } => {
                assert_eq!(lease_duration_millis, 30_000);
                (controller_id, session_id)
            }
            other => panic!("unexpected response {other:?}"),
        };
        assert_eq!(
            state.phase(),
            HumanControlConnectionPhase::Authenticated {
                controller_id,
                session_id,
            }
        );
        let broker_instance_id = runtime.process().broker_instance_id();
        for request in [
            HumanControlRequest::ControllerLeaseRenew {
                controller_session_id: ControllerSessionId::generate(),
                broker_instance_id,
            },
            HumanControlRequest::ControllerLeaseRenew {
                controller_session_id: session_id,
                broker_instance_id: BrokerInstanceId::generate(),
            },
        ] {
            let error = dispatcher
                .dispatch(&mut runtime, &mut state, request, now, timestamp(113))
                .expect_err("reject stale lease identity");
            assert_eq!(
                error.failure().code(),
                HumanControlFailureCode::InvalidRequest
            );
        }
        assert!(matches!(
            dispatcher.dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerLeaseRenew {
                    controller_session_id: session_id,
                    broker_instance_id,
                },
                now,
                timestamp(113),
            ),
            Ok(HumanControlResponse::ControllerLease {
                session_id: renewed,
                lease_duration_millis: 30_000,
            }) if renewed == session_id
        ));

        assert!(matches!(
            dispatcher.dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ReadinessGet,
                now,
                timestamp(114),
            ),
            Ok(HumanControlResponse::Readiness(_))
        ));
        assert!(matches!(
            dispatcher.dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::MachineAccessPauseSet { paused: true },
                now,
                timestamp(115),
            ),
            Ok(HumanControlResponse::PauseState { paused: true })
        ));
        let pending = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::PendingList,
                now,
                timestamp(116),
            )
            .expect("pending list");
        assert!(
            matches!(pending, HumanControlResponse::PendingQueue(requests) if requests.is_empty())
        );
        for occurred_at in [timestamp(115), timestamp(116)] {
            runtime
                .device_state()
                .append_audit_event(&crate::AuditEvent::new(
                    occurred_at,
                    crate::AuditEventKind::Authorization,
                    crate::AuditScope::new(None, None, None, None),
                    crate::AuditDecision::Allowed,
                    crate::ConfirmationMethod::UserApproval,
                ))
                .expect("seed audit event");
        }
        let listed = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditList {
                    filter: BrokerAuditFilter::all(),
                    cursor: None,
                    limit: 10,
                },
                now,
                timestamp(117),
            )
            .expect("bounded audit page");
        let HumanControlResponse::AuditPage(listed) = listed else {
            panic!("expected audit page");
        };
        assert_eq!(listed.page().events().len(), 2);
        let first_confirmation_id = listed.clear_confirmation_id();
        let export = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditExport {
                    filter: BrokerAuditFilter::all(),
                    limit: 1,
                },
                now,
                timestamp(118),
            )
            .expect("bounded audit export");
        assert!(matches!(
            export,
            HumanControlResponse::AuditExport(export) if export.event_count() == 1
        ));
        let clear_filter = BrokerAuditFilter::all();
        let wrong_id_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditClear {
                    filter: clear_filter,
                    confirmation_id: HumanControlAuditConfirmationId::generate(),
                },
                now,
                timestamp(118),
            )
            .expect_err("reject mismatched audit confirmation identity");
        assert_eq!(
            wrong_id_error.failure().code(),
            HumanControlFailureCode::InvalidRequest
        );
        let wrong_selection_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditClear {
                    filter: BrokerAuditFilter::all().with_consumer(ConsumerId::generate()),
                    confirmation_id: first_confirmation_id,
                },
                now,
                timestamp(118),
            )
            .expect_err("reject mismatched audit confirmation selection");
        assert_eq!(
            wrong_selection_error.failure().code(),
            HumanControlFailureCode::InvalidRequest
        );
        let relisted = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditList {
                    filter: clear_filter,
                    cursor: None,
                    limit: 10,
                },
                now,
                timestamp(118),
            )
            .expect("reissue audit clear confirmation");
        let HumanControlResponse::AuditPage(relisted) = relisted else {
            panic!("expected second audit page");
        };
        let clear_confirmation_id = relisted.clear_confirmation_id();
        let clear = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditClear {
                    filter: clear_filter,
                    confirmation_id: clear_confirmation_id,
                },
                now,
                timestamp(118),
            )
            .expect("clear exact confirmed audit selection");
        assert!(matches!(
            clear,
            HumanControlResponse::AuditClearSummary(summary)
                if summary.removed_events() == 2 && summary.remaining_events() == 0
        ));
        let replay_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditClear {
                    filter: clear_filter,
                    confirmation_id: clear_confirmation_id,
                },
                now,
                timestamp(118),
            )
            .expect_err("reject consumed audit confirmation");
        assert_eq!(
            replay_error.failure().code(),
            HumanControlFailureCode::InvalidRequest
        );
        let revoke_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ConsumerRevoke {
                    consumer_id: ConsumerId::generate(),
                    scope: "credential-only".to_owned(),
                },
                now,
                timestamp(118),
            )
            .expect_err("reject contradictory Consumer scope");
        assert_eq!(
            revoke_error.failure().code(),
            HumanControlFailureCode::InvalidRequest
        );
        let secret_marker = "seeded-human-control-secret-marker";
        let unlock_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::VaultUnlock {
                    vault_id: VaultId::generate(),
                    credential: HumanControlVaultUnlockCredential::MasterPassword(
                        SecretBytes::new(secret_marker.as_bytes().to_vec()),
                    ),
                },
                now,
                timestamp(119),
            )
            .expect_err("untracked Vault unlock must fail");
        assert_eq!(
            unlock_error.failure().code(),
            HumanControlFailureCode::UnlockFailed
        );
        assert!(!unlock_error.to_string().contains(secret_marker));
        assert!(!format!("{unlock_error:?}").contains(secret_marker));

        let shutdown_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::Shutdown {
                    reason: "repair".to_owned(),
                },
                now,
                timestamp(120),
            )
            .expect_err("reject contradictory shutdown reason");
        assert_eq!(
            shutdown_error.failure().code(),
            HumanControlFailureCode::InvalidRequest
        );
        assert!(!runtime
            .process()
            .vault_sessions()
            .is_shutdown()
            .expect("runtime remains active"));
        assert!(matches!(
            dispatcher.dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::Shutdown {
                    reason: HUMAN_CONTROL_SHUTDOWN_REASON.to_owned(),
                },
                now,
                timestamp(120),
            ),
            Ok(HumanControlResponse::ShutdownReceipt(_))
        ));
        assert_eq!(state.phase(), HumanControlConnectionPhase::Closed);
        let post_shutdown_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::MachineAccessPauseSet { paused: true },
                now,
                timestamp(121),
            )
            .expect_err("closed controller connection cannot mutate quiesced state");
        assert_eq!(
            post_shutdown_error.failure().code(),
            HumanControlFailureCode::AuthenticationRequired
        );
        drop(runtime);
        fs::remove_dir_all(home).expect("cleanup");
    }

    #[test]
    fn repair_prepare_closes_the_authenticated_connection_after_quiescence() {
        let (home, mut runtime) = runtime("repair-closes-connection");
        let seed = ControllerSigningKey::from_stored_bytes(vec![0x75; 32]).expect("seed");
        let dispatcher = HumanControlDispatcher::new(
            runtime.process().broker_instance_id(),
            MemoryControllerKeyStore::seeded(0x75),
        );
        let mut state = dispatcher.connection();
        let now = Instant::now();
        dispatcher
            .dispatch(&mut runtime, &mut state, hello(), now, timestamp(200))
            .expect("hello");
        let challenge = match dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerChallenge(ControllerChallengeRequest::new(
                    seed.controller_id(),
                    crate::ControllerNonce::from_bytes([0x76; 32]),
                )),
                now,
                timestamp(201),
            )
            .expect("challenge")
        {
            HumanControlResponse::ControllerChallenge(challenge) => challenge,
            _ => panic!("expected controller challenge"),
        };
        dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerAuthenticate(challenge.prove(&seed)),
                now,
                timestamp(202),
            )
            .expect("authenticate");

        assert!(matches!(
            dispatcher.dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::RepairPrepare {
                    expected_component: PackagedComponent::Broker,
                    expected_protocol: HumanControlProtocolVersion::current(),
                },
                now,
                timestamp(203),
            ),
            Ok(HumanControlResponse::RepairReadiness(_))
        ));
        assert_eq!(state.phase(), HumanControlConnectionPhase::Closed);
        let post_repair_error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::MachineAccessPauseSet { paused: true },
                now,
                timestamp(204),
            )
            .expect_err("closed repair connection cannot mutate quiesced state");
        assert_eq!(
            post_repair_error.failure().code(),
            HumanControlFailureCode::AuthenticationRequired
        );

        drop(runtime);
        fs::remove_dir_all(home).expect("cleanup");
    }

    #[test]
    fn authenticated_connection_lease_expires_and_only_valid_renewal_extends_it() {
        let (home, mut runtime) = runtime("controller-lease");
        let seed = ControllerSigningKey::from_stored_bytes(vec![0x72; 32]).expect("seed");
        let dispatcher = HumanControlDispatcher::new(
            runtime.process().broker_instance_id(),
            MemoryControllerKeyStore::seeded(0x72),
        );
        let broker_instance_id = runtime.process().broker_instance_id();
        let mut state = dispatcher.connection();
        let authenticated_at = Instant::now();
        dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                hello(),
                authenticated_at,
                timestamp(200),
            )
            .expect("hello");
        let challenge = match dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerChallenge(ControllerChallengeRequest::new(
                    seed.controller_id(),
                    crate::ControllerNonce::from_bytes([0x74; 32]),
                )),
                authenticated_at,
                timestamp(201),
            )
            .expect("challenge")
        {
            HumanControlResponse::ControllerChallenge(challenge) => challenge,
            other => panic!("unexpected response {other:?}"),
        };
        dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerAuthenticate(challenge.prove(&seed)),
                authenticated_at,
                timestamp(202),
            )
            .expect("authenticate");
        let initial_expiry = authenticated_at + HUMAN_CONTROL_CONTROLLER_LEASE_TTL;
        assert!(dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ReadinessGet,
                initial_expiry - std::time::Duration::from_nanos(1),
                timestamp(203),
            )
            .is_ok());

        let invalid_renewal = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerLeaseRenew {
                    controller_session_id: ControllerSessionId::generate(),
                    broker_instance_id,
                },
                initial_expiry - std::time::Duration::from_secs(1),
                timestamp(204),
            )
            .expect_err("reject mismatched renewal");
        assert_eq!(
            invalid_renewal.failure().code(),
            HumanControlFailureCode::InvalidRequest
        );
        let expired = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ReadinessGet,
                initial_expiry,
                timestamp(205),
            )
            .expect_err("exact deadline expires");
        assert_eq!(
            expired.failure(),
            HumanControlProtocolFailure::new(
                HumanControlFailureCode::AuthenticationRequired,
                false,
                Some(HumanControlRequiredAction::Reauthenticate),
            )
        );
        assert_eq!(state.phase(), HumanControlConnectionPhase::Closed);

        let mut renewed_state = dispatcher.connection();
        dispatcher
            .dispatch(
                &mut runtime,
                &mut renewed_state,
                hello(),
                authenticated_at,
                timestamp(206),
            )
            .expect("renewed hello");
        let challenge = match dispatcher
            .dispatch(
                &mut runtime,
                &mut renewed_state,
                HumanControlRequest::ControllerChallenge(ControllerChallengeRequest::new(
                    seed.controller_id(),
                    crate::ControllerNonce::from_bytes([0x75; 32]),
                )),
                authenticated_at,
                timestamp(207),
            )
            .expect("renewed challenge")
        {
            HumanControlResponse::ControllerChallenge(challenge) => challenge,
            other => panic!("unexpected response {other:?}"),
        };
        let renewed_session_id = challenge.session_id();
        dispatcher
            .dispatch(
                &mut runtime,
                &mut renewed_state,
                HumanControlRequest::ControllerAuthenticate(challenge.prove(&seed)),
                authenticated_at,
                timestamp(208),
            )
            .expect("renewed authenticate");
        let renewal_at = authenticated_at + std::time::Duration::from_secs(20);
        dispatcher
            .dispatch(
                &mut runtime,
                &mut renewed_state,
                HumanControlRequest::ControllerLeaseRenew {
                    controller_session_id: renewed_session_id,
                    broker_instance_id,
                },
                renewal_at,
                timestamp(209),
            )
            .expect("valid renewal");
        assert!(dispatcher
            .dispatch(
                &mut runtime,
                &mut renewed_state,
                HumanControlRequest::ReadinessGet,
                initial_expiry,
                timestamp(210),
            )
            .is_ok());
        let renewed_expiry = renewal_at + HUMAN_CONTROL_CONTROLLER_LEASE_TTL;
        let expired = dispatcher
            .dispatch(
                &mut runtime,
                &mut renewed_state,
                HumanControlRequest::ReadinessGet,
                renewed_expiry,
                timestamp(211),
            )
            .expect_err("renewed exact deadline expires");
        assert_eq!(
            expired.failure().required_action(),
            Some(HumanControlRequiredAction::Reauthenticate)
        );
        runtime.shutdown_at(timestamp(212)).expect("shutdown");
        drop(runtime);
        fs::remove_dir_all(home).expect("cleanup");
    }

    #[test]
    fn same_user_with_wrong_controller_key_cannot_replace_complete_authority() {
        let (home, mut runtime) = runtime("impersonation");
        let approved = ControllerSigningKey::from_stored_bytes(vec![0x41; 32]).expect("approved");
        runtime
            .insert_controller_authority_record(crate::ControllerAuthorityRecord::new(
                approved.public_key(),
                timestamp(120),
            ))
            .expect("record");
        let (store, load_count) = MemoryControllerKeyStore::seeded_with_load_counter(0x41);
        let dispatcher = HumanControlDispatcher::new(runtime.process().broker_instance_id(), store);
        let mut state = dispatcher.connection();
        let now = Instant::now();
        dispatcher
            .dispatch(&mut runtime, &mut state, hello(), now, timestamp(121))
            .expect("hello");
        let impostor = ControllerSigningKey::from_stored_bytes(vec![0x42; 32]).expect("impostor");
        for attempt in 0..MAX_CONTROLLER_FAILURES_PER_IDENTITY {
            let session_byte = 0x43_u8.wrapping_add(u8::try_from(attempt).expect("attempt"));
            let request = ControllerChallengeRequest::new(
                impostor.controller_id(),
                crate::ControllerNonce::from_bytes([session_byte.wrapping_add(1); 32]),
            );
            let error = dispatcher
                .dispatch(
                    &mut runtime,
                    &mut state,
                    HumanControlRequest::ControllerChallenge(request),
                    now,
                    timestamp(122),
                )
                .expect_err("wrong key rejected");
            assert_eq!(
                error.failure().code(),
                HumanControlFailureCode::AuthenticationFailed
            );
        }
        let request = ControllerChallengeRequest::new(
            impostor.controller_id(),
            crate::ControllerNonce::from_bytes([0x61; 32]),
        );
        let error = dispatcher
            .dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerChallenge(request),
                now,
                timestamp(122),
            )
            .expect_err("wrong key rate limited");
        assert_eq!(error.failure().code(), HumanControlFailureCode::RateLimited);
        assert_eq!(load_count.get(), MAX_CONTROLLER_FAILURES_PER_IDENTITY);
        assert_eq!(
            runtime
                .controller_authority_record()
                .expect("preserved record")
                .expect("record")
                .controller_id(),
            approved.controller_id()
        );
        runtime.shutdown_at(timestamp(123)).expect("shutdown");
        drop(runtime);
        fs::remove_dir_all(home).expect("cleanup");
    }
}
