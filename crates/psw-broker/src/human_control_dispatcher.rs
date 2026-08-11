use std::fmt::{Debug, Display, Formatter};
use std::time::Instant;

use psw_core::{SecretBytes, VaultId};

use crate::{
    bundled_usage_profile_templates, recommend_bundled_usage_profile, ApprovalRequestId,
    BrokerAppsToolsSnapshot, BrokerAuditClearConfirmation, BrokerAuditClearSummary,
    BrokerAuditCursor, BrokerAuditExport, BrokerAuditFilter, BrokerAuditPage, BrokerConsumerDetail,
    BrokerConsumerIdentityEvidence, BrokerCredentialCandidateSelection,
    BrokerGrantInvalidationSummary, BrokerHumanCredentialCandidate, BrokerHumanCredentialReview,
    BrokerHumanSecretFieldCandidate, BrokerInstanceId, BrokerPairingUserApproval,
    BrokerPendingRequest, BrokerPendingRequestId, BrokerPendingRequestKind,
    BrokerReadinessProjection, BrokerRevocationSummary, BrokerRuntime, BrokerRuntimeError,
    BrokerVaultSessionSnapshot, BundledUsageProfileRecommendation, BundledUsageProfileTemplate,
    Capability, ConfirmationPolicy, ConsumerEvidenceFingerprint, ConsumerId,
    ControllerAuthenticationChallenge, ControllerAuthenticationCompletion,
    ControllerAuthenticationConnection, ControllerAuthenticationError,
    ControllerAuthenticationMode, ControllerAuthenticationProof, ControllerAuthenticationService,
    ControllerAuthorityError, ControllerAuthorityManager, ControllerBootstrapMode,
    ControllerChallengeRequest, ControllerId, ControllerKeyStore, ControllerSessionId,
    CredentialFieldScope, CredentialId, HumanControlFailureCode, HumanControlOperation,
    HumanControlProtocolFailure, HumanControlProtocolVersion, HumanControlRequiredAction,
    HumanControlVersionOffer, PairingComparisonCode, PairingRequestId, SecretFieldId,
    SecretFieldKind, StateTimestamp, UsageProfile, UsageProfileDefinition, UsageProfileId,
    UseGrantId, HUMAN_CONTROL_SCHEMA_ID, MAX_HUMAN_CONTROL_AUDIT_EVENTS,
    MAX_HUMAN_CONTROL_COLLECTION_ITEMS, MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
};

const MAX_HUMAN_CONTROL_AUDIT_EXPORT_BYTES: usize = MAX_HUMAN_CONTROL_RESPONSE_LENGTH / 2;

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
    ControllerLeaseRenew,
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
        /// Exact candidate selection for a new-Credential request.
        selection: Option<BrokerCredentialCandidateSelection>,
    },
    /// Create one exact persistent Access Rule.
    CredentialAuthorize {
        /// Persisted field or credential-access approval identity.
        request_id: ApprovalRequestId,
        /// Exact candidate selection for a new-Credential request.
        selection: Option<BrokerCredentialCandidateSelection>,
        /// Human-selected confirmation policy for the Access Rule.
        confirmation_policy: ConfirmationPolicy,
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
        /// Capability token proving explicit local confirmation.
        confirmation: BrokerAuditClearConfirmation,
    },
    /// Export one bounded non-secret audit document.
    AuditExport {
        /// Exact non-secret audit selection.
        filter: BrokerAuditFilter,
    },
    /// Quiesce process state before App-managed repair.
    RepairPrepare,
    /// Gracefully stop process-owned sessions and grants.
    Shutdown,
}

impl HumanControlRequest {
    /// Returns the exact frozen operation represented by this request variant.
    #[must_use]
    pub const fn operation(&self) -> HumanControlOperation {
        match self {
            Self::Hello(_) => HumanControlOperation::Hello,
            Self::ControllerChallenge(_) => HumanControlOperation::ControllerChallenge,
            Self::ControllerAuthenticate(_) => HumanControlOperation::ControllerAuthenticate,
            Self::ControllerLeaseRenew => HumanControlOperation::ControllerLeaseRenew,
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
            Self::RepairPrepare => HumanControlOperation::RepairPrepare,
            Self::Shutdown => HumanControlOperation::Shutdown,
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

impl From<&BrokerHumanSecretFieldCandidate> for HumanControlSecretFieldCandidate {
    fn from(field: &BrokerHumanSecretFieldCandidate) -> Self {
        Self {
            secret_field_id: field.secret_field_id(),
            role: field.role().to_owned(),
            label: field.label().map(str::to_owned),
            kind: field.kind(),
        }
    }
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

impl From<&BrokerHumanCredentialCandidate> for HumanControlCredentialCandidate {
    fn from(candidate: &BrokerHumanCredentialCandidate) -> Self {
        Self {
            vault_id: candidate.vault_id(),
            credential_id: candidate.credential_id(),
            title: candidate.title().to_owned(),
            template_id: candidate.template_id().map(str::to_owned),
            tags: candidate.tags().to_vec(),
            favorite: candidate.favorite(),
            secret_fields: candidate
                .secret_fields()
                .iter()
                .map(HumanControlSecretFieldCandidate::from)
                .collect(),
        }
    }
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
    /// Whether additional candidates were omitted.
    pub truncated: bool,
}

impl From<&BrokerHumanCredentialReview> for HumanControlCredentialReview {
    fn from(review: &BrokerHumanCredentialReview) -> Self {
        Self {
            consumer_id: review.consumer_id(),
            vault_id: review.vault_id(),
            capability: review.capability(),
            candidates: review
                .candidates()
                .iter()
                .map(HumanControlCredentialCandidate::from)
                .collect(),
            truncated: review.truncated(),
        }
    }
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
    },
    /// Current connection lease remains active; timed expiry is added in task 3.6.
    ControllerLease {
        /// Ephemeral authenticated connection session.
        session_id: ControllerSessionId,
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
    AuthorizationSnapshot(BrokerAppsToolsSnapshot),
    /// Consumer management detail.
    ConsumerDetail(BrokerConsumerDetail),
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
    AuditPage(BrokerAuditPage),
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
        }
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
                self.dispatch_authenticated(runtime, request, session_id, observed_at)
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
        if !matches!(state.phase, HumanControlConnectionPhase::Negotiated(_)) {
            return Err(HumanControlDispatchError::code(
                HumanControlFailureCode::NegotiationRequired,
            ));
        }
        state
            .authentication
            .check_challenge_budget(request.controller_id(), now)
            .map_err(map_authentication_error)?;
        let record = runtime
            .controller_authority_record()
            .map_err(map_runtime_error)?;
        let prepared = self
            .authority
            .prepare_for_explicit_enable(record)
            .map_err(map_authority_error)?;
        let expected_mode = match prepared.mode() {
            ControllerBootstrapMode::BootstrapNew | ControllerBootstrapMode::ResumeBootstrap => {
                ControllerAuthenticationMode::Bootstrap
            }
            ControllerBootstrapMode::AuthenticateExisting => {
                ControllerAuthenticationMode::Authenticate
            }
        };
        if request.mode() != expected_mode || !request.matches_key(prepared.key()) {
            return Err(map_authentication_error(
                state
                    .authentication
                    .reject_challenge(request.controller_id(), now),
            ));
        }
        let challenge = state
            .authentication
            .challenge(request, record, now)
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
        Ok(HumanControlResponse::ControllerAuthenticated {
            controller_id,
            session_id,
        })
    }

    fn dispatch_authenticated(
        &self,
        runtime: &mut BrokerRuntime,
        request: HumanControlRequest,
        session_id: ControllerSessionId,
        observed_at: StateTimestamp,
    ) -> Result<HumanControlResponse, HumanControlDispatchError> {
        match request {
            HumanControlRequest::ControllerLeaseRenew => {
                Ok(HumanControlResponse::ControllerLease { session_id })
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
            HumanControlRequest::PendingDeny { request_id } => {
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
            HumanControlRequest::UnlockApprove { request_id } => {
                runtime
                    .approve_pending_unlock(request_id, observed_at)
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
                    .allow_once_pending_request(request_id, selection, observed_at)
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::DecisionReceipt { changed: true })
            }
            HumanControlRequest::CredentialAuthorize {
                request_id,
                selection,
                confirmation_policy,
            } => {
                let created = runtime
                    .configure_pending_request_access_rule(
                        request_id,
                        selection,
                        confirmation_policy,
                        observed_at,
                    )
                    .map_err(map_runtime_error)?;
                Ok(HumanControlResponse::DecisionReceipt {
                    changed: created.newly_created(),
                })
            }
            HumanControlRequest::AuthorizationSnapshot { vault_id } => runtime
                .apps_tools_snapshot(vault_id)
                .map(HumanControlResponse::AuthorizationSnapshot)
                .map_err(map_runtime_error),
            HumanControlRequest::ConsumerDetail { consumer_id } => runtime
                .apps_tools_consumer_detail(consumer_id)
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
            HumanControlRequest::ConsumerRevoke { consumer_id } => runtime
                .revoke_consumer_access(consumer_id)
                .map(HumanControlResponse::RevocationSummary)
                .map_err(map_runtime_error),
            HumanControlRequest::AllAccessRevoke => runtime
                .revoke_all_apps_and_tools_access()
                .map(HumanControlResponse::RevocationSummary)
                .map_err(map_runtime_error),
            HumanControlRequest::AuditList {
                filter,
                cursor,
                limit,
            } => runtime
                .view_audit_at(filter, cursor, limit, observed_at)
                .map(HumanControlResponse::AuditPage)
                .map_err(map_runtime_error),
            HumanControlRequest::AuditClear {
                filter,
                confirmation,
            } => runtime
                .clear_audit(filter, confirmation)
                .map(HumanControlResponse::AuditClearSummary)
                .map_err(map_runtime_error),
            HumanControlRequest::AuditExport { filter } => runtime
                .export_human_control_audit_json_at(
                    filter,
                    observed_at,
                    MAX_HUMAN_CONTROL_AUDIT_EVENTS,
                    MAX_HUMAN_CONTROL_AUDIT_EXPORT_BYTES,
                )
                .map(HumanControlResponse::AuditExport)
                .map_err(map_runtime_error),
            HumanControlRequest::RepairPrepare => runtime
                .shutdown_at(observed_at)
                .map(HumanControlResponse::RepairReadiness)
                .map_err(map_runtime_error),
            HumanControlRequest::Shutdown => runtime
                .shutdown_at(observed_at)
                .map(HumanControlResponse::ShutdownReceipt)
                .map_err(map_runtime_error),
            HumanControlRequest::Hello(_)
            | HumanControlRequest::ControllerChallenge(_)
            | HumanControlRequest::ControllerAuthenticate(_) => Err(
                HumanControlDispatchError::code(HumanControlFailureCode::InvalidRequest),
            ),
        }
    }
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
            HumanControlVersionOffer::new([
                HumanControlProtocolVersionRange::new(1, 0, 0).expect("range")
            ])
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

        let session_id = ControllerSessionId::from_bytes([0x72; 16]);
        let challenge_request = ControllerChallengeRequest::new(
            ControllerAuthenticationMode::Bootstrap,
            HumanControlProtocolVersion::current(),
            CONTROLLER_ROLE.to_owned(),
            seed.controller_id(),
            seed.public_key(),
            session_id,
            crate::ControllerNonce::from_bytes([0x73; 32]),
        )
        .expect("challenge request");
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
        assert!(matches!(
            dispatcher.dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::ControllerAuthenticate(challenge.prove(&seed)),
                now,
                timestamp(113),
            ),
            Ok(HumanControlResponse::ControllerAuthenticated { .. })
        ));
        assert!(matches!(
            state.phase(),
            HumanControlConnectionPhase::Authenticated { .. }
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
        assert!(matches!(
            dispatcher.dispatch(
                &mut runtime,
                &mut state,
                HumanControlRequest::AuditList {
                    filter: BrokerAuditFilter::all(),
                    cursor: None,
                    limit: 10,
                },
                now,
                timestamp(117),
            ),
            Ok(HumanControlResponse::AuditPage(_))
        ));
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
                timestamp(118),
            )
            .expect_err("untracked Vault unlock must fail");
        assert_eq!(
            unlock_error.failure().code(),
            HumanControlFailureCode::UnlockFailed
        );
        assert!(!unlock_error.to_string().contains(secret_marker));
        assert!(!format!("{unlock_error:?}").contains(secret_marker));

        runtime.shutdown_at(timestamp(119)).expect("shutdown");
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
                ControllerAuthenticationMode::Authenticate,
                HumanControlProtocolVersion::current(),
                CONTROLLER_ROLE.to_owned(),
                impostor.controller_id(),
                impostor.public_key(),
                ControllerSessionId::from_bytes([session_byte; 16]),
                crate::ControllerNonce::from_bytes([session_byte.wrapping_add(1); 32]),
            )
            .expect("request");
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
            ControllerAuthenticationMode::Authenticate,
            HumanControlProtocolVersion::current(),
            CONTROLLER_ROLE.to_owned(),
            impostor.controller_id(),
            impostor.public_key(),
            ControllerSessionId::from_bytes([0x60; 16]),
            crate::ControllerNonce::from_bytes([0x61; 32]),
        )
        .expect("limited request");
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
