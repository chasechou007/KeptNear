use std::fmt::{Display, Formatter};
use std::time::Duration;

use psw_core::{CredentialId, VaultId};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::approval::BrokerHumanApprovalSnapshot;
use crate::audit::{BrokerAuditError, BrokerAuditFilter, BrokerAuditManager};
use crate::pairing::{
    BrokerPairingIdentityEvidence, BrokerPairingRequestSnapshot, BrokerPairingRequestStatus,
    PairingComparisonCode,
};
use crate::state_model::{
    AccessRule, AccessRuleId, ApprovalRequestId, ApprovalSubject, AuditDecision, AuditEvent,
    AuditEventId, AuditEventKind, Capability, ConfirmationMethod, ConfirmationPolicy,
    ConsumerCodeSigningEvidence, ConsumerEvidenceFingerprint, ConsumerId, CredentialFieldScope,
    ObservedConsumerIdentity, PairingRequestId, RuleLifetime, StateTimestamp, UsagePlacement,
    UsageProfile, UsageProfileId,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};

/// Maximum recent events included in one Consumer detail projection.
pub const MAX_CONSUMER_DETAIL_AUDIT_EVENTS: usize = 50;

/// Storage boundary that owns one pending human decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerPendingRequestId {
    /// Process-local Consumer pairing request.
    Pairing(PairingRequestId),
    /// Authenticated asynchronous approval request.
    Approval(ApprovalRequestId),
}

/// Human decision category shown in the pending-request queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerPendingRequestKind {
    /// Pair one new local Consumer.
    Pairing,
    /// Unlock one Vault for a paired Consumer.
    Unlock,
    /// Authorize one exact existing Secret Field capability.
    Access,
    /// Match a new credential request in the human control plane.
    CredentialAccess,
}

/// One bounded, path-free pending request for the trusted human interface.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPendingRequest {
    request_id: BrokerPendingRequestId,
    kind: BrokerPendingRequestKind,
    consumer_id: Option<ConsumerId>,
    consumer_label: Option<String>,
    identity_evidence: Option<BrokerConsumerIdentityEvidence>,
    pairing_comparison_code: Option<PairingComparisonCode>,
    pairing_key_fingerprint: Option<ConsumerEvidenceFingerprint>,
    vault_id: Option<VaultId>,
    field_scope: Option<CredentialFieldScope>,
    capability: Option<Capability>,
    request_description: Option<String>,
    created_at: Option<StateTimestamp>,
    expires_at: Option<StateTimestamp>,
    remaining: Option<Duration>,
}

impl BrokerPendingRequest {
    /// Returns the typed stable request identity.
    #[must_use]
    pub const fn request_id(&self) -> BrokerPendingRequestId {
        self.request_id
    }

    /// Returns the human decision category.
    #[must_use]
    pub const fn kind(&self) -> BrokerPendingRequestKind {
        self.kind
    }

    /// Returns the paired Consumer identity when one has been allocated.
    #[must_use]
    pub const fn consumer_id(&self) -> Option<ConsumerId> {
        self.consumer_id
    }

    /// Returns the user-controlled Consumer label when paired.
    #[must_use]
    pub fn consumer_label(&self) -> Option<&str> {
        self.consumer_label.as_deref()
    }

    /// Returns bounded path-free operating-system evidence when available.
    #[must_use]
    pub const fn identity_evidence(&self) -> Option<&BrokerConsumerIdentityEvidence> {
        self.identity_evidence.as_ref()
    }

    /// Returns the comparison code for a process-local pairing request.
    #[must_use]
    pub const fn pairing_comparison_code(&self) -> Option<PairingComparisonCode> {
        self.pairing_comparison_code
    }

    /// Returns the short fingerprint of the proposed pairing key.
    #[must_use]
    pub const fn pairing_key_fingerprint(&self) -> Option<ConsumerEvidenceFingerprint> {
        self.pairing_key_fingerprint
    }

    /// Returns the requested Vault identity when applicable.
    #[must_use]
    pub const fn vault_id(&self) -> Option<VaultId> {
        self.vault_id
    }

    /// Returns the exact existing Secret Field scope when applicable.
    #[must_use]
    pub const fn field_scope(&self) -> Option<CredentialFieldScope> {
        self.field_scope
    }

    /// Returns the requested capability when applicable.
    #[must_use]
    pub const fn capability(&self) -> Option<Capability> {
        self.capability
    }

    /// Returns the bounded process-local matching description when applicable.
    #[must_use]
    pub fn request_description(&self) -> Option<&str> {
        self.request_description.as_deref()
    }

    /// Returns creation time for an authenticated asynchronous approval.
    #[must_use]
    pub const fn created_at(&self) -> Option<StateTimestamp> {
        self.created_at
    }

    /// Returns the exclusive expiry for an authenticated asynchronous approval.
    #[must_use]
    pub const fn expires_at(&self) -> Option<StateTimestamp> {
        self.expires_at
    }

    /// Returns remaining lifetime for a process-local pairing request.
    #[must_use]
    pub const fn remaining(&self) -> Option<Duration> {
        self.remaining
    }
}

impl std::fmt::Debug for BrokerPendingRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPendingRequest")
            .field("request_id", &self.request_id)
            .field("kind", &self.kind)
            .field("consumer_id", &self.consumer_id)
            .field("has_consumer_label", &self.consumer_label.is_some())
            .field("identity_evidence", &self.identity_evidence)
            .field("pairing_comparison_code", &self.pairing_comparison_code)
            .field("pairing_key_fingerprint", &self.pairing_key_fingerprint)
            .field("vault_id", &self.vault_id)
            .field("field_scope", &self.field_scope)
            .field("capability", &self.capability)
            .field(
                "request_description",
                &self.request_description.as_ref().map(|_| "<redacted>"),
            )
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("remaining", &self.remaining)
            .finish()
    }
}

impl Drop for BrokerPendingRequest {
    fn drop(&mut self) {
        if let Some(description) = &mut self.request_description {
            description.zeroize();
        }
    }
}

/// Complete bounded queue of requests still requiring a local human decision.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BrokerPendingRequestQueue {
    requests: Vec<BrokerPendingRequest>,
}

impl BrokerPendingRequestQueue {
    /// Returns pending requests in stable pairing-then-expiry order.
    #[must_use]
    pub fn requests(&self) -> &[BrokerPendingRequest] {
        &self.requests
    }

    /// Returns the exact visible pending count.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.requests.len()
    }
}

/// Sanitized failure while building the trusted human Apps & Tools projection.
#[derive(Debug)]
pub enum BrokerHumanControlError {
    /// Authenticated encrypted device state could not be read.
    DeviceState(DeviceStateError),
    /// The requested Consumer no longer exists.
    ConsumerUnavailable,
    /// The bounded local audit projection could not be read.
    Audit(BrokerAuditError),
}

impl Display for BrokerHumanControlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceState(source) => {
                write!(formatter, "Apps & Tools state failed: {source}")
            }
            Self::ConsumerUnavailable => {
                formatter.write_str("Apps & Tools Consumer is unavailable")
            }
            Self::Audit(source) => write!(formatter, "Apps & Tools audit failed: {source}"),
        }
    }
}

impl std::error::Error for BrokerHumanControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::Audit(source) => Some(source),
            Self::ConsumerUnavailable => None,
        }
    }
}

impl From<DeviceStateError> for BrokerHumanControlError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

impl From<BrokerAuditError> for BrokerHumanControlError {
    fn from(source: BrokerAuditError) -> Self {
        Self::Audit(source)
    }
}

/// Secret-free Apps & Tools state for the trusted local human interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerAppsToolsSnapshot {
    paused: bool,
    authorized_credential_ids: Vec<CredentialId>,
    consumers: Vec<BrokerConsumerSummary>,
}

impl BrokerAppsToolsSnapshot {
    /// Returns whether all machine credential access is paused.
    #[must_use]
    pub const fn paused(&self) -> bool {
        self.paused
    }

    /// Returns active authorized Credential identities for one requested Vault.
    #[must_use]
    pub fn authorized_credential_ids(&self) -> &[CredentialId] {
        &self.authorized_credential_ids
    }

    /// Returns paired Consumers in stable device-state order.
    #[must_use]
    pub fn consumers(&self) -> &[BrokerConsumerSummary] {
        &self.consumers
    }
}

/// Path-free and secret-free identity evidence shown for one paired Consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerConsumerIdentityEvidence {
    executable_name: Option<String>,
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    code_signing_evidence: ConsumerCodeSigningEvidence,
    code_signature_fingerprint: Option<ConsumerEvidenceFingerprint>,
}

impl BrokerConsumerIdentityEvidence {
    /// Returns the observed executable basename.
    #[must_use]
    pub fn executable_name(&self) -> Option<&str> {
        self.executable_name.as_deref()
    }

    /// Returns the observed bundle identifier.
    #[must_use]
    pub fn bundle_identifier(&self) -> Option<&str> {
        self.bundle_identifier.as_deref()
    }

    /// Returns the observed Apple team identifier.
    #[must_use]
    pub fn team_identifier(&self) -> Option<&str> {
        self.team_identifier.as_deref()
    }

    /// Returns the verified-signing evidence classification.
    #[must_use]
    pub const fn code_signing_evidence(&self) -> ConsumerCodeSigningEvidence {
        self.code_signing_evidence
    }

    /// Returns a short display fingerprint, never the complete signature digest.
    #[must_use]
    pub const fn code_signature_fingerprint(&self) -> Option<ConsumerEvidenceFingerprint> {
        self.code_signature_fingerprint
    }
}

/// One paired Consumer row for the trusted local human interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerConsumerSummary {
    consumer_id: ConsumerId,
    label: String,
    identity_evidence: BrokerConsumerIdentityEvidence,
    access_rule_count: usize,
    usage_profile_count: usize,
    created_at: StateTimestamp,
}

impl BrokerConsumerSummary {
    /// Returns the immutable Consumer identity.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the user-controlled local label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns bounded supporting operating-system identity evidence.
    #[must_use]
    pub const fn identity_evidence(&self) -> &BrokerConsumerIdentityEvidence {
        &self.identity_evidence
    }

    /// Returns the number of persistent field-scoped Access Rules.
    #[must_use]
    pub const fn access_rule_count(&self) -> usize {
        self.access_rule_count
    }

    /// Returns the number of declarative Usage Profiles.
    #[must_use]
    pub const fn usage_profile_count(&self) -> usize {
        self.usage_profile_count
    }

    /// Returns when the Consumer pairing was completed.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }
}

/// One field-scoped Access Rule shown to the trusted local human interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerFieldGrantSummary {
    access_rule_id: AccessRuleId,
    field_scope: CredentialFieldScope,
    capability: Capability,
    confirmation_policy: ConfirmationPolicy,
    lifetime: RuleLifetime,
    created_at: StateTimestamp,
    active: bool,
}

impl BrokerFieldGrantSummary {
    /// Returns the immutable Access Rule identity.
    #[must_use]
    pub const fn access_rule_id(&self) -> AccessRuleId {
        self.access_rule_id
    }

    /// Returns the exact Vault, Credential, and Secret Field scope.
    #[must_use]
    pub const fn field_scope(&self) -> CredentialFieldScope {
        self.field_scope
    }

    /// Returns the capability authorized by the rule.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the confirmation policy applied to use.
    #[must_use]
    pub const fn confirmation_policy(&self) -> ConfirmationPolicy {
        self.confirmation_policy
    }

    /// Returns the persistent or absolute-expiry lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> RuleLifetime {
        self.lifetime
    }

    /// Returns when the rule was created.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }

    /// Returns whether the rule is active at projection time.
    #[must_use]
    pub const fn active(&self) -> bool {
        self.active
    }
}

/// One declarative Usage Profile shown without secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerUsageProfileSummary {
    usage_profile_id: UsageProfileId,
    label: String,
    capability: Capability,
    placement: UsagePlacement,
    created_at: StateTimestamp,
}

impl BrokerUsageProfileSummary {
    /// Returns the immutable Usage Profile identity.
    #[must_use]
    pub const fn usage_profile_id(&self) -> UsageProfileId {
        self.usage_profile_id
    }

    /// Returns the user-controlled local profile label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the capability configured by the profile.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the declarative placement without any credential value.
    #[must_use]
    pub const fn placement(&self) -> &UsagePlacement {
        &self.placement
    }

    /// Returns when the profile was created.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }
}

/// One recent secret-free audit event attributed to a Consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerConsumerAuditSummary {
    audit_event_id: AuditEventId,
    occurred_at: StateTimestamp,
    kind: AuditEventKind,
    field_scope: Option<CredentialFieldScope>,
    capability: Option<Capability>,
    decision: AuditDecision,
    confirmation_method: ConfirmationMethod,
}

impl BrokerConsumerAuditSummary {
    /// Returns the immutable audit event identity.
    #[must_use]
    pub const fn audit_event_id(&self) -> AuditEventId {
        self.audit_event_id
    }

    /// Returns when the event occurred.
    #[must_use]
    pub const fn occurred_at(&self) -> StateTimestamp {
        self.occurred_at
    }

    /// Returns the event category.
    #[must_use]
    pub const fn kind(&self) -> AuditEventKind {
        self.kind
    }

    /// Returns the exact Secret Field scope when attributable.
    #[must_use]
    pub const fn field_scope(&self) -> Option<CredentialFieldScope> {
        self.field_scope
    }

    /// Returns the capability when attributable.
    #[must_use]
    pub const fn capability(&self) -> Option<Capability> {
        self.capability
    }

    /// Returns the non-secret decision.
    #[must_use]
    pub const fn decision(&self) -> AuditDecision {
        self.decision
    }

    /// Returns the non-secret confirmation method.
    #[must_use]
    pub const fn confirmation_method(&self) -> ConfirmationMethod {
        self.confirmation_method
    }
}

/// Complete secret-free detail for one paired Consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerConsumerDetail {
    consumer: BrokerConsumerSummary,
    field_grants: Vec<BrokerFieldGrantSummary>,
    usage_profiles: Vec<BrokerUsageProfileSummary>,
    recent_audit_events: Vec<BrokerConsumerAuditSummary>,
}

impl BrokerConsumerDetail {
    /// Returns the paired Consumer summary.
    #[must_use]
    pub const fn consumer(&self) -> &BrokerConsumerSummary {
        &self.consumer
    }

    /// Returns persistent field-scoped grants.
    #[must_use]
    pub fn field_grants(&self) -> &[BrokerFieldGrantSummary] {
        &self.field_grants
    }

    /// Returns declarative Usage Profiles.
    #[must_use]
    pub fn usage_profiles(&self) -> &[BrokerUsageProfileSummary] {
        &self.usage_profiles
    }

    /// Returns bounded newest-first local audit history.
    #[must_use]
    pub fn recent_audit_events(&self) -> &[BrokerConsumerAuditSummary] {
        &self.recent_audit_events
    }
}

pub(crate) struct BrokerHumanControlManager;

impl BrokerHumanControlManager {
    pub(crate) fn pending_requests(
        state: &DeviceStateStore,
        pairings: &[BrokerPairingRequestSnapshot],
        approvals: &[BrokerHumanApprovalSnapshot],
    ) -> Result<BrokerPendingRequestQueue, BrokerHumanControlError> {
        let mut requests = pairings
            .iter()
            .filter(|pairing| pairing.status() == BrokerPairingRequestStatus::AwaitingUserApproval)
            .map(Self::pending_pairing)
            .collect::<Vec<_>>();

        for approval in approvals {
            requests.push(Self::pending_approval(state, approval)?);
        }

        Ok(BrokerPendingRequestQueue { requests })
    }

    pub(crate) fn snapshot(
        state: &DeviceStateStore,
        vault_id: VaultId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerAppsToolsSnapshot, BrokerHumanControlError> {
        let paused = state.apps_tools_paused()?;
        let authorized_credential_ids = state
            .active_authorized_credential_ids_for_vault(vault_id, observed_at)?
            .into_iter()
            .collect();
        let consumers = state
            .consumers()?
            .into_iter()
            .map(|consumer| {
                let access_rule_count = state
                    .access_rules_for_consumer(consumer.consumer_id())?
                    .len();
                let usage_profile_count = state
                    .usage_profiles_for_consumer(consumer.consumer_id())?
                    .len();
                Ok(Self::consumer_summary(
                    &consumer,
                    access_rule_count,
                    usage_profile_count,
                ))
            })
            .collect::<Result<Vec<_>, DeviceStateError>>()?;
        Ok(BrokerAppsToolsSnapshot {
            paused,
            authorized_credential_ids,
            consumers,
        })
    }

    pub(crate) fn consumer_detail(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerConsumerDetail, BrokerHumanControlError> {
        let consumer = state
            .consumer(consumer_id)?
            .ok_or(BrokerHumanControlError::ConsumerUnavailable)?;
        let rules = state.access_rules_for_consumer(consumer_id)?;
        let profiles = state.usage_profiles_for_consumer(consumer_id)?;
        let audit_events = BrokerAuditManager::view(
            state,
            BrokerAuditFilter::all().with_consumer(consumer_id),
            None,
            MAX_CONSUMER_DETAIL_AUDIT_EVENTS,
            observed_at,
        )?
        .into_events();
        let consumer = Self::consumer_summary(&consumer, rules.len(), profiles.len());
        Ok(BrokerConsumerDetail {
            consumer,
            field_grants: rules
                .iter()
                .map(|rule| Self::field_grant(rule, observed_at))
                .collect(),
            usage_profiles: profiles.iter().map(Self::usage_profile).collect(),
            recent_audit_events: audit_events.iter().map(Self::audit_event).collect(),
        })
    }

    fn consumer_summary(
        consumer: &crate::state_model::Consumer,
        access_rule_count: usize,
        usage_profile_count: usize,
    ) -> BrokerConsumerSummary {
        let observed = consumer.observed_identity();
        BrokerConsumerSummary {
            consumer_id: consumer.consumer_id(),
            label: consumer.label().to_owned(),
            identity_evidence: BrokerConsumerIdentityEvidence {
                executable_name: observed.executable_name().map(str::to_owned),
                bundle_identifier: observed.bundle_identifier().map(str::to_owned),
                team_identifier: observed.team_identifier().map(str::to_owned),
                code_signing_evidence: observed.code_signing_evidence(),
                code_signature_fingerprint: observed.code_signature_fingerprint(),
            },
            access_rule_count,
            usage_profile_count,
            created_at: consumer.created_at(),
        }
    }

    fn pending_pairing(pairing: &BrokerPairingRequestSnapshot) -> BrokerPendingRequest {
        let evidence = pairing.identity_evidence();
        BrokerPendingRequest {
            request_id: BrokerPendingRequestId::Pairing(pairing.pairing_request_id()),
            kind: BrokerPendingRequestKind::Pairing,
            consumer_id: None,
            consumer_label: None,
            identity_evidence: Some(Self::pairing_identity_evidence(evidence)),
            pairing_comparison_code: Some(pairing.comparison_code()),
            pairing_key_fingerprint: Some(evidence.pairing_key_fingerprint()),
            vault_id: None,
            field_scope: None,
            capability: None,
            request_description: None,
            created_at: None,
            expires_at: None,
            remaining: Some(pairing.remaining()),
        }
    }

    fn pending_approval(
        state: &DeviceStateStore,
        approval: &BrokerHumanApprovalSnapshot,
    ) -> Result<BrokerPendingRequest, DeviceStateError> {
        let subject = approval.subject();
        let consumer_id = subject.consumer_id();
        let consumer = state.consumer(consumer_id)?;
        let mut consumer_label = consumer.as_ref().map(|value| value.label().to_owned());
        let mut identity_evidence = consumer
            .as_ref()
            .map(|value| Self::observed_identity_evidence(value.observed_identity()));
        let mut pairing_key_fingerprint = None;

        let (kind, vault_id, field_scope, capability) = match subject {
            ApprovalSubject::Pairing {
                pairing_public_key,
                observed_identity,
                ..
            } => {
                consumer_label = None;
                identity_evidence = Some(Self::observed_identity_evidence(observed_identity));
                pairing_key_fingerprint = Some(Self::pairing_key_fingerprint(pairing_public_key));
                (BrokerPendingRequestKind::Pairing, None, None, None)
            }
            ApprovalSubject::Unlock { vault_id, .. } => (
                BrokerPendingRequestKind::Unlock,
                Some(*vault_id),
                None,
                None,
            ),
            ApprovalSubject::Access { target } => (
                BrokerPendingRequestKind::Access,
                Some(target.field_scope().vault_id()),
                Some(target.field_scope()),
                Some(target.capability()),
            ),
            ApprovalSubject::CredentialAccess {
                vault_id,
                capability,
                ..
            } => (
                BrokerPendingRequestKind::CredentialAccess,
                Some(*vault_id),
                None,
                Some(*capability),
            ),
        };

        Ok(BrokerPendingRequest {
            request_id: BrokerPendingRequestId::Approval(approval.approval_request_id()),
            kind,
            consumer_id: Some(consumer_id),
            consumer_label,
            identity_evidence,
            pairing_comparison_code: None,
            pairing_key_fingerprint,
            vault_id,
            field_scope,
            capability,
            request_description: approval.credential_description().map(str::to_owned),
            created_at: Some(approval.created_at()),
            expires_at: Some(approval.expires_at()),
            remaining: None,
        })
    }

    fn pairing_identity_evidence(
        evidence: &BrokerPairingIdentityEvidence,
    ) -> BrokerConsumerIdentityEvidence {
        BrokerConsumerIdentityEvidence {
            executable_name: evidence.executable_name().map(str::to_owned),
            bundle_identifier: evidence.bundle_identifier().map(str::to_owned),
            team_identifier: evidence.team_identifier().map(str::to_owned),
            code_signing_evidence: evidence.code_signing_evidence(),
            code_signature_fingerprint: evidence.code_signature_fingerprint(),
        }
    }

    fn observed_identity_evidence(
        observed: &ObservedConsumerIdentity,
    ) -> BrokerConsumerIdentityEvidence {
        BrokerConsumerIdentityEvidence {
            executable_name: observed.executable_name().map(str::to_owned),
            bundle_identifier: observed.bundle_identifier().map(str::to_owned),
            team_identifier: observed.team_identifier().map(str::to_owned),
            code_signing_evidence: observed.code_signing_evidence(),
            code_signature_fingerprint: observed.code_signature_fingerprint(),
        }
    }

    fn pairing_key_fingerprint(pairing_public_key: &[u8; 32]) -> ConsumerEvidenceFingerprint {
        let digest: [u8; 32] = Sha256::digest(pairing_public_key).into();
        ConsumerEvidenceFingerprint::from_sha256_digest(&digest)
    }

    fn field_grant(rule: &AccessRule, observed_at: StateTimestamp) -> BrokerFieldGrantSummary {
        BrokerFieldGrantSummary {
            access_rule_id: rule.access_rule_id(),
            field_scope: rule.target().field_scope(),
            capability: rule.target().capability(),
            confirmation_policy: rule.confirmation_policy(),
            lifetime: rule.lifetime(),
            created_at: rule.created_at(),
            active: rule.is_active_at(observed_at),
        }
    }

    fn usage_profile(profile: &UsageProfile) -> BrokerUsageProfileSummary {
        BrokerUsageProfileSummary {
            usage_profile_id: profile.usage_profile_id(),
            label: profile.label().to_owned(),
            capability: profile.capability(),
            placement: profile.placement().clone(),
            created_at: profile.created_at(),
        }
    }

    fn audit_event(event: &AuditEvent) -> BrokerConsumerAuditSummary {
        BrokerConsumerAuditSummary {
            audit_event_id: event.audit_event_id(),
            occurred_at: event.occurred_at(),
            kind: event.kind(),
            field_scope: event.scope().field_scope(),
            capability: event.scope().capability(),
            decision: event.decision(),
            confirmation_method: event.confirmation_method(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use psw_core::{CredentialId, SecretFieldId, VaultId};

    use super::*;
    use crate::device_key::DeviceRootKey;
    use crate::state_model::{
        AccessRule, AuditScope, AuthorizationTarget, CapabilityName, Consumer,
        ObservedConsumerIdentity,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestStateDirectory {
        path: PathBuf,
    }

    impl TestStateDirectory {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keptnear-human-control-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create state directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect state directory");
            Self { path }
        }
    }

    impl Drop for TestStateDirectory {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn timestamp(value: i64) -> StateTimestamp {
        StateTimestamp::from_unix_millis(value).expect("timestamp")
    }

    #[test]
    fn projection_contains_bounded_identity_authorization_profile_and_audit_metadata() {
        let directory = TestStateDirectory::new();
        let key = DeviceRootKey::from_stored_bytes(vec![44_u8; 32]).expect("device root key");
        let state = DeviceStateStore::initialize_for_tests(&directory.path, &key, timestamp(1))
            .expect("device state");
        let consumer = Consumer::new(
            [7_u8; 32],
            "Local automation".to_owned(),
            ObservedConsumerIdentity::new(
                Some("runner".to_owned()),
                Some("com.example.runner".to_owned()),
                Some("EXAMPLE".to_owned()),
                Some([9_u8; 32]),
            )
            .expect("identity"),
            timestamp(10),
        )
        .expect("consumer");
        state.insert_consumer(&consumer).expect("insert consumer");
        let vault_id = VaultId::generate();
        let field_scope = CredentialFieldScope::new(
            vault_id,
            CredentialId::generate(),
            SecretFieldId::generate(),
        );
        let capability = Capability::v1(CapabilityName::ProcessRun);
        let rule = AccessRule::new(
            AuthorizationTarget::new(consumer.consumer_id(), field_scope, capability),
            ConfirmationPolicy::EveryUse,
            RuleLifetime::Persistent,
            timestamp(20),
        )
        .expect("rule");
        state.insert_access_rule(&rule).expect("insert rule");
        let profile = UsageProfile::new(
            consumer.consumer_id(),
            "Child environment".to_owned(),
            capability,
            UsagePlacement::ProcessEnvironment {
                variable_name: "SERVICE_TOKEN".to_owned(),
            },
            timestamp(30),
        )
        .expect("profile");
        state
            .insert_usage_profile(&profile)
            .expect("insert profile");
        let audit = AuditEvent::new(
            timestamp(40),
            AuditEventKind::Authorization,
            AuditScope::new(
                Some(consumer.consumer_id()),
                Some(field_scope),
                Some(capability),
                None,
            ),
            AuditDecision::Allowed,
            ConfirmationMethod::UserApproval,
        );
        state.append_audit_event(&audit).expect("append audit");

        let snapshot =
            BrokerHumanControlManager::snapshot(&state, vault_id, timestamp(50)).expect("snapshot");
        assert_eq!(snapshot.consumers().len(), 1);
        assert_eq!(snapshot.authorized_credential_ids().len(), 1);
        assert!(!snapshot.paused());
        let summary = &snapshot.consumers()[0];
        assert_eq!(summary.label(), "Local automation");
        assert_eq!(summary.access_rule_count(), 1);
        assert_eq!(summary.usage_profile_count(), 1);
        assert_eq!(
            summary.identity_evidence().code_signature_fingerprint(),
            consumer.observed_identity().code_signature_fingerprint()
        );

        let detail = BrokerHumanControlManager::consumer_detail(
            &state,
            consumer.consumer_id(),
            timestamp(50),
        )
        .expect("detail");
        assert_eq!(detail.field_grants().len(), 1);
        assert!(detail.field_grants()[0].active());
        assert_eq!(detail.usage_profiles().len(), 1);
        assert_eq!(detail.recent_audit_events().len(), 1);
        assert_eq!(
            detail.recent_audit_events()[0].decision(),
            AuditDecision::Allowed
        );
    }
}
