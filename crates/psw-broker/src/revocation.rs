use std::fmt::{Display, Formatter};

use crate::approval::{BrokerApprovalError, BrokerApprovalManager};
use crate::pairing::{BrokerPairingError, BrokerPairingManager};
use crate::protocol::BrokerErrorCode;
use crate::state_model::{ConsumerId, CredentialFieldScope};
use crate::state_store::{AuthorizationRemovalCounts, DeviceStateError, DeviceStateStore};

/// Scope of one explicit Apps & Tools revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerRevocationKind {
    /// Every capability for one Consumer and one Secret Field.
    ConsumerField,
    /// One paired Consumer and all of its authorization state.
    Consumer,
    /// Every paired Consumer and all machine authorization state.
    Global,
}

/// Non-secret counts from one committed revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerRevocationSummary {
    kind: BrokerRevocationKind,
    consumers_removed: usize,
    access_rules_removed: usize,
    use_grants_removed: usize,
    usage_profiles_removed: usize,
    approvals_removed: usize,
    pending_pairings_cancelled: usize,
    credential_contexts_discarded: usize,
}

impl BrokerRevocationSummary {
    /// Returns the requested revocation scope.
    #[must_use]
    pub const fn kind(self) -> BrokerRevocationKind {
        self.kind
    }

    /// Returns the number of paired Consumers removed.
    #[must_use]
    pub const fn consumers_removed(self) -> usize {
        self.consumers_removed
    }

    /// Returns the number of persistent Access Rules removed.
    #[must_use]
    pub const fn access_rules_removed(self) -> usize {
        self.access_rules_removed
    }

    /// Returns the number of active or stale Use Grants removed.
    #[must_use]
    pub const fn use_grants_removed(self) -> usize {
        self.use_grants_removed
    }

    /// Returns the number of declarative Usage Profiles removed.
    #[must_use]
    pub const fn usage_profiles_removed(self) -> usize {
        self.usage_profiles_removed
    }

    /// Returns the number of pending or terminal approval rows removed.
    #[must_use]
    pub const fn approvals_removed(self) -> usize {
        self.approvals_removed
    }

    /// Returns the number of process-local pairing handshakes cancelled.
    #[must_use]
    pub const fn pending_pairings_cancelled(self) -> usize {
        self.pending_pairings_cancelled
    }

    /// Returns the number of process-local new-Credential contexts discarded.
    #[must_use]
    pub const fn credential_contexts_discarded(self) -> usize {
        self.credential_contexts_discarded
    }

    /// Returns whether this invocation removed any durable or process-local state.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.consumers_removed != 0
            || self.access_rules_removed != 0
            || self.use_grants_removed != 0
            || self.usage_profiles_removed != 0
            || self.approvals_removed != 0
            || self.pending_pairings_cancelled != 0
            || self.credential_contexts_discarded != 0
    }

    fn from_counts(
        kind: BrokerRevocationKind,
        counts: AuthorizationRemovalCounts,
        pending_pairings_cancelled: usize,
        credential_contexts_discarded: usize,
    ) -> Self {
        Self {
            kind,
            consumers_removed: counts.consumers_removed(),
            access_rules_removed: counts.access_rules_removed(),
            use_grants_removed: counts.use_grants_removed(),
            usage_profiles_removed: counts.usage_profiles_removed(),
            approvals_removed: counts.approvals_removed(),
            pending_pairings_cancelled,
            credential_contexts_discarded,
        }
    }
}

/// Sanitized failure while applying an explicit revocation.
#[derive(Debug)]
pub enum BrokerRevocationError {
    /// The authenticated SQLCipher transaction could not commit.
    DeviceState(DeviceStateError),
    /// Process-local approval state could not be reconciled after deletion.
    Approval(BrokerApprovalError),
    /// Process-local pairing state could not be cancelled after deletion.
    Pairing(BrokerPairingError),
}

impl BrokerRevocationError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(&self) -> BrokerErrorCode {
        BrokerErrorCode::OperationFailed
    }
}

impl Display for BrokerRevocationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceState(source) => write!(formatter, "revocation state failed: {source}"),
            Self::Approval(source) => {
                write!(formatter, "revocation approval cleanup failed: {source}")
            }
            Self::Pairing(source) => {
                write!(formatter, "revocation pairing cleanup failed: {source}")
            }
        }
    }
}

impl std::error::Error for BrokerRevocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::Approval(source) => Some(source),
            Self::Pairing(source) => Some(source),
        }
    }
}

pub(crate) struct BrokerRevocationManager;

impl BrokerRevocationManager {
    pub(crate) fn revoke_consumer_field(
        state: &mut DeviceStateStore,
        approvals: &BrokerApprovalManager,
        consumer_id: ConsumerId,
        field_scope: CredentialFieldScope,
    ) -> Result<BrokerRevocationSummary, BrokerRevocationError> {
        let counts = state
            .remove_consumer_field_authorization(consumer_id, field_scope)
            .map_err(BrokerRevocationError::DeviceState)?;
        let credential_contexts_discarded = approvals
            .reconcile_after_revocation(state)
            .map_err(BrokerRevocationError::Approval)?;
        Ok(BrokerRevocationSummary::from_counts(
            BrokerRevocationKind::ConsumerField,
            counts,
            0,
            credential_contexts_discarded,
        ))
    }

    pub(crate) fn revoke_consumer(
        state: &mut DeviceStateStore,
        approvals: &BrokerApprovalManager,
        pairing: &BrokerPairingManager,
        consumer_id: ConsumerId,
    ) -> Result<BrokerRevocationSummary, BrokerRevocationError> {
        let counts = state
            .remove_consumer_authorization(consumer_id)
            .map_err(BrokerRevocationError::DeviceState)?;
        let approval_cleanup = approvals.reconcile_after_revocation(state);
        let pairing_cleanup = pairing.cancel_pending_for_consumer(consumer_id);
        let credential_contexts_discarded =
            approval_cleanup.map_err(BrokerRevocationError::Approval)?;
        let pending_pairings_cancelled = pairing_cleanup.map_err(BrokerRevocationError::Pairing)?;
        Ok(BrokerRevocationSummary::from_counts(
            BrokerRevocationKind::Consumer,
            counts,
            pending_pairings_cancelled,
            credential_contexts_discarded,
        ))
    }

    pub(crate) fn revoke_global(
        state: &mut DeviceStateStore,
        approvals: &BrokerApprovalManager,
        pairing: &BrokerPairingManager,
    ) -> Result<BrokerRevocationSummary, BrokerRevocationError> {
        let counts = state
            .remove_all_consumer_authorization()
            .map_err(BrokerRevocationError::DeviceState)?;
        let approval_cleanup = approvals.reconcile_after_revocation(state);
        let pairing_cleanup = pairing.cancel_all_pending();
        let credential_contexts_discarded =
            approval_cleanup.map_err(BrokerRevocationError::Approval)?;
        let pending_pairings_cancelled = pairing_cleanup.map_err(BrokerRevocationError::Pairing)?;
        Ok(BrokerRevocationSummary::from_counts(
            BrokerRevocationKind::Global,
            counts,
            pending_pairings_cancelled,
            credential_contexts_discarded,
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;
    use psw_core::{CredentialId, SecretFieldId, VaultId};

    use super::*;
    use crate::approval::BrokerApprovalManager;
    use crate::credential_matching::{BrokerCredentialMatchingManager, BrokerNewCredentialRequest};
    use crate::device_key::{DeviceRootKey, DEVICE_ROOT_KEY_LENGTH};
    use crate::pairing::{
        BrokerPairingUserApproval, ConsumerPairingProposal, PAIRING_NONCE_LENGTH,
    };
    use crate::protocol::BrokerProtocolVersion;
    use crate::state_model::{
        AccessRule, ApprovalRequestId, ApprovalSubject, AuditDecision, AuditEvent, AuditEventKind,
        AuditScope, AuthorizationTarget, Capability, CapabilityName, ConfirmationMethod,
        ConfirmationPolicy, Consumer, GrantScope, ObservedConsumerIdentity, RuleLifetime,
        StateTimestamp, UsagePlacement, UsageProfile, UseGrant, VaultSessionId,
    };
    use crate::state_store::StoredUseGrantAuthorization;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestStateDirectory {
        path: PathBuf,
        key_byte: u8,
    }

    impl TestStateDirectory {
        fn new(label: &str, key_byte: u8) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keptnear-revocation-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create state directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect state directory");
            Self { path, key_byte }
        }

        fn initialize(&self) -> DeviceStateStore {
            DeviceStateStore::initialize_for_tests(&self.path, &self.root_key(), timestamp(1))
                .expect("initialize state")
        }

        fn open(&self) -> DeviceStateStore {
            DeviceStateStore::open_for_tests(&self.path, &self.root_key()).expect("open state")
        }

        fn root_key(&self) -> DeviceRootKey {
            DeviceRootKey::from_stored_bytes(vec![self.key_byte; DEVICE_ROOT_KEY_LENGTH])
                .expect("root key")
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

    fn consumer(key_byte: u8) -> Consumer {
        Consumer::new(
            [key_byte; 32],
            format!("Consumer {key_byte}"),
            ObservedConsumerIdentity::default(),
            timestamp(10),
        )
        .expect("Consumer")
    }

    fn insert_consumer(state: &DeviceStateStore, key_byte: u8) -> Consumer {
        let consumer = consumer(key_byte);
        state.insert_consumer(&consumer).expect("insert Consumer");
        consumer
    }

    fn field_scope() -> CredentialFieldScope {
        CredentialFieldScope::new(
            VaultId::generate(),
            CredentialId::generate(),
            SecretFieldId::generate(),
        )
    }

    fn target(
        consumer_id: ConsumerId,
        field_scope: CredentialFieldScope,
        capability_name: CapabilityName,
    ) -> AuthorizationTarget {
        AuthorizationTarget::new(consumer_id, field_scope, Capability::v1(capability_name))
    }

    fn seed_rule_and_grant(
        state: &DeviceStateStore,
        target: AuthorizationTarget,
        time_offset: i64,
    ) -> (AccessRule, UseGrant) {
        let rule = AccessRule::new(
            target,
            ConfirmationPolicy::EveryUse,
            RuleLifetime::Persistent,
            timestamp(100 + time_offset),
        )
        .expect("rule");
        state.insert_access_rule(&rule).expect("insert rule");
        let grant = UseGrant::new(
            target,
            Some(rule.access_rule_id()),
            VaultSessionId::generate(),
            GrantScope::OneOperation,
            timestamp(200 + time_offset),
            timestamp(800 + time_offset),
        )
        .expect("grant");
        state.insert_use_grant(&grant).expect("insert grant");
        (rule, grant)
    }

    fn insert_profile(state: &DeviceStateStore, consumer_id: ConsumerId, label: &str) {
        let profile = UsageProfile::new(
            consumer_id,
            label.to_owned(),
            Capability::v1(CapabilityName::ProcessRun),
            UsagePlacement::ProcessEnvironment {
                variable_name: "KEPTNEAR_TOKEN".to_owned(),
            },
            timestamp(300),
        )
        .expect("profile");
        state
            .insert_usage_profile(&profile)
            .expect("insert profile");
    }

    fn approval_manager(state: &DeviceStateStore) -> BrokerApprovalManager {
        BrokerApprovalManager::restore(state, timestamp(20))
            .expect("approval manager")
            .0
    }

    fn submit_access_approval(
        manager: &BrokerApprovalManager,
        state: &DeviceStateStore,
        target: AuthorizationTarget,
        offset: i64,
    ) -> ApprovalRequestId {
        manager
            .submit(
                state,
                ApprovalSubject::Access { target },
                timestamp(400 + offset),
                timestamp(700 + offset),
            )
            .expect("approval")
            .receipt()
            .approval_request_id()
    }

    fn submit_credential_approval(
        manager: &BrokerApprovalManager,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        vault_id: VaultId,
    ) -> ApprovalRequestId {
        let request = BrokerNewCredentialRequest::new(
            consumer_id,
            vault_id,
            Capability::v1(CapabilityName::HttpRequest),
            "release token".to_owned(),
        )
        .expect("request");
        let admitted =
            BrokerCredentialMatchingManager::admit(state, request).expect("admitted request");
        manager
            .submit_credential_request(state, admitted, timestamp(400), timestamp(700))
            .expect("credential approval")
            .receipt()
            .approval_request_id()
    }

    fn begin_approved_pairing(
        state: &DeviceStateStore,
        pairing: &BrokerPairingManager,
        key_byte: u8,
    ) -> (ConsumerId, [u8; 32]) {
        let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let proposal = ConsumerPairingProposal::new(
            public_key,
            [key_byte.saturating_add(1); PAIRING_NONCE_LENGTH],
            BrokerProtocolVersion::current(),
        )
        .expect("proposal");
        let challenge = pairing
            .begin_pairing(state, proposal, ObservedConsumerIdentity::default())
            .expect("begin pairing");
        let proof = pairing
            .approve_pairing(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Pending Consumer".to_owned(),
                    timestamp(50),
                ),
            )
            .expect("approve pairing");
        (proof.consumer_id(), public_key)
    }

    #[test]
    fn consumer_field_revocation_is_exact_and_keeps_profiles_and_pairing() {
        let directory = TestStateDirectory::new("field", 21);
        let mut state = directory.initialize();
        let first = insert_consumer(&state, 31);
        let second = insert_consumer(&state, 32);
        let removed_field = field_scope();
        let retained_field = field_scope();
        let manager = approval_manager(&state);

        for (offset, capability) in [
            (0, CapabilityName::HttpRequest),
            (1, CapabilityName::ProcessRun),
        ] {
            let removed_target = target(first.consumer_id(), removed_field, capability);
            seed_rule_and_grant(&state, removed_target, offset);
            submit_access_approval(&manager, &state, removed_target, offset);
        }
        let retained_same_consumer = target(
            first.consumer_id(),
            retained_field,
            CapabilityName::HttpRequest,
        );
        seed_rule_and_grant(&state, retained_same_consumer, 10);
        submit_access_approval(&manager, &state, retained_same_consumer, 10);
        let retained_other_consumer = target(
            second.consumer_id(),
            removed_field,
            CapabilityName::HttpRequest,
        );
        seed_rule_and_grant(&state, retained_other_consumer, 20);
        submit_access_approval(&manager, &state, retained_other_consumer, 20);
        insert_profile(&state, first.consumer_id(), "Shared process placement");
        let pairing = BrokerPairingManager::new();

        let summary = BrokerRevocationManager::revoke_consumer_field(
            &mut state,
            &manager,
            first.consumer_id(),
            removed_field,
        )
        .expect("revoke field");
        assert_eq!(summary.kind(), BrokerRevocationKind::ConsumerField);
        assert_eq!(summary.access_rules_removed(), 2);
        assert_eq!(summary.use_grants_removed(), 2);
        assert_eq!(summary.approvals_removed(), 2);
        assert_eq!(summary.consumers_removed(), 0);
        assert_eq!(summary.usage_profiles_removed(), 0);
        assert!(summary.changed());
        assert_eq!(
            state
                .access_rules_for_consumer(first.consumer_id())
                .expect("first rules")
                .len(),
            1
        );
        assert_eq!(
            state
                .use_grants_for_consumer(first.consumer_id())
                .expect("first grants")
                .len(),
            1
        );
        assert_eq!(
            state
                .access_rules_for_consumer(second.consumer_id())
                .expect("second rules")
                .len(),
            1
        );
        assert_eq!(
            state
                .usage_profiles_for_consumer(first.consumer_id())
                .expect("profiles")
                .len(),
            1
        );
        assert_eq!(state.pending_approvals().expect("approvals").len(), 2);
        assert!(state
            .consumer(first.consumer_id())
            .expect("first Consumer")
            .is_some());
        assert!(pairing.pending_requests().expect("pairings").is_empty());

        let repeated = BrokerRevocationManager::revoke_consumer_field(
            &mut state,
            &manager,
            first.consumer_id(),
            removed_field,
        )
        .expect("repeat field revocation");
        assert!(!repeated.changed());
    }

    #[test]
    fn consumer_revocation_wakes_waiters_and_clears_process_context() {
        let directory = TestStateDirectory::new("consumer", 41);
        let mut state = directory.initialize();
        let pairing = BrokerPairingManager::new();
        let (consumer_id, public_key) = begin_approved_pairing(&state, &pairing, 42);
        let removed_consumer = Consumer::with_id(
            consumer_id,
            public_key,
            "Pending Consumer".to_owned(),
            ObservedConsumerIdentity::default(),
            timestamp(60),
        )
        .expect("Consumer");
        state
            .insert_consumer(&removed_consumer)
            .expect("insert Consumer");
        let retained_consumer = insert_consumer(&state, 43);
        let removed_target = target(consumer_id, field_scope(), CapabilityName::HttpRequest);
        seed_rule_and_grant(&state, removed_target, 0);
        insert_profile(&state, consumer_id, "Removed profile");
        let manager = Arc::new(approval_manager(&state));
        let access_approval = submit_access_approval(&manager, &state, removed_target, 0);
        let credential_approval =
            submit_credential_approval(&manager, &state, consumer_id, VaultId::generate());

        let waiter_manager = Arc::clone(&manager);
        let waiter_state = directory.open();
        let (started_tx, started_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            started_tx.send(()).expect("waiter started");
            waiter_manager.wait(
                &waiter_state,
                consumer_id,
                access_approval,
                timestamp(450),
                Duration::from_secs(2),
            )
        });
        started_rx.recv().expect("waiter signal");
        thread::sleep(Duration::from_millis(25));

        let summary =
            BrokerRevocationManager::revoke_consumer(&mut state, &manager, &pairing, consumer_id)
                .expect("revoke Consumer");
        assert_eq!(summary.kind(), BrokerRevocationKind::Consumer);
        assert_eq!(summary.consumers_removed(), 1);
        assert_eq!(summary.access_rules_removed(), 1);
        assert_eq!(summary.use_grants_removed(), 1);
        assert_eq!(summary.usage_profiles_removed(), 1);
        assert_eq!(summary.approvals_removed(), 2);
        assert_eq!(summary.pending_pairings_cancelled(), 1);
        assert_eq!(summary.credential_contexts_discarded(), 1);
        assert!(matches!(
            waiter.join().expect("waiter"),
            Err(BrokerApprovalError::ApprovalUnavailable)
        ));
        assert!(state
            .consumer(consumer_id)
            .expect("removed Consumer")
            .is_none());
        assert!(state
            .consumer(retained_consumer.consumer_id())
            .expect("retained Consumer")
            .is_some());
        assert!(pairing.pending_requests().expect("pairings").is_empty());
        assert!(matches!(
            manager.credential_request(&state, credential_approval, timestamp(500)),
            Err(BrokerApprovalError::ApprovalUnavailable)
        ));
    }

    #[test]
    fn global_revocation_preserves_audit_pause_and_device_state() {
        let directory = TestStateDirectory::new("global", 51);
        let mut state = directory.initialize();
        let first = insert_consumer(&state, 52);
        let second = insert_consumer(&state, 53);
        let manager = approval_manager(&state);
        let pairing = BrokerPairingManager::new();
        let first_target = target(
            first.consumer_id(),
            field_scope(),
            CapabilityName::HttpRequest,
        );
        let second_target = target(
            second.consumer_id(),
            field_scope(),
            CapabilityName::ProcessRun,
        );
        seed_rule_and_grant(&state, first_target, 0);
        seed_rule_and_grant(&state, second_target, 1);
        insert_profile(&state, first.consumer_id(), "First profile");
        insert_profile(&state, second.consumer_id(), "Second profile");
        submit_access_approval(&manager, &state, first_target, 0);
        submit_access_approval(&manager, &state, second_target, 1);
        submit_credential_approval(
            &manager,
            &state,
            first.consumer_id(),
            first_target.field_scope().vault_id(),
        );
        let signing_key = SigningKey::from_bytes(&[54; 32]);
        pairing
            .begin_pairing(
                &state,
                ConsumerPairingProposal::new(
                    signing_key.verifying_key().to_bytes(),
                    [55; PAIRING_NONCE_LENGTH],
                    BrokerProtocolVersion::current(),
                )
                .expect("proposal"),
                ObservedConsumerIdentity::default(),
            )
            .expect("pending pairing");
        let audit = AuditEvent::new(
            timestamp(500),
            AuditEventKind::Authorization,
            AuditScope::new(
                Some(first.consumer_id()),
                Some(first_target.field_scope()),
                Some(first_target.capability()),
                None,
            ),
            AuditDecision::Allowed,
            ConfirmationMethod::UserApproval,
        );
        state.append_audit_event(&audit).expect("audit");
        state
            .set_apps_tools_paused(true, timestamp(510))
            .expect("pause");

        let summary = BrokerRevocationManager::revoke_global(&mut state, &manager, &pairing)
            .expect("global revoke");
        assert_eq!(summary.kind(), BrokerRevocationKind::Global);
        assert_eq!(summary.consumers_removed(), 2);
        assert_eq!(summary.access_rules_removed(), 2);
        assert_eq!(summary.use_grants_removed(), 2);
        assert_eq!(summary.usage_profiles_removed(), 2);
        assert_eq!(summary.approvals_removed(), 3);
        assert_eq!(summary.pending_pairings_cancelled(), 1);
        assert_eq!(summary.credential_contexts_discarded(), 1);
        assert!(state.consumers().expect("Consumers").is_empty());
        assert!(state.pending_approvals().expect("approvals").is_empty());
        assert!(pairing.pending_requests().expect("pairings").is_empty());
        assert_eq!(state.recent_audit_events(10).expect("audit"), vec![audit]);
        assert!(state.apps_tools_paused().expect("pause retained"));
        assert_eq!(state.schema_version().expect("schema"), 2);

        let repeated = BrokerRevocationManager::revoke_global(&mut state, &manager, &pairing)
            .expect("repeat global revoke");
        assert!(!repeated.changed());
    }

    #[test]
    fn one_operation_use_and_field_revocation_linearize_without_retained_access() {
        let directory = TestStateDirectory::new("race", 61);
        let mut state = directory.initialize();
        let consumer = insert_consumer(&state, 62);
        let field = field_scope();
        let target = target(consumer.consumer_id(), field, CapabilityName::HttpRequest);
        let (_, grant) = seed_rule_and_grant(&state, target, 0);
        let manager = Arc::new(approval_manager(&state));
        let authorization_state = directory.open();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            authorization_state.authorize_stored_use_grant(
                grant.use_grant_id(),
                target,
                grant.vault_session_id(),
                timestamp(300),
            )
        });
        barrier.wait();
        let summary = BrokerRevocationManager::revoke_consumer_field(
            &mut state,
            &manager,
            consumer.consumer_id(),
            field,
        )
        .expect("revoke");
        let authorization = worker.join().expect("authorization").expect("state");
        assert!(matches!(
            authorization,
            StoredUseGrantAuthorization::Authorized(_) | StoredUseGrantAuthorization::Unavailable
        ));
        assert_eq!(summary.access_rules_removed(), 1);
        assert!(state
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("rules")
            .is_empty());
        assert!(state
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("grants")
            .is_empty());
    }
}
