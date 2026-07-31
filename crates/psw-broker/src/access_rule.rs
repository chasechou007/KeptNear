use std::fmt::{Display, Formatter};

use psw_core::{CredentialUseCapability, SecretFieldKind};

use crate::protocol::BrokerErrorCode;
use crate::state_model::{
    AccessRule, AuthorizationTarget, ConfirmationPolicy, RuleLifetime, StateTimestamp,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};

/// Explicit local approval used to create one field-scoped Access Rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAccessRuleApproval {
    target: AuthorizationTarget,
    secret_kind: SecretFieldKind,
    confirmation_policy: ConfirmationPolicy,
    lifetime: RuleLifetime,
    approved_at: StateTimestamp,
}

impl BrokerAccessRuleApproval {
    /// Validates the rule selected by a user in the local control plane.
    pub fn after_user_approval(
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        confirmation_policy: ConfirmationPolicy,
        lifetime: RuleLifetime,
        approved_at: StateTimestamp,
    ) -> Result<Self, BrokerAccessRuleError> {
        validate_capability(target, secret_kind)?;
        if matches!(lifetime, RuleLifetime::Until(expires_at) if expires_at <= approved_at) {
            return Err(BrokerAccessRuleError::InvalidLifetime);
        }
        Ok(Self {
            target,
            secret_kind,
            confirmation_policy,
            lifetime,
            approved_at,
        })
    }
}

/// Result of persisting one explicitly approved Access Rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerAccessRuleCreation {
    rule: AccessRule,
    newly_created: bool,
}

impl BrokerAccessRuleCreation {
    pub(crate) const fn from_persisted(rule: AccessRule, newly_created: bool) -> Self {
        Self {
            rule,
            newly_created,
        }
    }

    /// Returns the exact persisted rule.
    #[must_use]
    pub const fn rule(&self) -> &AccessRule {
        &self.rule
    }

    /// Returns whether this approval inserted a new rule.
    #[must_use]
    pub const fn newly_created(&self) -> bool {
        self.newly_created
    }
}

/// Result of matching one exact authorization target against active rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerAccessRuleEvaluation {
    /// No active rule matches the exact Consumer, field, capability, and version.
    NoMatchingRule,
    /// An active rule matched; a separate Use Grant is still required.
    MatchingRule(AccessRule),
}

impl BrokerAccessRuleEvaluation {
    /// Returns the matching rule without treating it as a Use Grant.
    #[must_use]
    pub const fn matching_rule(&self) -> Option<&AccessRule> {
        match self {
            Self::NoMatchingRule => None,
            Self::MatchingRule(rule) => Some(rule),
        }
    }
}

/// Sanitized Access Rule creation or evaluation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerAccessRuleError {
    /// The requested rule lifetime ended before or at approval.
    InvalidLifetime,
    /// The capability is not field-scoped or its version is unsupported.
    UnsupportedCapability,
    /// The credential-use capability cannot consume the selected secret kind.
    IncompatibleSecretKind,
    /// The Consumer is not paired or was removed.
    ConsumerUnavailable,
    /// A different active rule already owns the exact target.
    ConflictingRule,
    /// Authenticated encrypted device state could not be read or changed.
    DeviceState(DeviceStateError),
}

impl BrokerAccessRuleError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(&self) -> BrokerErrorCode {
        match self {
            Self::InvalidLifetime => BrokerErrorCode::InvalidRequest,
            Self::UnsupportedCapability => BrokerErrorCode::UnsupportedCapability,
            Self::IncompatibleSecretKind | Self::ConflictingRule => BrokerErrorCode::AccessDenied,
            Self::ConsumerUnavailable => BrokerErrorCode::ConsumerRevoked,
            Self::DeviceState(_) => BrokerErrorCode::OperationFailed,
        }
    }
}

impl Display for BrokerAccessRuleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLifetime => formatter.write_str("Access Rule lifetime is invalid"),
            Self::UnsupportedCapability => {
                formatter.write_str("Access Rule capability is unsupported")
            }
            Self::IncompatibleSecretKind => {
                formatter.write_str("Access Rule capability is incompatible with the secret kind")
            }
            Self::ConsumerUnavailable => formatter.write_str("Access Rule Consumer is unavailable"),
            Self::ConflictingRule => {
                formatter.write_str("a different active Access Rule already exists")
            }
            Self::DeviceState(source) => write!(formatter, "Access Rule state failed: {source}"),
        }
    }
}

impl std::error::Error for BrokerAccessRuleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            _ => None,
        }
    }
}

impl From<DeviceStateError> for BrokerAccessRuleError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

/// Field-scoped Access Rule lifecycle and matching boundary.
pub(crate) struct BrokerAccessRuleManager;

impl BrokerAccessRuleManager {
    pub(crate) fn prepare_rule(
        state: &DeviceStateStore,
        approval: BrokerAccessRuleApproval,
    ) -> Result<AccessRule, BrokerAccessRuleError> {
        validate_capability(approval.target, approval.secret_kind)?;
        if state.consumer(approval.target.consumer_id())?.is_none() {
            return Err(BrokerAccessRuleError::ConsumerUnavailable);
        }
        AccessRule::new(
            approval.target,
            approval.confirmation_policy,
            approval.lifetime,
            approval.approved_at,
        )
        .map_err(|_| BrokerAccessRuleError::InvalidLifetime)
    }

    pub(crate) fn create_rule(
        state: &DeviceStateStore,
        approval: BrokerAccessRuleApproval,
    ) -> Result<BrokerAccessRuleCreation, BrokerAccessRuleError> {
        let rule = Self::prepare_rule(state, approval)?;
        if let Some(existing) = state.access_rule_for_target(approval.target)? {
            if existing.is_active_at(approval.approved_at) {
                if existing.confirmation_policy() == approval.confirmation_policy
                    && existing.lifetime() == approval.lifetime
                {
                    return Ok(BrokerAccessRuleCreation {
                        rule: existing,
                        newly_created: false,
                    });
                }
                return Err(BrokerAccessRuleError::ConflictingRule);
            }
            state.remove_access_rule(existing.access_rule_id())?;
        }

        state.insert_access_rule(&rule)?;
        Ok(BrokerAccessRuleCreation::from_persisted(rule, true))
    }

    pub(crate) fn evaluate_rule(
        state: &DeviceStateStore,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        evaluated_at: StateTimestamp,
    ) -> Result<BrokerAccessRuleEvaluation, BrokerAccessRuleError> {
        if state.consumer(target.consumer_id())?.is_none() {
            return Err(BrokerAccessRuleError::ConsumerUnavailable);
        }
        validate_capability(target, secret_kind)?;
        let Some(rule) = state.access_rule_for_target(target)? else {
            return Ok(BrokerAccessRuleEvaluation::NoMatchingRule);
        };
        if !rule.is_active_at(evaluated_at) {
            return Ok(BrokerAccessRuleEvaluation::NoMatchingRule);
        }
        Ok(BrokerAccessRuleEvaluation::MatchingRule(rule))
    }
}

pub(crate) fn validate_capability(
    target: AuthorizationTarget,
    secret_kind: SecretFieldKind,
) -> Result<(), BrokerAccessRuleError> {
    let capability = target.capability();
    if capability.version() != 1 {
        return Err(BrokerAccessRuleError::UnsupportedCapability);
    }
    let compatible = match capability.name() {
        crate::state_model::CapabilityName::CredentialSearch => true,
        crate::state_model::CapabilityName::HttpRequest => {
            CredentialUseCapability::HttpRequest.supports_secret_kind(secret_kind)
        }
        crate::state_model::CapabilityName::ProcessRun => {
            CredentialUseCapability::ProcessRun.supports_secret_kind(secret_kind)
        }
        crate::state_model::CapabilityName::AccessRequest
        | crate::state_model::CapabilityName::GrantStatus
        | crate::state_model::CapabilityName::GrantRevoke => {
            return Err(BrokerAccessRuleError::UnsupportedCapability);
        }
    };
    if !compatible {
        return Err(BrokerAccessRuleError::IncompatibleSecretKind);
    }
    Ok(())
}

#[cfg(all(test, unix))]
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
        Capability, CapabilityName, Consumer, ConsumerId, CredentialFieldScope,
        ObservedConsumerIdentity,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestStateDirectory {
        path: PathBuf,
    }

    impl TestStateDirectory {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keptnear-access-rule-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create state directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect state directory");
            Self { path }
        }

        fn initialize(&self, key_byte: u8) -> DeviceStateStore {
            let key = DeviceRootKey::from_stored_bytes(vec![key_byte; 32]).expect("root key");
            DeviceStateStore::initialize_for_tests(&self.path, &key, timestamp(1))
                .expect("initialize state")
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

    fn consumer(key_byte: u8, created_at: i64) -> Consumer {
        Consumer::new(
            [key_byte; 32],
            format!("Consumer {key_byte}"),
            ObservedConsumerIdentity::default(),
            timestamp(created_at),
        )
        .expect("Consumer")
    }

    fn target(
        consumer_id: ConsumerId,
        field_scope: CredentialFieldScope,
        capability_name: CapabilityName,
    ) -> AuthorizationTarget {
        AuthorizationTarget::new(consumer_id, field_scope, Capability::v1(capability_name))
    }

    fn field_scope() -> CredentialFieldScope {
        CredentialFieldScope::new(
            VaultId::generate(),
            CredentialId::generate(),
            SecretFieldId::generate(),
        )
    }

    fn approval(
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        policy: ConfirmationPolicy,
        lifetime: RuleLifetime,
        approved_at: i64,
    ) -> BrokerAccessRuleApproval {
        BrokerAccessRuleApproval::after_user_approval(
            target,
            secret_kind,
            policy,
            lifetime,
            timestamp(approved_at),
        )
        .expect("approval")
    }

    #[test]
    fn explicit_approval_creates_one_exact_idempotent_rule() {
        let directory = TestStateDirectory::new("create");
        let state = directory.initialize(31);
        let consumer = consumer(41, 10);
        state.insert_consumer(&consumer).expect("insert Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(),
            CapabilityName::HttpRequest,
        );
        let approval = approval(
            target,
            SecretFieldKind::ApiToken,
            ConfirmationPolicy::EveryUse,
            RuleLifetime::Persistent,
            20,
        );

        let created = BrokerAccessRuleManager::create_rule(&state, approval).expect("create rule");
        assert!(created.newly_created());
        assert_eq!(created.rule().target(), target);
        assert_eq!(
            created.rule().confirmation_policy(),
            ConfirmationPolicy::EveryUse
        );
        assert_eq!(created.rule().lifetime(), RuleLifetime::Persistent);

        let repeated =
            BrokerAccessRuleManager::create_rule(&state, approval).expect("repeat approval");
        assert!(!repeated.newly_created());
        assert_eq!(
            repeated.rule().access_rule_id(),
            created.rule().access_rule_id()
        );
        assert_eq!(
            state
                .access_rules_for_consumer(consumer.consumer_id())
                .expect("rules")
                .len(),
            1
        );
    }

    #[test]
    fn matching_is_exact_across_consumer_field_capability_and_version() {
        let directory = TestStateDirectory::new("exact");
        let state = directory.initialize(32);
        let first = consumer(42, 10);
        let second = consumer(43, 11);
        state.insert_consumer(&first).expect("first Consumer");
        state.insert_consumer(&second).expect("second Consumer");
        let scope = field_scope();
        let matching = target(first.consumer_id(), scope, CapabilityName::CredentialSearch);
        BrokerAccessRuleManager::create_rule(
            &state,
            approval(
                matching,
                SecretFieldKind::Password,
                ConfirmationPolicy::OncePerUnlockSession,
                RuleLifetime::Persistent,
                20,
            ),
        )
        .expect("create rule");

        assert!(matches!(
            BrokerAccessRuleManager::evaluate_rule(
                &state,
                matching,
                SecretFieldKind::Password,
                timestamp(30),
            )
            .expect("matching evaluation"),
            BrokerAccessRuleEvaluation::MatchingRule(_)
        ));

        let different_field = target(
            first.consumer_id(),
            field_scope(),
            CapabilityName::CredentialSearch,
        );
        let different_capability = target(first.consumer_id(), scope, CapabilityName::ProcessRun);
        let different_consumer = target(
            second.consumer_id(),
            scope,
            CapabilityName::CredentialSearch,
        );
        let different_version = AuthorizationTarget::new(
            first.consumer_id(),
            scope,
            Capability::new(CapabilityName::CredentialSearch, 2).expect("version"),
        );
        for target in [different_field, different_capability, different_consumer] {
            assert_eq!(
                BrokerAccessRuleManager::evaluate_rule(
                    &state,
                    target,
                    SecretFieldKind::Password,
                    timestamp(30),
                )
                .expect("default deny"),
                BrokerAccessRuleEvaluation::NoMatchingRule
            );
        }
        assert_eq!(
            BrokerAccessRuleManager::evaluate_rule(
                &state,
                different_version,
                SecretFieldKind::Password,
                timestamp(30),
            ),
            Err(BrokerAccessRuleError::UnsupportedCapability)
        );
    }

    #[test]
    fn every_confirmation_policy_round_trips_without_issuing_a_grant() {
        let directory = TestStateDirectory::new("policies");
        let state = directory.initialize(33);
        let consumer = consumer(44, 10);
        state.insert_consumer(&consumer).expect("Consumer");
        for (index, policy) in [
            ConfirmationPolicy::EveryUse,
            ConfirmationPolicy::OncePerUnlockSession,
            ConfirmationPolicy::AutomaticWhileUnlocked,
        ]
        .into_iter()
        .enumerate()
        {
            let target = target(
                consumer.consumer_id(),
                field_scope(),
                CapabilityName::ProcessRun,
            );
            let created = BrokerAccessRuleManager::create_rule(
                &state,
                approval(
                    target,
                    SecretFieldKind::PrivateKey,
                    policy,
                    RuleLifetime::Persistent,
                    20 + i64::try_from(index).expect("index"),
                ),
            )
            .expect("create rule");
            let evaluated = BrokerAccessRuleManager::evaluate_rule(
                &state,
                target,
                SecretFieldKind::PrivateKey,
                timestamp(40),
            )
            .expect("evaluate");
            assert_eq!(
                evaluated
                    .matching_rule()
                    .expect("matching rule")
                    .confirmation_policy(),
                policy
            );
            assert!(state
                .use_grants_for_consumer(consumer.consumer_id())
                .expect("grants")
                .is_empty());
            assert!(created.newly_created());
        }
    }

    #[test]
    fn bounded_lifetime_fails_closed_before_creation_and_at_expiry() {
        let directory = TestStateDirectory::new("lifetime");
        let state = directory.initialize(34);
        let consumer = consumer(45, 10);
        state.insert_consumer(&consumer).expect("Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(),
            CapabilityName::ProcessRun,
        );
        BrokerAccessRuleManager::create_rule(
            &state,
            approval(
                target,
                SecretFieldKind::GenericSecret,
                ConfirmationPolicy::AutomaticWhileUnlocked,
                RuleLifetime::Until(timestamp(200)),
                100,
            ),
        )
        .expect("create bounded rule");

        for evaluated_at in [99, 200, 201] {
            assert_eq!(
                BrokerAccessRuleManager::evaluate_rule(
                    &state,
                    target,
                    SecretFieldKind::GenericSecret,
                    timestamp(evaluated_at),
                )
                .expect("evaluate boundary"),
                BrokerAccessRuleEvaluation::NoMatchingRule
            );
        }
        assert!(matches!(
            BrokerAccessRuleManager::evaluate_rule(
                &state,
                target,
                SecretFieldKind::GenericSecret,
                timestamp(199),
            )
            .expect("active rule"),
            BrokerAccessRuleEvaluation::MatchingRule(_)
        ));
        assert_eq!(
            BrokerAccessRuleApproval::after_user_approval(
                target,
                SecretFieldKind::GenericSecret,
                ConfirmationPolicy::EveryUse,
                RuleLifetime::Until(timestamp(100)),
                timestamp(100),
            ),
            Err(BrokerAccessRuleError::InvalidLifetime)
        );
    }

    #[test]
    fn expired_rule_can_be_reauthorized_but_active_rule_cannot_be_overwritten() {
        let directory = TestStateDirectory::new("reauthorize");
        let state = directory.initialize(35);
        let consumer = consumer(46, 10);
        state.insert_consumer(&consumer).expect("Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(),
            CapabilityName::CredentialSearch,
        );
        let expired = BrokerAccessRuleManager::create_rule(
            &state,
            approval(
                target,
                SecretFieldKind::ApiKey,
                ConfirmationPolicy::EveryUse,
                RuleLifetime::Until(timestamp(100)),
                20,
            ),
        )
        .expect("expired generation");
        let replacement = BrokerAccessRuleManager::create_rule(
            &state,
            approval(
                target,
                SecretFieldKind::ApiKey,
                ConfirmationPolicy::AutomaticWhileUnlocked,
                RuleLifetime::Persistent,
                100,
            ),
        )
        .expect("replace expired rule");
        assert_ne!(
            expired.rule().access_rule_id(),
            replacement.rule().access_rule_id()
        );
        assert_eq!(
            BrokerAccessRuleManager::create_rule(
                &state,
                approval(
                    target,
                    SecretFieldKind::ApiKey,
                    ConfirmationPolicy::EveryUse,
                    RuleLifetime::Persistent,
                    101,
                ),
            ),
            Err(BrokerAccessRuleError::ConflictingRule)
        );
        assert_eq!(
            state
                .access_rules_for_consumer(consumer.consumer_id())
                .expect("rules"),
            vec![replacement.rule().clone()]
        );
    }

    #[test]
    fn unsupported_and_incompatible_capabilities_fail_closed() {
        let consumer_id = ConsumerId::generate();
        let scope = field_scope();
        let unsupported = target(consumer_id, scope, CapabilityName::AccessRequest);
        assert_eq!(
            BrokerAccessRuleApproval::after_user_approval(
                unsupported,
                SecretFieldKind::ApiToken,
                ConfirmationPolicy::EveryUse,
                RuleLifetime::Persistent,
                timestamp(10),
            ),
            Err(BrokerAccessRuleError::UnsupportedCapability)
        );

        let incompatible = target(consumer_id, scope, CapabilityName::HttpRequest);
        assert_eq!(
            BrokerAccessRuleApproval::after_user_approval(
                incompatible,
                SecretFieldKind::PrivateKey,
                ConfirmationPolicy::EveryUse,
                RuleLifetime::Persistent,
                timestamp(10),
            ),
            Err(BrokerAccessRuleError::IncompatibleSecretKind)
        );
        assert_eq!(
            BrokerAccessRuleError::IncompatibleSecretKind.broker_error_code(),
            BrokerErrorCode::AccessDenied
        );
    }

    #[test]
    fn provider_neutral_authorization_matrix_is_exhaustive_and_fail_closed() {
        let consumer_id = ConsumerId::generate();
        let scope = field_scope();

        for secret_kind in SecretFieldKind::ALL.iter().copied() {
            let http_request_allowed = matches!(
                secret_kind,
                SecretFieldKind::Password
                    | SecretFieldKind::ApiToken
                    | SecretFieldKind::ApiKey
                    | SecretFieldKind::GenericSecret
            );
            for (capability_name, allowed) in [
                (CapabilityName::CredentialSearch, true),
                (CapabilityName::HttpRequest, http_request_allowed),
                (CapabilityName::ProcessRun, true),
            ] {
                let result = BrokerAccessRuleApproval::after_user_approval(
                    target(consumer_id, scope, capability_name),
                    secret_kind,
                    ConfirmationPolicy::EveryUse,
                    RuleLifetime::Persistent,
                    timestamp(10),
                );
                if allowed {
                    assert!(
                        result.is_ok(),
                        "{capability_name:?} must support {secret_kind:?}"
                    );
                } else {
                    assert_eq!(
                        result,
                        Err(BrokerAccessRuleError::IncompatibleSecretKind),
                        "{capability_name:?} must reject {secret_kind:?}"
                    );
                }
            }

            for capability_name in [
                CapabilityName::AccessRequest,
                CapabilityName::GrantStatus,
                CapabilityName::GrantRevoke,
            ] {
                assert_eq!(
                    BrokerAccessRuleApproval::after_user_approval(
                        target(consumer_id, scope, capability_name),
                        secret_kind,
                        ConfirmationPolicy::EveryUse,
                        RuleLifetime::Persistent,
                        timestamp(10),
                    ),
                    Err(BrokerAccessRuleError::UnsupportedCapability),
                    "{capability_name:?} must not become a field capability"
                );
            }

            for capability_name in [
                CapabilityName::CredentialSearch,
                CapabilityName::HttpRequest,
                CapabilityName::ProcessRun,
            ] {
                let future_target = AuthorizationTarget::new(
                    consumer_id,
                    scope,
                    Capability::new(capability_name, 2).expect("future capability"),
                );
                assert_eq!(
                    BrokerAccessRuleApproval::after_user_approval(
                        future_target,
                        secret_kind,
                        ConfirmationPolicy::EveryUse,
                        RuleLifetime::Persistent,
                        timestamp(10),
                    ),
                    Err(BrokerAccessRuleError::UnsupportedCapability),
                    "{capability_name:?} v2 must fail closed"
                );
            }
        }
    }

    #[test]
    fn unknown_consumer_cannot_create_or_evaluate_a_rule() {
        let directory = TestStateDirectory::new("unknown-consumer");
        let state = directory.initialize(36);
        let target = target(
            ConsumerId::generate(),
            field_scope(),
            CapabilityName::ProcessRun,
        );
        let approval = approval(
            target,
            SecretFieldKind::Password,
            ConfirmationPolicy::EveryUse,
            RuleLifetime::Persistent,
            20,
        );
        assert_eq!(
            BrokerAccessRuleManager::create_rule(&state, approval),
            Err(BrokerAccessRuleError::ConsumerUnavailable)
        );
        assert_eq!(
            BrokerAccessRuleManager::evaluate_rule(
                &state,
                target,
                SecretFieldKind::Password,
                timestamp(30),
            ),
            Err(BrokerAccessRuleError::ConsumerUnavailable)
        );
        assert_eq!(
            BrokerAccessRuleError::ConsumerUnavailable.broker_error_code(),
            BrokerErrorCode::ConsumerRevoked
        );
    }
}
