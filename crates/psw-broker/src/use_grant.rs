use std::fmt::{Display, Formatter};

use psw_core::SecretFieldKind;

use crate::access_rule::{
    validate_capability, BrokerAccessRuleError, BrokerAccessRuleEvaluation, BrokerAccessRuleManager,
};
use crate::protocol::BrokerErrorCode;
use crate::state_model::{
    AccessRule, AuthorizationTarget, ConfirmationPolicy, ConsumerId, GrantScope, RuleLifetime,
    StateTimestamp, UseGrant, UseGrantId, VaultSessionId,
};
use crate::state_store::{DeviceStateError, DeviceStateStore, StoredUseGrantAuthorization};
use crate::vault_session::BrokerVaultSessionError;

/// Explicit local approval for one operation without creating an Access Rule.
#[derive(Debug, Eq, PartialEq)]
pub struct BrokerAllowOnceApproval {
    target: AuthorizationTarget,
    secret_kind: SecretFieldKind,
    vault_session_id: VaultSessionId,
    approved_at: StateTimestamp,
    expires_at: StateTimestamp,
}

impl BrokerAllowOnceApproval {
    /// Validates one local Allow Once decision.
    pub fn after_user_approval(
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        approved_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<Self, BrokerUseGrantError> {
        validate_capability(target, secret_kind)?;
        validate_window(approved_at, expires_at)?;
        Ok(Self {
            target,
            secret_kind,
            vault_session_id,
            approved_at,
            expires_at,
        })
    }

    pub(crate) const fn target(&self) -> AuthorizationTarget {
        self.target
    }

    pub(crate) const fn vault_session_id(&self) -> VaultSessionId {
        self.vault_session_id
    }
}

/// Explicit local confirmation for one use of an existing Access Rule.
#[derive(Debug, Eq, PartialEq)]
pub struct BrokerRuleUseApproval {
    target: AuthorizationTarget,
    secret_kind: SecretFieldKind,
    vault_session_id: VaultSessionId,
    approved_at: StateTimestamp,
    expires_at: StateTimestamp,
}

impl BrokerRuleUseApproval {
    /// Validates one local confirmation associated with an Access Rule.
    pub fn after_user_approval(
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        approved_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<Self, BrokerUseGrantError> {
        validate_capability(target, secret_kind)?;
        validate_window(approved_at, expires_at)?;
        Ok(Self {
            target,
            secret_kind,
            vault_session_id,
            approved_at,
            expires_at,
        })
    }

    pub(crate) const fn target(&self) -> AuthorizationTarget {
        self.target
    }

    pub(crate) const fn vault_session_id(&self) -> VaultSessionId {
        self.vault_session_id
    }
}

/// Human or rule basis that authorized one Use Grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerUseGrantBasis {
    /// A local human approved one operation without creating a rule.
    AllowOnce,
    /// A local human confirmed an `every-use` rule.
    ConfirmedEveryUse,
    /// A local human confirmed a `once-per-unlock-session` rule.
    ConfirmedUnlockSession,
    /// An `automatic-while-unlocked` rule authorized the current session.
    AutomaticWhileUnlocked,
}

/// Result of issuing or reusing one bounded Use Grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerUseGrantIssuance {
    grant: UseGrant,
    basis: BrokerUseGrantBasis,
    newly_issued: bool,
}

impl BrokerUseGrantIssuance {
    /// Returns the exact Consumer, field, capability, and session grant.
    #[must_use]
    pub const fn grant(&self) -> &UseGrant {
        &self.grant
    }

    /// Returns the decision basis used to issue the grant.
    #[must_use]
    pub const fn basis(&self) -> BrokerUseGrantBasis {
        self.basis
    }

    /// Returns whether this call inserted a new grant.
    #[must_use]
    pub const fn newly_issued(&self) -> bool {
        self.newly_issued
    }
}

/// Result of authorizing one operation with a presented Use Grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerAuthorizedGrantUse {
    grant: UseGrant,
    consumed: bool,
}

/// Consumer-scoped status of one presented Use Grant identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerConsumerUseGrantStatus {
    /// The exact Consumer-owned grant is active at the observed time.
    Active(UseGrant),
    /// The exact Consumer-owned grant expired and was removed.
    Expired,
    /// The grant is absent, belongs elsewhere, or is not yet active.
    Unavailable,
}

impl BrokerAuthorizedGrantUse {
    /// Returns the exact grant that authorized the operation.
    #[must_use]
    pub const fn grant(&self) -> &UseGrant {
        &self.grant
    }

    /// Returns whether authorization atomically consumed a one-operation grant.
    #[must_use]
    pub const fn consumed(&self) -> bool {
        self.consumed
    }
}

/// Sanitized Use Grant issuance or authorization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerUseGrantError {
    /// The grant expiry does not follow its creation time.
    InvalidWindow,
    /// The Consumer is not paired or was removed.
    ConsumerUnavailable,
    /// No exact authorization permits this grant operation.
    AccessDenied,
    /// The matching Access Rule requires a local human confirmation.
    ApprovalRequired,
    /// A human-confirmed issuance was attempted for an automatic rule.
    ConfirmationNotApplicable,
    /// The grant or its unlock session has expired.
    GrantExpired,
    /// More than one active session grant exists for one exact rule target.
    ConflictingSessionGrant,
    /// Access Rule validation or lookup failed.
    AccessRule(BrokerAccessRuleError),
    /// Authenticated encrypted device state could not be read or changed.
    DeviceState(DeviceStateError),
    /// The process-owned vault session could not be inspected.
    VaultSession(BrokerVaultSessionError),
}

impl BrokerUseGrantError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(&self) -> BrokerErrorCode {
        match self {
            Self::InvalidWindow | Self::ConfirmationNotApplicable => {
                BrokerErrorCode::InvalidRequest
            }
            Self::ConsumerUnavailable => BrokerErrorCode::ConsumerRevoked,
            Self::AccessDenied => BrokerErrorCode::AccessDenied,
            Self::ApprovalRequired => BrokerErrorCode::ApprovalRequired,
            Self::GrantExpired => BrokerErrorCode::GrantExpired,
            Self::ConflictingSessionGrant | Self::DeviceState(_) => {
                BrokerErrorCode::OperationFailed
            }
            Self::AccessRule(source) => source.broker_error_code(),
            Self::VaultSession(source) => match source {
                BrokerVaultSessionError::ShutDown
                | BrokerVaultSessionError::VaultNotOpen
                | BrokerVaultSessionError::VaultLocked
                | BrokerVaultSessionError::VaultUnlockInProgress
                | BrokerVaultSessionError::VaultUnlockCancelled => BrokerErrorCode::VaultLocked,
                _ => BrokerErrorCode::OperationFailed,
            },
        }
    }
}

impl Display for BrokerUseGrantError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWindow => formatter.write_str("Use Grant window is invalid"),
            Self::ConsumerUnavailable => formatter.write_str("Use Grant Consumer is unavailable"),
            Self::AccessDenied => formatter.write_str("Use Grant authorization was denied"),
            Self::ApprovalRequired => formatter.write_str("Use Grant requires local approval"),
            Self::ConfirmationNotApplicable => {
                formatter.write_str("Use Grant confirmation does not apply to this rule")
            }
            Self::GrantExpired => formatter.write_str("Use Grant has expired"),
            Self::ConflictingSessionGrant => {
                formatter.write_str("Use Grant session state is inconsistent")
            }
            Self::AccessRule(source) => write!(formatter, "Use Grant rule failed: {source}"),
            Self::DeviceState(source) => write!(formatter, "Use Grant state failed: {source}"),
            Self::VaultSession(source) => {
                write!(formatter, "Use Grant vault session failed: {source}")
            }
        }
    }
}

impl std::error::Error for BrokerUseGrantError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AccessRule(source) => Some(source),
            Self::DeviceState(source) => Some(source),
            Self::VaultSession(source) => Some(source),
            _ => None,
        }
    }
}

impl From<BrokerAccessRuleError> for BrokerUseGrantError {
    fn from(source: BrokerAccessRuleError) -> Self {
        Self::AccessRule(source)
    }
}

impl From<DeviceStateError> for BrokerUseGrantError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

impl From<BrokerVaultSessionError> for BrokerUseGrantError {
    fn from(source: BrokerVaultSessionError) -> Self {
        Self::VaultSession(source)
    }
}

pub(crate) struct BrokerUseGrantManager;

impl BrokerUseGrantManager {
    pub(crate) fn status_for_consumer(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        use_grant_id: UseGrantId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerConsumerUseGrantStatus, BrokerUseGrantError> {
        ensure_consumer_id(state, consumer_id)?;
        let Some(grant) = state.use_grant_for_consumer(consumer_id, use_grant_id)? else {
            return Ok(BrokerConsumerUseGrantStatus::Unavailable);
        };
        if observed_at < grant.created_at() {
            return Ok(BrokerConsumerUseGrantStatus::Unavailable);
        }
        if observed_at >= grant.expires_at() {
            return if state.remove_use_grant_for_consumer(consumer_id, use_grant_id)? {
                Ok(BrokerConsumerUseGrantStatus::Expired)
            } else {
                Ok(BrokerConsumerUseGrantStatus::Unavailable)
            };
        }
        Ok(BrokerConsumerUseGrantStatus::Active(grant))
    }

    pub(crate) fn revoke_for_consumer(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        use_grant_id: UseGrantId,
    ) -> Result<bool, BrokerUseGrantError> {
        ensure_consumer_id(state, consumer_id)?;
        state
            .remove_use_grant_for_consumer(consumer_id, use_grant_id)
            .map_err(BrokerUseGrantError::DeviceState)
    }

    pub(crate) fn preflight_automatic_rule(
        state: &DeviceStateStore,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        evaluated_at: StateTimestamp,
    ) -> Result<(), BrokerUseGrantError> {
        let rule = matching_rule(state, target, secret_kind, evaluated_at)?;
        if rule.confirmation_policy() != ConfirmationPolicy::AutomaticWhileUnlocked {
            return Err(BrokerUseGrantError::ApprovalRequired);
        }
        Ok(())
    }

    pub(crate) fn preflight_use(
        state: &DeviceStateStore,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
    ) -> Result<(), BrokerUseGrantError> {
        validate_capability(target, secret_kind)?;
        ensure_consumer(state, target)?;
        if !state.use_grant_matches_target_session(use_grant_id, target, vault_session_id)? {
            return Err(BrokerUseGrantError::AccessDenied);
        }
        Ok(())
    }

    pub(crate) fn issue_allow_once(
        state: &DeviceStateStore,
        approval: BrokerAllowOnceApproval,
    ) -> Result<BrokerUseGrantIssuance, BrokerUseGrantError> {
        let issuance = Self::prepare_allow_once(state, approval)?;
        state.insert_use_grant(issuance.grant())?;
        Ok(issuance)
    }

    pub(crate) fn prepare_allow_once(
        state: &DeviceStateStore,
        approval: BrokerAllowOnceApproval,
    ) -> Result<BrokerUseGrantIssuance, BrokerUseGrantError> {
        validate_capability(approval.target, approval.secret_kind)?;
        validate_window(approval.approved_at, approval.expires_at)?;
        ensure_consumer(state, approval.target)?;
        let grant = UseGrant::new(
            approval.target,
            None,
            approval.vault_session_id,
            GrantScope::OneOperation,
            approval.approved_at,
            approval.expires_at,
        )
        .map_err(|_| BrokerUseGrantError::InvalidWindow)?;
        Ok(BrokerUseGrantIssuance {
            grant,
            basis: BrokerUseGrantBasis::AllowOnce,
            newly_issued: true,
        })
    }

    pub(crate) fn issue_confirmed_rule(
        state: &DeviceStateStore,
        approval: BrokerRuleUseApproval,
    ) -> Result<BrokerUseGrantIssuance, BrokerUseGrantError> {
        validate_capability(approval.target, approval.secret_kind)?;
        validate_window(approval.approved_at, approval.expires_at)?;
        let rule = matching_rule(
            state,
            approval.target,
            approval.secret_kind,
            approval.approved_at,
        )?;
        let expires_at = grant_expiry(&rule, approval.expires_at);
        match rule.confirmation_policy() {
            ConfirmationPolicy::EveryUse => issue_one_operation(
                state,
                &rule,
                approval.vault_session_id,
                approval.approved_at,
                expires_at,
                BrokerUseGrantBasis::ConfirmedEveryUse,
            ),
            ConfirmationPolicy::OncePerUnlockSession => issue_unlock_session(
                state,
                &rule,
                approval.vault_session_id,
                approval.approved_at,
                expires_at,
                BrokerUseGrantBasis::ConfirmedUnlockSession,
            ),
            ConfirmationPolicy::AutomaticWhileUnlocked => {
                Err(BrokerUseGrantError::ConfirmationNotApplicable)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_automatic_rule(
        state: &DeviceStateStore,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        issued_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<BrokerUseGrantIssuance, BrokerUseGrantError> {
        validate_capability(target, secret_kind)?;
        validate_window(issued_at, expires_at)?;
        let rule = matching_rule(state, target, secret_kind, issued_at)?;
        if rule.confirmation_policy() != ConfirmationPolicy::AutomaticWhileUnlocked {
            return Err(BrokerUseGrantError::ApprovalRequired);
        }
        let expires_at = grant_expiry(&rule, expires_at);
        issue_unlock_session(
            state,
            &rule,
            vault_session_id,
            issued_at,
            expires_at,
            BrokerUseGrantBasis::AutomaticWhileUnlocked,
        )
    }

    pub(crate) fn authorize_use(
        state: &DeviceStateStore,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        evaluated_at: StateTimestamp,
    ) -> Result<BrokerAuthorizedGrantUse, BrokerUseGrantError> {
        Self::preflight_use(state, use_grant_id, target, secret_kind, vault_session_id)?;
        match state.authorize_stored_use_grant(
            use_grant_id,
            target,
            vault_session_id,
            evaluated_at,
        )? {
            StoredUseGrantAuthorization::Unavailable
            | StoredUseGrantAuthorization::NotYetActive => Err(BrokerUseGrantError::AccessDenied),
            StoredUseGrantAuthorization::Expired => Err(BrokerUseGrantError::GrantExpired),
            StoredUseGrantAuthorization::Authorized(grant) => {
                let consumed = grant.scope() == GrantScope::OneOperation;
                Ok(BrokerAuthorizedGrantUse { grant, consumed })
            }
        }
    }

    pub(crate) fn remove_grant(
        state: &DeviceStateStore,
        use_grant_id: UseGrantId,
    ) -> Result<(), BrokerUseGrantError> {
        state.remove_use_grant(use_grant_id)?;
        Ok(())
    }
}

fn ensure_consumer(
    state: &DeviceStateStore,
    target: AuthorizationTarget,
) -> Result<(), BrokerUseGrantError> {
    if state.consumer(target.consumer_id())?.is_none() {
        return Err(BrokerUseGrantError::ConsumerUnavailable);
    }
    Ok(())
}

fn ensure_consumer_id(
    state: &DeviceStateStore,
    consumer_id: ConsumerId,
) -> Result<(), BrokerUseGrantError> {
    if state.consumer(consumer_id)?.is_none() {
        return Err(BrokerUseGrantError::ConsumerUnavailable);
    }
    Ok(())
}

fn matching_rule(
    state: &DeviceStateStore,
    target: AuthorizationTarget,
    secret_kind: SecretFieldKind,
    evaluated_at: StateTimestamp,
) -> Result<AccessRule, BrokerUseGrantError> {
    match BrokerAccessRuleManager::evaluate_rule(state, target, secret_kind, evaluated_at)? {
        BrokerAccessRuleEvaluation::NoMatchingRule => Err(BrokerUseGrantError::AccessDenied),
        BrokerAccessRuleEvaluation::MatchingRule(rule) => Ok(rule),
    }
}

fn grant_expiry(rule: &AccessRule, requested_expiry: StateTimestamp) -> StateTimestamp {
    match rule.lifetime() {
        RuleLifetime::Persistent => requested_expiry,
        RuleLifetime::Until(rule_expiry) => requested_expiry.min(rule_expiry),
    }
}

fn issue_one_operation(
    state: &DeviceStateStore,
    rule: &AccessRule,
    vault_session_id: VaultSessionId,
    issued_at: StateTimestamp,
    expires_at: StateTimestamp,
    basis: BrokerUseGrantBasis,
) -> Result<BrokerUseGrantIssuance, BrokerUseGrantError> {
    validate_window(issued_at, expires_at)?;
    let grant = UseGrant::new(
        rule.target(),
        Some(rule.access_rule_id()),
        vault_session_id,
        GrantScope::OneOperation,
        issued_at,
        expires_at,
    )
    .map_err(|_| BrokerUseGrantError::InvalidWindow)?;
    state.insert_use_grant(&grant)?;
    Ok(BrokerUseGrantIssuance {
        grant,
        basis,
        newly_issued: true,
    })
}

fn issue_unlock_session(
    state: &DeviceStateStore,
    rule: &AccessRule,
    vault_session_id: VaultSessionId,
    issued_at: StateTimestamp,
    expires_at: StateTimestamp,
    basis: BrokerUseGrantBasis,
) -> Result<BrokerUseGrantIssuance, BrokerUseGrantError> {
    validate_window(issued_at, expires_at)?;
    let existing = state.use_grants_for_rule_session(
        rule.target(),
        rule.access_rule_id(),
        vault_session_id,
    )?;
    match existing.as_slice() {
        [] => {}
        [grant] => {
            if grant.is_active_at(issued_at) {
                return Ok(BrokerUseGrantIssuance {
                    grant: grant.clone(),
                    basis,
                    newly_issued: false,
                });
            }
            if issued_at < grant.created_at() {
                return Err(BrokerUseGrantError::AccessDenied);
            }
            state.remove_use_grant(grant.use_grant_id())?;
        }
        [_, _, ..] => return Err(BrokerUseGrantError::ConflictingSessionGrant),
    }
    let grant = UseGrant::new(
        rule.target(),
        Some(rule.access_rule_id()),
        vault_session_id,
        GrantScope::UnlockSession,
        issued_at,
        expires_at,
    )
    .map_err(|_| BrokerUseGrantError::InvalidWindow)?;
    state.insert_use_grant(&grant)?;
    Ok(BrokerUseGrantIssuance {
        grant,
        basis,
        newly_issued: true,
    })
}

fn validate_window(
    issued_at: StateTimestamp,
    expires_at: StateTimestamp,
) -> Result<(), BrokerUseGrantError> {
    if expires_at <= issued_at {
        return Err(BrokerUseGrantError::InvalidWindow);
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
    use crate::access_rule::{BrokerAccessRuleApproval, BrokerAccessRuleManager};
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
                "keptnear-use-grant-{label}-{}-{nanos}-{sequence}",
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

    fn consumer(key_byte: u8) -> Consumer {
        Consumer::new(
            [key_byte; 32],
            format!("Consumer {key_byte}"),
            ObservedConsumerIdentity::default(),
            timestamp(10),
        )
        .expect("Consumer")
    }

    fn field_scope(vault_id: VaultId) -> CredentialFieldScope {
        CredentialFieldScope::new(
            vault_id,
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

    fn create_rule(
        state: &DeviceStateStore,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        policy: ConfirmationPolicy,
        lifetime: RuleLifetime,
    ) -> AccessRule {
        BrokerAccessRuleManager::create_rule(
            state,
            BrokerAccessRuleApproval::after_user_approval(
                target,
                secret_kind,
                policy,
                lifetime,
                timestamp(20),
            )
            .expect("rule approval"),
        )
        .expect("create rule")
        .rule()
        .clone()
    }

    fn allow_once(
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        approved_at: i64,
        expires_at: i64,
    ) -> BrokerAllowOnceApproval {
        BrokerAllowOnceApproval::after_user_approval(
            target,
            secret_kind,
            vault_session_id,
            timestamp(approved_at),
            timestamp(expires_at),
        )
        .expect("Allow Once approval")
    }

    fn confirm_rule(
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        approved_at: i64,
        expires_at: i64,
    ) -> BrokerRuleUseApproval {
        BrokerRuleUseApproval::after_user_approval(
            target,
            secret_kind,
            vault_session_id,
            timestamp(approved_at),
            timestamp(expires_at),
        )
        .expect("rule confirmation")
    }

    #[test]
    fn allow_once_is_source_less_and_consumed_exactly_once() {
        let directory = TestStateDirectory::new("allow-once");
        let state = directory.initialize(51);
        let consumer = consumer(61);
        state.insert_consumer(&consumer).expect("Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(VaultId::generate()),
            CapabilityName::HttpRequest,
        );
        let vault_session_id = VaultSessionId::generate();

        let issuance = BrokerUseGrantManager::issue_allow_once(
            &state,
            allow_once(target, SecretFieldKind::ApiToken, vault_session_id, 30, 100),
        )
        .expect("issue");
        assert_eq!(issuance.basis(), BrokerUseGrantBasis::AllowOnce);
        assert!(issuance.newly_issued());
        assert_eq!(issuance.grant().source_rule_id(), None);
        assert_eq!(issuance.grant().scope(), GrantScope::OneOperation);
        assert!(state
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("rules")
            .is_empty());

        let authorized = BrokerUseGrantManager::authorize_use(
            &state,
            issuance.grant().use_grant_id(),
            target,
            SecretFieldKind::ApiToken,
            vault_session_id,
            timestamp(40),
        )
        .expect("authorize");
        assert!(authorized.consumed());
        assert!(state
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("grants")
            .is_empty());
        assert_eq!(
            BrokerUseGrantManager::authorize_use(
                &state,
                issuance.grant().use_grant_id(),
                target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                timestamp(41),
            ),
            Err(BrokerUseGrantError::AccessDenied)
        );
    }

    #[test]
    fn exact_target_and_session_mismatch_do_not_consume_allow_once() {
        let directory = TestStateDirectory::new("exact");
        let state = directory.initialize(52);
        let first = consumer(62);
        let second = consumer(63);
        state.insert_consumer(&first).expect("first Consumer");
        state.insert_consumer(&second).expect("second Consumer");
        let scope = field_scope(VaultId::generate());
        let grant_target = target(first.consumer_id(), scope, CapabilityName::ProcessRun);
        let vault_session_id = VaultSessionId::generate();
        let issuance = BrokerUseGrantManager::issue_allow_once(
            &state,
            allow_once(
                grant_target,
                SecretFieldKind::GenericSecret,
                vault_session_id,
                30,
                100,
            ),
        )
        .expect("issue");
        let grant_id = issuance.grant().use_grant_id();

        for (wrong_target, wrong_session) in [
            (
                target(second.consumer_id(), scope, CapabilityName::ProcessRun),
                vault_session_id,
            ),
            (
                target(first.consumer_id(), scope, CapabilityName::HttpRequest),
                vault_session_id,
            ),
            (grant_target, VaultSessionId::generate()),
        ] {
            assert_eq!(
                BrokerUseGrantManager::authorize_use(
                    &state,
                    grant_id,
                    wrong_target,
                    SecretFieldKind::GenericSecret,
                    wrong_session,
                    timestamp(40),
                ),
                Err(BrokerUseGrantError::AccessDenied)
            );
        }
        assert_eq!(
            state
                .use_grants_for_consumer(first.consumer_id())
                .expect("grant count")
                .len(),
            1
        );
        assert!(BrokerUseGrantManager::authorize_use(
            &state,
            grant_id,
            grant_target,
            SecretFieldKind::GenericSecret,
            vault_session_id,
            timestamp(41),
        )
        .is_ok());
    }

    #[test]
    fn every_use_rule_requires_confirmation_and_issues_one_operation() {
        let directory = TestStateDirectory::new("every-use");
        let state = directory.initialize(53);
        let consumer = consumer(64);
        state.insert_consumer(&consumer).expect("Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(VaultId::generate()),
            CapabilityName::HttpRequest,
        );
        let rule = create_rule(
            &state,
            target,
            SecretFieldKind::ApiKey,
            ConfirmationPolicy::EveryUse,
            RuleLifetime::Persistent,
        );
        let vault_session_id = VaultSessionId::generate();

        assert_eq!(
            BrokerUseGrantManager::issue_automatic_rule(
                &state,
                target,
                SecretFieldKind::ApiKey,
                vault_session_id,
                timestamp(30),
                timestamp(100),
            ),
            Err(BrokerUseGrantError::ApprovalRequired)
        );
        let issuance = BrokerUseGrantManager::issue_confirmed_rule(
            &state,
            confirm_rule(target, SecretFieldKind::ApiKey, vault_session_id, 30, 100),
        )
        .expect("confirmed issue");
        assert_eq!(issuance.basis(), BrokerUseGrantBasis::ConfirmedEveryUse);
        assert_eq!(issuance.grant().scope(), GrantScope::OneOperation);
        assert_eq!(
            issuance.grant().source_rule_id(),
            Some(rule.access_rule_id())
        );
    }

    #[test]
    fn once_per_unlock_session_reuses_only_the_exact_session() {
        let directory = TestStateDirectory::new("unlock-session");
        let state = directory.initialize(54);
        let consumer = consumer(65);
        state.insert_consumer(&consumer).expect("Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(VaultId::generate()),
            CapabilityName::ProcessRun,
        );
        create_rule(
            &state,
            target,
            SecretFieldKind::PrivateKey,
            ConfirmationPolicy::OncePerUnlockSession,
            RuleLifetime::Persistent,
        );
        let first_session = VaultSessionId::generate();
        let first = BrokerUseGrantManager::issue_confirmed_rule(
            &state,
            confirm_rule(target, SecretFieldKind::PrivateKey, first_session, 30, 500),
        )
        .expect("first session");
        let repeated = BrokerUseGrantManager::issue_confirmed_rule(
            &state,
            confirm_rule(target, SecretFieldKind::PrivateKey, first_session, 31, 600),
        )
        .expect("same session");
        assert!(!repeated.newly_issued());
        assert_eq!(
            repeated.grant().use_grant_id(),
            first.grant().use_grant_id()
        );
        assert!(!BrokerUseGrantManager::authorize_use(
            &state,
            first.grant().use_grant_id(),
            target,
            SecretFieldKind::PrivateKey,
            first_session,
            timestamp(40),
        )
        .expect("first use")
        .consumed());
        assert!(BrokerUseGrantManager::authorize_use(
            &state,
            first.grant().use_grant_id(),
            target,
            SecretFieldKind::PrivateKey,
            first_session,
            timestamp(41),
        )
        .is_ok());

        let second = BrokerUseGrantManager::issue_confirmed_rule(
            &state,
            confirm_rule(
                target,
                SecretFieldKind::PrivateKey,
                VaultSessionId::generate(),
                32,
                500,
            ),
        )
        .expect("second session");
        assert!(second.newly_issued());
        assert_ne!(second.grant().use_grant_id(), first.grant().use_grant_id());
    }

    #[test]
    fn automatic_rule_reuses_session_grant_without_confirmation() {
        let directory = TestStateDirectory::new("automatic");
        let state = directory.initialize(55);
        let consumer = consumer(66);
        state.insert_consumer(&consumer).expect("Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(VaultId::generate()),
            CapabilityName::HttpRequest,
        );
        create_rule(
            &state,
            target,
            SecretFieldKind::Password,
            ConfirmationPolicy::AutomaticWhileUnlocked,
            RuleLifetime::Persistent,
        );
        let vault_session_id = VaultSessionId::generate();
        let first = BrokerUseGrantManager::issue_automatic_rule(
            &state,
            target,
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(30),
            timestamp(500),
        )
        .expect("automatic");
        let repeated = BrokerUseGrantManager::issue_automatic_rule(
            &state,
            target,
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(31),
            timestamp(600),
        )
        .expect("reuse");
        assert_eq!(first.basis(), BrokerUseGrantBasis::AutomaticWhileUnlocked);
        assert!(first.newly_issued());
        assert!(!repeated.newly_issued());
        assert_eq!(
            first.grant().use_grant_id(),
            repeated.grant().use_grant_id()
        );
        assert_eq!(
            BrokerUseGrantManager::issue_confirmed_rule(
                &state,
                confirm_rule(target, SecretFieldKind::Password, vault_session_id, 32, 500,),
            ),
            Err(BrokerUseGrantError::ConfirmationNotApplicable)
        );
    }

    #[test]
    fn rule_expiry_caps_session_grant_and_expires_at_exact_boundary() {
        let directory = TestStateDirectory::new("rule-expiry");
        let state = directory.initialize(56);
        let consumer = consumer(67);
        state.insert_consumer(&consumer).expect("Consumer");
        let target = target(
            consumer.consumer_id(),
            field_scope(VaultId::generate()),
            CapabilityName::CredentialSearch,
        );
        create_rule(
            &state,
            target,
            SecretFieldKind::Password,
            ConfirmationPolicy::AutomaticWhileUnlocked,
            RuleLifetime::Until(timestamp(200)),
        );
        let vault_session_id = VaultSessionId::generate();
        let issuance = BrokerUseGrantManager::issue_automatic_rule(
            &state,
            target,
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(150),
            timestamp(500),
        )
        .expect("issue");
        assert_eq!(issuance.grant().expires_at(), timestamp(200));
        assert!(BrokerUseGrantManager::authorize_use(
            &state,
            issuance.grant().use_grant_id(),
            target,
            SecretFieldKind::Password,
            vault_session_id,
            timestamp(199),
        )
        .is_ok());
        assert_eq!(
            BrokerUseGrantManager::authorize_use(
                &state,
                issuance.grant().use_grant_id(),
                target,
                SecretFieldKind::Password,
                vault_session_id,
                timestamp(200),
            ),
            Err(BrokerUseGrantError::GrantExpired)
        );
        assert_eq!(
            BrokerUseGrantManager::issue_automatic_rule(
                &state,
                target,
                SecretFieldKind::Password,
                vault_session_id,
                timestamp(200),
                timestamp(500),
            ),
            Err(BrokerUseGrantError::AccessDenied)
        );
    }

    #[test]
    fn invalid_windows_and_incompatible_fields_fail_before_state_writes() {
        let consumer_id = ConsumerId::generate();
        let target = target(
            consumer_id,
            field_scope(VaultId::generate()),
            CapabilityName::HttpRequest,
        );
        assert_eq!(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::ApiToken,
                VaultSessionId::generate(),
                timestamp(50),
                timestamp(50),
            ),
            Err(BrokerUseGrantError::InvalidWindow)
        );
        assert!(matches!(
            BrokerAllowOnceApproval::after_user_approval(
                target,
                SecretFieldKind::PrivateKey,
                VaultSessionId::generate(),
                timestamp(50),
                timestamp(60),
            ),
            Err(BrokerUseGrantError::AccessRule(
                BrokerAccessRuleError::IncompatibleSecretKind
            ))
        ));
    }

    #[test]
    fn grant_management_is_consumer_scoped_and_prunes_owned_expiry() {
        let directory = TestStateDirectory::new("consumer-management");
        let state = directory.initialize(59);
        let owner = consumer(69);
        let other = consumer(70);
        state.insert_consumer(&owner).expect("owner Consumer");
        state.insert_consumer(&other).expect("other Consumer");
        let owner_target = target(
            owner.consumer_id(),
            field_scope(VaultId::generate()),
            CapabilityName::HttpRequest,
        );
        let vault_session_id = VaultSessionId::generate();
        let active = BrokerUseGrantManager::issue_allow_once(
            &state,
            allow_once(
                owner_target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                30,
                100,
            ),
        )
        .expect("active grant");
        let active_id = active.grant().use_grant_id();

        assert!(matches!(
            BrokerUseGrantManager::status_for_consumer(
                &state,
                owner.consumer_id(),
                active_id,
                timestamp(40),
            )
            .expect("owner status"),
            BrokerConsumerUseGrantStatus::Active(grant)
                if grant.use_grant_id() == active_id
        ));
        assert_eq!(
            BrokerUseGrantManager::status_for_consumer(
                &state,
                other.consumer_id(),
                active_id,
                timestamp(40),
            )
            .expect("foreign status"),
            BrokerConsumerUseGrantStatus::Unavailable
        );
        assert!(!BrokerUseGrantManager::revoke_for_consumer(
            &state,
            other.consumer_id(),
            active_id,
        )
        .expect("foreign revoke"));
        assert!(
            BrokerUseGrantManager::revoke_for_consumer(&state, owner.consumer_id(), active_id,)
                .expect("owner revoke")
        );
        assert_eq!(
            BrokerUseGrantManager::status_for_consumer(
                &state,
                owner.consumer_id(),
                active_id,
                timestamp(41),
            )
            .expect("revoked status"),
            BrokerConsumerUseGrantStatus::Unavailable
        );

        let expired = BrokerUseGrantManager::issue_allow_once(
            &state,
            allow_once(
                owner_target,
                SecretFieldKind::ApiToken,
                vault_session_id,
                50,
                60,
            ),
        )
        .expect("expired grant");
        let expired_id = expired.grant().use_grant_id();
        assert_eq!(
            BrokerUseGrantManager::status_for_consumer(
                &state,
                owner.consumer_id(),
                expired_id,
                timestamp(60),
            )
            .expect("expired status"),
            BrokerConsumerUseGrantStatus::Expired
        );
        assert_eq!(
            BrokerUseGrantManager::status_for_consumer(
                &state,
                owner.consumer_id(),
                expired_id,
                timestamp(61),
            )
            .expect("pruned status"),
            BrokerConsumerUseGrantStatus::Unavailable
        );
        assert!(state
            .use_grants_for_consumer(owner.consumer_id())
            .expect("owner grants")
            .is_empty());
    }
}
