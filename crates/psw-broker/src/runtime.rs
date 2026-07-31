use std::fmt::{Debug, Display, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use psw_core::{SecretFieldKind, VaultId};

use crate::access_rule::{
    BrokerAccessRuleApproval, BrokerAccessRuleCreation, BrokerAccessRuleError,
    BrokerAccessRuleEvaluation, BrokerAccessRuleManager,
};
use crate::approval::{
    BrokerApprovalDecision, BrokerApprovalError, BrokerApprovalManager, BrokerApprovalReceipt,
    BrokerApprovalRestoreSummary, BrokerApprovalSubmission, BrokerApprovalWaitOutcome,
    BrokerHumanApprovalSnapshot, MAX_APPROVAL_LIFETIME,
};
use crate::audit::{
    BrokerAuditClearConfirmation, BrokerAuditClearSummary, BrokerAuditCursor, BrokerAuditError,
    BrokerAuditExport, BrokerAuditFilter, BrokerAuditManager, BrokerAuditPage,
};
use crate::authentication::{
    BrokerAuthenticationChallenge, BrokerAuthenticationCompletion, BrokerAuthenticationError,
    BrokerAuthenticationManager, AUTHENTICATION_PROOF_LENGTH,
};
use crate::credential_matching::{
    BrokerAdmittedCredentialRequest, BrokerApprovedCredentialSelection,
    BrokerCredentialCandidateSelection, BrokerCredentialMatchingError,
    BrokerCredentialMatchingManager, BrokerHumanCredentialReview, BrokerNewCredentialRequest,
};
use crate::credential_search::{
    BrokerCredentialSearchError, BrokerCredentialSearchManager, BrokerCredentialSearchQuery,
    BrokerCredentialSearchResult,
};
use crate::device_key::{DeviceKeyError, DeviceKeyManager, DeviceKeyStore};
use crate::grant_invalidation::{
    BrokerGrantInvalidationError, BrokerGrantInvalidationSummary, BrokerGrantInvalidator,
};
use crate::http_request::{
    BrokerHttpRequest, BrokerHttpRequestError, BrokerHttpRequestManager, BrokerHttpResponse,
    BrokerHttpTransport, UreqHttpTransport,
};
use crate::human_control::{
    BrokerAppsToolsSnapshot, BrokerConsumerDetail, BrokerHumanControlError,
    BrokerHumanControlManager, BrokerPendingRequestId, BrokerPendingRequestQueue,
};
use crate::local_data::{BrokerLocalDataError, BrokerLocalDataManager};
use crate::machine_access::{
    BrokerMachineAccessError, BrokerMachineAccessGate, BrokerMachineAccessTransition,
};
use crate::outbound_operation::{
    BrokerOutboundOperationAuthorization, BrokerOutboundOperationError,
    BrokerOutboundOperationManager, BrokerOutboundOperationOutcome,
};
use crate::pairing::{
    BrokerConsumerPairingProgress, BrokerPairingChallenge, BrokerPairingCompletion,
    BrokerPairingError, BrokerPairingManager, BrokerPairingProofChallenge,
    BrokerPairingRequestSnapshot, BrokerPairingUserApproval, ConsumerPairingProposal,
    PAIRING_PROOF_LENGTH, PAIRING_PUBLIC_KEY_LENGTH,
};
use crate::paths::{DevicePathError, DevicePaths};
use crate::process::BrokerProcess;
use crate::process_run::{
    BrokerProcessRunCancellation, BrokerProcessRunError, BrokerProcessRunManager,
    BrokerProcessRunRequest, BrokerProcessRunResponse,
};
use crate::protocol::{BrokerProtocolVersion, BrokerSessionId};
use crate::revocation::{BrokerRevocationError, BrokerRevocationManager, BrokerRevocationSummary};
use crate::state_model::{
    ApprovalRequestId, ApprovalStatus, ApprovalSubject, AuditDecision, AuditEventId,
    AuthorizationTarget, ConfirmationPolicy, ConsumerId, CredentialFieldScope,
    ObservedConsumerIdentity, PairingRequestId, RuleLifetime, StateTimestamp, UsageProfile,
    UsageProfileDefinition, UsageProfileId, UseGrantId, VaultSessionId,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};
use crate::usage_profile::{BrokerUsageProfileError, BrokerUsageProfileManager};
use crate::use_grant::{
    BrokerAllowOnceApproval, BrokerAuthorizedGrantUse, BrokerConsumerUseGrantStatus,
    BrokerRuleUseApproval, BrokerUseGrantError, BrokerUseGrantIssuance, BrokerUseGrantManager,
};
use crate::vault_session::BrokerVaultSessionError;

/// Sanitized failure while assembling or shutting down one Broker runtime.
#[derive(Debug)]
pub enum BrokerRuntimeError {
    /// Canonical current-user device paths could not be prepared safely.
    DevicePaths(DevicePathError),
    /// Preserved Keychain or encrypted state could not be opened.
    LocalData(BrokerLocalDataError),
    /// Stale or ending grants could not be removed transactionally.
    GrantInvalidation(BrokerGrantInvalidationError),
    /// Persisted machine-access state could not be loaded or changed.
    MachineAccess(BrokerMachineAccessError),
    /// Process-local Consumer pairing state could not be accessed safely.
    Pairing(BrokerPairingError),
    /// Paired-Consumer connection authentication failed safely.
    Authentication(BrokerAuthenticationError),
    /// Field-scoped Access Rule state could not be created or evaluated.
    AccessRule(BrokerAccessRuleError),
    /// Bounded Use Grant state could not be issued or authorized.
    UseGrant(BrokerUseGrantError),
    /// Authorized credential metadata could not be searched safely.
    CredentialSearch(BrokerCredentialSearchError),
    /// A new credential request could not be matched in the human control plane.
    CredentialMatching(BrokerCredentialMatchingError),
    /// Asynchronous approval state could not be restored or changed.
    Approval(BrokerApprovalError),
    /// Explicit Apps & Tools authorization could not be revoked completely.
    Revocation(BrokerRevocationError),
    /// Encrypted device-local audit viewing, retention, clearing, or export failed.
    Audit(BrokerAuditError),
    /// Trusted local Apps & Tools management state could not be projected.
    HumanControl(BrokerHumanControlError),
    /// A Consumer-owned declarative Usage Profile could not be changed.
    UsageProfile(BrokerUsageProfileError),
    /// An explicit brokered HTTP request failed without exposing operation material.
    HttpRequest(BrokerHttpRequestError),
    /// An explicit brokered child-process operation failed without exposing operation material.
    ProcessRun(BrokerProcessRunError),
    /// An explicit credential-bearing operation could not be attributed safely.
    OutboundOperation(BrokerOutboundOperationError),
    /// The process-owned vault-session worker could not start.
    VaultSession(BrokerVaultSessionError),
    /// The wall clock could not produce a canonical device-state timestamp.
    ClockUnavailable,
}

impl Display for BrokerRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DevicePaths(source) => write!(formatter, "Broker path startup failed: {source}"),
            Self::LocalData(source) => {
                write!(formatter, "Broker local-data startup failed: {source}")
            }
            Self::GrantInvalidation(source) => {
                write!(formatter, "Broker grant lifecycle failed: {source}")
            }
            Self::MachineAccess(source) => {
                write!(formatter, "Broker machine-access startup failed: {source}")
            }
            Self::Pairing(source) => write!(formatter, "Broker pairing lifecycle failed: {source}"),
            Self::Authentication(source) => {
                write!(
                    formatter,
                    "Broker authentication lifecycle failed: {source}"
                )
            }
            Self::AccessRule(source) => {
                write!(formatter, "Broker Access Rule lifecycle failed: {source}")
            }
            Self::UseGrant(source) => {
                write!(formatter, "Broker Use Grant lifecycle failed: {source}")
            }
            Self::CredentialSearch(source) => {
                write!(formatter, "Broker credential search failed: {source}")
            }
            Self::CredentialMatching(source) => {
                write!(formatter, "Broker credential matching failed: {source}")
            }
            Self::Approval(source) => {
                write!(formatter, "Broker approval lifecycle failed: {source}")
            }
            Self::Revocation(source) => {
                write!(formatter, "Broker revocation lifecycle failed: {source}")
            }
            Self::Audit(source) => write!(formatter, "Broker audit failed: {source}"),
            Self::HumanControl(source) => {
                write!(formatter, "Broker human control failed: {source}")
            }
            Self::UsageProfile(source) => {
                write!(formatter, "Broker Usage Profile operation failed: {source}")
            }
            Self::HttpRequest(source) => write!(formatter, "Broker HTTP request failed: {source}"),
            Self::ProcessRun(source) => {
                write!(formatter, "Broker child-process operation failed: {source}")
            }
            Self::OutboundOperation(source) => {
                write!(formatter, "Broker outbound operation failed: {source}")
            }
            Self::VaultSession(source) => {
                write!(formatter, "Broker vault-session startup failed: {source}")
            }
            Self::ClockUnavailable => formatter.write_str("Broker system clock is unavailable"),
        }
    }
}

impl std::error::Error for BrokerRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DevicePaths(source) => Some(source),
            Self::LocalData(source) => Some(source),
            Self::GrantInvalidation(source) => Some(source),
            Self::MachineAccess(source) => Some(source),
            Self::Pairing(source) => Some(source),
            Self::Authentication(source) => Some(source),
            Self::AccessRule(source) => Some(source),
            Self::UseGrant(source) => Some(source),
            Self::CredentialSearch(source) => Some(source),
            Self::CredentialMatching(source) => Some(source),
            Self::Approval(source) => Some(source),
            Self::Revocation(source) => Some(source),
            Self::Audit(source) => Some(source),
            Self::HumanControl(source) => Some(source),
            Self::UsageProfile(source) => Some(source),
            Self::HttpRequest(source) => Some(source),
            Self::ProcessRun(source) => Some(source),
            Self::OutboundOperation(source) => Some(source),
            Self::VaultSession(source) => Some(source),
            Self::ClockUnavailable => None,
        }
    }
}

/// Fully assembled local Broker foundation before a listener is exposed.
///
/// Startup authenticates preserved device state, loads the fail-closed machine
/// gate, deletes grants tied to sessions from an earlier process, and only then
/// creates a new process core. The installed service and listener loop remain
/// separate packaging boundaries.
pub struct BrokerRuntime {
    paths: DevicePaths,
    state: DeviceStateStore,
    machine_access: BrokerMachineAccessGate,
    pairing: BrokerPairingManager,
    authentication: BrokerAuthenticationManager,
    approvals: BrokerApprovalManager,
    process: BrokerProcess,
    stale_use_grants_removed: usize,
    approval_restore_summary: BrokerApprovalRestoreSummary,
}

impl BrokerRuntime {
    /// Opens or initializes the current user's device-local Broker state.
    ///
    /// Initialization occurs only when both the device key and every managed
    /// encrypted-state file are absent. Any one-sided or incomplete state
    /// fails closed without replacing preserved authority.
    pub fn open_or_initialize_for_current_user<S>(store: S) -> Result<Self, BrokerRuntimeError>
    where
        S: DeviceKeyStore,
    {
        let paths =
            DevicePaths::prepare_for_current_user().map_err(BrokerRuntimeError::DevicePaths)?;
        let observed_at = current_state_timestamp()?;
        Self::open_or_initialize_with_paths_at(paths, store, observed_at)
    }

    /// Reopens the current user's preserved Broker state.
    ///
    /// This method prepares canonical paths from the operating-system account
    /// database. It never initializes a missing key or database.
    pub fn reopen_existing_for_current_user<S>(store: S) -> Result<Self, BrokerRuntimeError>
    where
        S: DeviceKeyStore,
    {
        let paths =
            DevicePaths::prepare_for_current_user().map_err(BrokerRuntimeError::DevicePaths)?;
        Self::reopen_with_paths(paths, store)
    }

    pub(crate) fn reopen_with_paths<S>(
        paths: DevicePaths,
        store: S,
    ) -> Result<Self, BrokerRuntimeError>
    where
        S: DeviceKeyStore,
    {
        let observed_at = current_state_timestamp()?;
        Self::reopen_with_paths_at(paths, store, observed_at)
    }

    pub(crate) fn reopen_with_paths_at<S>(
        paths: DevicePaths,
        store: S,
        observed_at: StateTimestamp,
    ) -> Result<Self, BrokerRuntimeError>
    where
        S: DeviceKeyStore,
    {
        let local_data = BrokerLocalDataManager::new(store);
        let state = local_data
            .reopen_after_reinstall(&paths)
            .map_err(BrokerRuntimeError::LocalData)?;
        Self::assemble(paths, state, observed_at)
    }

    pub(crate) fn open_or_initialize_with_paths_at<S>(
        paths: DevicePaths,
        store: S,
        observed_at: StateTimestamp,
    ) -> Result<Self, BrokerRuntimeError>
    where
        S: DeviceKeyStore,
    {
        let has_managed_state = DeviceStateStore::has_managed_state(&paths)
            .map_err(BrokerLocalDataError::DeviceState)
            .map_err(BrokerRuntimeError::LocalData)?;
        let key_manager = DeviceKeyManager::new(store);
        let state = match key_manager.load_existing() {
            Ok(root_key) => {
                if !has_managed_state {
                    return Err(BrokerRuntimeError::LocalData(
                        BrokerLocalDataError::DeviceState(DeviceStateError::Missing),
                    ));
                }
                DeviceStateStore::open_existing(&paths, &root_key)
                    .map_err(BrokerLocalDataError::DeviceState)
                    .map_err(BrokerRuntimeError::LocalData)?
            }
            Err(DeviceKeyError::Missing) if has_managed_state => {
                return Err(BrokerRuntimeError::LocalData(
                    BrokerLocalDataError::DeviceKey(DeviceKeyError::Missing),
                ));
            }
            Err(DeviceKeyError::Missing) => {
                let root_key = key_manager
                    .initialize_new()
                    .map_err(BrokerLocalDataError::DeviceKey)
                    .map_err(BrokerRuntimeError::LocalData)?;
                match DeviceStateStore::initialize_new(&paths, &root_key, observed_at) {
                    Ok(state) => state,
                    Err(source) => {
                        key_manager
                            .delete_existing()
                            .map_err(BrokerLocalDataError::DeviceKey)
                            .map_err(BrokerRuntimeError::LocalData)?;
                        return Err(BrokerRuntimeError::LocalData(
                            BrokerLocalDataError::DeviceState(source),
                        ));
                    }
                }
            }
            Err(source) => {
                return Err(BrokerRuntimeError::LocalData(
                    BrokerLocalDataError::DeviceKey(source),
                ));
            }
        };
        Self::assemble(paths, state, observed_at)
    }

    fn assemble(
        paths: DevicePaths,
        mut state: DeviceStateStore,
        observed_at: StateTimestamp,
    ) -> Result<Self, BrokerRuntimeError> {
        state
            .enforce_audit_retention(observed_at)
            .map_err(BrokerAuditError::from)
            .map_err(BrokerRuntimeError::Audit)?;
        let machine_access = BrokerMachineAccessGate::from_device_state(&state)
            .map_err(BrokerRuntimeError::MachineAccess)?;
        let stale_use_grants_removed =
            BrokerGrantInvalidator::invalidate_stale_grants_on_startup(&mut state)
                .map_err(BrokerRuntimeError::GrantInvalidation)?;
        let (approvals, approval_restore_summary) =
            BrokerApprovalManager::restore(&state, observed_at)
                .map_err(BrokerRuntimeError::Approval)?;
        let pairing = BrokerPairingManager::new();
        let authentication = BrokerAuthenticationManager::new();
        let process = BrokerProcess::new().map_err(BrokerRuntimeError::VaultSession)?;
        Ok(Self {
            paths,
            state,
            machine_access,
            pairing,
            authentication,
            approvals,
            process,
            stale_use_grants_removed,
            approval_restore_summary,
        })
    }

    /// Returns canonical device-local paths used by this runtime.
    #[must_use]
    pub const fn paths(&self) -> &DevicePaths {
        &self.paths
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn device_state(&self) -> &DeviceStateStore {
        &self.state
    }

    /// Returns the process-local Apps & Tools gate.
    #[must_use]
    pub const fn machine_access(&self) -> &BrokerMachineAccessGate {
        &self.machine_access
    }

    /// Returns the transport-independent process core.
    #[must_use]
    pub const fn process(&self) -> &BrokerProcess {
        &self.process
    }

    /// Returns grants discarded because their process-owned sessions ended.
    #[must_use]
    pub const fn stale_use_grants_removed(&self) -> usize {
        self.stale_use_grants_removed
    }

    /// Returns approval records reconciled during this process startup.
    #[must_use]
    pub const fn approval_restore_summary(&self) -> BrokerApprovalRestoreSummary {
        self.approval_restore_summary
    }

    /// Returns secret-free Apps & Tools state for one trusted human Vault view.
    pub fn apps_tools_snapshot(
        &self,
        vault_id: psw_core::VaultId,
    ) -> Result<BrokerAppsToolsSnapshot, BrokerRuntimeError> {
        let observed_at = current_state_timestamp()?;
        BrokerHumanControlManager::snapshot(&self.state, vault_id, observed_at)
            .map_err(BrokerRuntimeError::HumanControl)
    }

    /// Returns bounded secret-free detail for one paired Consumer.
    pub fn apps_tools_consumer_detail(
        &self,
        consumer_id: ConsumerId,
    ) -> Result<BrokerConsumerDetail, BrokerRuntimeError> {
        let observed_at = current_state_timestamp()?;
        BrokerHumanControlManager::consumer_detail(&self.state, consumer_id, observed_at)
            .map_err(BrokerRuntimeError::HumanControl)
    }

    /// Creates one validated Consumer-owned Usage Profile in encrypted state.
    pub fn create_usage_profile(
        &mut self,
        consumer_id: ConsumerId,
        label: String,
        definition: UsageProfileDefinition,
    ) -> Result<UsageProfile, BrokerRuntimeError> {
        let created_at = current_state_timestamp()?;
        BrokerUsageProfileManager::create(&self.state, consumer_id, label, definition, created_at)
            .map_err(BrokerRuntimeError::UsageProfile)
    }

    /// Removes one exact Consumer-owned Usage Profile idempotently.
    pub fn remove_usage_profile(
        &mut self,
        consumer_id: ConsumerId,
        usage_profile_id: UsageProfileId,
    ) -> Result<bool, BrokerRuntimeError> {
        BrokerUsageProfileManager::remove(&self.state, consumer_id, usage_profile_id)
            .map_err(BrokerRuntimeError::UsageProfile)
    }

    /// Returns one bounded newest-first audit page to the trusted local control plane.
    pub fn view_audit(
        &self,
        filter: BrokerAuditFilter,
        cursor: Option<BrokerAuditCursor>,
        limit: usize,
    ) -> Result<BrokerAuditPage, BrokerRuntimeError> {
        let observed_at = current_state_timestamp()?;
        self.view_audit_at(filter, cursor, limit, observed_at)
    }

    pub(crate) fn view_audit_at(
        &self,
        filter: BrokerAuditFilter,
        cursor: Option<BrokerAuditCursor>,
        limit: usize,
        observed_at: StateTimestamp,
    ) -> Result<BrokerAuditPage, BrokerRuntimeError> {
        BrokerAuditManager::view(&self.state, filter, cursor, limit, observed_at)
            .map_err(BrokerRuntimeError::Audit)
    }

    /// Clears exactly the confirmed local audit selection without changing a Vault.
    pub fn clear_audit(
        &self,
        filter: BrokerAuditFilter,
        confirmation: BrokerAuditClearConfirmation,
    ) -> Result<BrokerAuditClearSummary, BrokerRuntimeError> {
        BrokerAuditManager::clear(&self.state, filter, confirmation)
            .map_err(BrokerRuntimeError::Audit)
    }

    /// Builds one versioned non-secret JSON audit export for local troubleshooting.
    pub fn export_audit_json(
        &self,
        filter: BrokerAuditFilter,
    ) -> Result<BrokerAuditExport, BrokerRuntimeError> {
        let generated_at = current_state_timestamp()?;
        self.export_audit_json_at(filter, generated_at)
    }

    pub(crate) fn export_audit_json_at(
        &self,
        filter: BrokerAuditFilter,
        generated_at: StateTimestamp,
    ) -> Result<BrokerAuditExport, BrokerRuntimeError> {
        BrokerAuditManager::export_json(&self.state, filter, generated_at)
            .map_err(BrokerRuntimeError::Audit)
    }

    /// Starts a bounded Consumer pairing without granting credential access.
    pub fn begin_pairing(
        &self,
        proposal: ConsumerPairingProposal,
        observed_identity: ObservedConsumerIdentity,
    ) -> Result<BrokerPairingChallenge, BrokerRuntimeError> {
        self.pairing
            .begin_pairing(&self.state, proposal, observed_identity)
            .map_err(BrokerRuntimeError::Pairing)
    }

    /// Starts or resumes a pairing without exposing trusted App metadata.
    pub fn begin_or_resume_pairing(
        &self,
        proposal: ConsumerPairingProposal,
        observed_identity: ObservedConsumerIdentity,
    ) -> Result<BrokerConsumerPairingProgress, BrokerRuntimeError> {
        self.pairing
            .begin_or_resume_pairing(&self.state, proposal, observed_identity)
            .map_err(BrokerRuntimeError::Pairing)
    }

    /// Polls resumable pairing state for the exact pending identity and key.
    pub fn pairing_progress(
        &self,
        pairing_request_id: PairingRequestId,
        pairing_public_key: &[u8; PAIRING_PUBLIC_KEY_LENGTH],
    ) -> Result<BrokerConsumerPairingProgress, BrokerRuntimeError> {
        self.pairing
            .pairing_progress(&self.state, pairing_request_id, pairing_public_key)
            .map_err(BrokerRuntimeError::Pairing)
    }

    /// Lists pending pairing requests for the trusted local control plane.
    pub fn pending_pairings(
        &self,
    ) -> Result<Vec<BrokerPairingRequestSnapshot>, BrokerRuntimeError> {
        self.pairing
            .pending_requests()
            .map_err(BrokerRuntimeError::Pairing)
    }

    /// Applies one explicit local user decision to a pending pairing.
    pub fn approve_pairing(
        &self,
        pairing_request_id: PairingRequestId,
        approval: BrokerPairingUserApproval,
    ) -> Result<BrokerPairingProofChallenge, BrokerRuntimeError> {
        self.pairing
            .approve_pairing(pairing_request_id, approval)
            .map_err(BrokerRuntimeError::Pairing)
    }

    /// Denies and consumes one pending pairing without changing authorization.
    pub fn deny_pairing(
        &self,
        pairing_request_id: PairingRequestId,
    ) -> Result<(), BrokerRuntimeError> {
        self.pairing
            .deny_pairing(pairing_request_id)
            .map_err(BrokerRuntimeError::Pairing)
    }

    /// Activates a proved Consumer while leaving authorization unchanged.
    pub fn complete_pairing(
        &self,
        pairing_request_id: PairingRequestId,
        proof: [u8; PAIRING_PROOF_LENGTH],
    ) -> Result<BrokerPairingCompletion, BrokerRuntimeError> {
        self.pairing
            .complete_pairing(&self.state, pairing_request_id, proof)
            .map_err(BrokerRuntimeError::Pairing)
    }

    /// Issues a fresh connection-bound challenge for an active Consumer.
    pub fn begin_authentication(
        &self,
        consumer_id: ConsumerId,
        selected_protocol: BrokerProtocolVersion,
    ) -> Result<BrokerAuthenticationChallenge, BrokerRuntimeError> {
        let occurred_at = current_state_timestamp()?;
        self.authentication
            .begin(&self.state, consumer_id, selected_protocol, occurred_at)
            .map_err(BrokerRuntimeError::Authentication)
    }

    /// Consumes and verifies one connection-bound authentication challenge.
    pub fn complete_authentication(
        &self,
        challenge: BrokerAuthenticationChallenge,
        session_id: BrokerSessionId,
        consumer_id: ConsumerId,
        proof: [u8; AUTHENTICATION_PROOF_LENGTH],
    ) -> Result<BrokerAuthenticationCompletion, BrokerRuntimeError> {
        let occurred_at = current_state_timestamp()?;
        self.authentication
            .complete(
                &self.state,
                challenge,
                session_id,
                consumer_id,
                proof,
                occurred_at,
            )
            .map_err(BrokerRuntimeError::Authentication)
    }

    /// Creates one explicitly approved field-scoped Access Rule.
    ///
    /// This human control-plane operation remains available while machine
    /// access is paused and does not issue a Use Grant.
    pub fn create_access_rule(
        &self,
        approval: BrokerAccessRuleApproval,
    ) -> Result<BrokerAccessRuleCreation, BrokerRuntimeError> {
        BrokerAccessRuleManager::create_rule(&self.state, approval)
            .map_err(BrokerRuntimeError::AccessRule)
    }

    /// Matches one machine request against an exact active Access Rule.
    ///
    /// The global pause gate is checked first. A matching rule still requires
    /// the separate Use Grant lifecycle.
    pub fn evaluate_access_rule(
        &self,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        evaluated_at: StateTimestamp,
    ) -> Result<BrokerAccessRuleEvaluation, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        BrokerAccessRuleManager::evaluate_rule(&self.state, target, secret_kind, evaluated_at)
            .map_err(BrokerRuntimeError::AccessRule)
    }

    /// Issues one user-approved operation grant without creating an Access Rule.
    ///
    /// This is a human control-plane action and remains available while Apps &
    /// Tools are paused. The approved vault session must still be current.
    pub fn issue_allow_once_grant(
        &self,
        approval: BrokerAllowOnceApproval,
    ) -> Result<BrokerUseGrantIssuance, BrokerRuntimeError> {
        let target = approval.target();
        let vault_session_id = approval.vault_session_id();
        self.require_current_vault_session(target, vault_session_id)
            .map_err(BrokerRuntimeError::UseGrant)?;
        let issuance = BrokerUseGrantManager::issue_allow_once(&self.state, approval)
            .map_err(BrokerRuntimeError::UseGrant)?;
        self.verify_issued_grant_session(issuance, target, vault_session_id)
    }

    /// Issues a user-confirmed grant from an active Access Rule.
    ///
    /// `every-use` rules issue one-operation grants. `once-per-unlock-session`
    /// rules issue or reuse one grant for the exact current unlock session.
    pub fn issue_confirmed_rule_grant(
        &self,
        approval: BrokerRuleUseApproval,
    ) -> Result<BrokerUseGrantIssuance, BrokerRuntimeError> {
        let target = approval.target();
        let vault_session_id = approval.vault_session_id();
        self.require_current_vault_session(target, vault_session_id)
            .map_err(BrokerRuntimeError::UseGrant)?;
        let issuance = BrokerUseGrantManager::issue_confirmed_rule(&self.state, approval)
            .map_err(BrokerRuntimeError::UseGrant)?;
        self.verify_issued_grant_session(issuance, target, vault_session_id)
    }

    /// Issues or reuses a current-session grant from an automatic Access Rule.
    ///
    /// The global machine-access pause gate is checked before session or
    /// authorization state.
    pub fn issue_automatic_rule_grant(
        &self,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        issued_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<BrokerUseGrantIssuance, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        BrokerUseGrantManager::preflight_automatic_rule(
            &self.state,
            target,
            secret_kind,
            issued_at,
        )
        .map_err(BrokerRuntimeError::UseGrant)?;
        self.require_current_vault_session(target, vault_session_id)
            .map_err(BrokerRuntimeError::UseGrant)?;
        let issuance = BrokerUseGrantManager::issue_automatic_rule(
            &self.state,
            target,
            secret_kind,
            vault_session_id,
            issued_at,
            expires_at,
        )
        .map_err(BrokerRuntimeError::UseGrant)?;
        self.verify_issued_grant_session(issuance, target, vault_session_id)
    }

    /// Authorizes one exact internal operation with a Consumer-bound Use Grant.
    ///
    /// One-operation grants are atomically consumed. Unlock-session grants
    /// remain reusable only for the exact current unlock-session identity.
    /// External outbound executors must use the attributed begin/finish API.
    #[cfg(test)]
    pub(crate) fn authorize_use_grant(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        evaluated_at: StateTimestamp,
    ) -> Result<BrokerAuthorizedGrantUse, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        self.authorize_use_grant_after_gate(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            evaluated_at,
        )
    }

    /// Authorizes and attributes one explicit HTTP or child-process operation.
    ///
    /// A pending encrypted audit event is committed before the returned opaque
    /// authorization may be used. Denied and paused attempts are also audited.
    /// No destination or operation payload is accepted by this boundary.
    pub fn begin_outbound_credential_operation(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
    ) -> Result<BrokerOutboundOperationAuthorization, BrokerRuntimeError> {
        let evaluated_at = current_state_timestamp()?;
        self.begin_outbound_credential_operation_at(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            evaluated_at,
        )
    }

    pub(crate) fn begin_outbound_credential_operation_at(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        evaluated_at: StateTimestamp,
    ) -> Result<BrokerOutboundOperationAuthorization, BrokerRuntimeError> {
        self.authorize_outbound_machine_gate_at(target, use_grant_id, evaluated_at)?;
        self.begin_outbound_credential_operation_after_gate_at(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            evaluated_at,
        )
    }

    fn authorize_outbound_machine_gate_at(
        &self,
        target: AuthorizationTarget,
        use_grant_id: UseGrantId,
        evaluated_at: StateTimestamp,
    ) -> Result<(), BrokerRuntimeError> {
        BrokerOutboundOperationManager::validate_target(target)
            .map_err(BrokerRuntimeError::OutboundOperation)?;
        if let Err(error) = self
            .machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)
        {
            let decision = if matches!(
                &error,
                BrokerRuntimeError::MachineAccess(BrokerMachineAccessError::Paused)
            ) {
                AuditDecision::Paused
            } else {
                AuditDecision::Denied
            };
            BrokerOutboundOperationManager::record_denied(
                &self.state,
                target,
                use_grant_id,
                decision,
                evaluated_at,
            )
            .map_err(BrokerRuntimeError::OutboundOperation)?;
            return Err(error);
        }
        Ok(())
    }

    fn begin_outbound_credential_operation_after_gate_at(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        evaluated_at: StateTimestamp,
    ) -> Result<BrokerOutboundOperationAuthorization, BrokerRuntimeError> {
        let authorized = match self.authorize_use_grant_after_gate(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            evaluated_at,
        ) {
            Ok(authorized) => authorized,
            Err(error) => {
                BrokerOutboundOperationManager::record_denied(
                    &self.state,
                    target,
                    use_grant_id,
                    AuditDecision::Denied,
                    evaluated_at,
                )
                .map_err(BrokerRuntimeError::OutboundOperation)?;
                return Err(error);
            }
        };
        BrokerOutboundOperationManager::begin(&self.state, authorized, evaluated_at)
            .map_err(BrokerRuntimeError::OutboundOperation)
    }

    /// Finalizes one explicit outbound operation with a non-secret outcome.
    ///
    /// Consuming the opaque authorization prevents one execution path from
    /// recording more than one final outcome through this API.
    pub fn finish_outbound_credential_operation(
        &self,
        authorization: BrokerOutboundOperationAuthorization,
        outcome: BrokerOutboundOperationOutcome,
    ) -> Result<AuditEventId, BrokerRuntimeError> {
        let completed_at = current_state_timestamp()?;
        self.finish_outbound_credential_operation_at(authorization, outcome, completed_at)
    }

    pub(crate) fn finish_outbound_credential_operation_at(
        &self,
        authorization: BrokerOutboundOperationAuthorization,
        outcome: BrokerOutboundOperationOutcome,
        completed_at: StateTimestamp,
    ) -> Result<AuditEventId, BrokerRuntimeError> {
        BrokerOutboundOperationManager::finish(&self.state, authorization, outcome, completed_at)
            .map_err(BrokerRuntimeError::OutboundOperation)
    }

    /// Performs one explicitly authorized HTTPS request inside the Broker.
    ///
    /// The selected Consumer-owned Usage Profile controls credential placement.
    /// The request never receives the secret, redirects are not followed, and
    /// the returned bounded body has exact secret echoes replaced.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_http_request(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        usage_profile_id: UsageProfileId,
        request: BrokerHttpRequest,
    ) -> Result<BrokerHttpResponse, BrokerRuntimeError> {
        let started_at = current_state_timestamp()?;
        self.execute_http_request_with_transport(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            usage_profile_id,
            request,
            &UreqHttpTransport,
            started_at,
            None,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_http_request_with_transport_at<T>(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        usage_profile_id: UsageProfileId,
        request: BrokerHttpRequest,
        transport: &T,
        started_at: StateTimestamp,
        completed_at: StateTimestamp,
    ) -> Result<BrokerHttpResponse, BrokerRuntimeError>
    where
        T: BrokerHttpTransport,
    {
        self.execute_http_request_with_transport(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            usage_profile_id,
            request,
            transport,
            started_at,
            Some(completed_at),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_http_request_with_transport<T>(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        usage_profile_id: UsageProfileId,
        request: BrokerHttpRequest,
        transport: &T,
        started_at: StateTimestamp,
        completed_at: Option<StateTimestamp>,
    ) -> Result<BrokerHttpResponse, BrokerRuntimeError>
    where
        T: BrokerHttpTransport,
    {
        if target.capability().name() != crate::state_model::CapabilityName::HttpRequest
            || target.capability().version() != 1
        {
            return Err(BrokerRuntimeError::HttpRequest(
                BrokerHttpRequestError::UnsupportedPlacement,
            ));
        }
        self.authorize_outbound_machine_gate_at(target, use_grant_id, started_at)?;
        let profile = BrokerUsageProfileManager::resolve_for_operation(
            &self.state,
            target.consumer_id(),
            usage_profile_id,
            target.capability(),
        )
        .map_err(BrokerRuntimeError::UsageProfile)?;
        let authorization = self.begin_outbound_credential_operation_after_gate_at(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            started_at,
        )?;

        let operation_result = (|| {
            let scope = target.field_scope();
            let secret = self
                .process
                .vault_sessions()
                .credential_secret_field(
                    scope.vault_id(),
                    vault_session_id,
                    scope.credential_id(),
                    scope.secret_field_id(),
                    secret_kind,
                )
                .map_err(BrokerRuntimeError::VaultSession)?
                .ok_or(BrokerRuntimeError::HttpRequest(
                    BrokerHttpRequestError::SecretUnavailable,
                ))?;
            BrokerHttpRequestManager::execute(transport, &request, profile.placement(), &secret)
                .map_err(BrokerRuntimeError::HttpRequest)
        })();

        let outcome = if operation_result.is_ok() {
            BrokerOutboundOperationOutcome::Succeeded
        } else {
            BrokerOutboundOperationOutcome::Failed
        };
        let completed_at =
            completed_at.unwrap_or_else(|| current_state_timestamp().unwrap_or(started_at));
        self.finish_outbound_credential_operation_at(authorization, outcome, completed_at)?;
        operation_result
    }

    /// Performs one explicitly authorized direct child-process operation.
    ///
    /// The selected Consumer-owned Usage Profile controls the only secret
    /// placement. The Broker clears inherited environment state, never inserts
    /// a shell, captures both output streams, and replaces exact secret echoes
    /// before returning bounded output.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_process_run(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        usage_profile_id: UsageProfileId,
        request: BrokerProcessRunRequest,
    ) -> Result<BrokerProcessRunResponse, BrokerRuntimeError> {
        self.execute_process_run_with_cancellation(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            usage_profile_id,
            request,
            &BrokerProcessRunCancellation::default(),
        )
    }

    /// Performs one authorized child-process operation with cooperative
    /// cancellation controlled by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_process_run_with_cancellation(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        usage_profile_id: UsageProfileId,
        request: BrokerProcessRunRequest,
        cancellation: &BrokerProcessRunCancellation,
    ) -> Result<BrokerProcessRunResponse, BrokerRuntimeError> {
        let started_at = current_state_timestamp()?;
        self.execute_process_run_at(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            usage_profile_id,
            request,
            cancellation,
            started_at,
            None,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_process_run_with_timestamps(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        usage_profile_id: UsageProfileId,
        request: BrokerProcessRunRequest,
        cancellation: &BrokerProcessRunCancellation,
        started_at: StateTimestamp,
        completed_at: StateTimestamp,
    ) -> Result<BrokerProcessRunResponse, BrokerRuntimeError> {
        self.execute_process_run_at(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            usage_profile_id,
            request,
            cancellation,
            started_at,
            Some(completed_at),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_process_run_at(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        usage_profile_id: UsageProfileId,
        request: BrokerProcessRunRequest,
        cancellation: &BrokerProcessRunCancellation,
        started_at: StateTimestamp,
        completed_at: Option<StateTimestamp>,
    ) -> Result<BrokerProcessRunResponse, BrokerRuntimeError> {
        if target.capability().name() != crate::state_model::CapabilityName::ProcessRun
            || target.capability().version() != 1
        {
            return Err(BrokerRuntimeError::ProcessRun(
                BrokerProcessRunError::UnsupportedPlacement,
            ));
        }
        self.authorize_outbound_machine_gate_at(target, use_grant_id, started_at)?;
        let profile = BrokerUsageProfileManager::resolve_for_operation(
            &self.state,
            target.consumer_id(),
            usage_profile_id,
            target.capability(),
        )
        .map_err(BrokerRuntimeError::UsageProfile)?;
        let authorization = self.begin_outbound_credential_operation_after_gate_at(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            started_at,
        )?;

        let operation_result = (|| {
            let scope = target.field_scope();
            let secret = self
                .process
                .vault_sessions()
                .credential_secret_field(
                    scope.vault_id(),
                    vault_session_id,
                    scope.credential_id(),
                    scope.secret_field_id(),
                    secret_kind,
                )
                .map_err(BrokerRuntimeError::VaultSession)?
                .ok_or(BrokerRuntimeError::ProcessRun(
                    BrokerProcessRunError::SecretUnavailable,
                ))?;
            BrokerProcessRunManager::execute(&request, profile.placement(), &secret, cancellation)
                .map_err(BrokerRuntimeError::ProcessRun)
        })();

        let outcome = if operation_result.is_ok() {
            BrokerOutboundOperationOutcome::Succeeded
        } else {
            BrokerOutboundOperationOutcome::Failed
        };
        let completed_at =
            completed_at.unwrap_or_else(|| current_state_timestamp().unwrap_or(started_at));
        self.finish_outbound_credential_operation_at(authorization, outcome, completed_at)?;
        operation_result
    }

    /// Searches minimum metadata for one exact, already-authorized credential.
    pub fn search_authorized_credential_now(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        query: BrokerCredentialSearchQuery,
    ) -> Result<BrokerCredentialSearchResult, BrokerRuntimeError> {
        let evaluated_at = current_state_timestamp()?;
        self.search_authorized_credential(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            evaluated_at,
            query,
        )
    }

    /// Searches minimum metadata for one exact, already-authorized credential.
    ///
    /// This timestamp-explicit form is retained for deterministic control-plane
    /// tests and trusted callers. Protocol adapters should use
    /// [`Self::search_authorized_credential_now`].
    ///
    /// The result can contain at most the title and the one Secret Field
    /// descriptor named by a `credential.search` grant. It never returns tags,
    /// templates, other field descriptors, or field values.
    pub fn search_authorized_credential(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        evaluated_at: StateTimestamp,
        query: BrokerCredentialSearchQuery,
    ) -> Result<BrokerCredentialSearchResult, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        BrokerCredentialSearchManager::validate_target(target)
            .map_err(BrokerRuntimeError::CredentialSearch)?;
        self.authorize_use_grant_after_gate(
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            evaluated_at,
        )?;
        let summary = self
            .process
            .vault_sessions()
            .credential_summary(
                target.field_scope().vault_id(),
                vault_session_id,
                target.field_scope().credential_id(),
            )
            .map_err(BrokerRuntimeError::VaultSession)?;
        BrokerCredentialSearchManager::project(&query, target, secret_kind, summary)
            .map_err(BrokerRuntimeError::CredentialSearch)
    }

    /// Admits one paired Consumer's bounded new-credential description.
    ///
    /// The machine pause gate and Consumer identity are checked before the
    /// request is admitted. The returned value contains no candidate metadata.
    pub fn admit_new_credential_request(
        &self,
        request: BrokerNewCredentialRequest,
    ) -> Result<BrokerAdmittedCredentialRequest, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        BrokerCredentialMatchingManager::admit(&self.state, request)
            .map_err(BrokerRuntimeError::CredentialMatching)
    }

    /// Creates or coalesces one exact-field access request using a Broker-owned
    /// bounded approval window.
    pub fn request_exact_access(
        &self,
        target: AuthorizationTarget,
    ) -> Result<BrokerApprovalSubmission, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        let created_at = current_state_timestamp()?;
        let expires_at = timestamp_after(created_at, MAX_APPROVAL_LIFETIME)?;
        self.submit_approval(ApprovalSubject::Access { target }, created_at, expires_at)
    }

    /// Creates or coalesces one human-matched credential access request using
    /// a Broker-owned bounded approval window.
    pub fn request_new_credential_access(
        &self,
        request: BrokerNewCredentialRequest,
    ) -> Result<BrokerApprovalSubmission, BrokerRuntimeError> {
        let admitted = self.admit_new_credential_request(request)?;
        let created_at = current_state_timestamp()?;
        let expires_at = timestamp_after(created_at, MAX_APPROVAL_LIFETIME)?;
        self.submit_new_credential_approval(admitted, created_at, expires_at)
    }

    /// Returns one authenticated Consumer's grant state without disclosing
    /// another Consumer's grant metadata.
    pub fn consumer_use_grant_status(
        &self,
        consumer_id: ConsumerId,
        use_grant_id: UseGrantId,
    ) -> Result<BrokerConsumerUseGrantStatus, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        let observed_at = current_state_timestamp()?;
        BrokerUseGrantManager::status_for_consumer(
            &self.state,
            consumer_id,
            use_grant_id,
            observed_at,
        )
        .map_err(BrokerRuntimeError::UseGrant)
    }

    /// Revokes one grant only when it belongs to the authenticated Consumer.
    ///
    /// An absent or foreign grant returns `false` without disclosing which
    /// condition applied.
    pub fn revoke_consumer_use_grant(
        &self,
        consumer_id: ConsumerId,
        use_grant_id: UseGrantId,
    ) -> Result<bool, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        BrokerUseGrantManager::revoke_for_consumer(&self.state, consumer_id, use_grant_id)
            .map_err(BrokerRuntimeError::UseGrant)
    }

    /// Builds a human-only candidate review for one admitted request.
    ///
    /// This trusted local control-plane operation is not a Consumer protocol
    /// result and remains available if Apps & Tools is paused after admission.
    pub fn review_new_credential_request(
        &self,
        admitted: BrokerAdmittedCredentialRequest,
        vault_session_id: VaultSessionId,
    ) -> Result<BrokerHumanCredentialReview, BrokerRuntimeError> {
        BrokerCredentialMatchingManager::require_consumer(&self.state, admitted.consumer_id())
            .map_err(BrokerRuntimeError::CredentialMatching)?;
        let summaries = self
            .process
            .vault_sessions()
            .matching_credential_summaries(
                admitted.vault_id(),
                vault_session_id,
                admitted.normalized_description(),
            )
            .map_err(BrokerRuntimeError::VaultSession)?;
        Ok(BrokerCredentialMatchingManager::review(
            admitted,
            vault_session_id,
            summaries,
        ))
    }

    /// Confirms one exact human selection after revalidating current metadata.
    ///
    /// The review is consumed. Any session, title, tag, template, compatible
    /// field, label, or kind change makes it stale. This does not create an
    /// Access Rule or Use Grant.
    pub fn approve_new_credential_selection(
        &self,
        review: BrokerHumanCredentialReview,
        selection: BrokerCredentialCandidateSelection,
    ) -> Result<BrokerApprovedCredentialSelection, BrokerRuntimeError> {
        BrokerCredentialMatchingManager::require_consumer(&self.state, review.consumer_id())
            .map_err(BrokerRuntimeError::CredentialMatching)?;
        let summary = self
            .process
            .vault_sessions()
            .credential_summary(
                review.vault_id(),
                review.vault_session_id(),
                selection.credential_id(),
            )
            .map_err(BrokerRuntimeError::VaultSession)?;
        BrokerCredentialMatchingManager::approve(review, selection, summary)
            .map_err(BrokerRuntimeError::CredentialMatching)
    }

    /// Creates or coalesces one bounded asynchronous approval.
    pub fn submit_approval(
        &self,
        subject: ApprovalSubject,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<BrokerApprovalSubmission, BrokerRuntimeError> {
        self.approvals
            .submit(&self.state, subject, created_at, expires_at)
            .map_err(BrokerRuntimeError::Approval)
    }

    /// Creates or coalesces one new-Credential approval without persisting its description.
    pub fn submit_new_credential_approval(
        &self,
        admitted: BrokerAdmittedCredentialRequest,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<BrokerApprovalSubmission, BrokerRuntimeError> {
        self.approvals
            .submit_credential_request(&self.state, admitted, created_at, expires_at)
            .map_err(BrokerRuntimeError::Approval)
    }

    /// Returns one Consumer-scoped approval status without its subject.
    pub fn poll_approval(
        &self,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerApprovalReceipt, BrokerRuntimeError> {
        self.approvals
            .poll(&self.state, consumer_id, approval_request_id, observed_at)
            .map_err(BrokerRuntimeError::Approval)
    }

    /// Returns one Consumer-scoped approval status using Broker-owned time.
    ///
    /// Protocol adapters use this entry point so the global Apps & Tools pause
    /// gate and wall-clock boundary are enforced inside the Broker.
    pub fn approval_status_now(
        &self,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
    ) -> Result<BrokerApprovalReceipt, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        self.poll_approval(consumer_id, approval_request_id, current_state_timestamp()?)
    }

    /// Resumes one prior Consumer approval by stable identity.
    pub fn resume_approval(
        &self,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerApprovalReceipt, BrokerRuntimeError> {
        self.approvals
            .resume(&self.state, consumer_id, approval_request_id, observed_at)
            .map_err(BrokerRuntimeError::Approval)
    }

    /// Resumes one Consumer-scoped approval using Broker-owned time.
    pub fn resume_approval_now(
        &self,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
    ) -> Result<BrokerApprovalReceipt, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        self.resume_approval(consumer_id, approval_request_id, current_state_timestamp()?)
    }

    /// Waits for one approval for no longer than the bounded caller timeout.
    pub fn wait_for_approval(
        &self,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
        timeout: Duration,
    ) -> Result<BrokerApprovalWaitOutcome, BrokerRuntimeError> {
        self.approvals
            .wait(
                &self.state,
                consumer_id,
                approval_request_id,
                observed_at,
                timeout,
            )
            .map_err(BrokerRuntimeError::Approval)
    }

    /// Waits for one Consumer-scoped approval using Broker-owned time.
    pub fn wait_for_approval_now(
        &self,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
        timeout: Duration,
    ) -> Result<BrokerApprovalWaitOutcome, BrokerRuntimeError> {
        self.machine_access
            .authorize_machine_operation()
            .map_err(BrokerRuntimeError::MachineAccess)?;
        self.wait_for_approval(
            consumer_id,
            approval_request_id,
            current_state_timestamp()?,
            timeout,
        )
    }

    /// Lists pending requests only for the trusted local human control plane.
    pub fn pending_approvals_for_human(
        &self,
        observed_at: StateTimestamp,
    ) -> Result<Vec<BrokerHumanApprovalSnapshot>, BrokerRuntimeError> {
        self.approvals
            .pending_for_human(&self.state, observed_at)
            .map_err(BrokerRuntimeError::Approval)
    }

    /// Returns one bounded queue of requests requiring a trusted local decision.
    pub fn pending_requests_for_human(
        &self,
    ) -> Result<BrokerPendingRequestQueue, BrokerRuntimeError> {
        let observed_at = current_state_timestamp()?;
        let pairings = self.pending_pairings()?;
        let approvals = self.pending_approvals_for_human(observed_at)?;
        BrokerHumanControlManager::pending_requests(&self.state, &pairings, &approvals)
            .map_err(BrokerRuntimeError::HumanControl)
    }

    /// Denies one still-pending pairing or asynchronous approval.
    pub fn deny_pending_request(
        &self,
        request_id: BrokerPendingRequestId,
        denied_at: StateTimestamp,
    ) -> Result<(), BrokerRuntimeError> {
        match request_id {
            BrokerPendingRequestId::Pairing(request_id) => self.deny_pairing(request_id),
            BrokerPendingRequestId::Approval(request_id) => {
                let receipt =
                    self.resolve_approval(request_id, BrokerApprovalDecision::Deny, denied_at)?;
                if receipt.status() != ApprovalStatus::Denied {
                    return Err(BrokerRuntimeError::Approval(
                        BrokerApprovalError::ApprovalUnavailable,
                    ));
                }
                Ok(())
            }
        }
    }

    /// Approves one unlock request only after its exact Vault is already unlocked.
    pub fn approve_pending_unlock(
        &self,
        approval_request_id: ApprovalRequestId,
        approved_at: StateTimestamp,
    ) -> Result<(), BrokerRuntimeError> {
        let pending = self.pending_approval_snapshot(approval_request_id, approved_at)?;
        let ApprovalSubject::Unlock { vault_id, .. } = pending.subject() else {
            return Err(BrokerRuntimeError::Approval(
                BrokerApprovalError::ApprovalUnavailable,
            ));
        };
        self.current_vault_session_id(*vault_id)?;
        let receipt = self.resolve_approval(
            approval_request_id,
            BrokerApprovalDecision::Approve,
            approved_at,
        )?;
        if receipt.status() != ApprovalStatus::Approved {
            return Err(BrokerRuntimeError::Approval(
                BrokerApprovalError::ApprovalUnavailable,
            ));
        }
        Ok(())
    }

    /// Reviews a new-Credential request against its exact current Vault session.
    pub fn review_pending_new_credential_for_current_session(
        &self,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerHumanCredentialReview, BrokerRuntimeError> {
        let pending = self.pending_approval_snapshot(approval_request_id, observed_at)?;
        let ApprovalSubject::CredentialAccess { vault_id, .. } = pending.subject() else {
            return Err(BrokerRuntimeError::Approval(
                BrokerApprovalError::ApprovalUnavailable,
            ));
        };
        let vault_session_id = self.current_vault_session_id(*vault_id)?;
        self.review_pending_new_credential_approval(
            approval_request_id,
            vault_session_id,
            observed_at,
        )
    }

    /// Approves one exact first request with a source-less one-operation grant.
    ///
    /// Existing-field requests derive their Secret Field kind from current
    /// authenticated Vault metadata. New-Credential requests require one exact
    /// human candidate selection. Grant insertion and approval resolution
    /// commit in one encrypted device-state transaction.
    pub fn allow_once_pending_request(
        &mut self,
        approval_request_id: ApprovalRequestId,
        selection: Option<BrokerCredentialCandidateSelection>,
        approved_at: StateTimestamp,
    ) -> Result<BrokerUseGrantIssuance, BrokerRuntimeError> {
        let pending = self.pending_approval_snapshot(approval_request_id, approved_at)?;
        let expected_subject = pending.subject().clone();
        let approval_expires_at = pending.expires_at();

        let (target, secret_kind, vault_session_id) =
            self.pending_access_target(approval_request_id, &pending, selection, approved_at)?;

        let approval = BrokerAllowOnceApproval::after_user_approval(
            target,
            secret_kind,
            vault_session_id,
            approved_at,
            approval_expires_at,
        )
        .map_err(BrokerRuntimeError::UseGrant)?;
        let issuance = BrokerUseGrantManager::prepare_allow_once(&self.state, approval)
            .map_err(BrokerRuntimeError::UseGrant)?;
        self.approvals
            .approve_with_allow_once_grant(
                &mut self.state,
                approval_request_id,
                &expected_subject,
                issuance.grant(),
                approved_at,
            )
            .map_err(BrokerRuntimeError::Approval)?;
        self.verify_issued_grant_session(issuance, target, vault_session_id)
    }

    /// Creates one exact persistent rule while approving its first request.
    ///
    /// The selected policy never creates a Use Grant here. The original
    /// operation must pass through the normal policy-specific grant boundary.
    pub fn configure_pending_request_access_rule(
        &mut self,
        approval_request_id: ApprovalRequestId,
        selection: Option<BrokerCredentialCandidateSelection>,
        confirmation_policy: ConfirmationPolicy,
        approved_at: StateTimestamp,
    ) -> Result<BrokerAccessRuleCreation, BrokerRuntimeError> {
        let pending = self.pending_approval_snapshot(approval_request_id, approved_at)?;
        let expected_subject = pending.subject().clone();
        let (target, secret_kind, _) =
            self.pending_access_target(approval_request_id, &pending, selection, approved_at)?;
        let approval = BrokerAccessRuleApproval::after_user_approval(
            target,
            secret_kind,
            confirmation_policy,
            RuleLifetime::Persistent,
            approved_at,
        )
        .map_err(BrokerRuntimeError::AccessRule)?;
        let proposed_rule = BrokerAccessRuleManager::prepare_rule(&self.state, approval)
            .map_err(BrokerRuntimeError::AccessRule)?;
        let (_, persisted_rule, newly_created) = self
            .approvals
            .approve_with_access_rule(
                &mut self.state,
                approval_request_id,
                &expected_subject,
                &proposed_rule,
                approved_at,
            )
            .map_err(BrokerRuntimeError::Approval)?;
        Ok(BrokerAccessRuleCreation::from_persisted(
            persisted_rule,
            newly_created,
        ))
    }

    /// Applies one idempotent terminal human decision.
    pub fn resolve_approval(
        &self,
        approval_request_id: ApprovalRequestId,
        decision: BrokerApprovalDecision,
        resolved_at: StateTimestamp,
    ) -> Result<BrokerApprovalReceipt, BrokerRuntimeError> {
        self.approvals
            .resolve(&self.state, approval_request_id, decision, resolved_at)
            .map_err(BrokerRuntimeError::Approval)
    }

    /// Builds a human-only candidate review for one still-pending approval.
    pub fn review_pending_new_credential_approval(
        &self,
        approval_request_id: ApprovalRequestId,
        vault_session_id: VaultSessionId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerHumanCredentialReview, BrokerRuntimeError> {
        let admitted = self
            .approvals
            .credential_request(&self.state, approval_request_id, observed_at)
            .map_err(BrokerRuntimeError::Approval)?;
        self.review_new_credential_request(admitted, vault_session_id)
    }

    fn pending_access_target(
        &self,
        approval_request_id: ApprovalRequestId,
        pending: &BrokerHumanApprovalSnapshot,
        selection: Option<BrokerCredentialCandidateSelection>,
        observed_at: StateTimestamp,
    ) -> Result<(AuthorizationTarget, SecretFieldKind, VaultSessionId), BrokerRuntimeError> {
        match pending.subject() {
            ApprovalSubject::Access { target } => {
                if selection.is_some() {
                    return Err(BrokerRuntimeError::Approval(
                        BrokerApprovalError::ApprovalUnavailable,
                    ));
                }
                let vault_session_id =
                    self.current_vault_session_id(target.field_scope().vault_id())?;
                let secret_kind = self.secret_kind_for_target(*target, vault_session_id)?;
                Ok((*target, secret_kind, vault_session_id))
            }
            ApprovalSubject::CredentialAccess { vault_id, .. } => {
                let selection = selection.ok_or(BrokerRuntimeError::Approval(
                    BrokerApprovalError::ApprovalUnavailable,
                ))?;
                let vault_session_id = self.current_vault_session_id(*vault_id)?;
                let review = self.review_pending_new_credential_approval(
                    approval_request_id,
                    vault_session_id,
                    observed_at,
                )?;
                let approved = self.approve_new_credential_selection(review, selection)?;
                Ok((approved.target(), approved.secret_kind(), vault_session_id))
            }
            ApprovalSubject::Pairing { .. } | ApprovalSubject::Unlock { .. } => Err(
                BrokerRuntimeError::Approval(BrokerApprovalError::ApprovalUnavailable),
            ),
        }
    }

    fn authorize_use_grant_after_gate(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
        evaluated_at: StateTimestamp,
    ) -> Result<BrokerAuthorizedGrantUse, BrokerRuntimeError> {
        BrokerUseGrantManager::preflight_use(
            &self.state,
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
        )
        .map_err(BrokerRuntimeError::UseGrant)?;
        self.require_current_vault_session(target, vault_session_id)
            .map_err(BrokerRuntimeError::UseGrant)?;
        let authorized = BrokerUseGrantManager::authorize_use(
            &self.state,
            use_grant_id,
            target,
            secret_kind,
            vault_session_id,
            evaluated_at,
        )
        .map_err(BrokerRuntimeError::UseGrant)?;
        if let Err(session_error) = self.require_current_vault_session(target, vault_session_id) {
            BrokerUseGrantManager::remove_grant(&self.state, use_grant_id)
                .map_err(BrokerRuntimeError::UseGrant)?;
            return Err(BrokerRuntimeError::UseGrant(session_error));
        }
        Ok(authorized)
    }

    /// Persists and applies the global Apps & Tools pause state.
    pub fn set_machine_access_paused(
        &self,
        paused: bool,
        updated_at: StateTimestamp,
    ) -> Result<BrokerMachineAccessTransition, BrokerRuntimeError> {
        self.machine_access
            .set_paused(&self.state, paused, updated_at)
            .map_err(BrokerRuntimeError::MachineAccess)
    }

    /// Locks one process-owned Vault session and commits grant invalidation.
    pub fn lock_vault_for_human(
        &mut self,
        vault_id: VaultId,
    ) -> Result<BrokerGrantInvalidationSummary, BrokerRuntimeError> {
        self.process
            .vault_sessions()
            .lock_vault(vault_id)
            .map_err(BrokerRuntimeError::VaultSession)?;
        BrokerGrantInvalidator::synchronize_lock_events(
            self.process.vault_sessions(),
            &mut self.state,
        )
        .map_err(BrokerRuntimeError::GrantInvalidation)
    }

    /// Revokes every capability for one Consumer and one exact Secret Field.
    ///
    /// Other Consumers, other fields, shared Usage Profiles, audit history,
    /// the pause setting, and human vault sessions remain unchanged.
    pub fn revoke_consumer_field_access(
        &mut self,
        consumer_id: ConsumerId,
        field_scope: CredentialFieldScope,
    ) -> Result<BrokerRevocationSummary, BrokerRuntimeError> {
        BrokerRevocationManager::revoke_consumer_field(
            &mut self.state,
            &self.approvals,
            consumer_id,
            field_scope,
        )
        .map_err(BrokerRuntimeError::Revocation)
    }

    /// Unpairs one Consumer and revokes all of its machine authorization.
    ///
    /// Non-secret audit history, other Consumers, pause state, and human vault
    /// sessions remain unchanged.
    pub fn revoke_consumer_access(
        &mut self,
        consumer_id: ConsumerId,
    ) -> Result<BrokerRevocationSummary, BrokerRuntimeError> {
        BrokerRevocationManager::revoke_consumer(
            &mut self.state,
            &self.approvals,
            &self.pairing,
            consumer_id,
        )
        .map_err(BrokerRuntimeError::Revocation)
    }

    /// Unpairs every Consumer and revokes all Apps & Tools authorization.
    ///
    /// This is intentionally distinct from pause and device-data reset. It
    /// preserves audit history, settings, the device root, and human sessions.
    pub fn revoke_all_apps_and_tools_access(
        &mut self,
    ) -> Result<BrokerRevocationSummary, BrokerRuntimeError> {
        BrokerRevocationManager::revoke_global(&mut self.state, &self.approvals, &self.pairing)
            .map_err(BrokerRuntimeError::Revocation)
    }

    /// Gracefully ends process sessions and invalidates every current grant.
    pub fn shutdown(&mut self) -> Result<BrokerGrantInvalidationSummary, BrokerRuntimeError> {
        let resolved_at = current_state_timestamp()?;
        self.shutdown_at(resolved_at)
    }

    pub(crate) fn shutdown_at(
        &mut self,
        resolved_at: StateTimestamp,
    ) -> Result<BrokerGrantInvalidationSummary, BrokerRuntimeError> {
        self.approvals
            .cancel_process_local_pending(&self.state, resolved_at)
            .map_err(BrokerRuntimeError::Approval)?;
        self.pairing
            .cancel_all_pending()
            .map_err(BrokerRuntimeError::Pairing)?;
        BrokerGrantInvalidator::prepare_process_shutdown(
            self.process.vault_sessions(),
            &mut self.state,
        )
        .map_err(BrokerRuntimeError::GrantInvalidation)
    }

    fn pending_approval_snapshot(
        &self,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerHumanApprovalSnapshot, BrokerRuntimeError> {
        self.pending_approvals_for_human(observed_at)?
            .into_iter()
            .find(|pending| pending.approval_request_id() == approval_request_id)
            .ok_or(BrokerRuntimeError::Approval(
                BrokerApprovalError::ApprovalUnavailable,
            ))
    }

    fn current_vault_session_id(
        &self,
        vault_id: VaultId,
    ) -> Result<VaultSessionId, BrokerRuntimeError> {
        self.process
            .vault_sessions()
            .snapshot(vault_id)
            .map_err(BrokerRuntimeError::VaultSession)?
            .vault_session_id()
            .ok_or(BrokerRuntimeError::VaultSession(
                BrokerVaultSessionError::VaultLocked,
            ))
    }

    fn secret_kind_for_target(
        &self,
        target: AuthorizationTarget,
        vault_session_id: VaultSessionId,
    ) -> Result<SecretFieldKind, BrokerRuntimeError> {
        let field_scope = target.field_scope();
        let summary = self
            .process
            .vault_sessions()
            .credential_summary(
                field_scope.vault_id(),
                vault_session_id,
                field_scope.credential_id(),
            )
            .map_err(BrokerRuntimeError::VaultSession)?
            .ok_or(BrokerRuntimeError::UseGrant(
                BrokerUseGrantError::AccessDenied,
            ))?;
        summary
            .secret_fields
            .iter()
            .find(|field| field.secret_field_id == field_scope.secret_field_id())
            .map(|field| field.kind)
            .ok_or(BrokerRuntimeError::UseGrant(
                BrokerUseGrantError::AccessDenied,
            ))
    }

    fn verify_issued_grant_session(
        &self,
        issuance: BrokerUseGrantIssuance,
        target: AuthorizationTarget,
        vault_session_id: VaultSessionId,
    ) -> Result<BrokerUseGrantIssuance, BrokerRuntimeError> {
        if let Err(session_error) = self.require_current_vault_session(target, vault_session_id) {
            BrokerUseGrantManager::remove_grant(&self.state, issuance.grant().use_grant_id())
                .map_err(BrokerRuntimeError::UseGrant)?;
            return Err(BrokerRuntimeError::UseGrant(session_error));
        }
        Ok(issuance)
    }

    fn require_current_vault_session(
        &self,
        target: AuthorizationTarget,
        vault_session_id: VaultSessionId,
    ) -> Result<(), BrokerUseGrantError> {
        let snapshot = self
            .process
            .vault_sessions()
            .snapshot(target.field_scope().vault_id())?;
        match snapshot.vault_session_id() {
            Some(current) if current == vault_session_id => Ok(()),
            Some(_) => Err(BrokerUseGrantError::GrantExpired),
            None => Err(BrokerVaultSessionError::VaultLocked.into()),
        }
    }
}

impl Debug for BrokerRuntime {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerRuntime")
            .field("paths", &"<redacted>")
            .field("process", &self.process.broker_instance_id())
            .field("stale_use_grants_removed", &self.stale_use_grants_removed)
            .field("approval_restore_summary", &self.approval_restore_summary)
            .finish_non_exhaustive()
    }
}

fn current_state_timestamp() -> Result<StateTimestamp, BrokerRuntimeError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrokerRuntimeError::ClockUnavailable)?;
    let millis =
        i64::try_from(elapsed.as_millis()).map_err(|_| BrokerRuntimeError::ClockUnavailable)?;
    StateTimestamp::from_unix_millis(millis).map_err(|_| BrokerRuntimeError::ClockUnavailable)
}

fn timestamp_after(
    timestamp: StateTimestamp,
    duration: Duration,
) -> Result<StateTimestamp, BrokerRuntimeError> {
    let duration_millis =
        i64::try_from(duration.as_millis()).map_err(|_| BrokerRuntimeError::ClockUnavailable)?;
    let value = timestamp
        .unix_millis()
        .checked_add(duration_millis)
        .ok_or(BrokerRuntimeError::ClockUnavailable)?;
    StateTimestamp::from_unix_millis(value).map_err(|_| BrokerRuntimeError::ClockUnavailable)
}
