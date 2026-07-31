use std::collections::{BTreeSet, HashMap};
use std::fmt::{Debug, Display, Formatter};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::credential_matching::BrokerAdmittedCredentialRequest;
use crate::protocol::BrokerErrorCode;
use crate::state_model::{
    AccessRule, ApprovalRequest, ApprovalRequestId, ApprovalStatus, ApprovalSubject,
    CapabilityName, ConsumerId, StateTimestamp, UseGrant,
};
use crate::state_store::{
    DeviceStateError, DeviceStateStore, StoredAccessRuleResolution, StoredAllowOnceResolution,
    StoredApprovalResolution,
};

/// Maximum lifetime accepted for one pending approval request.
pub const MAX_APPROVAL_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Maximum duration of one blocking approval wait call.
pub const MAX_APPROVAL_WAIT: Duration = Duration::from_secs(5 * 60);

/// Maximum number of pending approvals retained in encrypted device state.
pub const MAX_PENDING_APPROVALS: usize = 256;

const APPROVAL_EQUIVALENCE_DOMAIN: &[u8] = b"KeptNear approval equivalence v1";
const MAX_INSERT_RETRIES: usize = 3;

/// Explicit terminal decision made by the trusted local control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerApprovalDecision {
    /// Approve the immutable request subject.
    Approve,
    /// Deny the immutable request subject.
    Deny,
    /// Cancel the request without approving it.
    Cancel,
}

impl BrokerApprovalDecision {
    const fn status(self) -> ApprovalStatus {
        match self {
            Self::Approve => ApprovalStatus::Approved,
            Self::Deny => ApprovalStatus::Denied,
            Self::Cancel => ApprovalStatus::Cancelled,
        }
    }
}

/// Consumer-safe status receipt containing no approval subject or candidates.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerApprovalReceipt {
    approval_request_id: ApprovalRequestId,
    status: ApprovalStatus,
    expires_at: StateTimestamp,
    resolved_at: Option<StateTimestamp>,
}

impl BrokerApprovalReceipt {
    /// Returns the stable request identity used for polling or resumption.
    #[must_use]
    pub const fn approval_request_id(&self) -> ApprovalRequestId {
        self.approval_request_id
    }

    /// Returns the current request status.
    #[must_use]
    pub const fn status(&self) -> ApprovalStatus {
        self.status
    }

    /// Returns the exclusive request expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> StateTimestamp {
        self.expires_at
    }

    /// Returns when a terminal state was committed.
    #[must_use]
    pub const fn resolved_at(&self) -> Option<StateTimestamp> {
        self.resolved_at
    }

    /// Returns whether this receipt is terminal.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.status != ApprovalStatus::Pending
    }
}

impl Debug for BrokerApprovalReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerApprovalReceipt")
            .field("status", &self.status)
            .field("terminal", &self.is_terminal())
            .finish_non_exhaustive()
    }
}

impl From<&ApprovalRequest> for BrokerApprovalReceipt {
    fn from(request: &ApprovalRequest) -> Self {
        Self {
            approval_request_id: request.approval_request_id(),
            status: request.status(),
            expires_at: request.expires_at(),
            resolved_at: request.resolved_at(),
        }
    }
}

/// Result of creating or coalescing one pending approval.
#[derive(Debug, Eq, PartialEq)]
pub struct BrokerApprovalSubmission {
    receipt: BrokerApprovalReceipt,
    coalesced: bool,
}

impl BrokerApprovalSubmission {
    /// Returns the stable pending receipt.
    #[must_use]
    pub const fn receipt(&self) -> &BrokerApprovalReceipt {
        &self.receipt
    }

    /// Returns whether an equivalent pending request already existed.
    #[must_use]
    pub const fn coalesced(&self) -> bool {
        self.coalesced
    }
}

/// Result of one bounded wait operation.
#[derive(Debug, Eq, PartialEq)]
pub struct BrokerApprovalWaitOutcome {
    receipt: BrokerApprovalReceipt,
    timed_out: bool,
}

impl BrokerApprovalWaitOutcome {
    /// Returns the latest Consumer-safe receipt.
    #[must_use]
    pub const fn receipt(&self) -> &BrokerApprovalReceipt {
        &self.receipt
    }

    /// Returns whether the caller's wait duration elapsed while still pending.
    #[must_use]
    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }
}

/// Pending approval information shown only in the trusted human control plane.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerHumanApprovalSnapshot {
    approval_request_id: ApprovalRequestId,
    subject: ApprovalSubject,
    created_at: StateTimestamp,
    expires_at: StateTimestamp,
    credential_description: Option<String>,
}

impl BrokerHumanApprovalSnapshot {
    /// Returns the stable approval identity.
    #[must_use]
    pub const fn approval_request_id(&self) -> ApprovalRequestId {
        self.approval_request_id
    }

    /// Returns the immutable secret-free approval subject.
    #[must_use]
    pub const fn subject(&self) -> &ApprovalSubject {
        &self.subject
    }

    /// Returns when the request was created.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }

    /// Returns the exclusive pending expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> StateTimestamp {
        self.expires_at
    }

    /// Returns the process-local new-Credential description when applicable.
    #[must_use]
    pub fn credential_description(&self) -> Option<&str> {
        self.credential_description.as_deref()
    }
}

impl Debug for BrokerHumanApprovalSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHumanApprovalSnapshot")
            .field("kind", &self.subject.kind())
            .field(
                "credential_description",
                &self.credential_description.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerHumanApprovalSnapshot {
    fn drop(&mut self) {
        if let Some(description) = &mut self.credential_description {
            description.zeroize();
        }
    }
}

/// Startup reconciliation of encrypted approval state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerApprovalRestoreSummary {
    expired: usize,
    process_local_cancelled: usize,
}

impl BrokerApprovalRestoreSummary {
    /// Returns pending requests expired during startup.
    #[must_use]
    pub const fn expired(self) -> usize {
        self.expired
    }

    /// Returns requests cancelled because required process context was lost.
    #[must_use]
    pub const fn process_local_cancelled(self) -> usize {
        self.process_local_cancelled
    }
}

/// Sanitized asynchronous approval lifecycle failure.
#[derive(Debug)]
pub enum BrokerApprovalError {
    /// The immutable request cannot be represented by this approval contract.
    InvalidRequest,
    /// Creation and expiry do not form a supported bounded lifetime.
    InvalidLifetime,
    /// A wait duration is zero or exceeds the supported bound.
    InvalidWait,
    /// The approval identity is unknown or belongs to another Consumer.
    ApprovalUnavailable,
    /// The request requires process-local context that is no longer available.
    ContextUnavailable,
    /// A non-pairing subject names a Consumer that is no longer paired.
    ConsumerUnavailable,
    /// The pending approval limit has been reached.
    PendingLimitReached,
    /// A keyed digest collision produced a different immutable subject.
    EquivalenceCollision,
    /// A decision timestamp precedes request creation.
    InvalidDecisionTime,
    /// In-memory waiter or context state is unavailable.
    RuntimeStateUnavailable,
    /// Authenticated encrypted approval state could not be read or changed.
    DeviceState(DeviceStateError),
}

impl BrokerApprovalError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(&self) -> BrokerErrorCode {
        match self {
            Self::InvalidRequest
            | Self::InvalidLifetime
            | Self::InvalidWait
            | Self::InvalidDecisionTime => BrokerErrorCode::InvalidRequest,
            Self::ConsumerUnavailable => BrokerErrorCode::ConsumerRevoked,
            Self::ApprovalUnavailable
            | Self::ContextUnavailable
            | Self::PendingLimitReached
            | Self::EquivalenceCollision => BrokerErrorCode::AccessDenied,
            Self::RuntimeStateUnavailable | Self::DeviceState(_) => {
                BrokerErrorCode::OperationFailed
            }
        }
    }
}

impl Display for BrokerApprovalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("approval request is invalid"),
            Self::InvalidLifetime => formatter.write_str("approval lifetime is invalid"),
            Self::InvalidWait => formatter.write_str("approval wait duration is invalid"),
            Self::ApprovalUnavailable => formatter.write_str("approval is unavailable"),
            Self::ContextUnavailable => {
                formatter.write_str("approval process context is unavailable")
            }
            Self::ConsumerUnavailable => formatter.write_str("approval Consumer is unavailable"),
            Self::PendingLimitReached => formatter.write_str("pending approval limit was reached"),
            Self::EquivalenceCollision => {
                formatter.write_str("approval equivalence state is inconsistent")
            }
            Self::InvalidDecisionTime => {
                formatter.write_str("approval decision timestamp is invalid")
            }
            Self::RuntimeStateUnavailable => {
                formatter.write_str("approval runtime state is unavailable")
            }
            Self::DeviceState(source) => write!(formatter, "approval state failed: {source}"),
        }
    }
}

impl std::error::Error for BrokerApprovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::InvalidRequest
            | Self::InvalidLifetime
            | Self::InvalidWait
            | Self::ApprovalUnavailable
            | Self::ContextUnavailable
            | Self::ConsumerUnavailable
            | Self::PendingLimitReached
            | Self::EquivalenceCollision
            | Self::InvalidDecisionTime
            | Self::RuntimeStateUnavailable => None,
        }
    }
}

#[derive(Default)]
struct ApprovalRuntimeState {
    generation: u64,
    credential_requests: HashMap<ApprovalRequestId, BrokerAdmittedCredentialRequest>,
}

/// Process-shared coordinator for encrypted approval state and local waiters.
pub(crate) struct BrokerApprovalManager {
    submission: Mutex<()>,
    runtime: Mutex<ApprovalRuntimeState>,
    changed: Condvar,
}

impl Debug for BrokerApprovalManager {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerApprovalManager")
            .finish_non_exhaustive()
    }
}

impl BrokerApprovalManager {
    /// Reconciles persisted approvals after Broker process startup.
    ///
    /// Exact Access and Unlock approvals remain resumable. Pairing and
    /// new-Credential approvals are cancelled because their required
    /// process-local proof or description context cannot survive restart.
    pub(crate) fn restore(
        state: &DeviceStateStore,
        observed_at: StateTimestamp,
    ) -> Result<(Self, BrokerApprovalRestoreSummary), BrokerApprovalError> {
        let expired = state
            .expire_pending_approvals(observed_at)
            .map_err(BrokerApprovalError::DeviceState)?;
        let pending = state
            .pending_approvals()
            .map_err(BrokerApprovalError::DeviceState)?;
        let mut process_local_cancelled = 0_usize;
        for request in pending {
            if matches!(
                request.subject(),
                ApprovalSubject::Pairing { .. } | ApprovalSubject::CredentialAccess { .. }
            ) {
                let resolved_at = later_timestamp(observed_at, request.created_at());
                if matches!(
                    state
                        .resolve_pending_approval(
                            request.approval_request_id(),
                            ApprovalStatus::Cancelled,
                            resolved_at,
                        )
                        .map_err(BrokerApprovalError::DeviceState)?,
                    StoredApprovalResolution::Resolved(_) | StoredApprovalResolution::Expired(_)
                ) {
                    process_local_cancelled = process_local_cancelled.saturating_add(1);
                }
            }
        }
        Ok((
            Self {
                submission: Mutex::new(()),
                runtime: Mutex::new(ApprovalRuntimeState::default()),
                changed: Condvar::new(),
            },
            BrokerApprovalRestoreSummary {
                expired,
                process_local_cancelled,
            },
        ))
    }

    /// Creates or coalesces one secret-free exact approval subject.
    pub(crate) fn submit(
        &self,
        state: &DeviceStateStore,
        subject: ApprovalSubject,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<BrokerApprovalSubmission, BrokerApprovalError> {
        self.submit_internal(state, subject, None, created_at, expires_at)
    }

    /// Creates or coalesces one process-local new-Credential approval.
    pub(crate) fn submit_credential_request(
        &self,
        state: &DeviceStateStore,
        admitted: BrokerAdmittedCredentialRequest,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<BrokerApprovalSubmission, BrokerApprovalError> {
        let subject = ApprovalSubject::CredentialAccess {
            consumer_id: admitted.consumer_id(),
            vault_id: admitted.vault_id(),
            capability: admitted.capability(),
        };
        self.submit_internal(state, subject, Some(admitted), created_at, expires_at)
    }

    /// Returns a Consumer-scoped status without approval subject metadata.
    pub(crate) fn poll(
        &self,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerApprovalReceipt, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        if state
            .expire_pending_approvals(observed_at)
            .map_err(BrokerApprovalError::DeviceState)?
            != 0
        {
            self.notify_change()?;
        }
        let request = self.load_for_consumer(state, consumer_id, approval_request_id)?;
        if request.status() != ApprovalStatus::Pending {
            self.remove_credential_context(approval_request_id)?;
        }
        Ok(BrokerApprovalReceipt::from(&request))
    }

    /// Resumes a prior Consumer request by its stable approval identity.
    pub(crate) fn resume(
        &self,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerApprovalReceipt, BrokerApprovalError> {
        self.poll(state, consumer_id, approval_request_id, observed_at)
    }

    /// Waits for a terminal decision, expiry, notification, or bounded timeout.
    pub(crate) fn wait(
        &self,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
        timeout: Duration,
    ) -> Result<BrokerApprovalWaitOutcome, BrokerApprovalError> {
        if timeout.is_zero() || timeout > MAX_APPROVAL_WAIT {
            return Err(BrokerApprovalError::InvalidWait);
        }
        let initial = self.poll(state, consumer_id, approval_request_id, observed_at)?;
        if initial.is_terminal() {
            return Ok(BrokerApprovalWaitOutcome {
                receipt: initial,
                timed_out: false,
            });
        }

        let until_expiry = millis_between(observed_at, initial.expires_at());
        let effective_wait = timeout.min(until_expiry);
        if effective_wait.is_zero() {
            let receipt = self.poll(
                state,
                consumer_id,
                approval_request_id,
                initial.expires_at(),
            )?;
            return Ok(BrokerApprovalWaitOutcome {
                timed_out: !receipt.is_terminal(),
                receipt,
            });
        }

        let started = Instant::now();
        loop {
            let guard = self.lock_runtime()?;
            let generation = guard.generation;
            let request = self.load_for_consumer(state, consumer_id, approval_request_id)?;
            if request.status() != ApprovalStatus::Pending {
                drop(guard);
                let receipt = BrokerApprovalReceipt::from(&request);
                self.remove_credential_context(approval_request_id)?;
                return Ok(BrokerApprovalWaitOutcome {
                    receipt,
                    timed_out: false,
                });
            }
            let remaining = effective_wait.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                drop(guard);
                let receipt = self.poll(
                    state,
                    consumer_id,
                    approval_request_id,
                    add_elapsed(observed_at, effective_wait),
                )?;
                return Ok(BrokerApprovalWaitOutcome {
                    timed_out: !receipt.is_terminal(),
                    receipt,
                });
            }

            let (guard, wait_result) = self
                .changed
                .wait_timeout_while(guard, remaining, |runtime| runtime.generation == generation)
                .map_err(|_| BrokerApprovalError::RuntimeStateUnavailable)?;
            drop(guard);

            let logical_now = if wait_result.timed_out() {
                add_elapsed(observed_at, effective_wait)
            } else {
                add_elapsed(observed_at, started.elapsed())
            };
            let receipt = self.poll(state, consumer_id, approval_request_id, logical_now)?;
            if receipt.is_terminal() {
                return Ok(BrokerApprovalWaitOutcome {
                    receipt,
                    timed_out: false,
                });
            }
            if wait_result.timed_out() {
                return Ok(BrokerApprovalWaitOutcome {
                    receipt,
                    timed_out: true,
                });
            }
        }
    }

    /// Lists pending requests for the trusted local human control plane.
    pub(crate) fn pending_for_human(
        &self,
        state: &DeviceStateStore,
        observed_at: StateTimestamp,
    ) -> Result<Vec<BrokerHumanApprovalSnapshot>, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        if state
            .expire_pending_approvals(observed_at)
            .map_err(BrokerApprovalError::DeviceState)?
            != 0
        {
            self.notify_change()?;
        }
        let pending = state
            .pending_approvals()
            .map_err(BrokerApprovalError::DeviceState)?;
        let pending_ids = pending
            .iter()
            .map(ApprovalRequest::approval_request_id)
            .collect::<BTreeSet<_>>();
        let mut runtime = self.lock_runtime()?;
        runtime
            .credential_requests
            .retain(|approval_id, _| pending_ids.contains(approval_id));
        let snapshots = pending
            .into_iter()
            .map(|request| {
                let credential_description = runtime
                    .credential_requests
                    .get(&request.approval_request_id())
                    .map(|context| context.display_description().to_owned());
                BrokerHumanApprovalSnapshot {
                    approval_request_id: request.approval_request_id(),
                    subject: request.subject().clone(),
                    created_at: request.created_at(),
                    expires_at: request.expires_at(),
                    credential_description,
                }
            })
            .collect();
        Ok(snapshots)
    }

    /// Applies one idempotent terminal human decision.
    pub(crate) fn resolve(
        &self,
        state: &DeviceStateStore,
        approval_request_id: ApprovalRequestId,
        decision: BrokerApprovalDecision,
        resolved_at: StateTimestamp,
    ) -> Result<BrokerApprovalReceipt, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        let resolution = state
            .resolve_pending_approval(approval_request_id, decision.status(), resolved_at)
            .map_err(BrokerApprovalError::DeviceState)?;
        let request = match resolution {
            StoredApprovalResolution::Resolved(request)
            | StoredApprovalResolution::Expired(request)
            | StoredApprovalResolution::AlreadyTerminal(request) => request,
            StoredApprovalResolution::NotYetCreated => {
                return Err(BrokerApprovalError::InvalidDecisionTime);
            }
            StoredApprovalResolution::Missing => {
                return Err(BrokerApprovalError::ApprovalUnavailable);
            }
        };
        self.remove_credential_context(approval_request_id)?;
        self.notify_change()?;
        Ok(BrokerApprovalReceipt::from(&request))
    }

    pub(crate) fn approve_with_allow_once_grant(
        &self,
        state: &mut DeviceStateStore,
        approval_request_id: ApprovalRequestId,
        expected_subject: &ApprovalSubject,
        grant: &UseGrant,
        resolved_at: StateTimestamp,
    ) -> Result<BrokerApprovalReceipt, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        let resolution = state
            .approve_pending_with_allow_once_grant(
                approval_request_id,
                expected_subject,
                grant,
                resolved_at,
            )
            .map_err(BrokerApprovalError::DeviceState)?;
        let request = match resolution {
            StoredAllowOnceResolution::Approved(request) => request,
            StoredAllowOnceResolution::Expired => {
                self.remove_credential_context(approval_request_id)?;
                self.notify_change()?;
                return Err(BrokerApprovalError::ApprovalUnavailable);
            }
            StoredAllowOnceResolution::AlreadyTerminal(request)
            | StoredAllowOnceResolution::SubjectMismatch(request) => {
                if request.status() != ApprovalStatus::Pending {
                    self.remove_credential_context(approval_request_id)?;
                }
                return Err(BrokerApprovalError::ApprovalUnavailable);
            }
            StoredAllowOnceResolution::NotYetCreated => {
                return Err(BrokerApprovalError::InvalidDecisionTime);
            }
            StoredAllowOnceResolution::Missing => {
                return Err(BrokerApprovalError::ApprovalUnavailable);
            }
        };
        self.remove_credential_context(approval_request_id)?;
        self.notify_change()?;
        Ok(BrokerApprovalReceipt::from(&request))
    }

    pub(crate) fn approve_with_access_rule(
        &self,
        state: &mut DeviceStateStore,
        approval_request_id: ApprovalRequestId,
        expected_subject: &ApprovalSubject,
        proposed_rule: &AccessRule,
        resolved_at: StateTimestamp,
    ) -> Result<(BrokerApprovalReceipt, AccessRule, bool), BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        let resolution = state
            .approve_pending_with_access_rule(
                approval_request_id,
                expected_subject,
                proposed_rule,
                resolved_at,
            )
            .map_err(BrokerApprovalError::DeviceState)?;
        let (request, rule, newly_created) = match resolution {
            StoredAccessRuleResolution::Approved {
                request,
                rule,
                newly_created,
            } => (request, rule, newly_created),
            StoredAccessRuleResolution::Expired => {
                self.remove_credential_context(approval_request_id)?;
                self.notify_change()?;
                return Err(BrokerApprovalError::ApprovalUnavailable);
            }
            StoredAccessRuleResolution::AlreadyTerminal(request)
            | StoredAccessRuleResolution::SubjectMismatch(request)
            | StoredAccessRuleResolution::ConflictingRule(request) => {
                if request.status() != ApprovalStatus::Pending {
                    self.remove_credential_context(approval_request_id)?;
                }
                return Err(BrokerApprovalError::ApprovalUnavailable);
            }
            StoredAccessRuleResolution::NotYetCreated => {
                return Err(BrokerApprovalError::InvalidDecisionTime);
            }
            StoredAccessRuleResolution::Missing => {
                return Err(BrokerApprovalError::ApprovalUnavailable);
            }
        };
        self.remove_credential_context(approval_request_id)?;
        self.notify_change()?;
        Ok((BrokerApprovalReceipt::from(&request), rule, newly_created))
    }

    pub(crate) fn credential_request(
        &self,
        state: &DeviceStateStore,
        approval_request_id: ApprovalRequestId,
        observed_at: StateTimestamp,
    ) -> Result<BrokerAdmittedCredentialRequest, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        if state
            .expire_pending_approvals(observed_at)
            .map_err(BrokerApprovalError::DeviceState)?
            != 0
        {
            self.notify_change()?;
        }
        let request = state
            .approval(approval_request_id)
            .map_err(BrokerApprovalError::DeviceState)?
            .ok_or(BrokerApprovalError::ApprovalUnavailable)?;
        if request.status() != ApprovalStatus::Pending
            || !matches!(request.subject(), ApprovalSubject::CredentialAccess { .. })
        {
            self.remove_credential_context(approval_request_id)?;
            return Err(BrokerApprovalError::ContextUnavailable);
        }
        let context = self
            .lock_runtime()?
            .credential_requests
            .get(&approval_request_id)
            .map(BrokerAdmittedCredentialRequest::duplicate)
            .ok_or(BrokerApprovalError::ContextUnavailable)?;
        let ApprovalSubject::CredentialAccess {
            consumer_id,
            vault_id,
            capability,
        } = request.subject()
        else {
            return Err(BrokerApprovalError::ContextUnavailable);
        };
        if context.consumer_id() != *consumer_id
            || context.vault_id() != *vault_id
            || context.capability() != *capability
        {
            return Err(BrokerApprovalError::ContextUnavailable);
        }
        Ok(context)
    }

    pub(crate) fn cancel_process_local_pending(
        &self,
        state: &DeviceStateStore,
        resolved_at: StateTimestamp,
    ) -> Result<usize, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        let expired = state
            .expire_pending_approvals(resolved_at)
            .map_err(BrokerApprovalError::DeviceState)?;
        let pending = state
            .pending_approvals()
            .map_err(BrokerApprovalError::DeviceState)?;
        let mut cancelled = 0_usize;
        for request in pending {
            if matches!(
                request.subject(),
                ApprovalSubject::Pairing { .. } | ApprovalSubject::CredentialAccess { .. }
            ) {
                let decision_time = later_timestamp(resolved_at, request.created_at());
                if matches!(
                    state
                        .resolve_pending_approval(
                            request.approval_request_id(),
                            ApprovalStatus::Cancelled,
                            decision_time,
                        )
                        .map_err(BrokerApprovalError::DeviceState)?,
                    StoredApprovalResolution::Resolved(_)
                ) {
                    cancelled = cancelled.saturating_add(1);
                }
            }
        }
        self.lock_runtime()?.credential_requests.clear();
        if expired != 0 || cancelled != 0 {
            self.notify_change()?;
        }
        Ok(cancelled)
    }

    pub(crate) fn reconcile_after_revocation(
        &self,
        state: &DeviceStateStore,
    ) -> Result<usize, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        let pending_ids = state
            .pending_approvals()
            .map_err(BrokerApprovalError::DeviceState)?
            .into_iter()
            .map(|request| request.approval_request_id())
            .collect::<BTreeSet<_>>();
        let mut runtime = self.lock_runtime()?;
        let before = runtime.credential_requests.len();
        runtime
            .credential_requests
            .retain(|approval_id, _| pending_ids.contains(approval_id));
        let removed = before.saturating_sub(runtime.credential_requests.len());
        runtime.generation = runtime.generation.wrapping_add(1);
        drop(runtime);
        self.changed.notify_all();
        Ok(removed)
    }

    fn submit_internal(
        &self,
        state: &DeviceStateStore,
        subject: ApprovalSubject,
        credential_context: Option<BrokerAdmittedCredentialRequest>,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<BrokerApprovalSubmission, BrokerApprovalError> {
        let _submission = self.lock_submission()?;
        let mut credential_context = credential_context;
        validate_lifetime(created_at, expires_at)?;
        validate_subject(state, &subject)?;
        state
            .expire_pending_approvals(created_at)
            .map_err(BrokerApprovalError::DeviceState)?;
        let mut canonical =
            Zeroizing::new(canonical_approval(&subject, credential_context.as_ref())?);
        let digest = state
            .approval_coalescing_digest(&canonical)
            .map_err(BrokerApprovalError::DeviceState)?;
        canonical.zeroize();

        for _ in 0..MAX_INSERT_RETRIES {
            if let Some(existing) = state
                .pending_approval_by_digest(&digest)
                .map_err(BrokerApprovalError::DeviceState)?
            {
                if existing.subject() != &subject {
                    return Err(BrokerApprovalError::EquivalenceCollision);
                }
                self.require_equivalent_credential_context(
                    existing.approval_request_id(),
                    credential_context.as_ref(),
                )?;
                self.register_credential_context(
                    existing.approval_request_id(),
                    credential_context.take(),
                )?;
                return Ok(BrokerApprovalSubmission {
                    receipt: BrokerApprovalReceipt::from(&existing),
                    coalesced: true,
                });
            }
            if state
                .pending_approvals()
                .map_err(BrokerApprovalError::DeviceState)?
                .len()
                >= MAX_PENDING_APPROVALS
            {
                return Err(BrokerApprovalError::PendingLimitReached);
            }
            let request = ApprovalRequest::pending(subject.clone(), digest, created_at, expires_at)
                .map_err(|_| BrokerApprovalError::InvalidLifetime)?;
            match state.insert_approval(&request) {
                Ok(()) => {
                    self.register_credential_context(
                        request.approval_request_id(),
                        credential_context.take(),
                    )?;
                    self.notify_change()?;
                    return Ok(BrokerApprovalSubmission {
                        receipt: BrokerApprovalReceipt::from(&request),
                        coalesced: false,
                    });
                }
                Err(DeviceStateError::Conflict) => continue,
                Err(error) => return Err(BrokerApprovalError::DeviceState(error)),
            }
        }
        Err(BrokerApprovalError::EquivalenceCollision)
    }

    fn load_for_consumer(
        &self,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        approval_request_id: ApprovalRequestId,
    ) -> Result<ApprovalRequest, BrokerApprovalError> {
        let request = state
            .approval(approval_request_id)
            .map_err(BrokerApprovalError::DeviceState)?
            .ok_or(BrokerApprovalError::ApprovalUnavailable)?;
        if request.subject().consumer_id() != consumer_id {
            return Err(BrokerApprovalError::ApprovalUnavailable);
        }
        Ok(request)
    }

    fn register_credential_context(
        &self,
        approval_request_id: ApprovalRequestId,
        credential_context: Option<BrokerAdmittedCredentialRequest>,
    ) -> Result<(), BrokerApprovalError> {
        let Some(context) = credential_context else {
            return Ok(());
        };
        self.lock_runtime()?
            .credential_requests
            .entry(approval_request_id)
            .or_insert(context);
        Ok(())
    }

    fn require_equivalent_credential_context(
        &self,
        approval_request_id: ApprovalRequestId,
        proposed: Option<&BrokerAdmittedCredentialRequest>,
    ) -> Result<(), BrokerApprovalError> {
        let Some(proposed) = proposed else {
            return Ok(());
        };
        let runtime = self.lock_runtime()?;
        let existing = runtime
            .credential_requests
            .get(&approval_request_id)
            .ok_or(BrokerApprovalError::ContextUnavailable)?;
        if existing.consumer_id() != proposed.consumer_id()
            || existing.vault_id() != proposed.vault_id()
            || existing.capability() != proposed.capability()
            || existing.normalized_description() != proposed.normalized_description()
        {
            return Err(BrokerApprovalError::EquivalenceCollision);
        }
        Ok(())
    }

    fn remove_credential_context(
        &self,
        approval_request_id: ApprovalRequestId,
    ) -> Result<(), BrokerApprovalError> {
        self.lock_runtime()?
            .credential_requests
            .remove(&approval_request_id);
        Ok(())
    }

    fn notify_change(&self) -> Result<(), BrokerApprovalError> {
        let mut runtime = self.lock_runtime()?;
        runtime.generation = runtime.generation.wrapping_add(1);
        drop(runtime);
        self.changed.notify_all();
        Ok(())
    }

    fn lock_runtime(&self) -> Result<MutexGuard<'_, ApprovalRuntimeState>, BrokerApprovalError> {
        self.runtime
            .lock()
            .map_err(|_| BrokerApprovalError::RuntimeStateUnavailable)
    }

    fn lock_submission(&self) -> Result<MutexGuard<'_, ()>, BrokerApprovalError> {
        self.submission
            .lock()
            .map_err(|_| BrokerApprovalError::RuntimeStateUnavailable)
    }
}

fn validate_lifetime(
    created_at: StateTimestamp,
    expires_at: StateTimestamp,
) -> Result<(), BrokerApprovalError> {
    let lifetime_ms = expires_at
        .unix_millis()
        .checked_sub(created_at.unix_millis())
        .ok_or(BrokerApprovalError::InvalidLifetime)?;
    let maximum_ms = i64::try_from(MAX_APPROVAL_LIFETIME.as_millis())
        .map_err(|_| BrokerApprovalError::InvalidLifetime)?;
    if lifetime_ms <= 0 || lifetime_ms > maximum_ms {
        return Err(BrokerApprovalError::InvalidLifetime);
    }
    Ok(())
}

fn validate_subject(
    state: &DeviceStateStore,
    subject: &ApprovalSubject,
) -> Result<(), BrokerApprovalError> {
    if !matches!(subject, ApprovalSubject::Pairing { .. })
        && state
            .consumer(subject.consumer_id())
            .map_err(BrokerApprovalError::DeviceState)?
            .is_none()
    {
        return Err(BrokerApprovalError::ConsumerUnavailable);
    }
    let capability = match subject {
        ApprovalSubject::Access { target } => Some(target.capability()),
        ApprovalSubject::CredentialAccess { capability, .. } => Some(*capability),
        ApprovalSubject::Pairing { .. } | ApprovalSubject::Unlock { .. } => None,
    };
    if let Some(capability) = capability {
        if capability.version() != 1
            || !matches!(
                capability.name(),
                CapabilityName::CredentialSearch
                    | CapabilityName::HttpRequest
                    | CapabilityName::ProcessRun
            )
        {
            return Err(BrokerApprovalError::InvalidRequest);
        }
    }
    Ok(())
}

fn canonical_approval(
    subject: &ApprovalSubject,
    credential_context: Option<&BrokerAdmittedCredentialRequest>,
) -> Result<Vec<u8>, BrokerApprovalError> {
    let mut canonical = Vec::with_capacity(512);
    push_chunk(&mut canonical, APPROVAL_EQUIVALENCE_DOMAIN)?;
    match subject {
        ApprovalSubject::Pairing {
            consumer_id,
            pairing_public_key,
            observed_identity,
        } => {
            push_chunk(&mut canonical, b"pairing")?;
            push_chunk(&mut canonical, consumer_id.as_bytes())?;
            push_chunk(&mut canonical, pairing_public_key)?;
            push_optional(&mut canonical, observed_identity.executable_name())?;
            push_optional(&mut canonical, observed_identity.bundle_identifier())?;
            push_optional(&mut canonical, observed_identity.team_identifier())?;
            push_optional_bytes(
                &mut canonical,
                observed_identity
                    .code_signature_digest()
                    .map(|value| value.as_slice()),
            )?;
        }
        ApprovalSubject::Unlock {
            consumer_id,
            vault_id,
        } => {
            push_chunk(&mut canonical, b"unlock")?;
            push_chunk(&mut canonical, consumer_id.as_bytes())?;
            push_chunk(&mut canonical, vault_id.as_bytes())?;
        }
        ApprovalSubject::Access { target } => {
            let field = target.field_scope();
            push_chunk(&mut canonical, b"access")?;
            push_chunk(&mut canonical, target.consumer_id().as_bytes())?;
            push_chunk(&mut canonical, field.vault_id().as_bytes())?;
            push_chunk(&mut canonical, field.credential_id().as_bytes())?;
            push_chunk(&mut canonical, field.secret_field_id().as_bytes())?;
            push_capability(&mut canonical, target.capability())?;
        }
        ApprovalSubject::CredentialAccess {
            consumer_id,
            vault_id,
            capability,
        } => {
            let context = credential_context.ok_or(BrokerApprovalError::ContextUnavailable)?;
            if context.consumer_id() != *consumer_id
                || context.vault_id() != *vault_id
                || context.capability() != *capability
            {
                return Err(BrokerApprovalError::ContextUnavailable);
            }
            push_chunk(&mut canonical, b"credential-access")?;
            push_chunk(&mut canonical, consumer_id.as_bytes())?;
            push_chunk(&mut canonical, vault_id.as_bytes())?;
            push_capability(&mut canonical, *capability)?;
            push_chunk(&mut canonical, context.normalized_description().as_bytes())?;
        }
    }
    Ok(canonical)
}

fn push_capability(
    canonical: &mut Vec<u8>,
    capability: crate::Capability,
) -> Result<(), BrokerApprovalError> {
    push_chunk(canonical, capability.name().as_str().as_bytes())?;
    canonical.extend_from_slice(&capability.version().to_be_bytes());
    Ok(())
}

fn push_optional(canonical: &mut Vec<u8>, value: Option<&str>) -> Result<(), BrokerApprovalError> {
    push_optional_bytes(canonical, value.map(str::as_bytes))
}

fn push_optional_bytes(
    canonical: &mut Vec<u8>,
    value: Option<&[u8]>,
) -> Result<(), BrokerApprovalError> {
    match value {
        Some(value) => {
            canonical.push(1);
            push_chunk(canonical, value)?;
        }
        None => canonical.push(0),
    }
    Ok(())
}

fn push_chunk(canonical: &mut Vec<u8>, value: &[u8]) -> Result<(), BrokerApprovalError> {
    let length = u32::try_from(value.len()).map_err(|_| BrokerApprovalError::InvalidRequest)?;
    canonical.extend_from_slice(&length.to_be_bytes());
    canonical.extend_from_slice(value);
    Ok(())
}

fn millis_between(start: StateTimestamp, end: StateTimestamp) -> Duration {
    let millis = end.unix_millis().saturating_sub(start.unix_millis());
    Duration::from_millis(u64::try_from(millis).unwrap_or(0))
}

fn add_elapsed(start: StateTimestamp, elapsed: Duration) -> StateTimestamp {
    let elapsed_ms = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
    StateTimestamp::from_unix_millis(start.unix_millis().saturating_add(elapsed_ms))
        .unwrap_or(start)
}

fn later_timestamp(left: StateTimestamp, right: StateTimestamp) -> StateTimestamp {
    if left >= right {
        left
    } else {
        right
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use psw_core::{CredentialId, SecretFieldId, VaultId};

    use super::*;
    use crate::credential_matching::{BrokerCredentialMatchingManager, BrokerNewCredentialRequest};
    use crate::device_key::DeviceRootKey;
    use crate::state_model::{
        AuthorizationTarget, Capability, Consumer, CredentialFieldScope, ObservedConsumerIdentity,
    };

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
                "keptnear-approval-{label}-{}-{nanos}-{sequence}",
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
            DeviceRootKey::from_stored_bytes(vec![self.key_byte; 32]).expect("root key")
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

    fn insert_consumer(state: &DeviceStateStore, key_byte: u8) -> Consumer {
        let consumer = consumer(key_byte, 10);
        state.insert_consumer(&consumer).expect("insert Consumer");
        consumer
    }

    fn manager(state: &DeviceStateStore) -> BrokerApprovalManager {
        BrokerApprovalManager::restore(state, timestamp(20))
            .expect("restore approvals")
            .0
    }

    fn access_subject(consumer_id: ConsumerId) -> ApprovalSubject {
        ApprovalSubject::Access {
            target: AuthorizationTarget::new(
                consumer_id,
                CredentialFieldScope::new(
                    VaultId::generate(),
                    CredentialId::generate(),
                    SecretFieldId::generate(),
                ),
                Capability::v1(CapabilityName::HttpRequest),
            ),
        }
    }

    fn admitted_request(
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        vault_id: VaultId,
        description: &str,
    ) -> BrokerAdmittedCredentialRequest {
        let request = BrokerNewCredentialRequest::new(
            consumer_id,
            vault_id,
            Capability::v1(CapabilityName::CredentialSearch),
            description.to_owned(),
        )
        .expect("request");
        BrokerCredentialMatchingManager::admit(state, request).expect("admit request")
    }

    #[test]
    fn exact_requests_coalesce_to_one_stable_consumer_safe_receipt() {
        let directory = TestStateDirectory::new("coalesce", 31);
        let state = directory.initialize();
        let consumer = insert_consumer(&state, 41);
        let manager = manager(&state);
        let subject = access_subject(consumer.consumer_id());

        let first = manager
            .submit(&state, subject.clone(), timestamp(100), timestamp(200))
            .expect("submit");
        let repeated = manager
            .submit(&state, subject, timestamp(110), timestamp(250))
            .expect("coalesce");

        assert!(!first.coalesced());
        assert!(repeated.coalesced());
        assert_eq!(
            repeated.receipt().approval_request_id(),
            first.receipt().approval_request_id()
        );
        assert_eq!(repeated.receipt().expires_at(), timestamp(200));
        assert_eq!(
            state.pending_approvals().expect("pending approvals").len(),
            1
        );

        let debug = format!("{:?}", repeated.receipt());
        assert!(!debug.contains("approval_request_"));
        assert!(!debug.contains("credential_"));
        assert!(!debug.contains("vault_"));
    }

    #[test]
    fn coalescing_digest_is_device_keyed_and_request_specific() {
        let first_directory = TestStateDirectory::new("digest-first", 51);
        let second_directory = TestStateDirectory::new("digest-second", 52);
        let first = first_directory.initialize();
        let second = second_directory.initialize();
        let consumer_id = ConsumerId::generate();
        let subject = access_subject(consumer_id);
        let canonical = canonical_approval(&subject, None).expect("canonical request");
        let changed = canonical_approval(
            &ApprovalSubject::Unlock {
                consumer_id,
                vault_id: VaultId::generate(),
            },
            None,
        )
        .expect("changed canonical request");

        let first_digest = first
            .approval_coalescing_digest(&canonical)
            .expect("first digest");
        let second_digest = second
            .approval_coalescing_digest(&canonical)
            .expect("second digest");
        let changed_digest = first
            .approval_coalescing_digest(&changed)
            .expect("changed digest");

        assert_ne!(first_digest, second_digest);
        assert_ne!(first_digest, changed_digest);
        assert!(!format!("{first:?}").contains(&hex::encode(first_digest)));
    }

    #[test]
    fn polling_is_consumer_scoped_and_expiry_wins_at_exact_boundary() {
        let directory = TestStateDirectory::new("expiry", 61);
        let state = directory.initialize();
        let owner = insert_consumer(&state, 62);
        let other = insert_consumer(&state, 63);
        let manager = manager(&state);
        let submission = manager
            .submit(
                &state,
                access_subject(owner.consumer_id()),
                timestamp(100),
                timestamp(200),
            )
            .expect("submit");
        let approval_id = submission.receipt().approval_request_id();

        assert!(matches!(
            manager.poll(&state, other.consumer_id(), approval_id, timestamp(150)),
            Err(BrokerApprovalError::ApprovalUnavailable)
        ));
        assert!(matches!(
            manager.resolve(
                &state,
                approval_id,
                BrokerApprovalDecision::Approve,
                timestamp(99)
            ),
            Err(BrokerApprovalError::InvalidDecisionTime)
        ));
        assert_eq!(
            manager
                .poll(&state, owner.consumer_id(), approval_id, timestamp(199))
                .expect("pending")
                .status(),
            ApprovalStatus::Pending
        );

        let expired = manager
            .resolve(
                &state,
                approval_id,
                BrokerApprovalDecision::Approve,
                timestamp(200),
            )
            .expect("expire at boundary");
        assert_eq!(expired.status(), ApprovalStatus::Expired);
        assert_eq!(expired.resolved_at(), Some(timestamp(200)));
        assert_eq!(
            manager
                .resolve(
                    &state,
                    approval_id,
                    BrokerApprovalDecision::Deny,
                    timestamp(220)
                )
                .expect("idempotent terminal state")
                .status(),
            ApprovalStatus::Expired
        );
    }

    #[test]
    fn first_terminal_decision_is_idempotent() {
        let directory = TestStateDirectory::new("decision", 71);
        let state = directory.initialize();
        let consumer = insert_consumer(&state, 72);
        let manager = manager(&state);
        let approval_id = manager
            .submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(100),
                timestamp(300),
            )
            .expect("submit")
            .receipt()
            .approval_request_id();

        let approved = manager
            .resolve(
                &state,
                approval_id,
                BrokerApprovalDecision::Approve,
                timestamp(150),
            )
            .expect("approve");
        let repeated = manager
            .resolve(
                &state,
                approval_id,
                BrokerApprovalDecision::Deny,
                timestamp(160),
            )
            .expect("repeat decision");

        assert_eq!(approved.status(), ApprovalStatus::Approved);
        assert_eq!(repeated.status(), ApprovalStatus::Approved);
        assert_eq!(repeated.resolved_at(), Some(timestamp(150)));
    }

    #[test]
    fn lifetime_wait_and_pending_count_are_bounded() {
        let directory = TestStateDirectory::new("bounds", 81);
        let state = directory.initialize();
        let consumer = insert_consumer(&state, 82);
        let manager = manager(&state);

        assert!(matches!(
            manager.submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(100),
                timestamp(100)
            ),
            Err(BrokerApprovalError::InvalidLifetime)
        ));
        let over_limit = timestamp(
            100 + i64::try_from(MAX_APPROVAL_LIFETIME.as_millis()).expect("duration") + 1,
        );
        assert!(matches!(
            manager.submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(100),
                over_limit
            ),
            Err(BrokerApprovalError::InvalidLifetime)
        ));
        let unsupported = ApprovalSubject::Access {
            target: AuthorizationTarget::new(
                consumer.consumer_id(),
                CredentialFieldScope::new(
                    VaultId::generate(),
                    CredentialId::generate(),
                    SecretFieldId::generate(),
                ),
                Capability::v1(CapabilityName::GrantStatus),
            ),
        };
        assert!(matches!(
            manager.submit(&state, unsupported, timestamp(100), timestamp(200)),
            Err(BrokerApprovalError::InvalidRequest)
        ));
        assert!(matches!(
            manager.wait(
                &state,
                consumer.consumer_id(),
                ApprovalRequestId::generate(),
                timestamp(100),
                Duration::ZERO
            ),
            Err(BrokerApprovalError::InvalidWait)
        ));
        assert!(matches!(
            manager.wait(
                &state,
                consumer.consumer_id(),
                ApprovalRequestId::generate(),
                timestamp(100),
                MAX_APPROVAL_WAIT + Duration::from_millis(1)
            ),
            Err(BrokerApprovalError::InvalidWait)
        ));

        for _ in 0..MAX_PENDING_APPROVALS {
            manager
                .submit(
                    &state,
                    ApprovalSubject::Unlock {
                        consumer_id: consumer.consumer_id(),
                        vault_id: VaultId::generate(),
                    },
                    timestamp(100),
                    timestamp(300),
                )
                .expect("bounded pending approval");
        }
        assert!(matches!(
            manager.submit(
                &state,
                ApprovalSubject::Unlock {
                    consumer_id: consumer.consumer_id(),
                    vault_id: VaultId::generate(),
                },
                timestamp(100),
                timestamp(300)
            ),
            Err(BrokerApprovalError::PendingLimitReached)
        ));
    }

    #[test]
    fn credential_request_description_stays_process_local_and_is_zeroized_on_terminal_state() {
        let directory = TestStateDirectory::new("credential-context", 91);
        let state = directory.initialize();
        let consumer = insert_consumer(&state, 92);
        let vault_id = VaultId::generate();
        let manager = manager(&state);
        let first = admitted_request(
            &state,
            consumer.consumer_id(),
            vault_id,
            "  GitHub Release Token  ",
        );
        let equivalent = admitted_request(
            &state,
            consumer.consumer_id(),
            vault_id,
            "github release token",
        );

        let submission = manager
            .submit_credential_request(&state, first, timestamp(100), timestamp(300))
            .expect("submit credential request");
        let repeated = manager
            .submit_credential_request(&state, equivalent, timestamp(110), timestamp(300))
            .expect("coalesce credential request");
        let approval_id = submission.receipt().approval_request_id();
        assert!(repeated.coalesced());
        assert_eq!(repeated.receipt().approval_request_id(), approval_id);

        let snapshots = manager
            .pending_for_human(&state, timestamp(120))
            .expect("human snapshots");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].credential_description(),
            Some("GitHub Release Token")
        );
        let debug = format!("{:?}", snapshots[0]);
        assert!(!debug.contains("GitHub"));
        assert!(!debug.contains("approval_request_"));
        assert_eq!(
            manager
                .credential_request(&state, approval_id, timestamp(120))
                .expect("process context")
                .normalized_description(),
            "github release token"
        );

        manager
            .resolve(
                &state,
                approval_id,
                BrokerApprovalDecision::Deny,
                timestamp(130),
            )
            .expect("deny");
        assert!(matches!(
            manager.credential_request(&state, approval_id, timestamp(140)),
            Err(BrokerApprovalError::ContextUnavailable)
        ));
        assert!(state
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("rules")
            .is_empty());
        assert!(state
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("grants")
            .is_empty());
    }

    #[test]
    fn restart_resumes_exact_requests_and_cancels_process_local_requests() {
        let directory = TestStateDirectory::new("restore", 101);
        let state = directory.initialize();
        let consumer = insert_consumer(&state, 102);
        let manager = manager(&state);
        let exact_access = manager
            .submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(100),
                timestamp(300),
            )
            .expect("exact access");
        let unlock = manager
            .submit(
                &state,
                ApprovalSubject::Unlock {
                    consumer_id: consumer.consumer_id(),
                    vault_id: VaultId::generate(),
                },
                timestamp(100),
                timestamp(300),
            )
            .expect("unlock");
        let pairing = manager
            .submit(
                &state,
                ApprovalSubject::Pairing {
                    consumer_id: ConsumerId::generate(),
                    pairing_public_key: [103; 32],
                    observed_identity: ObservedConsumerIdentity::default(),
                },
                timestamp(100),
                timestamp(300),
            )
            .expect("pairing");
        let credential = manager
            .submit_credential_request(
                &state,
                admitted_request(
                    &state,
                    consumer.consumer_id(),
                    VaultId::generate(),
                    "deployment token",
                ),
                timestamp(100),
                timestamp(300),
            )
            .expect("credential");
        let expired = manager
            .submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(100),
                timestamp(150),
            )
            .expect("soon expired");
        drop(manager);
        drop(state);

        let reopened = directory.open();
        let (restored, summary) =
            BrokerApprovalManager::restore(&reopened, timestamp(200)).expect("restore");
        assert_eq!(summary.expired(), 1);
        assert_eq!(summary.process_local_cancelled(), 2);
        assert_eq!(
            reopened
                .approval(exact_access.receipt().approval_request_id())
                .expect("access")
                .expect("access exists")
                .status(),
            ApprovalStatus::Pending
        );
        assert_eq!(
            reopened
                .approval(unlock.receipt().approval_request_id())
                .expect("unlock")
                .expect("unlock exists")
                .status(),
            ApprovalStatus::Pending
        );
        assert_eq!(
            reopened
                .approval(pairing.receipt().approval_request_id())
                .expect("pairing")
                .expect("pairing exists")
                .status(),
            ApprovalStatus::Cancelled
        );
        assert_eq!(
            reopened
                .approval(credential.receipt().approval_request_id())
                .expect("credential")
                .expect("credential exists")
                .status(),
            ApprovalStatus::Cancelled
        );
        assert_eq!(
            reopened
                .approval(expired.receipt().approval_request_id())
                .expect("expired")
                .expect("expired exists")
                .status(),
            ApprovalStatus::Expired
        );
        assert!(matches!(
            restored.credential_request(
                &reopened,
                credential.receipt().approval_request_id(),
                timestamp(210)
            ),
            Err(BrokerApprovalError::ContextUnavailable)
        ));
    }

    #[test]
    fn unrelated_approval_changes_do_not_end_a_targeted_wait() {
        let directory = TestStateDirectory::new("unrelated-wakeup", 106);
        let state = directory.initialize();
        let consumer = insert_consumer(&state, 107);
        let manager = Arc::new(manager(&state));
        let target_id = manager
            .submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(100),
                timestamp(500),
            )
            .expect("target approval")
            .receipt()
            .approval_request_id();
        let unrelated_id = manager
            .submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(100),
                timestamp(500),
            )
            .expect("unrelated approval")
            .receipt()
            .approval_request_id();
        let waiter_manager = Arc::clone(&manager);
        let waiter_state = directory.open();
        let consumer_id = consumer.consumer_id();
        let (started_tx, started_rx) = mpsc::channel();
        let (outcome_tx, outcome_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            started_tx.send(()).expect("signal waiter");
            let outcome = waiter_manager
                .wait(
                    &waiter_state,
                    consumer_id,
                    target_id,
                    timestamp(120),
                    Duration::from_secs(2),
                )
                .expect("wait");
            outcome_tx.send(outcome).expect("send outcome");
        });

        started_rx.recv().expect("waiter started");
        thread::sleep(Duration::from_millis(25));
        manager
            .resolve(
                &state,
                unrelated_id,
                BrokerApprovalDecision::Approve,
                timestamp(130),
            )
            .expect("resolve unrelated approval");
        thread::sleep(Duration::from_millis(50));
        assert!(matches!(
            outcome_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        manager
            .resolve(
                &state,
                target_id,
                BrokerApprovalDecision::Deny,
                timestamp(140),
            )
            .expect("resolve target");
        let outcome = outcome_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("target outcome");
        assert!(!outcome.timed_out());
        assert_eq!(outcome.receipt().status(), ApprovalStatus::Denied);
        waiter.join().expect("waiter");
    }

    #[test]
    fn concurrent_submissions_coalesce_and_waiters_observe_resolution() {
        let directory = TestStateDirectory::new("concurrency", 111);
        let state = directory.initialize();
        let consumer = insert_consumer(&state, 112);
        let manager = Arc::new(manager(&state));
        let subject = access_subject(consumer.consumer_id());
        let barrier = Arc::new(Barrier::new(8));
        let mut submitters = Vec::new();
        for _ in 0..8 {
            let worker_manager = Arc::clone(&manager);
            let worker_barrier = Arc::clone(&barrier);
            let worker_state = directory.open();
            let worker_subject = subject.clone();
            submitters.push(thread::spawn(move || {
                worker_barrier.wait();
                worker_manager
                    .submit(
                        &worker_state,
                        worker_subject,
                        timestamp(100),
                        timestamp(300),
                    )
                    .expect("concurrent submit")
                    .receipt()
                    .approval_request_id()
            }));
        }
        let ids = submitters
            .into_iter()
            .map(|submitter| submitter.join().expect("submitter"))
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 1);
        let approval_id = *ids.iter().next().expect("approval id");
        assert_eq!(state.pending_approvals().expect("pending").len(), 1);

        let waiter_manager = Arc::clone(&manager);
        let waiter_state = directory.open();
        let consumer_id = consumer.consumer_id();
        let (started_tx, started_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            started_tx.send(()).expect("signal waiter");
            waiter_manager
                .wait(
                    &waiter_state,
                    consumer_id,
                    approval_id,
                    timestamp(120),
                    Duration::from_secs(2),
                )
                .expect("wait")
        });
        started_rx.recv().expect("waiter started");
        thread::sleep(Duration::from_millis(25));
        manager
            .resolve(
                &state,
                approval_id,
                BrokerApprovalDecision::Approve,
                timestamp(130),
            )
            .expect("resolve");
        let outcome = waiter.join().expect("waiter");
        assert!(!outcome.timed_out());
        assert_eq!(outcome.receipt().status(), ApprovalStatus::Approved);

        let timeout_id = manager
            .submit(
                &state,
                access_subject(consumer.consumer_id()),
                timestamp(200),
                timestamp(400),
            )
            .expect("timeout request")
            .receipt()
            .approval_request_id();
        let timed_out = manager
            .wait(
                &state,
                consumer.consumer_id(),
                timeout_id,
                timestamp(210),
                Duration::from_millis(5),
            )
            .expect("bounded timeout");
        assert!(timed_out.timed_out());
        assert_eq!(timed_out.receipt().status(), ApprovalStatus::Pending);
    }
}
