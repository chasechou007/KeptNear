use std::fmt::{Debug, Formatter};
use std::time::Duration;

use psw_core::{CredentialId, SecretFieldId, SecretFieldKind, VaultId};
use zeroize::Zeroize;

use crate::approval::{
    BrokerApprovalReceipt, BrokerApprovalSubmission, BrokerApprovalWaitOutcome, MAX_APPROVAL_WAIT,
};
use crate::credential_search::BrokerCredentialSearchQuery;
use crate::http_request::{
    BrokerHttpHeader, BrokerHttpMethod, BrokerHttpRequest, BrokerHttpResponse,
};
use crate::process_run::{
    BrokerProcessEnvironment, BrokerProcessRunRequest, BrokerProcessRunResponse,
};
use crate::protocol::BrokerProtocolValidationError;
use crate::state_model::{
    ApprovalRequestId, ApprovalStatus, Capability, CapabilityName, CredentialFieldScope,
    GrantScope, StateTimestamp, UsageProfileId, UseGrant, UseGrantId, VaultSessionId,
};

/// Common exact credential scope presented by an authenticated capability call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerCredentialOperationTarget {
    use_grant_id: UseGrantId,
    field_scope: CredentialFieldScope,
    secret_kind: SecretFieldKind,
    vault_session_id: VaultSessionId,
}

impl BrokerCredentialOperationTarget {
    /// Creates an exact Use Grant, field, kind, and unlock-session reference.
    #[must_use]
    pub const fn new(
        use_grant_id: UseGrantId,
        field_scope: CredentialFieldScope,
        secret_kind: SecretFieldKind,
        vault_session_id: VaultSessionId,
    ) -> Self {
        Self {
            use_grant_id,
            field_scope,
            secret_kind,
            vault_session_id,
        }
    }

    /// Returns the presented Use Grant identity.
    #[must_use]
    pub const fn use_grant_id(self) -> UseGrantId {
        self.use_grant_id
    }

    /// Returns the exact stable credential field scope.
    #[must_use]
    pub const fn field_scope(self) -> CredentialFieldScope {
        self.field_scope
    }

    /// Returns the expected provider-neutral secret kind.
    #[must_use]
    pub const fn secret_kind(self) -> SecretFieldKind {
        self.secret_kind
    }

    /// Returns the process-owned unlock session identity.
    #[must_use]
    pub const fn vault_session_id(self) -> VaultSessionId {
        self.vault_session_id
    }
}

/// Structured `credential.search` version 1 request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerCredentialSearchRequest {
    target: BrokerCredentialOperationTarget,
    query: String,
}

impl BrokerCredentialSearchRequest {
    /// Creates a bounded exact-scope metadata search request.
    pub fn new(
        target: BrokerCredentialOperationTarget,
        query: String,
    ) -> Result<Self, BrokerProtocolValidationError> {
        BrokerCredentialSearchQuery::new(query.clone())
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?;
        Ok(Self { target, query })
    }

    /// Returns the presented exact operation scope.
    #[must_use]
    pub const fn target(&self) -> BrokerCredentialOperationTarget {
        self.target
    }

    /// Rebuilds the validated runtime query.
    pub(crate) fn runtime_query(
        &self,
    ) -> Result<BrokerCredentialSearchQuery, BrokerProtocolValidationError> {
        BrokerCredentialSearchQuery::new(self.query.clone())
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)
    }

    pub(crate) fn query(&self) -> &str {
        &self.query
    }
}

impl Debug for BrokerCredentialSearchRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerCredentialSearchRequest")
            .field("target", &self.target)
            .field("query", &"<redacted>")
            .finish()
    }
}

impl Drop for BrokerCredentialSearchRequest {
    fn drop(&mut self) {
        self.query.zeroize();
    }
}

/// Structured request for a new exact-field or human-matched authorization.
#[derive(Clone, Eq, PartialEq)]
pub enum BrokerAccessRequest {
    /// Requests access to one already-known stable field scope.
    Exact {
        /// Exact vault, credential, and Secret Field identity.
        field_scope: CredentialFieldScope,
        /// Credential-use capability being requested.
        capability: Capability,
    },
    /// Requests that the local human match a credential without exposing candidates.
    Credential {
        /// Stable vault in which matching is allowed.
        vault_id: VaultId,
        /// Credential-use capability being requested.
        capability: Capability,
        /// Bounded human-facing description, never candidate metadata.
        description: String,
    },
    /// Polls one prior Consumer-owned approval without returning its subject.
    Status {
        /// Stable approval identity returned by an earlier submission.
        approval_request_id: ApprovalRequestId,
    },
    /// Re-establishes one prior Consumer-owned approval after adapter restart.
    Resume {
        /// Stable approval identity returned by an earlier submission.
        approval_request_id: ApprovalRequestId,
    },
    /// Waits for one prior Consumer-owned approval for a bounded duration.
    Wait {
        /// Stable approval identity returned by an earlier submission.
        approval_request_id: ApprovalRequestId,
        /// Caller-selected wait bounded by [`MAX_APPROVAL_WAIT`].
        timeout: Duration,
    },
}

impl BrokerAccessRequest {
    /// Creates an access request for one already-known exact field.
    pub fn exact(
        field_scope: CredentialFieldScope,
        capability: Capability,
    ) -> Result<Self, BrokerProtocolValidationError> {
        validate_requested_credential_capability(capability)?;
        Ok(Self::Exact {
            field_scope,
            capability,
        })
    }

    /// Creates a bounded request for human-side credential matching.
    pub fn credential(
        vault_id: VaultId,
        capability: Capability,
        description: String,
    ) -> Result<Self, BrokerProtocolValidationError> {
        validate_requested_credential_capability(capability)?;
        crate::credential_matching::validate_credential_request_description(&description)
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?;
        Ok(Self::Credential {
            vault_id,
            capability,
            description,
        })
    }

    /// Creates a Consumer-scoped approval status request.
    #[must_use]
    pub const fn status(approval_request_id: ApprovalRequestId) -> Self {
        Self::Status {
            approval_request_id,
        }
    }

    /// Creates a Consumer-scoped approval resumption request.
    #[must_use]
    pub const fn resume(approval_request_id: ApprovalRequestId) -> Self {
        Self::Resume {
            approval_request_id,
        }
    }

    /// Creates a bounded Consumer-scoped approval wait request.
    pub fn wait(
        approval_request_id: ApprovalRequestId,
        timeout: Duration,
    ) -> Result<Self, BrokerProtocolValidationError> {
        if timeout.is_zero() || timeout > MAX_APPROVAL_WAIT {
            return Err(BrokerProtocolValidationError::InvalidRequest);
        }
        Ok(Self::Wait {
            approval_request_id,
            timeout,
        })
    }

    /// Returns the downstream credential-use capability requested by a submission.
    #[must_use]
    pub const fn requested_capability(&self) -> Option<Capability> {
        match self {
            Self::Exact { capability, .. } | Self::Credential { capability, .. } => {
                Some(*capability)
            }
            Self::Status { .. } | Self::Resume { .. } | Self::Wait { .. } => None,
        }
    }
}

impl Debug for BrokerAccessRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact {
                field_scope,
                capability,
            } => formatter
                .debug_struct("BrokerAccessRequest::Exact")
                .field("field_scope", field_scope)
                .field("capability", capability)
                .finish(),
            Self::Credential { capability, .. } => formatter
                .debug_struct("BrokerAccessRequest::Credential")
                .field("capability", capability)
                .field("description", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Status { .. } => formatter
                .debug_struct("BrokerAccessRequest::Status")
                .finish_non_exhaustive(),
            Self::Resume { .. } => formatter
                .debug_struct("BrokerAccessRequest::Resume")
                .finish_non_exhaustive(),
            Self::Wait { timeout, .. } => formatter
                .debug_struct("BrokerAccessRequest::Wait")
                .field("timeout", timeout)
                .finish_non_exhaustive(),
        }
    }
}

impl Drop for BrokerAccessRequest {
    fn drop(&mut self) {
        if let Self::Credential { description, .. } = self {
            description.zeroize();
        }
    }
}

/// Consumer-safe status for one access approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAccessReceiptResponse {
    approval_request_id: ApprovalRequestId,
    status: ApprovalStatus,
    expires_at: StateTimestamp,
    resolved_at: Option<StateTimestamp>,
}

impl BrokerAccessReceiptResponse {
    pub(crate) fn from_receipt(receipt: &BrokerApprovalReceipt) -> Self {
        Self {
            approval_request_id: receipt.approval_request_id(),
            status: receipt.status(),
            expires_at: receipt.expires_at(),
            resolved_at: receipt.resolved_at(),
        }
    }

    pub(crate) const fn from_protocol(
        approval_request_id: ApprovalRequestId,
        status: ApprovalStatus,
        expires_at: StateTimestamp,
        resolved_at: Option<StateTimestamp>,
    ) -> Self {
        Self {
            approval_request_id,
            status,
            expires_at,
            resolved_at,
        }
    }

    /// Returns the stable approval identity.
    #[must_use]
    pub const fn approval_request_id(self) -> ApprovalRequestId {
        self.approval_request_id
    }

    /// Returns the current approval status.
    #[must_use]
    pub const fn status(self) -> ApprovalStatus {
        self.status
    }

    /// Returns the exclusive pending expiry boundary.
    #[must_use]
    pub const fn expires_at(self) -> StateTimestamp {
        self.expires_at
    }

    /// Returns when a terminal state was committed.
    #[must_use]
    pub const fn resolved_at(self) -> Option<StateTimestamp> {
        self.resolved_at
    }
}

/// Consumer-safe result of submitting one access request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAccessSubmissionResponse {
    receipt: BrokerAccessReceiptResponse,
    coalesced: bool,
}

impl BrokerAccessSubmissionResponse {
    pub(crate) fn from_submission(submission: &BrokerApprovalSubmission) -> Self {
        Self {
            receipt: BrokerAccessReceiptResponse::from_receipt(submission.receipt()),
            coalesced: submission.coalesced(),
        }
    }

    pub(crate) const fn from_protocol(
        approval_request_id: ApprovalRequestId,
        status: ApprovalStatus,
        expires_at: StateTimestamp,
        resolved_at: Option<StateTimestamp>,
        coalesced: bool,
    ) -> Self {
        Self {
            receipt: BrokerAccessReceiptResponse::from_protocol(
                approval_request_id,
                status,
                expires_at,
                resolved_at,
            ),
            coalesced,
        }
    }

    /// Returns the Consumer-safe status receipt.
    #[must_use]
    pub const fn receipt(self) -> BrokerAccessReceiptResponse {
        self.receipt
    }

    /// Returns the stable identity used for later status or resumption.
    #[must_use]
    pub const fn approval_request_id(self) -> ApprovalRequestId {
        self.receipt.approval_request_id()
    }

    /// Returns the current approval status.
    #[must_use]
    pub const fn status(self) -> ApprovalStatus {
        self.receipt.status()
    }

    /// Returns the exclusive pending expiry boundary.
    #[must_use]
    pub const fn expires_at(self) -> StateTimestamp {
        self.receipt.expires_at()
    }

    /// Returns when a terminal state was committed.
    #[must_use]
    pub const fn resolved_at(self) -> Option<StateTimestamp> {
        self.receipt.resolved_at()
    }

    /// Returns whether an equivalent pending request already existed.
    #[must_use]
    pub const fn coalesced(self) -> bool {
        self.coalesced
    }
}

/// Consumer-safe result of one bounded access-approval wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAccessWaitResponse {
    receipt: BrokerAccessReceiptResponse,
    timed_out: bool,
}

impl BrokerAccessWaitResponse {
    pub(crate) fn from_outcome(outcome: &BrokerApprovalWaitOutcome) -> Self {
        Self {
            receipt: BrokerAccessReceiptResponse::from_receipt(outcome.receipt()),
            timed_out: outcome.timed_out(),
        }
    }

    pub(crate) const fn from_protocol(
        receipt: BrokerAccessReceiptResponse,
        timed_out: bool,
    ) -> Self {
        Self { receipt, timed_out }
    }

    /// Returns the latest Consumer-safe approval receipt.
    #[must_use]
    pub const fn receipt(self) -> BrokerAccessReceiptResponse {
        self.receipt
    }

    /// Returns whether the bounded wait elapsed while the request remained pending.
    #[must_use]
    pub const fn timed_out(self) -> bool {
        self.timed_out
    }
}

/// Result variant for the `access.request` capability lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAccessResponse {
    /// A new exact or human-matched request was created or coalesced.
    Submission(BrokerAccessSubmissionResponse),
    /// A prior request was polled.
    Status(BrokerAccessReceiptResponse),
    /// A prior request was resumed after adapter restart.
    Resume(BrokerAccessReceiptResponse),
    /// A bounded wait completed or timed out.
    Wait(BrokerAccessWaitResponse),
}

/// Structured `grant.status` version 1 request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerGrantStatusRequest {
    use_grant_id: UseGrantId,
}

impl BrokerGrantStatusRequest {
    /// Creates a Consumer-scoped Use Grant status request.
    #[must_use]
    pub const fn new(use_grant_id: UseGrantId) -> Self {
        Self { use_grant_id }
    }

    /// Returns the requested Use Grant identity.
    #[must_use]
    pub const fn use_grant_id(self) -> UseGrantId {
        self.use_grant_id
    }
}

/// Structured `grant.revoke` version 1 request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerGrantRevokeRequest {
    use_grant_id: UseGrantId,
}

impl BrokerGrantRevokeRequest {
    /// Creates a Consumer-scoped single-grant revocation request.
    #[must_use]
    pub const fn new(use_grant_id: UseGrantId) -> Self {
        Self { use_grant_id }
    }

    /// Returns the requested Use Grant identity.
    #[must_use]
    pub const fn use_grant_id(self) -> UseGrantId {
        self.use_grant_id
    }
}

/// Consumer-visible Use Grant lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerGrantStatus {
    /// The exact Consumer-owned grant is active now.
    Active,
    /// The exact Consumer-owned grant exists but has expired.
    Expired,
    /// The identity is absent, belongs elsewhere, or is not yet active.
    Unavailable,
}

impl BrokerGrantStatus {
    /// Returns the canonical protocol value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Non-secret projection of one active Consumer-owned Use Grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerActiveGrantMetadata {
    use_grant_id: UseGrantId,
    field_scope: CredentialFieldScope,
    capability: Capability,
    vault_session_id: VaultSessionId,
    scope: GrantScope,
    created_at: StateTimestamp,
    expires_at: StateTimestamp,
}

impl BrokerActiveGrantMetadata {
    pub(crate) fn from_grant(grant: &UseGrant) -> Self {
        Self {
            use_grant_id: grant.use_grant_id(),
            field_scope: grant.target().field_scope(),
            capability: grant.target().capability(),
            vault_session_id: grant.vault_session_id(),
            scope: grant.scope(),
            created_at: grant.created_at(),
            expires_at: grant.expires_at(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_protocol(
        use_grant_id: UseGrantId,
        field_scope: CredentialFieldScope,
        capability: Capability,
        vault_session_id: VaultSessionId,
        scope: GrantScope,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Self {
        Self {
            use_grant_id,
            field_scope,
            capability,
            vault_session_id,
            scope,
            created_at,
            expires_at,
        }
    }

    /// Returns the immutable Use Grant identity.
    #[must_use]
    pub const fn use_grant_id(self) -> UseGrantId {
        self.use_grant_id
    }

    /// Returns the exact authorized field scope.
    #[must_use]
    pub const fn field_scope(self) -> CredentialFieldScope {
        self.field_scope
    }

    /// Returns the exact authorized capability.
    #[must_use]
    pub const fn capability(self) -> Capability {
        self.capability
    }

    /// Returns the bound unlock session identity.
    #[must_use]
    pub const fn vault_session_id(self) -> VaultSessionId {
        self.vault_session_id
    }

    /// Returns the operation-count scope.
    #[must_use]
    pub const fn scope(self) -> GrantScope {
        self.scope
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(self) -> StateTimestamp {
        self.created_at
    }

    /// Returns the exclusive expiry boundary.
    #[must_use]
    pub const fn expires_at(self) -> StateTimestamp {
        self.expires_at
    }
}

/// Structured Consumer-safe result of `grant.status`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerGrantStatusResponse {
    status: BrokerGrantStatus,
    active_grant: Option<BrokerActiveGrantMetadata>,
}

impl BrokerGrantStatusResponse {
    pub(crate) const fn active(grant: BrokerActiveGrantMetadata) -> Self {
        Self {
            status: BrokerGrantStatus::Active,
            active_grant: Some(grant),
        }
    }

    pub(crate) const fn expired() -> Self {
        Self {
            status: BrokerGrantStatus::Expired,
            active_grant: None,
        }
    }

    pub(crate) const fn unavailable() -> Self {
        Self {
            status: BrokerGrantStatus::Unavailable,
            active_grant: None,
        }
    }

    /// Returns the Consumer-visible lifecycle state.
    #[must_use]
    pub const fn status(self) -> BrokerGrantStatus {
        self.status
    }

    /// Returns exact non-secret metadata only while the grant is active.
    #[must_use]
    pub const fn active_grant(self) -> Option<BrokerActiveGrantMetadata> {
        self.active_grant
    }
}

/// Structured Consumer-safe result of `grant.revoke`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerGrantRevokeResponse {
    revoked: bool,
}

impl BrokerGrantRevokeResponse {
    pub(crate) const fn new(revoked: bool) -> Self {
        Self { revoked }
    }

    /// Returns whether this call removed the Consumer-owned grant.
    #[must_use]
    pub const fn revoked(self) -> bool {
        self.revoked
    }
}

/// One caller-supplied non-secret HTTP header in a protocol request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerHttpCapabilityHeader {
    name: String,
    value: String,
}

impl BrokerHttpCapabilityHeader {
    /// Creates one validated non-secret HTTP header.
    pub fn new(name: String, value: String) -> Result<Self, BrokerProtocolValidationError> {
        BrokerHttpHeader::new(name.clone(), value.clone())
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?;
        Ok(Self { name, value })
    }

    /// Returns the validated header name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the validated header value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    fn runtime_header(&self) -> Result<BrokerHttpHeader, BrokerProtocolValidationError> {
        BrokerHttpHeader::new(self.name.clone(), self.value.clone())
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)
    }
}

impl Debug for BrokerHttpCapabilityHeader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHttpCapabilityHeader")
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for BrokerHttpCapabilityHeader {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

/// Structured `http.request` version 1 request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerHttpCapabilityRequest {
    target: BrokerCredentialOperationTarget,
    usage_profile_id: UsageProfileId,
    method: BrokerHttpMethod,
    url: String,
    headers: Vec<BrokerHttpCapabilityHeader>,
    body: Vec<u8>,
}

impl BrokerHttpCapabilityRequest {
    /// Creates and validates an exact-scope HTTPS request.
    pub fn new(
        target: BrokerCredentialOperationTarget,
        usage_profile_id: UsageProfileId,
        method: BrokerHttpMethod,
        url: String,
        headers: Vec<BrokerHttpCapabilityHeader>,
        body: Vec<u8>,
    ) -> Result<Self, BrokerProtocolValidationError> {
        let request = Self {
            target,
            usage_profile_id,
            method,
            url,
            headers,
            body,
        };
        request.runtime_request()?;
        Ok(request)
    }

    /// Returns the presented exact operation scope.
    #[must_use]
    pub const fn target(&self) -> BrokerCredentialOperationTarget {
        self.target
    }

    /// Returns the selected Consumer-owned Usage Profile.
    #[must_use]
    pub const fn usage_profile_id(&self) -> UsageProfileId {
        self.usage_profile_id
    }

    /// Returns the validated HTTP method.
    #[must_use]
    pub const fn method(&self) -> BrokerHttpMethod {
        self.method
    }

    /// Returns the validated canonical HTTPS destination.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the caller-supplied non-secret headers.
    #[must_use]
    pub fn headers(&self) -> &[BrokerHttpCapabilityHeader] {
        &self.headers
    }

    /// Returns the bounded caller-supplied body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn runtime_request(
        &self,
    ) -> Result<BrokerHttpRequest, BrokerProtocolValidationError> {
        let headers = self
            .headers
            .iter()
            .map(BrokerHttpCapabilityHeader::runtime_header)
            .collect::<Result<Vec<_>, _>>()?;
        BrokerHttpRequest::new(self.method, self.url.clone(), headers, self.body.clone())
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)
    }
}

impl Debug for BrokerHttpCapabilityRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHttpCapabilityRequest")
            .field("target", &self.target)
            .field("usage_profile_id", &self.usage_profile_id)
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl Drop for BrokerHttpCapabilityRequest {
    fn drop(&mut self) {
        self.url.zeroize();
        self.body.zeroize();
    }
}

/// Structured bounded response from `http.request`.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerHttpCapabilityResponse {
    status_code: u16,
    body: Vec<u8>,
    truncated: bool,
}

impl BrokerHttpCapabilityResponse {
    pub(crate) fn from_runtime(response: &BrokerHttpResponse) -> Self {
        Self {
            status_code: response.status_code(),
            body: response.body().to_vec(),
            truncated: response.truncated(),
        }
    }

    pub(crate) const fn from_protocol(status_code: u16, body: Vec<u8>, truncated: bool) -> Self {
        Self {
            status_code,
            body,
            truncated,
        }
    }

    /// Returns the numeric HTTP status.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Returns the bounded body after exact-secret redaction.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns whether response bytes were omitted.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

impl Debug for BrokerHttpCapabilityResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHttpCapabilityResponse")
            .field("status_code", &self.status_code)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl Drop for BrokerHttpCapabilityResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// One explicit non-secret child environment entry in a protocol request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerProcessCapabilityEnvironment {
    name: String,
    value: String,
}

impl BrokerProcessCapabilityEnvironment {
    /// Creates one validated child-only environment entry.
    pub fn new(name: String, value: String) -> Result<Self, BrokerProtocolValidationError> {
        BrokerProcessEnvironment::new(name.clone(), value.clone())
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?;
        Ok(Self { name, value })
    }

    /// Returns the validated environment name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the validated non-secret environment value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    fn runtime_environment(
        &self,
    ) -> Result<BrokerProcessEnvironment, BrokerProtocolValidationError> {
        BrokerProcessEnvironment::new(self.name.clone(), self.value.clone())
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)
    }
}

impl Debug for BrokerProcessCapabilityEnvironment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerProcessCapabilityEnvironment")
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for BrokerProcessCapabilityEnvironment {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

/// Structured `process.run` version 1 request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerProcessCapabilityRequest {
    target: BrokerCredentialOperationTarget,
    usage_profile_id: UsageProfileId,
    executable: String,
    arguments: Vec<String>,
    working_directory: Option<String>,
    environment: Vec<BrokerProcessCapabilityEnvironment>,
    timeout_millis: u64,
}

impl BrokerProcessCapabilityRequest {
    /// Creates and validates one direct child-process request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: BrokerCredentialOperationTarget,
        usage_profile_id: UsageProfileId,
        executable: String,
        arguments: Vec<String>,
        working_directory: Option<String>,
        environment: Vec<BrokerProcessCapabilityEnvironment>,
        timeout_millis: u64,
    ) -> Result<Self, BrokerProtocolValidationError> {
        let request = Self {
            target,
            usage_profile_id,
            executable,
            arguments,
            working_directory,
            environment,
            timeout_millis,
        };
        request.runtime_request()?;
        Ok(request)
    }

    /// Returns the presented exact operation scope.
    #[must_use]
    pub const fn target(&self) -> BrokerCredentialOperationTarget {
        self.target
    }

    /// Returns the selected Consumer-owned Usage Profile.
    #[must_use]
    pub const fn usage_profile_id(&self) -> UsageProfileId {
        self.usage_profile_id
    }

    /// Returns the validated absolute executable path.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Returns the bounded non-secret child arguments.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Returns the optional absolute working directory.
    #[must_use]
    pub fn working_directory(&self) -> Option<&str> {
        self.working_directory.as_deref()
    }

    /// Returns the explicit child-only environment entries.
    #[must_use]
    pub fn environment(&self) -> &[BrokerProcessCapabilityEnvironment] {
        &self.environment
    }

    /// Returns the bounded timeout in milliseconds.
    #[must_use]
    pub const fn timeout_millis(&self) -> u64 {
        self.timeout_millis
    }

    pub(crate) fn runtime_request(
        &self,
    ) -> Result<BrokerProcessRunRequest, BrokerProtocolValidationError> {
        let environment = self
            .environment
            .iter()
            .map(BrokerProcessCapabilityEnvironment::runtime_environment)
            .collect::<Result<Vec<_>, _>>()?;
        BrokerProcessRunRequest::new(
            self.executable.clone(),
            self.arguments.clone(),
            self.working_directory.clone(),
            environment,
            Duration::from_millis(self.timeout_millis),
        )
        .map_err(|_| BrokerProtocolValidationError::InvalidRequest)
    }
}

impl Debug for BrokerProcessCapabilityRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerProcessCapabilityRequest")
            .field("target", &self.target)
            .field("usage_profile_id", &self.usage_profile_id)
            .field("executable", &"<redacted>")
            .field("argument_count", &self.arguments.len())
            .field(
                "working_directory",
                &self.working_directory.as_ref().map(|_| "<redacted>"),
            )
            .field("environment_count", &self.environment.len())
            .field("timeout_millis", &self.timeout_millis)
            .finish()
    }
}

impl Drop for BrokerProcessCapabilityRequest {
    fn drop(&mut self) {
        self.executable.zeroize();
        for argument in &mut self.arguments {
            argument.zeroize();
        }
        if let Some(directory) = self.working_directory.as_mut() {
            directory.zeroize();
        }
    }
}

/// Structured bounded response from `process.run`.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerProcessCapabilityResponse {
    exit_code: Option<i32>,
    terminated_by_signal: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

impl BrokerProcessCapabilityResponse {
    pub(crate) fn from_runtime(response: &BrokerProcessRunResponse) -> Self {
        Self {
            exit_code: response.exit_code(),
            terminated_by_signal: response.terminated_by_signal(),
            stdout: response.stdout().to_vec(),
            stderr: response.stderr().to_vec(),
            stdout_truncated: response.stdout_truncated(),
            stderr_truncated: response.stderr_truncated(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_protocol(
        exit_code: Option<i32>,
        terminated_by_signal: bool,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        stdout_truncated: bool,
        stderr_truncated: bool,
    ) -> Self {
        Self {
            exit_code,
            terminated_by_signal,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        }
    }

    /// Returns the child exit code, when one exists.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Returns whether the platform reported signal-based termination.
    #[must_use]
    pub const fn terminated_by_signal(&self) -> bool {
        self.terminated_by_signal
    }

    /// Returns bounded standard output after exact-secret redaction.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns bounded standard error after exact-secret redaction.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Returns whether standard output bytes were omitted.
    #[must_use]
    pub const fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    /// Returns whether standard error bytes were omitted.
    #[must_use]
    pub const fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }
}

impl Debug for BrokerProcessCapabilityResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerProcessCapabilityResponse")
            .field("exit_code", &self.exit_code)
            .field("terminated_by_signal", &self.terminated_by_signal)
            .field("stdout", &"<redacted>")
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr", &"<redacted>")
            .field("stderr_bytes", &self.stderr.len())
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr_truncated", &self.stderr_truncated)
            .finish()
    }
}

impl Drop for BrokerProcessCapabilityResponse {
    fn drop(&mut self) {
        self.stdout.zeroize();
        self.stderr.zeroize();
    }
}

/// Minimum authorized credential metadata returned by `credential.search`.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerCredentialSearchResponse {
    credential: Option<BrokerCredentialMetadataResponse>,
}

impl BrokerCredentialSearchResponse {
    pub(crate) fn from_runtime(
        result: &crate::credential_search::BrokerCredentialSearchResult,
    ) -> Self {
        Self {
            credential: result
                .credential()
                .map(BrokerCredentialMetadataResponse::from_runtime),
        }
    }

    pub(crate) const fn from_protocol(
        credential: Option<BrokerCredentialMetadataResponse>,
    ) -> Self {
        Self { credential }
    }

    /// Returns the zero-or-one authorized credential projection.
    #[must_use]
    pub const fn credential(&self) -> Option<&BrokerCredentialMetadataResponse> {
        self.credential.as_ref()
    }
}

impl Debug for BrokerCredentialSearchResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerCredentialSearchResponse")
            .field("matched", &self.credential.is_some())
            .finish()
    }
}

/// One exact authorized credential and field metadata projection.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerCredentialMetadataResponse {
    vault_id: VaultId,
    credential_id: CredentialId,
    title: String,
    secret_field_id: SecretFieldId,
    role: String,
    label: Option<String>,
    kind: SecretFieldKind,
}

impl BrokerCredentialMetadataResponse {
    fn from_runtime(metadata: &crate::credential_search::BrokerCredentialMetadata) -> Self {
        let field = metadata.authorized_field();
        Self {
            vault_id: metadata.vault_id(),
            credential_id: metadata.credential_id(),
            title: metadata.title().to_owned(),
            secret_field_id: field.secret_field_id(),
            role: field.role().to_owned(),
            label: field.label().map(str::to_owned),
            kind: field.kind(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn from_protocol(
        vault_id: VaultId,
        credential_id: CredentialId,
        title: String,
        secret_field_id: SecretFieldId,
        role: String,
        label: Option<String>,
        kind: SecretFieldKind,
    ) -> Self {
        Self {
            vault_id,
            credential_id,
            title,
            secret_field_id,
            role,
            label,
            kind,
        }
    }

    /// Returns the stable vault identity.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the stable credential identity.
    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// Returns the authorized credential title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the one authorized Secret Field identity.
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

    /// Returns the authenticated provider-neutral Secret Field kind.
    #[must_use]
    pub const fn kind(&self) -> SecretFieldKind {
        self.kind
    }
}

impl Debug for BrokerCredentialMetadataResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerCredentialMetadataResponse")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerCredentialMetadataResponse {
    fn drop(&mut self) {
        self.title.zeroize();
        self.role.zeroize();
        if let Some(label) = self.label.as_mut() {
            label.zeroize();
        }
    }
}

fn validate_requested_credential_capability(
    capability: Capability,
) -> Result<(), BrokerProtocolValidationError> {
    let supported = capability.version() == 1
        && matches!(
            capability.name(),
            CapabilityName::CredentialSearch
                | CapabilityName::HttpRequest
                | CapabilityName::ProcessRun
        );
    if supported {
        Ok(())
    } else {
        Err(BrokerProtocolValidationError::InvalidRequest)
    }
}
