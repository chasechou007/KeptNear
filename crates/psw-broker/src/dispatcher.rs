use std::fmt::{Display, Formatter};

use crate::authentication::{BrokerAuthenticationChallenge, BrokerAuthenticationError};
use crate::capability_protocol::{
    BrokerAccessReceiptResponse, BrokerAccessRequest, BrokerAccessResponse,
    BrokerAccessSubmissionResponse, BrokerAccessWaitResponse, BrokerActiveGrantMetadata,
    BrokerCredentialSearchResponse, BrokerGrantRevokeResponse, BrokerGrantStatusResponse,
    BrokerHttpCapabilityResponse, BrokerProcessCapabilityResponse,
};
use crate::credential_matching::BrokerNewCredentialRequest;
use crate::pairing::{BrokerConsumerPairingProgress, BrokerPairingError};
use crate::process_run::BrokerProcessRunCancellation;
use crate::protocol::{
    decode_broker_request, encode_broker_response, BrokerAuthenticationChallengeResponse,
    BrokerAuthenticationResponse, BrokerCapabilitySet, BrokerErrorCode, BrokerInstanceId,
    BrokerNegotiatedCapability, BrokerPairingCompleteResponse, BrokerPairingPendingResponse,
    BrokerPairingProgressResponse, BrokerProtocolError, BrokerProtocolVersion, BrokerRequest,
    BrokerRequestId, BrokerRequiredAction, BrokerResponse, BrokerResponseEnvelope, BrokerSessionId,
    BrokerStatusResponse,
};
use crate::runtime::{BrokerRuntime, BrokerRuntimeError};
use crate::state_model::{AuthorizationTarget, Capability, ConsumerId, ObservedConsumerIdentity};
use crate::use_grant::BrokerConsumerUseGrantStatus;

#[derive(Clone, Copy)]
struct BrokerRuntimeDispatchContext<'a> {
    runtime: &'a BrokerRuntime,
    observed_identity: &'a ObservedConsumerIdentity,
    process_cancellation: &'a BrokerProcessRunCancellation,
}

/// Per-peer protocol negotiation state.
#[derive(Debug, Eq, PartialEq)]
pub struct BrokerConnectionState {
    negotiated_protocol: Option<BrokerProtocolVersion>,
    negotiated_capabilities: Vec<BrokerNegotiatedCapability>,
    authentication_challenge: Option<BrokerAuthenticationChallenge>,
    authenticated_session: Option<(BrokerSessionId, ConsumerId)>,
}

impl BrokerConnectionState {
    /// Creates a connection that accepts only `hello`.
    #[must_use]
    pub const fn awaiting_hello() -> Self {
        Self {
            negotiated_protocol: None,
            negotiated_capabilities: Vec::new(),
            authentication_challenge: None,
            authenticated_session: None,
        }
    }

    /// Returns the selected protocol after successful negotiation.
    #[must_use]
    pub const fn negotiated_protocol(&self) -> Option<BrokerProtocolVersion> {
        self.negotiated_protocol
    }

    /// Returns whether `hello` completed successfully.
    #[must_use]
    pub const fn is_negotiated(&self) -> bool {
        self.negotiated_protocol.is_some()
    }

    /// Returns whether one exact capability version was selected by `hello`.
    #[must_use]
    pub fn supports_capability(&self, capability: Capability) -> bool {
        self.negotiated_capabilities.iter().any(|selected| {
            selected.capability_name() == capability.name()
                && selected.version() == capability.version()
        })
    }

    /// Returns the authenticated session and Consumer after proof succeeds.
    #[must_use]
    pub const fn authenticated_session(&self) -> Option<(BrokerSessionId, ConsumerId)> {
        self.authenticated_session
    }

    /// Returns whether this connection completed paired-Consumer proof.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.authenticated_session.is_some()
    }
}

impl Default for BrokerConnectionState {
    fn default() -> Self {
        Self::awaiting_hello()
    }
}

/// Encoded response and connection disposition produced by one dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerDispatchOutcome {
    response_payload: Vec<u8>,
    close_connection: bool,
}

impl BrokerDispatchOutcome {
    /// Returns the strict response JSON without frame bytes.
    #[must_use]
    pub fn response_payload(&self) -> &[u8] {
        &self.response_payload
    }

    /// Returns whether the transport must close after writing the response.
    #[must_use]
    pub const fn should_close_connection(&self) -> bool {
        self.close_connection
    }
}

/// Internal dispatcher failure with no request or secret payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerDispatchError;

impl Display for BrokerDispatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Broker response encoding failed")
    }
}

impl std::error::Error for BrokerDispatchError {}

/// Versioned, transport-independent local Broker request dispatcher.
#[derive(Clone, Debug)]
pub struct BrokerDispatcher {
    broker_instance_id: BrokerInstanceId,
    supported_capabilities: BrokerCapabilitySet,
}

impl BrokerDispatcher {
    #[must_use]
    pub(crate) const fn new(
        broker_instance_id: BrokerInstanceId,
        supported_capabilities: BrokerCapabilitySet,
    ) -> Self {
        Self {
            broker_instance_id,
            supported_capabilities,
        }
    }

    /// Returns the ephemeral process instance identity.
    #[must_use]
    pub const fn broker_instance_id(&self) -> BrokerInstanceId {
        self.broker_instance_id
    }

    /// Dispatches one complete JSON frame payload.
    ///
    /// Source bytes and parser errors are never included in the response.
    pub fn dispatch(
        &self,
        state: &mut BrokerConnectionState,
        payload: &[u8],
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.dispatch_internal(state, payload, None)
    }

    #[cfg(test)]
    pub(crate) fn dispatch_runtime(
        &self,
        runtime: &BrokerRuntime,
        observed_identity: &ObservedConsumerIdentity,
        state: &mut BrokerConnectionState,
        payload: &[u8],
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.dispatch_runtime_with_process_cancellation(
            runtime,
            observed_identity,
            state,
            payload,
            &BrokerProcessRunCancellation::default(),
        )
    }

    pub(crate) fn dispatch_runtime_with_process_cancellation(
        &self,
        runtime: &BrokerRuntime,
        observed_identity: &ObservedConsumerIdentity,
        state: &mut BrokerConnectionState,
        payload: &[u8],
        process_cancellation: &BrokerProcessRunCancellation,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.dispatch_internal(
            state,
            payload,
            Some(BrokerRuntimeDispatchContext {
                runtime,
                observed_identity,
                process_cancellation,
            }),
        )
    }

    fn dispatch_internal(
        &self,
        state: &mut BrokerConnectionState,
        payload: &[u8],
        runtime_context: Option<BrokerRuntimeDispatchContext<'_>>,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        let request = match decode_broker_request(payload) {
            Ok(request) => request,
            Err(error) => {
                let error_code = error.error_code();
                let request_id = error.request_id().unwrap_or_else(BrokerRequestId::generate);
                let required_action = (error_code == BrokerErrorCode::ProtocolIncompatible)
                    .then_some(BrokerRequiredAction::UpdateClient);
                let close_connection = !state.is_negotiated()
                    || matches!(
                        error_code,
                        BrokerErrorCode::MalformedFrame
                            | BrokerErrorCode::OversizedFrame
                            | BrokerErrorCode::ProtocolIncompatible
                    );
                return self.error_outcome(
                    BrokerProtocolVersion::current(),
                    request_id,
                    BrokerProtocolError::new(error_code, false, required_action, None),
                    close_connection,
                );
            }
        };

        match state.negotiated_protocol {
            None => match request.request() {
                BrokerRequest::Hello(hello) => {
                    let Some(negotiated) = hello.negotiate(&self.supported_capabilities) else {
                        return self.error_outcome(
                            BrokerProtocolVersion::current(),
                            request.request_id(),
                            BrokerProtocolError::new(
                                BrokerErrorCode::ProtocolIncompatible,
                                false,
                                Some(BrokerRequiredAction::UpdateClient),
                                None,
                            ),
                            true,
                        );
                    };
                    let selected_protocol = negotiated.selected_protocol();
                    state.negotiated_protocol = Some(selected_protocol);
                    state.negotiated_capabilities = negotiated.capabilities().to_vec();
                    self.response_outcome(
                        BrokerResponseEnvelope::new(
                            selected_protocol,
                            request.request_id(),
                            BrokerResponse::Hello(negotiated),
                        ),
                        false,
                    )
                }
                BrokerRequest::Status
                | BrokerRequest::PairingStart(_)
                | BrokerRequest::PairingStatus(_)
                | BrokerRequest::PairingComplete(_)
                | BrokerRequest::AuthenticationStart(_)
                | BrokerRequest::AuthenticationComplete(_)
                | BrokerRequest::CredentialSearch(_)
                | BrokerRequest::AccessRequest(_)
                | BrokerRequest::GrantStatus(_)
                | BrokerRequest::GrantRevoke(_)
                | BrokerRequest::HttpRequest(_)
                | BrokerRequest::ProcessRun(_) => self.error_outcome(
                    BrokerProtocolVersion::current(),
                    request.request_id(),
                    BrokerProtocolError::new(
                        BrokerErrorCode::ProtocolIncompatible,
                        false,
                        Some(BrokerRequiredAction::SendHello),
                        None,
                    ),
                    true,
                ),
            },
            Some(negotiated_protocol) => {
                if request.version() != negotiated_protocol {
                    return self.error_outcome(
                        negotiated_protocol,
                        request.request_id(),
                        BrokerProtocolError::new(
                            BrokerErrorCode::ProtocolIncompatible,
                            false,
                            Some(BrokerRequiredAction::UpdateClient),
                            None,
                        ),
                        true,
                    );
                }
                match request.request() {
                    BrokerRequest::Hello(_) => self.error_outcome(
                        negotiated_protocol,
                        request.request_id(),
                        BrokerProtocolError::new(
                            BrokerErrorCode::InvalidRequest,
                            false,
                            None,
                            None,
                        ),
                        false,
                    ),
                    BrokerRequest::Status => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request.request_id(),
                            BrokerResponse::Status(BrokerStatusResponse::new(
                                self.broker_instance_id,
                            )),
                        ),
                        false,
                    ),
                    BrokerRequest::PairingStart(_)
                    | BrokerRequest::PairingStatus(_)
                    | BrokerRequest::PairingComplete(_)
                    | BrokerRequest::AuthenticationStart(_)
                    | BrokerRequest::AuthenticationComplete(_)
                    | BrokerRequest::CredentialSearch(_)
                    | BrokerRequest::AccessRequest(_)
                    | BrokerRequest::GrantStatus(_)
                    | BrokerRequest::GrantRevoke(_)
                    | BrokerRequest::HttpRequest(_)
                    | BrokerRequest::ProcessRun(_) => {
                        let Some(runtime_context) = runtime_context else {
                            return self.error_outcome(
                                negotiated_protocol,
                                request.request_id(),
                                BrokerProtocolError::new(
                                    BrokerErrorCode::InvalidRequest,
                                    false,
                                    None,
                                    None,
                                ),
                                false,
                            );
                        };
                        self.dispatch_runtime_request(
                            runtime_context,
                            state,
                            negotiated_protocol,
                            request.request_id(),
                            request.request(),
                        )
                    }
                }
            }
        }
    }

    fn dispatch_runtime_request(
        &self,
        runtime_context: BrokerRuntimeDispatchContext<'_>,
        state: &mut BrokerConnectionState,
        negotiated_protocol: BrokerProtocolVersion,
        request_id: BrokerRequestId,
        request: &BrokerRequest,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        let runtime = runtime_context.runtime;
        let observed_identity = runtime_context.observed_identity;
        if let Some(required_capability) = request.required_capability() {
            if !state.supports_capability(required_capability) {
                return self.unsupported_capability_outcome(negotiated_protocol, request_id);
            }
            if !state.is_authenticated() {
                return self.authentication_required_outcome(negotiated_protocol, request_id);
            }
        }
        match request {
            BrokerRequest::PairingStart(pairing) => {
                if state.is_authenticated() {
                    return self.invalid_request_outcome(negotiated_protocol, request_id);
                }
                let proposal = match crate::pairing::ConsumerPairingProposal::new(
                    *pairing.pairing_public_key(),
                    *pairing.client_nonce(),
                    negotiated_protocol,
                ) {
                    Ok(proposal) => proposal,
                    Err(error) => {
                        return self.runtime_error_outcome(
                            negotiated_protocol,
                            request_id,
                            BrokerRuntimeError::Pairing(error),
                            false,
                        );
                    }
                };
                match runtime.begin_or_resume_pairing(proposal, observed_identity.clone()) {
                    Ok(progress) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::PairingProgress(pairing_progress_response(progress)),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::PairingStatus(pairing) => {
                if state.is_authenticated() {
                    return self.invalid_request_outcome(negotiated_protocol, request_id);
                }
                match runtime
                    .pairing_progress(pairing.pairing_request_id(), pairing.pairing_public_key())
                {
                    Ok(progress) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::PairingProgress(pairing_progress_response(progress)),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::PairingComplete(pairing) => {
                if state.is_authenticated() {
                    return self.invalid_request_outcome(negotiated_protocol, request_id);
                }
                match runtime.complete_pairing(pairing.pairing_request_id(), *pairing.proof()) {
                    Ok(completion) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::PairingComplete(BrokerPairingCompleteResponse::new(
                                completion.consumer_id(),
                            )),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::AuthenticationStart(authentication) => {
                if state.is_authenticated() || state.authentication_challenge.is_some() {
                    return self.invalid_request_outcome(negotiated_protocol, request_id);
                }
                match runtime
                    .begin_authentication(authentication.consumer_id(), negotiated_protocol)
                {
                    Ok(challenge) => {
                        let session_id = challenge.session_id();
                        let consumer_id = challenge.consumer_id();
                        let broker_nonce = *challenge.broker_nonce();
                        let valid_for_seconds = challenge.valid_for().as_secs();
                        state.authentication_challenge = Some(challenge);
                        self.response_outcome(
                            BrokerResponseEnvelope::new(
                                negotiated_protocol,
                                request_id,
                                BrokerResponse::AuthenticationChallenge(
                                    BrokerAuthenticationChallengeResponse::new(
                                        session_id,
                                        consumer_id,
                                        broker_nonce,
                                        valid_for_seconds,
                                    ),
                                ),
                            ),
                            false,
                        )
                    }
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, true)
                    }
                }
            }
            BrokerRequest::AuthenticationComplete(authentication) => {
                if state.is_authenticated() {
                    return self.invalid_request_outcome(negotiated_protocol, request_id);
                }
                let Some(challenge) = state.authentication_challenge.take() else {
                    return self.invalid_request_outcome(negotiated_protocol, request_id);
                };
                match runtime.complete_authentication(
                    challenge,
                    authentication.session_id(),
                    authentication.consumer_id(),
                    *authentication.proof(),
                ) {
                    Ok(completion) => {
                        state.authenticated_session =
                            Some((completion.session_id(), completion.consumer_id()));
                        self.response_outcome(
                            BrokerResponseEnvelope::new(
                                negotiated_protocol,
                                request_id,
                                BrokerResponse::Authenticated(BrokerAuthenticationResponse::new(
                                    completion.session_id(),
                                    completion.consumer_id(),
                                )),
                            ),
                            false,
                        )
                    }
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, true)
                    }
                }
            }
            BrokerRequest::CredentialSearch(search) => {
                let consumer_id = authenticated_consumer(state);
                let operation = search.target();
                let target = AuthorizationTarget::new(
                    consumer_id,
                    operation.field_scope(),
                    Capability::v1(crate::state_model::CapabilityName::CredentialSearch),
                );
                let query = match search.runtime_query() {
                    Ok(query) => query,
                    Err(_) => {
                        return self.invalid_request_outcome(negotiated_protocol, request_id);
                    }
                };
                match runtime.search_authorized_credential_now(
                    operation.use_grant_id(),
                    target,
                    operation.secret_kind(),
                    operation.vault_session_id(),
                    query,
                ) {
                    Ok(result) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::CredentialSearch(
                                BrokerCredentialSearchResponse::from_runtime(&result),
                            ),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::AccessRequest(access) => {
                if let Some(requested_capability) = access.requested_capability() {
                    if !state.supports_capability(requested_capability) {
                        return self
                            .unsupported_capability_outcome(negotiated_protocol, request_id);
                    }
                }
                let consumer_id = authenticated_consumer(state);
                let result = match access {
                    BrokerAccessRequest::Exact {
                        field_scope,
                        capability,
                    } => runtime
                        .request_exact_access(AuthorizationTarget::new(
                            consumer_id,
                            *field_scope,
                            *capability,
                        ))
                        .map(|submission| {
                            BrokerAccessResponse::Submission(
                                BrokerAccessSubmissionResponse::from_submission(&submission),
                            )
                        }),
                    BrokerAccessRequest::Credential {
                        vault_id,
                        capability,
                        description,
                    } => {
                        let credential_request = match BrokerNewCredentialRequest::new(
                            consumer_id,
                            *vault_id,
                            *capability,
                            description.clone(),
                        ) {
                            Ok(request) => request,
                            Err(_) => {
                                return self
                                    .invalid_request_outcome(negotiated_protocol, request_id);
                            }
                        };
                        runtime
                            .request_new_credential_access(credential_request)
                            .map(|submission| {
                                BrokerAccessResponse::Submission(
                                    BrokerAccessSubmissionResponse::from_submission(&submission),
                                )
                            })
                    }
                    BrokerAccessRequest::Status {
                        approval_request_id,
                    } => runtime
                        .approval_status_now(consumer_id, *approval_request_id)
                        .map(|receipt| {
                            BrokerAccessResponse::Status(BrokerAccessReceiptResponse::from_receipt(
                                &receipt,
                            ))
                        }),
                    BrokerAccessRequest::Resume {
                        approval_request_id,
                    } => runtime
                        .resume_approval_now(consumer_id, *approval_request_id)
                        .map(|receipt| {
                            BrokerAccessResponse::Resume(BrokerAccessReceiptResponse::from_receipt(
                                &receipt,
                            ))
                        }),
                    BrokerAccessRequest::Wait {
                        approval_request_id,
                        timeout,
                    } => runtime
                        .wait_for_approval_now(consumer_id, *approval_request_id, *timeout)
                        .map(|outcome| {
                            BrokerAccessResponse::Wait(BrokerAccessWaitResponse::from_outcome(
                                &outcome,
                            ))
                        }),
                };
                match result {
                    Ok(access_response) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::AccessRequest(access_response),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::GrantStatus(status) => {
                let consumer_id = authenticated_consumer(state);
                match runtime.consumer_use_grant_status(consumer_id, status.use_grant_id()) {
                    Ok(BrokerConsumerUseGrantStatus::Active(grant)) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::GrantStatus(BrokerGrantStatusResponse::active(
                                BrokerActiveGrantMetadata::from_grant(&grant),
                            )),
                        ),
                        false,
                    ),
                    Ok(BrokerConsumerUseGrantStatus::Expired) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::GrantStatus(BrokerGrantStatusResponse::expired()),
                        ),
                        false,
                    ),
                    Ok(BrokerConsumerUseGrantStatus::Unavailable) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::GrantStatus(BrokerGrantStatusResponse::unavailable()),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::GrantRevoke(revoke) => {
                let consumer_id = authenticated_consumer(state);
                match runtime.revoke_consumer_use_grant(consumer_id, revoke.use_grant_id()) {
                    Ok(revoked) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::GrantRevoke(BrokerGrantRevokeResponse::new(revoked)),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::HttpRequest(http) => {
                let consumer_id = authenticated_consumer(state);
                let operation = http.target();
                let target = AuthorizationTarget::new(
                    consumer_id,
                    operation.field_scope(),
                    Capability::v1(crate::state_model::CapabilityName::HttpRequest),
                );
                let runtime_request = match http.runtime_request() {
                    Ok(request) => request,
                    Err(_) => {
                        return self.invalid_request_outcome(negotiated_protocol, request_id);
                    }
                };
                match runtime.execute_http_request(
                    operation.use_grant_id(),
                    target,
                    operation.secret_kind(),
                    operation.vault_session_id(),
                    http.usage_profile_id(),
                    runtime_request,
                ) {
                    Ok(response) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::HttpRequest(
                                BrokerHttpCapabilityResponse::from_runtime(&response),
                            ),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::ProcessRun(process) => {
                let consumer_id = authenticated_consumer(state);
                let operation = process.target();
                let target = AuthorizationTarget::new(
                    consumer_id,
                    operation.field_scope(),
                    Capability::v1(crate::state_model::CapabilityName::ProcessRun),
                );
                let runtime_request = match process.runtime_request() {
                    Ok(request) => request,
                    Err(_) => {
                        return self.invalid_request_outcome(negotiated_protocol, request_id);
                    }
                };
                match runtime.execute_process_run_with_cancellation(
                    operation.use_grant_id(),
                    target,
                    operation.secret_kind(),
                    operation.vault_session_id(),
                    process.usage_profile_id(),
                    runtime_request,
                    runtime_context.process_cancellation,
                ) {
                    Ok(response) => self.response_outcome(
                        BrokerResponseEnvelope::new(
                            negotiated_protocol,
                            request_id,
                            BrokerResponse::ProcessRun(
                                BrokerProcessCapabilityResponse::from_runtime(&response),
                            ),
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.runtime_error_outcome(negotiated_protocol, request_id, error, false)
                    }
                }
            }
            BrokerRequest::Hello(_) | BrokerRequest::Status => {
                self.invalid_request_outcome(negotiated_protocol, request_id)
            }
        }
    }

    fn unsupported_capability_outcome(
        &self,
        version: BrokerProtocolVersion,
        request_id: BrokerRequestId,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.error_outcome(
            version,
            request_id,
            BrokerProtocolError::new(BrokerErrorCode::UnsupportedCapability, false, None, None),
            false,
        )
    }

    fn authentication_required_outcome(
        &self,
        version: BrokerProtocolVersion,
        request_id: BrokerRequestId,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.error_outcome(
            version,
            request_id,
            BrokerProtocolError::new(BrokerErrorCode::AuthenticationFailed, false, None, None),
            false,
        )
    }

    fn invalid_request_outcome(
        &self,
        version: BrokerProtocolVersion,
        request_id: BrokerRequestId,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.error_outcome(
            version,
            request_id,
            BrokerProtocolError::new(BrokerErrorCode::InvalidRequest, false, None, None),
            false,
        )
    }

    fn runtime_error_outcome(
        &self,
        version: BrokerProtocolVersion,
        request_id: BrokerRequestId,
        error: BrokerRuntimeError,
        close_connection: bool,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        let protocol_error = match error {
            BrokerRuntimeError::Pairing(error) => pairing_protocol_error(error),
            BrokerRuntimeError::Authentication(error) => authentication_protocol_error(error),
            BrokerRuntimeError::MachineAccess(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::AccessRule(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::UseGrant(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::CredentialSearch(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::CredentialMatching(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::Approval(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::Revocation(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::UsageProfile(error) => {
                let code = match error {
                    crate::usage_profile::BrokerUsageProfileError::ConsumerUnavailable => {
                        BrokerErrorCode::ConsumerRevoked
                    }
                    crate::usage_profile::BrokerUsageProfileError::Validation(_) => {
                        BrokerErrorCode::InvalidRequest
                    }
                    crate::usage_profile::BrokerUsageProfileError::ProfileUnavailable
                    | crate::usage_profile::BrokerUsageProfileError::CapabilityMismatch => {
                        BrokerErrorCode::AccessDenied
                    }
                    crate::usage_profile::BrokerUsageProfileError::DeviceState(_) => {
                        BrokerErrorCode::OperationFailed
                    }
                };
                protocol_error_for_code(code)
            }
            BrokerRuntimeError::HttpRequest(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::ProcessRun(error) => {
                protocol_error_for_code(error.broker_error_code())
            }
            BrokerRuntimeError::OutboundOperation(error) => {
                let code = match error {
                    crate::outbound_operation::BrokerOutboundOperationError::UnsupportedCapability => {
                        BrokerErrorCode::UnsupportedCapability
                    }
                    crate::outbound_operation::BrokerOutboundOperationError::DeviceState(_) => {
                        BrokerErrorCode::OperationFailed
                    }
                };
                protocol_error_for_code(code)
            }
            BrokerRuntimeError::VaultSession(error) => {
                let code = match error {
                    crate::vault_session::BrokerVaultSessionError::ShutDown
                    | crate::vault_session::BrokerVaultSessionError::VaultNotOpen
                    | crate::vault_session::BrokerVaultSessionError::VaultLocked
                    | crate::vault_session::BrokerVaultSessionError::VaultUnlockInProgress
                    | crate::vault_session::BrokerVaultSessionError::VaultUnlockCancelled => {
                        BrokerErrorCode::VaultLocked
                    }
                    crate::vault_session::BrokerVaultSessionError::UnsupportedCoreOperation
                    | crate::vault_session::BrokerVaultSessionError::UnsupportedVaultFormat => {
                        BrokerErrorCode::UnsupportedCapability
                    }
                    crate::vault_session::BrokerVaultSessionError::InvalidCredentials
                    | crate::vault_session::BrokerVaultSessionError::StableVaultIdentityRequired
                    | crate::vault_session::BrokerVaultSessionError::VaultIdentityAlreadyOpen
                    | crate::vault_session::BrokerVaultSessionError::VaultPathIdentityChanged
                    | crate::vault_session::BrokerVaultSessionError::VaultAlreadyUnlocked
                    | crate::vault_session::BrokerVaultSessionError::InvalidVault
                    | crate::vault_session::BrokerVaultSessionError::CryptographicFailure
                    | crate::vault_session::BrokerVaultSessionError::InvalidCoreState
                    | crate::vault_session::BrokerVaultSessionError::Io { .. }
                    | crate::vault_session::BrokerVaultSessionError::StateUnavailable
                    | crate::vault_session::BrokerVaultSessionError::AutoLockWorkerUnavailable
                    | crate::vault_session::BrokerVaultSessionError::InvalidAutoLockTimeout => {
                        BrokerErrorCode::OperationFailed
                    }
                };
                protocol_error_for_code(code)
            }
            BrokerRuntimeError::DevicePaths(_)
            | BrokerRuntimeError::LocalData(_)
            | BrokerRuntimeError::GrantInvalidation(_)
            | BrokerRuntimeError::Audit(_)
            | BrokerRuntimeError::HumanControl(_)
            | BrokerRuntimeError::ClockUnavailable => {
                BrokerProtocolError::new(BrokerErrorCode::OperationFailed, false, None, None)
            }
        };
        self.error_outcome(version, request_id, protocol_error, close_connection)
    }

    pub(crate) fn transport_error_outcome(
        &self,
        error_code: BrokerErrorCode,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.error_outcome(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerProtocolError::new(error_code, false, None, None),
            true,
        )
    }

    fn error_outcome(
        &self,
        version: BrokerProtocolVersion,
        request_id: BrokerRequestId,
        error: BrokerProtocolError,
        close_connection: bool,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        self.response_outcome(
            BrokerResponseEnvelope::new(version, request_id, BrokerResponse::Error(error)),
            close_connection,
        )
    }

    fn response_outcome(
        &self,
        response: BrokerResponseEnvelope,
        close_connection: bool,
    ) -> Result<BrokerDispatchOutcome, BrokerDispatchError> {
        let response_payload =
            encode_broker_response(&response).map_err(|_| BrokerDispatchError)?;
        Ok(BrokerDispatchOutcome {
            response_payload,
            close_connection,
        })
    }
}

fn protocol_error_for_code(error_code: BrokerErrorCode) -> BrokerProtocolError {
    let required_action = match error_code {
        BrokerErrorCode::PairingRequired | BrokerErrorCode::ConsumerRevoked => {
            Some(BrokerRequiredAction::PairConsumer)
        }
        BrokerErrorCode::PairingPending => Some(BrokerRequiredAction::WaitForPairing),
        BrokerErrorCode::VaultLocked => Some(BrokerRequiredAction::UnlockVault),
        BrokerErrorCode::ApprovalRequired => Some(BrokerRequiredAction::ApproveRequest),
        BrokerErrorCode::ApprovalPending => Some(BrokerRequiredAction::WaitForApproval),
        BrokerErrorCode::RateLimited => Some(BrokerRequiredAction::RetryLater),
        BrokerErrorCode::ProtocolIncompatible
        | BrokerErrorCode::MalformedFrame
        | BrokerErrorCode::OversizedFrame
        | BrokerErrorCode::AuthenticationFailed
        | BrokerErrorCode::AccessDenied
        | BrokerErrorCode::GrantExpired
        | BrokerErrorCode::UnsupportedCapability
        | BrokerErrorCode::InvalidRequest
        | BrokerErrorCode::BrokerPaused
        | BrokerErrorCode::OperationFailed => None,
    };
    let retryable = matches!(
        error_code,
        BrokerErrorCode::PairingPending
            | BrokerErrorCode::ApprovalPending
            | BrokerErrorCode::RateLimited
    );
    BrokerProtocolError::new(error_code, retryable, required_action, None)
}

fn authenticated_consumer(state: &BrokerConnectionState) -> ConsumerId {
    state
        .authenticated_session()
        .expect("Consumer-scoped dispatch requires connection authentication")
        .1
}

fn pairing_progress_response(
    progress: BrokerConsumerPairingProgress,
) -> BrokerPairingProgressResponse {
    match progress {
        BrokerConsumerPairingProgress::Active { consumer_id } => {
            BrokerPairingProgressResponse::active(consumer_id)
        }
        BrokerConsumerPairingProgress::Pending(pending) => {
            BrokerPairingProgressResponse::pending(BrokerPairingPendingResponse::new(
                pending.pairing_request_id(),
                *pending.client_nonce(),
                *pending.server_nonce(),
                pending.comparison_code(),
                pending.consumer_id(),
                pending.status(),
                pending.remaining().as_secs().max(1),
            ))
        }
    }
}

fn pairing_protocol_error(error: BrokerPairingError) -> BrokerProtocolError {
    match error {
        BrokerPairingError::InvalidProposal | BrokerPairingError::InvalidApproval => {
            BrokerProtocolError::new(BrokerErrorCode::InvalidRequest, false, None, None)
        }
        BrokerPairingError::AlreadyPaired { .. } => {
            BrokerProtocolError::new(BrokerErrorCode::InvalidRequest, false, None, None)
        }
        BrokerPairingError::AlreadyPending { .. }
        | BrokerPairingError::AwaitingUserApproval
        | BrokerPairingError::AlreadyApproved => BrokerProtocolError::new(
            BrokerErrorCode::PairingPending,
            true,
            Some(BrokerRequiredAction::WaitForPairing),
            None,
        ),
        BrokerPairingError::TooManyPending => BrokerProtocolError::new(
            BrokerErrorCode::RateLimited,
            true,
            Some(BrokerRequiredAction::RetryLater),
            None,
        ),
        BrokerPairingError::RequestUnavailable | BrokerPairingError::Expired => {
            BrokerProtocolError::new(
                BrokerErrorCode::PairingRequired,
                false,
                Some(BrokerRequiredAction::PairConsumer),
                None,
            )
        }
        BrokerPairingError::InvalidProof => BrokerProtocolError::new(
            BrokerErrorCode::AuthenticationFailed,
            false,
            Some(BrokerRequiredAction::PairConsumer),
            None,
        ),
        BrokerPairingError::StateUnavailable | BrokerPairingError::DeviceState(_) => {
            BrokerProtocolError::new(BrokerErrorCode::OperationFailed, false, None, None)
        }
    }
}

fn authentication_protocol_error(error: BrokerAuthenticationError) -> BrokerProtocolError {
    match error {
        BrokerAuthenticationError::ConsumerUnavailable => BrokerProtocolError::new(
            BrokerErrorCode::ConsumerRevoked,
            false,
            Some(BrokerRequiredAction::PairConsumer),
            None,
        ),
        BrokerAuthenticationError::Expired | BrokerAuthenticationError::InvalidProof => {
            BrokerProtocolError::new(BrokerErrorCode::AuthenticationFailed, false, None, None)
        }
        BrokerAuthenticationError::RateLimited => BrokerProtocolError::new(
            BrokerErrorCode::RateLimited,
            true,
            Some(BrokerRequiredAction::RetryLater),
            None,
        ),
        BrokerAuthenticationError::StateUnavailable | BrokerAuthenticationError::DeviceState(_) => {
            BrokerProtocolError::new(BrokerErrorCode::OperationFailed, false, None, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::protocol::{
        decode_broker_response, encode_broker_request, BrokerCapabilityVersions,
        BrokerHelloRequest, BrokerProtocolVersionRange, BrokerRequestEnvelope,
    };
    use crate::{Capability, CapabilityName};

    use super::*;

    fn dispatcher() -> BrokerDispatcher {
        let mut capabilities = BrokerCapabilitySet::empty();
        capabilities.insert(Capability::v1(CapabilityName::CredentialSearch));
        BrokerDispatcher::new(BrokerInstanceId::generate(), capabilities)
    }

    fn hello(request_id: BrokerRequestId, ranges: Vec<BrokerProtocolVersionRange>) -> Vec<u8> {
        encode_broker_request(&BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            request_id,
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    ranges,
                    vec![
                        BrokerCapabilityVersions::new(CapabilityName::CredentialSearch, [1, 2])
                            .expect("capability"),
                    ],
                )
                .expect("hello"),
            ),
        ))
        .expect("encode")
    }

    fn status(request_id: BrokerRequestId, version: BrokerProtocolVersion) -> Vec<u8> {
        encode_broker_request(&BrokerRequestEnvelope::new(
            version,
            request_id,
            BrokerRequest::Status,
        ))
        .expect("encode")
    }

    #[test]
    fn connection_requires_hello_before_status() {
        let dispatcher = dispatcher();
        let mut state = BrokerConnectionState::awaiting_hello();
        let request_id = BrokerRequestId::generate();
        let outcome = dispatcher
            .dispatch(
                &mut state,
                &status(request_id, BrokerProtocolVersion::current()),
            )
            .expect("dispatch");
        assert!(outcome.should_close_connection());
        let response = decode_broker_response(outcome.response_payload()).expect("response");
        assert_eq!(response.request_id(), request_id);
        assert_eq!(
            response.response(),
            &BrokerResponse::Error(BrokerProtocolError::new(
                BrokerErrorCode::ProtocolIncompatible,
                false,
                Some(BrokerRequiredAction::SendHello),
                None,
            ))
        );
        assert!(!state.is_negotiated());
    }

    #[test]
    fn hello_negotiates_then_status_returns_stable_instance_identity() {
        let dispatcher = dispatcher();
        let mut state = BrokerConnectionState::awaiting_hello();
        let hello_id = BrokerRequestId::generate();
        let outcome = dispatcher
            .dispatch(
                &mut state,
                &hello(
                    hello_id,
                    vec![BrokerProtocolVersionRange::new(1, 0, 4).expect("range")],
                ),
            )
            .expect("hello");
        assert!(!outcome.should_close_connection());
        assert_eq!(
            state.negotiated_protocol(),
            Some(BrokerProtocolVersion::current())
        );
        let response = decode_broker_response(outcome.response_payload()).expect("response");
        let BrokerResponse::Hello(hello) = response.response() else {
            panic!("hello response");
        };
        assert_eq!(hello.capabilities().len(), 1);
        assert_eq!(
            hello.capabilities()[0].capability_name(),
            CapabilityName::CredentialSearch
        );
        assert_eq!(hello.capabilities()[0].version(), 1);

        let status_id = BrokerRequestId::generate();
        let outcome = dispatcher
            .dispatch(
                &mut state,
                &status(status_id, BrokerProtocolVersion::current()),
            )
            .expect("status");
        let response = decode_broker_response(outcome.response_payload()).expect("response");
        assert_eq!(response.request_id(), status_id);
        assert_eq!(
            response.response(),
            &BrokerResponse::Status(BrokerStatusResponse::new(dispatcher.broker_instance_id()))
        );
    }

    #[test]
    fn incompatible_hello_and_post_negotiation_version_mismatch_close() {
        let dispatcher = dispatcher();
        let mut state = BrokerConnectionState::awaiting_hello();
        let incompatible = dispatcher
            .dispatch(
                &mut state,
                &hello(
                    BrokerRequestId::generate(),
                    vec![BrokerProtocolVersionRange::new(2, 0, 0).expect("range")],
                ),
            )
            .expect("dispatch");
        assert!(incompatible.should_close_connection());
        assert!(!state.is_negotiated());

        let mut state = BrokerConnectionState::awaiting_hello();
        dispatcher
            .dispatch(
                &mut state,
                &hello(
                    BrokerRequestId::generate(),
                    vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                ),
            )
            .expect("hello");
        let mismatched = dispatcher
            .dispatch(
                &mut state,
                &status(
                    BrokerRequestId::generate(),
                    BrokerProtocolVersion::new(1, 1).expect("version"),
                ),
            )
            .expect("dispatch");
        assert!(mismatched.should_close_connection());
    }

    #[test]
    fn repeated_hello_is_rejected_without_resetting_negotiation() {
        let dispatcher = dispatcher();
        let mut state = BrokerConnectionState::awaiting_hello();
        let payload = hello(
            BrokerRequestId::generate(),
            vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
        );
        dispatcher
            .dispatch(&mut state, &payload)
            .expect("first hello");
        let repeated = dispatcher.dispatch(&mut state, &payload).expect("repeat");
        assert!(!repeated.should_close_connection());
        assert!(state.is_negotiated());
        let response = decode_broker_response(repeated.response_payload()).expect("response");
        assert_eq!(
            response.response(),
            &BrokerResponse::Error(BrokerProtocolError::new(
                BrokerErrorCode::InvalidRequest,
                false,
                None,
                None,
            ))
        );
    }

    #[test]
    fn malformed_or_unknown_input_is_never_reflected_in_errors() {
        let dispatcher = dispatcher();
        let mut state = BrokerConnectionState::awaiting_hello();
        let secret_marker = "KN_SECRET_SHOULD_NOT_RETURN";
        let malformed = format!(r#"{{"secret":"{secret_marker}","secret":"again"}}"#);
        let outcome = dispatcher
            .dispatch(&mut state, malformed.as_bytes())
            .expect("dispatch");
        assert!(outcome.should_close_connection());
        assert!(!String::from_utf8_lossy(outcome.response_payload()).contains(secret_marker));

        let request_id = BrokerRequestId::generate();
        let unknown = format!(
            r#"{{"protocol_name":"keptnear.broker","protocol_major":1,"protocol_minor":0,"message_type":"secret.get","request_id":"{request_id}","body":{{"value":"{secret_marker}"}}}}"#
        );
        let mut negotiated = BrokerConnectionState {
            negotiated_protocol: Some(BrokerProtocolVersion::current()),
            negotiated_capabilities: Vec::new(),
            authentication_challenge: None,
            authenticated_session: None,
        };
        let outcome = dispatcher
            .dispatch(&mut negotiated, unknown.as_bytes())
            .expect("dispatch");
        assert!(!outcome.should_close_connection());
        assert!(!String::from_utf8_lossy(outcome.response_payload()).contains(secret_marker));
        let response = decode_broker_response(outcome.response_payload()).expect("response");
        assert_eq!(response.request_id(), request_id);

        let status_id = BrokerRequestId::generate();
        let extension = format!(
            r#"{{"protocol_name":"keptnear.broker","protocol_major":1,"protocol_minor":0,"message_type":"broker.status","request_id":"{status_id}","body":{{}},"extensions":{{"future":{{"opaque":"{secret_marker}"}}}}}}"#
        );
        let outcome = dispatcher
            .dispatch(&mut negotiated, extension.as_bytes())
            .expect("extension");
        assert!(!outcome.should_close_connection());
        assert!(!String::from_utf8_lossy(outcome.response_payload()).contains(secret_marker));
        let response = decode_broker_response(outcome.response_payload()).expect("response");
        assert_eq!(response.request_id(), status_id);
        assert!(matches!(response.response(), BrokerResponse::Status(_)));
    }

    #[test]
    fn vault_path_conflicts_project_to_one_generic_consumer_error() {
        let dispatcher = dispatcher();
        for error in [
            crate::vault_session::BrokerVaultSessionError::VaultIdentityAlreadyOpen,
            crate::vault_session::BrokerVaultSessionError::VaultPathIdentityChanged,
        ] {
            let request_id = BrokerRequestId::generate();
            let outcome = dispatcher
                .runtime_error_outcome(
                    BrokerProtocolVersion::current(),
                    request_id,
                    BrokerRuntimeError::VaultSession(error),
                    false,
                )
                .expect("project runtime error");
            let response =
                decode_broker_response(outcome.response_payload()).expect("decode response");
            assert_eq!(response.request_id(), request_id);
            assert_eq!(
                response.response(),
                &BrokerResponse::Error(BrokerProtocolError::new(
                    BrokerErrorCode::OperationFailed,
                    false,
                    None,
                    None,
                ))
            );
            let encoded = String::from_utf8_lossy(outcome.response_payload()).to_lowercase();
            assert!(!encoded.contains("path"));
            assert!(!encoded.contains("identity"));
            assert!(!encoded.contains("vaultidentityalreadyopen"));
            assert!(!encoded.contains("vaultpathidentitychanged"));
        }
    }

    #[test]
    fn request_ids_are_not_derived_from_labels_or_payloads() {
        let parsed = BrokerRequestId::from_str("request_00000000000000000000000000000000")
            .expect("canonical");
        assert_eq!(
            parsed.to_string(),
            "request_00000000000000000000000000000000"
        );
    }
}
