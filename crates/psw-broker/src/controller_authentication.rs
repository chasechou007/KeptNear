use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Debug, Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};

use crate::controller_authority_contract::{
    controller_authentication_transcript, controller_bootstrap_transcript,
    ControllerTranscriptFields, CONTROLLER_CHALLENGE_TTL, CONTROLLER_FAILURE_WINDOW,
    MAX_CONTROLLER_FAILURES_GLOBALLY, MAX_CONTROLLER_FAILURES_PER_IDENTITY,
};
use crate::{
    BrokerInstanceId, ControllerAuthorityRecord, ControllerDeadline, ControllerId, ControllerNonce,
    ControllerSessionId, ControllerSignature, ControllerSigningKey, HumanControlFailureCode,
    HumanControlProtocolFailure, HumanControlProtocolVersion, HumanControlRequiredAction,
    StateTimestamp,
};

/// Signed controller proof domain selected before a challenge is issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAuthenticationMode {
    /// First proof that permits insertion of the public Broker record.
    Bootstrap,
    /// Ordinary proof against an existing exact public record.
    Authenticate,
}

impl ControllerAuthenticationMode {
    /// Returns the canonical Human Control wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Authenticate => "authenticate",
        }
    }

    /// Parses one canonical Human Control wire value.
    pub fn from_wire(value: &str) -> Result<Self, HumanControlProtocolFailure> {
        match value {
            "bootstrap" => Ok(Self::Bootstrap),
            "authenticate" => Ok(Self::Authenticate),
            _ => Err(HumanControlProtocolFailure::new(
                HumanControlFailureCode::MalformedFrame,
                false,
                None,
            )),
        }
    }
}

/// Strict request for one fresh controller challenge.
#[derive(Clone, Eq, PartialEq)]
pub struct ControllerChallengeRequest {
    controller_id: ControllerId,
    client_nonce: ControllerNonce,
}

impl ControllerChallengeRequest {
    /// Creates the exact closed wire request. Challenge-only fields are Broker-derived.
    #[must_use]
    pub const fn new(controller_id: ControllerId, client_nonce: ControllerNonce) -> Self {
        Self {
            controller_id,
            client_nonce,
        }
    }

    /// Returns the claimed public controller identity for bounded admission checks.
    #[must_use]
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Returns the independently generated client nonce retained for this request.
    #[must_use]
    pub const fn client_nonce(&self) -> ControllerNonce {
        self.client_nonce
    }
}

impl Debug for ControllerChallengeRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerChallengeRequest")
            .field("authentication_material", &"<redacted>")
            .finish()
    }
}

/// One process- and connection-bound controller challenge.
#[derive(Clone, Eq, PartialEq)]
pub struct ControllerAuthenticationChallenge {
    mode: ControllerAuthenticationMode,
    protocol: HumanControlProtocolVersion,
    broker_instance_id: BrokerInstanceId,
    controller_id: ControllerId,
    public_key: [u8; 32],
    session_id: ControllerSessionId,
    client_nonce: ControllerNonce,
    broker_nonce: ControllerNonce,
    deadline: ControllerDeadline,
}

impl ControllerAuthenticationChallenge {
    /// Reconstructs a challenge from a closed, validated Broker response.
    #[allow(clippy::too_many_arguments)]
    pub fn from_validated_wire_bindings(
        mode: ControllerAuthenticationMode,
        protocol: HumanControlProtocolVersion,
        broker_instance_id: BrokerInstanceId,
        controller_id: ControllerId,
        public_key: [u8; 32],
        session_id: ControllerSessionId,
        client_nonce: ControllerNonce,
        broker_nonce: ControllerNonce,
        deadline: ControllerDeadline,
    ) -> Result<Self, HumanControlProtocolFailure> {
        if protocol.major() == 0
            || crate::derive_controller_id(&public_key) != *controller_id.as_bytes()
        {
            return Err(HumanControlProtocolFailure::new(
                HumanControlFailureCode::MalformedFrame,
                false,
                None,
            ));
        }
        Ok(Self {
            mode,
            protocol,
            broker_instance_id,
            controller_id,
            public_key,
            session_id,
            client_nonce,
            broker_nonce,
            deadline,
        })
    }

    /// Returns the proof domain selected for this challenge.
    #[must_use]
    pub const fn mode(&self) -> ControllerAuthenticationMode {
        self.mode
    }

    /// Returns the selected protocol version.
    #[must_use]
    pub const fn protocol(&self) -> HumanControlProtocolVersion {
        self.protocol
    }

    /// Returns the process instance identity bound into the proof.
    #[must_use]
    pub const fn broker_instance_id(&self) -> BrokerInstanceId {
        self.broker_instance_id
    }

    /// Returns the public controller identity bound into the proof.
    #[must_use]
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Returns the non-secret Ed25519 public key bound into the proof.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the controller session identity bound into the proof.
    #[must_use]
    pub const fn session_id(&self) -> ControllerSessionId {
        self.session_id
    }

    /// Returns the independently generated client nonce.
    #[must_use]
    pub const fn client_nonce(&self) -> ControllerNonce {
        self.client_nonce
    }

    /// Returns the independently generated Broker nonce.
    #[must_use]
    pub const fn broker_nonce(&self) -> ControllerNonce {
        self.broker_nonce
    }

    /// Returns the opaque monotonic deadline token.
    #[must_use]
    pub const fn deadline(&self) -> ControllerDeadline {
        self.deadline
    }

    /// Builds the exact domain-separated transcript that the App must sign.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let fields = ControllerTranscriptFields::new(
            self.protocol,
            *self.controller_id.as_bytes(),
            self.public_key,
            *self.broker_instance_id.as_bytes(),
            *self.session_id.as_bytes(),
            *self.client_nonce.as_bytes(),
            *self.broker_nonce.as_bytes(),
            self.deadline.token(),
        )
        .expect("challenge fields were validated before construction");
        match self.mode {
            ControllerAuthenticationMode::Bootstrap => controller_bootstrap_transcript(&fields),
            ControllerAuthenticationMode::Authenticate => {
                controller_authentication_transcript(&fields)
            }
        }
    }

    /// Signs this exact challenge with the controller seed.
    #[must_use]
    pub fn prove(&self, key: &ControllerSigningKey) -> ControllerAuthenticationProof {
        ControllerAuthenticationProof {
            broker_instance_id: self.broker_instance_id,
            controller_id: self.controller_id,
            session_id: self.session_id,
            client_nonce: self.client_nonce,
            broker_nonce: self.broker_nonce,
            deadline: self.deadline,
            signature: key.sign(&self.transcript()),
        }
    }
}

impl Debug for ControllerAuthenticationChallenge {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerAuthenticationChallenge")
            .field("mode", &self.mode)
            .field("protocol", &self.protocol)
            .field("authentication_material", &"<redacted>")
            .finish()
    }
}

/// Echoed challenge binding plus one Ed25519 controller signature.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ControllerAuthenticationProof {
    broker_instance_id: BrokerInstanceId,
    controller_id: ControllerId,
    session_id: ControllerSessionId,
    client_nonce: ControllerNonce,
    broker_nonce: ControllerNonce,
    deadline: ControllerDeadline,
    signature: ControllerSignature,
}

impl ControllerAuthenticationProof {
    /// Reconstructs one proof from an already validated closed wire body.
    ///
    /// Construction does not authenticate these public bindings. Completion
    /// still consumes and compares the outstanding challenge before verifying
    /// the Ed25519 signature.
    #[must_use]
    pub const fn from_validated_wire_bindings(
        broker_instance_id: BrokerInstanceId,
        controller_id: ControllerId,
        session_id: ControllerSessionId,
        client_nonce: ControllerNonce,
        broker_nonce: ControllerNonce,
        deadline: ControllerDeadline,
        signature: ControllerSignature,
    ) -> Self {
        Self {
            broker_instance_id,
            controller_id,
            session_id,
            client_nonce,
            broker_nonce,
            deadline,
            signature,
        }
    }

    pub(crate) const fn broker_instance_id(self) -> BrokerInstanceId {
        self.broker_instance_id
    }

    pub(crate) const fn controller_id(self) -> ControllerId {
        self.controller_id
    }

    pub(crate) const fn session_id(self) -> ControllerSessionId {
        self.session_id
    }

    pub(crate) const fn client_nonce(self) -> ControllerNonce {
        self.client_nonce
    }

    pub(crate) const fn broker_nonce(self) -> ControllerNonce {
        self.broker_nonce
    }

    pub(crate) const fn deadline(self) -> ControllerDeadline {
        self.deadline
    }

    pub(crate) const fn signature(self) -> ControllerSignature {
        self.signature
    }

    /// Replaces the echoed controller identity, useful to reject identity substitution.
    #[must_use]
    pub fn with_controller_id(mut self, controller_id: ControllerId) -> Self {
        self.controller_id = controller_id;
        self
    }

    /// Replaces the echoed session identity, useful to reject stale clients before verification.
    #[must_use]
    pub fn with_session_id(mut self, session_id: ControllerSessionId) -> Self {
        self.session_id = session_id;
        self
    }

    /// Replaces the echoed Broker instance, useful to reject cross-process replay.
    #[must_use]
    pub fn with_broker_instance_id(mut self, broker_instance_id: BrokerInstanceId) -> Self {
        self.broker_instance_id = broker_instance_id;
        self
    }

    /// Replaces the signature with exact bytes for strict protocol decoding.
    #[must_use]
    pub fn with_signature(mut self, signature: ControllerSignature) -> Self {
        self.signature = signature;
        self
    }
}

impl Debug for ControllerAuthenticationProof {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerAuthenticationProof(<redacted>)")
    }
}

/// Successful proof result, with a public record only for first bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAuthenticationCompletion {
    /// Bootstrap proof succeeded and this exact public record may be inserted once.
    Bootstrap {
        /// Public record that may be inserted once.
        record: ControllerAuthorityRecord,
        /// Ephemeral authenticated controller session.
        session_id: ControllerSessionId,
    },
    /// Existing matching authority authenticated for this session.
    Authenticated {
        /// Stable public controller identity.
        controller_id: ControllerId,
        /// Ephemeral authenticated controller session.
        session_id: ControllerSessionId,
    },
}

/// Fixed non-reflective controller authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAuthenticationError {
    /// No valid challenge exists or an echoed binding changed.
    ReplayRejected,
    /// Role, authority, deadline, or Ed25519 proof validation failed.
    AuthenticationFailed,
    /// The process-local bounded failure budget is exhausted.
    RateLimited,
    /// Internal synchronization failed without exposing details.
    OperationFailed,
}

impl ControllerAuthenticationError {
    /// Maps the internal category to one fixed human-control failure.
    #[must_use]
    pub const fn protocol_failure(self) -> HumanControlProtocolFailure {
        match self {
            Self::ReplayRejected => HumanControlProtocolFailure::new(
                HumanControlFailureCode::ReplayRejected,
                false,
                Some(HumanControlRequiredAction::Reauthenticate),
            ),
            Self::AuthenticationFailed => HumanControlProtocolFailure::new(
                HumanControlFailureCode::AuthenticationFailed,
                false,
                Some(HumanControlRequiredAction::Reauthenticate),
            ),
            Self::RateLimited => HumanControlProtocolFailure::new(
                HumanControlFailureCode::RateLimited,
                true,
                Some(HumanControlRequiredAction::RetryLater),
            ),
            Self::OperationFailed => HumanControlProtocolFailure::new(
                HumanControlFailureCode::OperationFailed,
                true,
                Some(HumanControlRequiredAction::RetryLater),
            ),
        }
    }
}

impl Display for ControllerAuthenticationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ReplayRejected => "controller proof was rejected",
            Self::AuthenticationFailed => "controller authentication failed",
            Self::RateLimited => "controller authentication is rate limited",
            Self::OperationFailed => "controller authentication operation failed",
        })
    }
}

impl std::error::Error for ControllerAuthenticationError {}

#[derive(Default)]
struct FailureTracker {
    global: VecDeque<Instant>,
    by_controller: BTreeMap<ControllerId, VecDeque<Instant>>,
}

impl FailureTracker {
    fn is_limited(&mut self, controller_id: ControllerId, now: Instant) -> bool {
        self.prune(now);
        self.global.len() >= MAX_CONTROLLER_FAILURES_GLOBALLY
            || self
                .by_controller
                .get(&controller_id)
                .is_some_and(|events| events.len() >= MAX_CONTROLLER_FAILURES_PER_IDENTITY)
    }

    fn record_if_allowed(&mut self, controller_id: ControllerId, now: Instant) -> bool {
        self.prune(now);
        if self.global.len() >= MAX_CONTROLLER_FAILURES_GLOBALLY
            || self
                .by_controller
                .get(&controller_id)
                .is_some_and(|events| events.len() >= MAX_CONTROLLER_FAILURES_PER_IDENTITY)
        {
            return false;
        }
        self.global.push_back(now);
        self.by_controller
            .entry(controller_id)
            .or_default()
            .push_back(now);
        true
    }

    fn prune(&mut self, now: Instant) {
        while self
            .global
            .front()
            .is_some_and(|event| now.saturating_duration_since(*event) >= CONTROLLER_FAILURE_WINDOW)
        {
            self.global.pop_front();
        }
        self.by_controller.retain(|_, events| {
            while events.front().is_some_and(|event| {
                now.saturating_duration_since(*event) >= CONTROLLER_FAILURE_WINDOW
            }) {
                events.pop_front();
            }
            !events.is_empty()
        });
    }
}

/// Process-local controller authentication service shared by control connections.
#[derive(Clone)]
pub struct ControllerAuthenticationService {
    broker_instance_id: BrokerInstanceId,
    next_deadline: Arc<AtomicU64>,
    failures: Arc<Mutex<FailureTracker>>,
}

impl ControllerAuthenticationService {
    /// Creates a fresh process-local service. Restarting creates a new instance binding.
    #[must_use]
    pub fn new(broker_instance_id: BrokerInstanceId) -> Self {
        let mut token = OsRng.next_u64();
        if token == 0 {
            token = 1;
        }
        Self {
            broker_instance_id,
            next_deadline: Arc::new(AtomicU64::new(token)),
            failures: Arc::new(Mutex::new(FailureTracker::default())),
        }
    }

    /// Creates one connection state with no outstanding challenge.
    #[must_use]
    pub fn connection(&self) -> ControllerAuthenticationConnection {
        ControllerAuthenticationConnection {
            service: self.clone(),
            outstanding: None,
        }
    }
}

struct OutstandingChallenge {
    challenge: ControllerAuthenticationChallenge,
    expires_at: Instant,
}

/// Per-connection state enforcing at most one live, single-use challenge.
pub struct ControllerAuthenticationConnection {
    service: ControllerAuthenticationService,
    outstanding: Option<OutstandingChallenge>,
}

#[derive(Clone, Copy)]
struct ControllerProtocolCompatibility {
    selected: HumanControlProtocolVersion,
    broker: HumanControlProtocolVersion,
}

impl ControllerAuthenticationConnection {
    /// Refuses challenge work before protected key access once a shared budget is exhausted.
    pub fn check_challenge_budget(
        &self,
        controller_id: ControllerId,
        now: Instant,
    ) -> Result<(), ControllerAuthenticationError> {
        if self.is_limited(controller_id, now)? {
            Err(ControllerAuthenticationError::RateLimited)
        } else {
            Ok(())
        }
    }

    /// Consumes challenge state and records a dispatcher-side authority mismatch.
    pub fn reject_challenge(
        &mut self,
        controller_id: ControllerId,
        now: Instant,
    ) -> ControllerAuthenticationError {
        self.outstanding.take();
        self.record_failure(
            controller_id,
            now,
            ControllerAuthenticationError::AuthenticationFailed,
        )
    }

    /// Replaces any prior challenge and issues a fresh process-bound challenge.
    pub(crate) fn challenge(
        &mut self,
        request: ControllerChallengeRequest,
        mode: ControllerAuthenticationMode,
        protocol: HumanControlProtocolVersion,
        public_key: [u8; 32],
        record: Option<ControllerAuthorityRecord>,
        now: Instant,
    ) -> Result<ControllerAuthenticationChallenge, ControllerAuthenticationError> {
        self.challenge_for_broker_protocol(
            request,
            mode,
            ControllerProtocolCompatibility {
                selected: protocol,
                broker: HumanControlProtocolVersion::current(),
            },
            public_key,
            record,
            now,
        )
    }

    fn challenge_for_broker_protocol(
        &mut self,
        request: ControllerChallengeRequest,
        mode: ControllerAuthenticationMode,
        compatibility: ControllerProtocolCompatibility,
        public_key: [u8; 32],
        record: Option<ControllerAuthorityRecord>,
        now: Instant,
    ) -> Result<ControllerAuthenticationChallenge, ControllerAuthenticationError> {
        self.outstanding.take();
        if !compatibility.selected.is_supported_by(compatibility.broker)
            || request.controller_id.as_bytes() != &crate::derive_controller_id(&public_key)
        {
            return self.fail(
                request.controller_id,
                now,
                ControllerAuthenticationError::AuthenticationFailed,
            );
        }
        match (mode, record) {
            (ControllerAuthenticationMode::Bootstrap, None) => {}
            (ControllerAuthenticationMode::Authenticate, Some(record))
                if record.controller_id() == request.controller_id
                    && record.public_key() == public_key => {}
            _ => {
                return self.fail(
                    request.controller_id,
                    now,
                    ControllerAuthenticationError::AuthenticationFailed,
                );
            }
        }
        if self.is_limited(request.controller_id, now)? {
            return Err(ControllerAuthenticationError::RateLimited);
        }
        let deadline = self.next_deadline()?;
        let challenge = ControllerAuthenticationChallenge {
            mode,
            protocol: compatibility.selected,
            broker_instance_id: self.service.broker_instance_id,
            controller_id: request.controller_id,
            public_key,
            session_id: ControllerSessionId::generate(),
            client_nonce: request.client_nonce,
            broker_nonce: ControllerNonce::generate(),
            deadline,
        };
        self.outstanding = Some(OutstandingChallenge {
            challenge: challenge.clone(),
            expires_at: now + CONTROLLER_CHALLENGE_TTL,
        });
        Ok(challenge)
    }

    /// Consumes the challenge before validating any echoed field or signature.
    pub fn complete(
        &mut self,
        proof: ControllerAuthenticationProof,
        now: Instant,
        approved_at: StateTimestamp,
    ) -> Result<ControllerAuthenticationCompletion, ControllerAuthenticationError> {
        let Some(outstanding) = self.outstanding.take() else {
            return Err(ControllerAuthenticationError::ReplayRejected);
        };
        let challenge = outstanding.challenge;
        if self.is_limited(challenge.controller_id, now)? {
            return Err(ControllerAuthenticationError::RateLimited);
        }
        if now >= outstanding.expires_at
            || proof.broker_instance_id != challenge.broker_instance_id
            || proof.controller_id != challenge.controller_id
            || proof.session_id != challenge.session_id
            || proof.client_nonce != challenge.client_nonce
            || proof.broker_nonce != challenge.broker_nonce
            || proof.deadline != challenge.deadline
        {
            return self.fail(
                challenge.controller_id,
                now,
                ControllerAuthenticationError::ReplayRejected,
            );
        }
        let verifying_key = match VerifyingKey::from_bytes(&challenge.public_key) {
            Ok(key) => key,
            Err(_) => {
                return self.fail(
                    challenge.controller_id,
                    now,
                    ControllerAuthenticationError::AuthenticationFailed,
                );
            }
        };
        let signature = Signature::from_bytes(proof.signature.as_bytes());
        if verifying_key
            .verify_strict(&challenge.transcript(), &signature)
            .is_err()
        {
            return self.fail(
                challenge.controller_id,
                now,
                ControllerAuthenticationError::AuthenticationFailed,
            );
        }
        Ok(match challenge.mode {
            ControllerAuthenticationMode::Bootstrap => {
                ControllerAuthenticationCompletion::Bootstrap {
                    record: ControllerAuthorityRecord::new(challenge.public_key, approved_at),
                    session_id: challenge.session_id,
                }
            }
            ControllerAuthenticationMode::Authenticate => {
                ControllerAuthenticationCompletion::Authenticated {
                    controller_id: challenge.controller_id,
                    session_id: challenge.session_id,
                }
            }
        })
    }

    /// Consumes any outstanding challenge when a connection closes or changes session.
    pub fn consume_outstanding(&mut self) {
        self.outstanding.take();
    }

    fn next_deadline(&self) -> Result<ControllerDeadline, ControllerAuthenticationError> {
        let token = self
            .service
            .next_deadline
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.wrapping_add(1).max(1))
            })
            .map_err(|_| ControllerAuthenticationError::OperationFailed)?;
        ControllerDeadline::new(token.max(1))
            .map_err(|_| ControllerAuthenticationError::OperationFailed)
    }

    fn is_limited(
        &self,
        controller_id: ControllerId,
        now: Instant,
    ) -> Result<bool, ControllerAuthenticationError> {
        self.service
            .failures
            .lock()
            .map_err(|_| ControllerAuthenticationError::OperationFailed)
            .map(|mut failures| failures.is_limited(controller_id, now))
    }

    fn fail<T>(
        &self,
        controller_id: ControllerId,
        now: Instant,
        error: ControllerAuthenticationError,
    ) -> Result<T, ControllerAuthenticationError> {
        Err(self.record_failure(controller_id, now, error))
    }

    fn record_failure(
        &self,
        controller_id: ControllerId,
        now: Instant,
        error: ControllerAuthenticationError,
    ) -> ControllerAuthenticationError {
        let Ok(mut failures) = self.service.failures.lock() else {
            return ControllerAuthenticationError::OperationFailed;
        };
        if failures.record_if_allowed(controller_id, now) {
            error
        } else {
            ControllerAuthenticationError::RateLimited
        }
    }
}

impl Debug for ControllerAuthenticationConnection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerAuthenticationConnection")
            .field("outstanding", &self.outstanding.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn signing_key(byte: u8) -> ControllerSigningKey {
        ControllerSigningKey::from_stored_bytes(vec![byte; 32]).expect("signing key")
    }

    fn request(key: &ControllerSigningKey, nonce_byte: u8) -> ControllerChallengeRequest {
        ControllerChallengeRequest::new(
            key.controller_id(),
            ControllerNonce::from_bytes([nonce_byte; 32]),
        )
    }

    fn issue_challenge(
        connection: &mut ControllerAuthenticationConnection,
        key: &ControllerSigningKey,
        mode: ControllerAuthenticationMode,
        nonce_byte: u8,
        record: Option<ControllerAuthorityRecord>,
        now: Instant,
    ) -> Result<ControllerAuthenticationChallenge, ControllerAuthenticationError> {
        connection.challenge(
            request(key, nonce_byte),
            mode,
            HumanControlProtocolVersion::current(),
            key.public_key(),
            record,
            now,
        )
    }

    fn timestamp() -> StateTimestamp {
        StateTimestamp::from_unix_millis(100).expect("timestamp")
    }

    #[test]
    fn bootstrap_and_ordinary_authentication_use_separate_domains() {
        let key = signing_key(7);
        let service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        let now = Instant::now();
        let mut bootstrap = service.connection();
        let challenge = issue_challenge(
            &mut bootstrap,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            1,
            None,
            now,
        )
        .expect("bootstrap challenge");
        assert_eq!(challenge.controller_id(), key.controller_id());
        assert_eq!(challenge.public_key(), key.public_key());
        let auth_key = signing_key(7);
        let completion = bootstrap
            .complete(challenge.prove(&auth_key), now, timestamp())
            .expect("bootstrap proof");
        let ControllerAuthenticationCompletion::Bootstrap { record, .. } = completion else {
            panic!("expected bootstrap record")
        };

        let mut ordinary = service.connection();
        let challenge = issue_challenge(
            &mut ordinary,
            &auth_key,
            ControllerAuthenticationMode::Authenticate,
            2,
            Some(record),
            now,
        )
        .expect("auth challenge");
        assert!(matches!(
            ordinary.complete(challenge.prove(&auth_key), now, timestamp()),
            Ok(ControllerAuthenticationCompletion::Authenticated { .. })
        ));
    }

    #[test]
    fn challenge_accepts_the_connection_selected_minor_supported_by_the_broker() {
        let key = signing_key(6);
        let service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        let now = Instant::now();
        let selected = HumanControlProtocolVersion::new(1, 0).expect("selected protocol");
        let future_broker = HumanControlProtocolVersion::new(1, 7).expect("future broker");
        let mut connection = service.connection();

        let challenge = connection
            .challenge_for_broker_protocol(
                request(&key, 1),
                ControllerAuthenticationMode::Bootstrap,
                ControllerProtocolCompatibility {
                    selected,
                    broker: future_broker,
                },
                key.public_key(),
                None,
                now,
            )
            .expect("selected version challenge");
        assert_eq!(challenge.protocol(), selected);

        let mut incompatible = service.connection();
        assert_eq!(
            incompatible.challenge_for_broker_protocol(
                request(&key, 2),
                ControllerAuthenticationMode::Bootstrap,
                ControllerProtocolCompatibility {
                    selected: future_broker,
                    broker: selected,
                },
                key.public_key(),
                None,
                now,
            ),
            Err(ControllerAuthenticationError::AuthenticationFailed)
        );
    }

    #[test]
    fn validated_wire_bindings_reconstruct_a_proof_without_controller_seed_access() {
        let key = signing_key(6);
        let service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        let now = Instant::now();
        let mut connection = service.connection();
        let challenge = issue_challenge(
            &mut connection,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            6,
            None,
            now,
        )
        .expect("challenge");
        let signature = key.sign(&challenge.transcript());
        let proof = ControllerAuthenticationProof::from_validated_wire_bindings(
            challenge.broker_instance_id(),
            key.controller_id(),
            challenge.session_id(),
            challenge.client_nonce(),
            challenge.broker_nonce(),
            challenge.deadline(),
            signature,
        );
        assert!(!format!("{proof:?}").contains(&format!("{signature:?}")));
        assert!(matches!(
            connection.complete(proof, now, timestamp()),
            Ok(ControllerAuthenticationCompletion::Bootstrap { .. })
        ));

        let mut changed_connection = service.connection();
        let challenge = issue_challenge(
            &mut changed_connection,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            7,
            None,
            now,
        )
        .expect("changed challenge");
        let proof = ControllerAuthenticationProof::from_validated_wire_bindings(
            challenge.broker_instance_id(),
            key.controller_id(),
            challenge.session_id(),
            challenge.client_nonce(),
            ControllerNonce::from_bytes([0xff; 32]),
            challenge.deadline(),
            key.sign(&challenge.transcript()),
        );
        assert_eq!(
            changed_connection.complete(proof, now, timestamp()),
            Err(ControllerAuthenticationError::ReplayRejected)
        );
    }

    #[test]
    fn every_attempt_consumes_challenge_and_replay_or_changed_bindings_fail() {
        let key = signing_key(8);
        let other_key = signing_key(9);
        let service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        let now = Instant::now();

        let mut identity_connection = service.connection();
        let identity_challenge = issue_challenge(
            &mut identity_connection,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            2,
            None,
            now,
        )
        .expect("identity challenge");
        let changed_identity = identity_challenge
            .prove(&key)
            .with_controller_id(other_key.controller_id());
        assert_eq!(
            identity_connection.complete(changed_identity, now, timestamp()),
            Err(ControllerAuthenticationError::ReplayRejected)
        );

        let mut connection = service.connection();
        let challenge = issue_challenge(
            &mut connection,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            3,
            None,
            now,
        )
        .expect("challenge");
        let proof = challenge.prove(&key);
        let changed = proof.with_session_id(ControllerSessionId::from_bytes([9; 16]));
        assert_eq!(
            connection.complete(changed, now, timestamp()),
            Err(ControllerAuthenticationError::ReplayRejected)
        );
        assert_eq!(
            connection.complete(proof, now, timestamp()),
            Err(ControllerAuthenticationError::ReplayRejected)
        );
    }

    #[test]
    fn expiry_wrong_key_and_broker_restart_fail_non_reflectively() {
        let key = signing_key(9);
        let wrong = signing_key(10);
        let instance = BrokerInstanceId::generate();
        let service = ControllerAuthenticationService::new(instance);
        let now = Instant::now();

        let mut expired = service.connection();
        let challenge = issue_challenge(
            &mut expired,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            5,
            None,
            now,
        )
        .expect("challenge");
        assert_eq!(
            expired.complete(
                challenge.prove(&key),
                now + CONTROLLER_CHALLENGE_TTL,
                timestamp()
            ),
            Err(ControllerAuthenticationError::ReplayRejected)
        );

        let mut invalid = service.connection();
        let challenge = issue_challenge(
            &mut invalid,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            6,
            None,
            now,
        )
        .expect("challenge");
        assert_eq!(
            invalid.complete(challenge.prove(&wrong), now, timestamp()),
            Err(ControllerAuthenticationError::AuthenticationFailed)
        );

        let fresh_service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        let mut fresh_connection = fresh_service.connection();
        assert_eq!(
            fresh_connection.complete(challenge.prove(&key), now, timestamp()),
            Err(ControllerAuthenticationError::ReplayRejected)
        );
        assert!(!ControllerAuthenticationError::AuthenticationFailed
            .to_string()
            .contains(&key.controller_id().to_string()));
    }

    #[test]
    fn replacement_disconnect_and_failure_budget_consume_state() {
        let key = signing_key(11);
        let service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        let now = Instant::now();
        let mut connection = service.connection();
        let first = issue_challenge(
            &mut connection,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            7,
            None,
            now,
        )
        .expect("first");
        let second = issue_challenge(
            &mut connection,
            &key,
            ControllerAuthenticationMode::Bootstrap,
            8,
            None,
            now,
        )
        .expect("replacement");
        assert_ne!(first.session_id(), second.session_id());
        assert_eq!(
            connection.complete(first.prove(&key), now, timestamp()),
            Err(ControllerAuthenticationError::ReplayRejected)
        );
        connection.consume_outstanding();
        assert_eq!(
            connection.complete(second.prove(&key), now, timestamp()),
            Err(ControllerAuthenticationError::ReplayRejected)
        );

        let budget_service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        for offset in 0..MAX_CONTROLLER_FAILURES_PER_IDENTITY {
            let mut attempt = budget_service.connection();
            let challenge = issue_challenge(
                &mut attempt,
                &key,
                ControllerAuthenticationMode::Bootstrap,
                20 + u8::try_from(offset).expect("offset"),
                None,
                now + Duration::from_millis(offset as u64),
            )
            .expect("challenge before limit");
            let bad_signature = ControllerSignature::from_bytes([0; 64]);
            assert_eq!(
                attempt.complete(
                    challenge.prove(&key).with_signature(bad_signature),
                    now + Duration::from_millis(offset as u64),
                    timestamp(),
                ),
                Err(ControllerAuthenticationError::AuthenticationFailed)
            );
        }
        let mut limited = budget_service.connection();
        assert_eq!(
            limited.challenge(
                request(&key, 40),
                ControllerAuthenticationMode::Bootstrap,
                HumanControlProtocolVersion::current(),
                key.public_key(),
                None,
                now + Duration::from_secs(1),
            ),
            Err(ControllerAuthenticationError::RateLimited)
        );

        for nonce in 50..150 {
            let mut malformed = budget_service.connection();
            assert_eq!(
                malformed.challenge(
                    request(&key, nonce),
                    ControllerAuthenticationMode::Bootstrap,
                    HumanControlProtocolVersion::current(),
                    key.public_key(),
                    None,
                    now + Duration::from_secs(1),
                ),
                Err(ControllerAuthenticationError::RateLimited)
            );
        }
        let failures = budget_service.failures.lock().expect("failure tracker");
        assert_eq!(failures.global.len(), MAX_CONTROLLER_FAILURES_PER_IDENTITY);
        assert_eq!(
            failures
                .by_controller
                .get(&key.controller_id())
                .expect("controller failures")
                .len(),
            MAX_CONTROLLER_FAILURES_PER_IDENTITY
        );
    }
}
