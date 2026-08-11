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
    CONTROLLER_ROLE, MAX_CONTROLLER_FAILURES_GLOBALLY, MAX_CONTROLLER_FAILURES_PER_IDENTITY,
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

/// Strict request for one fresh controller challenge.
#[derive(Clone, Eq, PartialEq)]
pub struct ControllerChallengeRequest {
    mode: ControllerAuthenticationMode,
    protocol: HumanControlProtocolVersion,
    role: String,
    controller_id: ControllerId,
    public_key: [u8; 32],
    session_id: ControllerSessionId,
    client_nonce: ControllerNonce,
}

impl ControllerChallengeRequest {
    /// Creates a bounded challenge request. Role validity is checked by the Broker.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: ControllerAuthenticationMode,
        protocol: HumanControlProtocolVersion,
        role: String,
        controller_id: ControllerId,
        public_key: [u8; 32],
        session_id: ControllerSessionId,
        client_nonce: ControllerNonce,
    ) -> Result<Self, ControllerAuthenticationError> {
        if role.is_empty() || role.len() > 64 || !role.is_ascii() {
            return Err(ControllerAuthenticationError::AuthenticationFailed);
        }
        Ok(Self {
            mode,
            protocol,
            role,
            controller_id,
            public_key,
            session_id,
            client_nonce,
        })
    }

    /// Returns the requested bootstrap or ordinary authentication mode.
    #[must_use]
    pub const fn mode(&self) -> ControllerAuthenticationMode {
        self.mode
    }

    /// Returns whether this request exactly names the loaded restricted seed.
    #[must_use]
    pub fn matches_key(&self, key: &ControllerSigningKey) -> bool {
        self.controller_id == key.controller_id() && self.public_key == key.public_key()
    }
}

impl Debug for ControllerChallengeRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerChallengeRequest")
            .field("mode", &self.mode)
            .field("protocol", &self.protocol)
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
    session_id: ControllerSessionId,
    client_nonce: ControllerNonce,
    broker_nonce: ControllerNonce,
    deadline: ControllerDeadline,
    signature: ControllerSignature,
}

impl ControllerAuthenticationProof {
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

    fn record(&mut self, controller_id: ControllerId, now: Instant) {
        self.prune(now);
        self.global.push_back(now);
        self.by_controller
            .entry(controller_id)
            .or_default()
            .push_back(now);
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

impl ControllerAuthenticationConnection {
    /// Replaces any prior challenge and issues a fresh process-bound challenge.
    pub fn challenge(
        &mut self,
        request: ControllerChallengeRequest,
        record: Option<ControllerAuthorityRecord>,
        now: Instant,
    ) -> Result<ControllerAuthenticationChallenge, ControllerAuthenticationError> {
        self.outstanding.take();
        if request.role != CONTROLLER_ROLE
            || request.protocol != HumanControlProtocolVersion::current()
            || request.controller_id.as_bytes() != &crate::derive_controller_id(&request.public_key)
        {
            return self.fail(
                request.controller_id,
                now,
                ControllerAuthenticationError::AuthenticationFailed,
            );
        }
        match (request.mode, record) {
            (ControllerAuthenticationMode::Bootstrap, None) => {}
            (ControllerAuthenticationMode::Authenticate, Some(record))
                if record.controller_id() == request.controller_id
                    && record.public_key() == request.public_key => {}
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
            mode: request.mode,
            protocol: request.protocol,
            broker_instance_id: self.service.broker_instance_id,
            controller_id: request.controller_id,
            public_key: request.public_key,
            session_id: request.session_id,
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
        self.service
            .failures
            .lock()
            .map_err(|_| ControllerAuthenticationError::OperationFailed)?
            .record(controller_id, now);
        Err(error)
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

    fn request(
        key: &ControllerSigningKey,
        mode: ControllerAuthenticationMode,
        session_byte: u8,
        role: &str,
    ) -> ControllerChallengeRequest {
        ControllerChallengeRequest::new(
            mode,
            HumanControlProtocolVersion::current(),
            role.to_owned(),
            key.controller_id(),
            key.public_key(),
            ControllerSessionId::from_bytes([session_byte; 16]),
            ControllerNonce::from_bytes([session_byte.wrapping_add(1); 32]),
        )
        .expect("request")
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
        let challenge = bootstrap
            .challenge(
                request(
                    &key,
                    ControllerAuthenticationMode::Bootstrap,
                    1,
                    CONTROLLER_ROLE,
                ),
                None,
                now,
            )
            .expect("bootstrap challenge");
        let auth_key = signing_key(7);
        let completion = bootstrap
            .complete(challenge.prove(&auth_key), now, timestamp())
            .expect("bootstrap proof");
        let ControllerAuthenticationCompletion::Bootstrap { record, .. } = completion else {
            panic!("expected bootstrap record")
        };

        let mut ordinary = service.connection();
        let challenge = ordinary
            .challenge(
                request(
                    &auth_key,
                    ControllerAuthenticationMode::Authenticate,
                    2,
                    CONTROLLER_ROLE,
                ),
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
    fn every_attempt_consumes_challenge_and_replay_or_changed_bindings_fail() {
        let key = signing_key(8);
        let service = ControllerAuthenticationService::new(BrokerInstanceId::generate());
        let now = Instant::now();
        let mut connection = service.connection();
        let challenge = connection
            .challenge(
                request(
                    &key,
                    ControllerAuthenticationMode::Bootstrap,
                    3,
                    CONTROLLER_ROLE,
                ),
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
    fn expiry_wrong_role_wrong_key_and_broker_restart_fail_non_reflectively() {
        let key = signing_key(9);
        let wrong = signing_key(10);
        let instance = BrokerInstanceId::generate();
        let service = ControllerAuthenticationService::new(instance);
        let now = Instant::now();

        let mut wrong_role = service.connection();
        assert_eq!(
            wrong_role.challenge(
                request(&key, ControllerAuthenticationMode::Bootstrap, 4, "consumer"),
                None,
                now,
            ),
            Err(ControllerAuthenticationError::AuthenticationFailed)
        );

        let mut expired = service.connection();
        let challenge = expired
            .challenge(
                request(
                    &key,
                    ControllerAuthenticationMode::Bootstrap,
                    5,
                    CONTROLLER_ROLE,
                ),
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
        let challenge = invalid
            .challenge(
                request(
                    &key,
                    ControllerAuthenticationMode::Bootstrap,
                    6,
                    CONTROLLER_ROLE,
                ),
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
        let first = connection
            .challenge(
                request(
                    &key,
                    ControllerAuthenticationMode::Bootstrap,
                    7,
                    CONTROLLER_ROLE,
                ),
                None,
                now,
            )
            .expect("first");
        let second = connection
            .challenge(
                request(
                    &key,
                    ControllerAuthenticationMode::Bootstrap,
                    8,
                    CONTROLLER_ROLE,
                ),
                None,
                now,
            )
            .expect("replacement");
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
            let challenge = attempt
                .challenge(
                    request(
                        &key,
                        ControllerAuthenticationMode::Bootstrap,
                        20 + u8::try_from(offset).expect("offset"),
                        CONTROLLER_ROLE,
                    ),
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
                request(
                    &key,
                    ControllerAuthenticationMode::Bootstrap,
                    40,
                    CONTROLLER_ROLE
                ),
                None,
                now + Duration::from_secs(1),
            ),
            Err(ControllerAuthenticationError::RateLimited)
        );
    }
}
