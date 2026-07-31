use std::collections::{BTreeMap, VecDeque};
use std::fmt::{Debug, Display, Formatter};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};

use crate::protocol::{BrokerProtocolVersion, BrokerSessionId};
use crate::state_model::{
    AuditDecision, AuditEvent, AuditEventKind, AuditScope, ConfirmationMethod, ConsumerId,
    StateTimestamp,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};

const AUTHENTICATION_DOMAIN: &[u8] = b"KeptNear broker auth v1";
const AUTHENTICATION_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const MAX_AUTHENTICATION_FAILURES_PER_CONSUMER: usize = 5;
const MAX_AUTHENTICATION_FAILURES_GLOBALLY: usize = 64;
const MAX_TRACKED_AUTHENTICATION_CONSUMERS: usize = 256;

/// Number of bytes in one fresh Broker authentication challenge.
pub const AUTHENTICATION_NONCE_LENGTH: usize = 32;
/// Number of bytes in one Ed25519 authentication proof.
pub const AUTHENTICATION_PROOF_LENGTH: usize = 64;
/// Maximum lifetime of one connection-bound authentication challenge.
pub const AUTHENTICATION_CHALLENGE_TTL: Duration = Duration::from_secs(30);

/// One connection-bound challenge for an already paired Consumer.
#[derive(Eq, PartialEq)]
pub struct BrokerAuthenticationChallenge {
    session_id: BrokerSessionId,
    consumer_id: ConsumerId,
    selected_protocol: BrokerProtocolVersion,
    pairing_public_key: [u8; 32],
    broker_nonce: [u8; AUTHENTICATION_NONCE_LENGTH],
    deadline: Instant,
}

impl BrokerAuthenticationChallenge {
    /// Returns the random identity of the prospective authenticated session.
    #[must_use]
    pub const fn session_id(&self) -> BrokerSessionId {
        self.session_id
    }

    /// Returns the Consumer that must prove possession of its pairing key.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the fresh nonce that is bound into the proof transcript.
    #[must_use]
    pub const fn broker_nonce(&self) -> &[u8; AUTHENTICATION_NONCE_LENGTH] {
        &self.broker_nonce
    }

    /// Returns the fixed challenge lifetime at issue time.
    #[must_use]
    pub const fn valid_for(&self) -> Duration {
        AUTHENTICATION_CHALLENGE_TTL
    }
}

impl Debug for BrokerAuthenticationChallenge {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerAuthenticationChallenge")
            .field("session_id", &self.session_id)
            .field("consumer_id", &self.consumer_id)
            .field("selected_protocol", &self.selected_protocol)
            .field("pairing_public_key", &"<redacted>")
            .field("broker_nonce", &"<redacted>")
            .field("valid_for", &AUTHENTICATION_CHALLENGE_TTL)
            .finish()
    }
}

/// Result of a successful one-attempt Consumer authentication proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAuthenticationCompletion {
    session_id: BrokerSessionId,
    consumer_id: ConsumerId,
}

impl BrokerAuthenticationCompletion {
    /// Returns the authenticated connection session identity.
    #[must_use]
    pub const fn session_id(self) -> BrokerSessionId {
        self.session_id
    }

    /// Returns the authenticated immutable Consumer identity.
    #[must_use]
    pub const fn consumer_id(self) -> ConsumerId {
        self.consumer_id
    }
}

/// Sanitized failure from Consumer connection authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerAuthenticationError {
    /// No active Consumer matches the requested immutable identity.
    ConsumerUnavailable,
    /// The challenge expired before the proof was submitted.
    Expired,
    /// The session, Consumer, public key, or signature did not match.
    InvalidProof,
    /// The process-local failure budget was exhausted.
    RateLimited,
    /// Process-local authentication state could not be accessed safely.
    StateUnavailable,
    /// Encrypted device state could not be read or updated.
    DeviceState(DeviceStateError),
}

impl Display for BrokerAuthenticationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::ConsumerUnavailable => "Consumer authentication is unavailable",
            Self::Expired => "Consumer authentication challenge expired",
            Self::InvalidProof => "Consumer authentication proof is invalid",
            Self::RateLimited => "Consumer authentication is rate limited",
            Self::StateUnavailable => "Consumer authentication state is unavailable",
            Self::DeviceState(_) => "Consumer authentication device state is unavailable",
        };
        formatter.write_str(label)
    }
}

impl std::error::Error for BrokerAuthenticationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            Self::ConsumerUnavailable
            | Self::Expired
            | Self::InvalidProof
            | Self::RateLimited
            | Self::StateUnavailable => None,
        }
    }
}

/// Process-local authentication challenge factory and failure limiter.
#[derive(Default)]
pub struct BrokerAuthenticationManager {
    failures: Mutex<AuthenticationFailures>,
}

impl BrokerAuthenticationManager {
    /// Creates an empty authentication failure window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a fresh 30-second challenge for an active Consumer.
    pub fn begin(
        &self,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        selected_protocol: BrokerProtocolVersion,
        occurred_at: StateTimestamp,
    ) -> Result<BrokerAuthenticationChallenge, BrokerAuthenticationError> {
        self.begin_at(
            state,
            consumer_id,
            selected_protocol,
            occurred_at,
            Instant::now(),
        )
    }

    fn begin_at(
        &self,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        selected_protocol: BrokerProtocolVersion,
        occurred_at: StateTimestamp,
        now: Instant,
    ) -> Result<BrokerAuthenticationChallenge, BrokerAuthenticationError> {
        self.require_failure_budget(consumer_id, now)?;
        let Some(consumer) = state
            .consumer(consumer_id)
            .map_err(BrokerAuthenticationError::DeviceState)?
        else {
            self.record_failure(consumer_id, now)?;
            append_authentication_audit(state, None, occurred_at, AuditDecision::Denied)?;
            return Err(BrokerAuthenticationError::ConsumerUnavailable);
        };

        let mut broker_nonce = [0_u8; AUTHENTICATION_NONCE_LENGTH];
        OsRng.fill_bytes(&mut broker_nonce);
        Ok(BrokerAuthenticationChallenge {
            session_id: BrokerSessionId::generate(),
            consumer_id,
            selected_protocol,
            pairing_public_key: *consumer.pairing_public_key(),
            broker_nonce,
            deadline: now + AUTHENTICATION_CHALLENGE_TTL,
        })
    }

    /// Consumes and verifies one connection-bound challenge.
    pub fn complete(
        &self,
        state: &DeviceStateStore,
        challenge: BrokerAuthenticationChallenge,
        session_id: BrokerSessionId,
        consumer_id: ConsumerId,
        proof: [u8; AUTHENTICATION_PROOF_LENGTH],
        occurred_at: StateTimestamp,
    ) -> Result<BrokerAuthenticationCompletion, BrokerAuthenticationError> {
        self.complete_at(
            state,
            challenge,
            AuthenticationProof {
                session_id,
                consumer_id,
                proof,
            },
            occurred_at,
            Instant::now(),
        )
    }

    fn complete_at(
        &self,
        state: &DeviceStateStore,
        challenge: BrokerAuthenticationChallenge,
        proof: AuthenticationProof,
        occurred_at: StateTimestamp,
        now: Instant,
    ) -> Result<BrokerAuthenticationCompletion, BrokerAuthenticationError> {
        let AuthenticationProof {
            session_id,
            consumer_id,
            proof,
        } = proof;
        self.require_failure_budget(consumer_id, now)?;
        if challenge.deadline <= now {
            self.fail_known_consumer(state, challenge.consumer_id, occurred_at, now)?;
            return Err(BrokerAuthenticationError::Expired);
        }
        if challenge.session_id != session_id || challenge.consumer_id != consumer_id {
            self.fail_known_consumer(state, challenge.consumer_id, occurred_at, now)?;
            return Err(BrokerAuthenticationError::InvalidProof);
        }

        let Some(consumer) = state
            .consumer(consumer_id)
            .map_err(BrokerAuthenticationError::DeviceState)?
        else {
            self.record_failure(consumer_id, now)?;
            append_authentication_audit(state, None, occurred_at, AuditDecision::Denied)?;
            return Err(BrokerAuthenticationError::ConsumerUnavailable);
        };
        if consumer.pairing_public_key() != &challenge.pairing_public_key {
            self.fail_known_consumer(state, consumer_id, occurred_at, now)?;
            return Err(BrokerAuthenticationError::InvalidProof);
        }

        let transcript = broker_authentication_transcript(
            challenge.selected_protocol,
            session_id,
            consumer_id,
            consumer.pairing_public_key(),
            &challenge.broker_nonce,
        );
        let verifying_key = VerifyingKey::from_bytes(consumer.pairing_public_key())
            .map_err(|_| BrokerAuthenticationError::InvalidProof)?;
        if verifying_key
            .verify_strict(&transcript, &Signature::from_bytes(&proof))
            .is_err()
        {
            self.fail_known_consumer(state, consumer_id, occurred_at, now)?;
            return Err(BrokerAuthenticationError::InvalidProof);
        }

        append_authentication_audit(
            state,
            Some(consumer_id),
            occurred_at,
            AuditDecision::Allowed,
        )?;
        self.record_success(consumer_id, now)?;
        Ok(BrokerAuthenticationCompletion {
            session_id,
            consumer_id,
        })
    }

    fn fail_known_consumer(
        &self,
        state: &DeviceStateStore,
        consumer_id: ConsumerId,
        occurred_at: StateTimestamp,
        now: Instant,
    ) -> Result<(), BrokerAuthenticationError> {
        self.record_failure(consumer_id, now)?;
        append_authentication_audit(state, Some(consumer_id), occurred_at, AuditDecision::Denied)
    }

    fn require_failure_budget(
        &self,
        consumer_id: ConsumerId,
        now: Instant,
    ) -> Result<(), BrokerAuthenticationError> {
        let mut failures = self.lock_failures()?;
        failures.prune(now);
        let consumer_failures = failures
            .by_consumer
            .get(&consumer_id)
            .map_or(0, VecDeque::len);
        if consumer_failures >= MAX_AUTHENTICATION_FAILURES_PER_CONSUMER
            || failures.global.len() >= MAX_AUTHENTICATION_FAILURES_GLOBALLY
        {
            return Err(BrokerAuthenticationError::RateLimited);
        }
        Ok(())
    }

    fn record_failure(
        &self,
        consumer_id: ConsumerId,
        now: Instant,
    ) -> Result<(), BrokerAuthenticationError> {
        let mut failures = self.lock_failures()?;
        failures.prune(now);
        if !failures.by_consumer.contains_key(&consumer_id)
            && failures.by_consumer.len() >= MAX_TRACKED_AUTHENTICATION_CONSUMERS
        {
            let oldest_key = failures.by_consumer.keys().next().copied();
            if let Some(oldest_key) = oldest_key {
                failures.by_consumer.remove(&oldest_key);
            }
        }
        failures
            .by_consumer
            .entry(consumer_id)
            .or_default()
            .push_back(now);
        failures.global.push_back(now);
        Ok(())
    }

    fn record_success(
        &self,
        consumer_id: ConsumerId,
        now: Instant,
    ) -> Result<(), BrokerAuthenticationError> {
        let mut failures = self.lock_failures()?;
        failures.prune(now);
        failures.by_consumer.remove(&consumer_id);
        Ok(())
    }

    fn lock_failures(
        &self,
    ) -> Result<MutexGuard<'_, AuthenticationFailures>, BrokerAuthenticationError> {
        self.failures
            .lock()
            .map_err(|_| BrokerAuthenticationError::StateUnavailable)
    }
}

impl Debug for BrokerAuthenticationManager {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let counts = self
            .failures
            .lock()
            .map(|failures| (failures.by_consumer.len(), failures.global.len()))
            .ok();
        formatter
            .debug_struct("BrokerAuthenticationManager")
            .field("failure_counts", &counts)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct AuthenticationFailures {
    by_consumer: BTreeMap<ConsumerId, VecDeque<Instant>>,
    global: VecDeque<Instant>,
}

impl AuthenticationFailures {
    fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(AUTHENTICATION_FAILURE_WINDOW);
        self.global
            .retain(|failure| cutoff.map_or(true, |cutoff| *failure > cutoff));
        self.by_consumer.retain(|_, failures| {
            failures.retain(|failure| cutoff.map_or(true, |cutoff| *failure > cutoff));
            !failures.is_empty()
        });
    }
}

struct AuthenticationProof {
    session_id: BrokerSessionId,
    consumer_id: ConsumerId,
    proof: [u8; AUTHENTICATION_PROOF_LENGTH],
}

/// Builds the fixed-order, length-prefixed Ed25519 authentication transcript.
#[must_use]
pub fn broker_authentication_transcript(
    selected_protocol: BrokerProtocolVersion,
    session_id: BrokerSessionId,
    consumer_id: ConsumerId,
    pairing_public_key: &[u8; 32],
    broker_nonce: &[u8; AUTHENTICATION_NONCE_LENGTH],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(140);
    append_length_prefixed(&mut transcript, AUTHENTICATION_DOMAIN);
    let mut protocol = [0_u8; 4];
    protocol[..2].copy_from_slice(&selected_protocol.major().to_be_bytes());
    protocol[2..].copy_from_slice(&selected_protocol.minor().to_be_bytes());
    append_length_prefixed(&mut transcript, &protocol);
    append_length_prefixed(&mut transcript, session_id.as_bytes());
    append_length_prefixed(&mut transcript, consumer_id.as_bytes());
    append_length_prefixed(&mut transcript, pairing_public_key);
    append_length_prefixed(&mut transcript, broker_nonce);
    transcript
}

fn append_authentication_audit(
    state: &DeviceStateStore,
    consumer_id: Option<ConsumerId>,
    occurred_at: StateTimestamp,
    decision: AuditDecision,
) -> Result<(), BrokerAuthenticationError> {
    state
        .append_audit_event(&AuditEvent::new(
            occurred_at,
            AuditEventKind::Pairing,
            AuditScope::new(consumer_id, None, None, None),
            decision,
            ConfirmationMethod::None,
        ))
        .map_err(BrokerAuthenticationError::DeviceState)
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("authentication fields have bounded lengths");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::device_key::DeviceRootKey;
    use crate::state_model::{Consumer, ObservedConsumerIdentity};

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
                "keptnear-authentication-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create state directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect state directory");
            Self { path }
        }

        fn initialize(&self) -> DeviceStateStore {
            let key = DeviceRootKey::from_stored_bytes(vec![0x91; 32]).expect("device root key");
            DeviceStateStore::initialize_for_tests(&self.path, &key, timestamp(1))
                .expect("initialize device state")
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

    fn paired_consumer(state: &DeviceStateStore, seed: u8) -> (SigningKey, ConsumerId) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let consumer = Consumer::new(
            signing_key.verifying_key().to_bytes(),
            "MCP adapter".to_owned(),
            ObservedConsumerIdentity::default(),
            timestamp(2),
        )
        .expect("consumer");
        let consumer_id = consumer.consumer_id();
        state.insert_consumer(&consumer).expect("insert consumer");
        (signing_key, consumer_id)
    }

    fn proof(
        signing_key: &SigningKey,
        challenge: &BrokerAuthenticationChallenge,
    ) -> [u8; AUTHENTICATION_PROOF_LENGTH] {
        signing_key
            .sign(&broker_authentication_transcript(
                challenge.selected_protocol,
                challenge.session_id,
                challenge.consumer_id,
                &challenge.pairing_public_key,
                &challenge.broker_nonce,
            ))
            .to_bytes()
    }

    fn attempt(
        session_id: BrokerSessionId,
        consumer_id: ConsumerId,
        proof: [u8; AUTHENTICATION_PROOF_LENGTH],
    ) -> AuthenticationProof {
        AuthenticationProof {
            session_id,
            consumer_id,
            proof,
        }
    }

    #[test]
    fn valid_proof_authenticates_once_and_records_only_stable_audit_state() {
        let directory = TestStateDirectory::new("success");
        let state = directory.initialize();
        let (signing_key, consumer_id) = paired_consumer(&state, 0x42);
        let manager = BrokerAuthenticationManager::new();
        let now = Instant::now();
        let challenge = manager
            .begin_at(
                &state,
                consumer_id,
                BrokerProtocolVersion::current(),
                timestamp(3),
                now,
            )
            .expect("challenge");
        let session_id = challenge.session_id();
        let signed = proof(&signing_key, &challenge);
        let debug = format!("{challenge:?}");
        assert!(!debug.contains(&hex::encode(signing_key.verifying_key().to_bytes())));
        assert!(!debug.contains(&hex::encode(challenge.broker_nonce())));

        let completion = manager
            .complete_at(
                &state,
                challenge,
                attempt(session_id, consumer_id, signed),
                timestamp(4),
                now + Duration::from_secs(1),
            )
            .expect("authenticate");
        assert_eq!(completion.session_id(), session_id);
        assert_eq!(completion.consumer_id(), consumer_id);

        let audit = state.recent_audit_events(10).expect("audit");
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].kind(), AuditEventKind::Pairing);
        assert_eq!(audit[0].decision(), AuditDecision::Allowed);
        assert_eq!(audit[0].scope().consumer_id(), Some(consumer_id));
    }

    #[test]
    fn expired_wrong_and_revoked_challenges_fail_closed_and_are_audited() {
        let directory = TestStateDirectory::new("failures");
        let mut state = directory.initialize();
        let (_, consumer_id) = paired_consumer(&state, 0x43);
        let manager = BrokerAuthenticationManager::new();
        let now = Instant::now();

        let expired = manager
            .begin_at(
                &state,
                consumer_id,
                BrokerProtocolVersion::current(),
                timestamp(5),
                now,
            )
            .expect("expired challenge");
        let expired_session = expired.session_id();
        assert_eq!(
            manager.complete_at(
                &state,
                expired,
                attempt(
                    expired_session,
                    consumer_id,
                    [0_u8; AUTHENTICATION_PROOF_LENGTH],
                ),
                timestamp(6),
                now + AUTHENTICATION_CHALLENGE_TTL,
            ),
            Err(BrokerAuthenticationError::Expired)
        );

        let wrong = manager
            .begin_at(
                &state,
                consumer_id,
                BrokerProtocolVersion::current(),
                timestamp(7),
                now + Duration::from_secs(1),
            )
            .expect("wrong challenge");
        let wrong_session = wrong.session_id();
        assert_eq!(
            manager.complete_at(
                &state,
                wrong,
                attempt(
                    wrong_session,
                    consumer_id,
                    [0x7f; AUTHENTICATION_PROOF_LENGTH],
                ),
                timestamp(8),
                now + Duration::from_secs(2),
            ),
            Err(BrokerAuthenticationError::InvalidProof)
        );

        let revoked = manager
            .begin_at(
                &state,
                consumer_id,
                BrokerProtocolVersion::current(),
                timestamp(9),
                now + Duration::from_secs(3),
            )
            .expect("revoked challenge");
        let revoked_session = revoked.session_id();
        assert!(state.remove_consumer(consumer_id).expect("remove consumer"));
        assert_eq!(
            manager.complete_at(
                &state,
                revoked,
                attempt(
                    revoked_session,
                    consumer_id,
                    [0_u8; AUTHENTICATION_PROOF_LENGTH],
                ),
                timestamp(10),
                now + Duration::from_secs(4),
            ),
            Err(BrokerAuthenticationError::ConsumerUnavailable)
        );

        let audit = state.recent_audit_events(10).expect("audit");
        assert_eq!(audit.len(), 3);
        assert!(audit
            .iter()
            .all(|event| event.decision() == AuditDecision::Denied));
    }

    #[test]
    fn repeated_failures_exhaust_the_bounded_consumer_budget() {
        let directory = TestStateDirectory::new("rate-limit");
        let state = directory.initialize();
        let (_, consumer_id) = paired_consumer(&state, 0x44);
        let manager = BrokerAuthenticationManager::new();
        let now = Instant::now();

        for offset in 0..MAX_AUTHENTICATION_FAILURES_PER_CONSUMER {
            let challenge = manager
                .begin_at(
                    &state,
                    consumer_id,
                    BrokerProtocolVersion::current(),
                    timestamp(20 + offset as i64),
                    now + Duration::from_millis(offset as u64),
                )
                .expect("challenge");
            let session_id = challenge.session_id();
            assert_eq!(
                manager.complete_at(
                    &state,
                    challenge,
                    attempt(session_id, consumer_id, [0x55; AUTHENTICATION_PROOF_LENGTH],),
                    timestamp(40 + offset as i64),
                    now + Duration::from_millis(offset as u64),
                ),
                Err(BrokerAuthenticationError::InvalidProof)
            );
        }

        assert!(matches!(
            manager.begin_at(
                &state,
                consumer_id,
                BrokerProtocolVersion::current(),
                timestamp(60),
                now + Duration::from_secs(1),
            ),
            Err(BrokerAuthenticationError::RateLimited)
        ));
        assert_eq!(
            state.recent_audit_events(10).expect("audit").len(),
            MAX_AUTHENTICATION_FAILURES_PER_CONSUMER
        );
    }

    #[test]
    fn transcript_is_domain_separated_and_length_unambiguous() {
        let session_id = BrokerSessionId::generate();
        let consumer_id = ConsumerId::generate();
        let public_key = [0x61; 32];
        let nonce = [0x62; AUTHENTICATION_NONCE_LENGTH];
        let transcript = broker_authentication_transcript(
            BrokerProtocolVersion::current(),
            session_id,
            consumer_id,
            &public_key,
            &nonce,
        );

        assert!(transcript
            .windows(AUTHENTICATION_DOMAIN.len())
            .any(|window| window == AUTHENTICATION_DOMAIN));
        assert!(transcript
            .windows(public_key.len())
            .any(|window| window == public_key));
        assert!(transcript
            .windows(nonce.len())
            .any(|window| window == nonce));
        assert_ne!(
            transcript,
            broker_authentication_transcript(
                BrokerProtocolVersion::current(),
                BrokerSessionId::generate(),
                consumer_id,
                &public_key,
                &nonce,
            )
        );
    }
}
