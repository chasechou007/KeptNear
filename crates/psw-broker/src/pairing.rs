use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::protocol::BrokerProtocolVersion;
use crate::state_model::{
    Consumer, ConsumerCodeSigningEvidence, ConsumerEvidenceFingerprint, ConsumerId,
    ObservedConsumerIdentity, PairingRequestId, StateTimestamp,
};
use crate::state_store::{DeviceStateError, DeviceStateStore};

const PAIRING_DOMAIN: &[u8] = b"KeptNear pairing v1";
const PAIRING_COMPARISON_DOMAIN: &[u8] = b"KeptNear pairing comparison v1";
const CROCKFORD_BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of bytes in each fresh pairing nonce.
pub const PAIRING_NONCE_LENGTH: usize = 32;
/// Number of bytes in one Ed25519 pairing public key.
pub const PAIRING_PUBLIC_KEY_LENGTH: usize = 32;
/// Number of bytes in one Ed25519 pairing proof.
pub const PAIRING_PROOF_LENGTH: usize = 64;
/// Maximum lifetime of an uncompleted pairing request.
pub const PAIRING_REQUEST_TTL: Duration = Duration::from_secs(5 * 60);
/// Process-local bound on concurrently pending pairing requests.
pub const MAX_PENDING_PAIRING_REQUESTS: usize = 64;

/// Untrusted Consumer material supplied when starting local pairing.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsumerPairingProposal {
    pairing_public_key: [u8; PAIRING_PUBLIC_KEY_LENGTH],
    client_nonce: [u8; PAIRING_NONCE_LENGTH],
    selected_protocol: BrokerProtocolVersion,
}

impl ConsumerPairingProposal {
    /// Creates a proposal with a structurally valid Ed25519 public key and nonce.
    pub fn new(
        pairing_public_key: [u8; PAIRING_PUBLIC_KEY_LENGTH],
        client_nonce: [u8; PAIRING_NONCE_LENGTH],
        selected_protocol: BrokerProtocolVersion,
    ) -> Result<Self, BrokerPairingError> {
        if pairing_public_key.iter().all(|byte| *byte == 0)
            || client_nonce.iter().all(|byte| *byte == 0)
            || VerifyingKey::from_bytes(&pairing_public_key).is_err()
        {
            return Err(BrokerPairingError::InvalidProposal);
        }
        Ok(Self {
            pairing_public_key,
            client_nonce,
            selected_protocol,
        })
    }

    /// Returns the proposed Ed25519 public key.
    #[must_use]
    pub const fn pairing_public_key(&self) -> &[u8; PAIRING_PUBLIC_KEY_LENGTH] {
        &self.pairing_public_key
    }

    /// Returns the fresh Consumer nonce.
    #[must_use]
    pub const fn client_nonce(&self) -> &[u8; PAIRING_NONCE_LENGTH] {
        &self.client_nonce
    }

    /// Returns the negotiated protocol version bound into pairing.
    #[must_use]
    pub const fn selected_protocol(&self) -> BrokerProtocolVersion {
        self.selected_protocol
    }
}

impl Debug for ConsumerPairingProposal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsumerPairingProposal")
            .field("pairing_public_key", &"<redacted>")
            .field("client_nonce", &"<redacted>")
            .field("selected_protocol", &self.selected_protocol)
            .finish()
    }
}

/// Ten-character code independently displayed by the Consumer and local App.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PairingComparisonCode([u8; 10]);

impl PairingComparisonCode {
    /// Returns the canonical Crockford Base32 code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("comparison code is always ASCII")
    }

    /// Parses one canonical ten-character Crockford Base32 comparison code.
    #[must_use]
    pub fn from_ascii(value: &str) -> Option<Self> {
        if value.len() != 10 || !value.bytes().all(|byte| CROCKFORD_BASE32.contains(&byte)) {
            return None;
        }
        let mut code = [0_u8; 10];
        code.copy_from_slice(value.as_bytes());
        Some(Self(code))
    }
}

impl Debug for PairingComparisonCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("PairingComparisonCode")
            .field(&self.as_str())
            .finish()
    }
}

impl Display for PairingComparisonCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Consumer-facing challenge returned for a newly pending pairing request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingChallenge {
    pairing_request_id: PairingRequestId,
    server_nonce: [u8; PAIRING_NONCE_LENGTH],
    comparison_code: PairingComparisonCode,
    valid_for: Duration,
}

impl BrokerPairingChallenge {
    /// Returns the immutable request identity.
    #[must_use]
    pub const fn pairing_request_id(&self) -> PairingRequestId {
        self.pairing_request_id
    }

    /// Returns the fresh Broker nonce needed for the proof transcript.
    #[must_use]
    pub const fn server_nonce(&self) -> &[u8; PAIRING_NONCE_LENGTH] {
        &self.server_nonce
    }

    /// Returns the human comparison code.
    #[must_use]
    pub const fn comparison_code(&self) -> PairingComparisonCode {
        self.comparison_code
    }

    /// Returns the maximum remaining request lifetime at issue time.
    #[must_use]
    pub const fn valid_for(&self) -> Duration {
        self.valid_for
    }
}

impl Debug for BrokerPairingChallenge {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingChallenge")
            .field("pairing_request_id", &self.pairing_request_id)
            .field("server_nonce", &"<redacted>")
            .field("comparison_code", &self.comparison_code)
            .field("valid_for", &self.valid_for)
            .finish()
    }
}

/// Consumer-facing progress for an active or still-pending pairing identity.
#[derive(Clone, Eq, PartialEq)]
pub enum BrokerConsumerPairingProgress {
    /// The public key already belongs to one active Consumer.
    Active {
        /// Existing immutable Consumer identity.
        consumer_id: ConsumerId,
    },
    /// The pairing request remains process-local and incomplete.
    Pending(BrokerConsumerPairingSnapshot),
}

impl Debug for BrokerConsumerPairingProgress {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active { consumer_id } => formatter
                .debug_struct("Active")
                .field("consumer_id", consumer_id)
                .finish(),
            Self::Pending(snapshot) => formatter.debug_tuple("Pending").field(snapshot).finish(),
        }
    }
}

/// Secret-free Consumer view needed to resume one pending pairing.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerConsumerPairingSnapshot {
    pairing_request_id: PairingRequestId,
    client_nonce: [u8; PAIRING_NONCE_LENGTH],
    server_nonce: [u8; PAIRING_NONCE_LENGTH],
    comparison_code: PairingComparisonCode,
    consumer_id: Option<ConsumerId>,
    status: BrokerPairingRequestStatus,
    remaining: Duration,
}

impl BrokerConsumerPairingSnapshot {
    /// Returns the immutable pending request identity.
    #[must_use]
    pub const fn pairing_request_id(&self) -> PairingRequestId {
        self.pairing_request_id
    }

    /// Returns the original client nonce bound into the pending request.
    #[must_use]
    pub const fn client_nonce(&self) -> &[u8; PAIRING_NONCE_LENGTH] {
        &self.client_nonce
    }

    /// Returns the Broker nonce bound into the pending request.
    #[must_use]
    pub const fn server_nonce(&self) -> &[u8; PAIRING_NONCE_LENGTH] {
        &self.server_nonce
    }

    /// Returns the comparison code shown by the Consumer and local App.
    #[must_use]
    pub const fn comparison_code(&self) -> PairingComparisonCode {
        self.comparison_code
    }

    /// Returns the approved Consumer identity only when proof is required.
    #[must_use]
    pub const fn consumer_id(&self) -> Option<ConsumerId> {
        self.consumer_id
    }

    /// Returns whether the request awaits local approval or key proof.
    #[must_use]
    pub const fn status(&self) -> BrokerPairingRequestStatus {
        self.status
    }

    /// Returns the request lifetime remaining at snapshot creation.
    #[must_use]
    pub const fn remaining(&self) -> Duration {
        self.remaining
    }
}

impl Debug for BrokerConsumerPairingSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerConsumerPairingSnapshot")
            .field("pairing_request_id", &self.pairing_request_id)
            .field("client_nonce", &"<redacted>")
            .field("server_nonce", &"<redacted>")
            .field("comparison_code", &self.comparison_code)
            .field("consumer_id", &self.consumer_id)
            .field("status", &self.status)
            .field("remaining", &self.remaining)
            .finish()
    }
}

/// Marker carrying the local user's explicit approval and chosen Consumer name.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingUserApproval {
    label: String,
    approved_at: StateTimestamp,
}

impl BrokerPairingUserApproval {
    /// Records the result of an explicit local user approval interaction.
    #[must_use]
    pub fn after_user_approval(label: String, approved_at: StateTimestamp) -> Self {
        Self { label, approved_at }
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }
}

impl Debug for BrokerPairingUserApproval {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingUserApproval")
            .field("label", &"<redacted>")
            .field("approved_at", &self.approved_at)
            .finish()
    }
}

/// Consumer-facing canonical transcript produced after local approval.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingProofChallenge {
    pairing_request_id: PairingRequestId,
    consumer_id: ConsumerId,
    transcript: Vec<u8>,
    valid_for: Duration,
}

impl BrokerPairingProofChallenge {
    /// Returns the pending pairing request identity.
    #[must_use]
    pub const fn pairing_request_id(&self) -> PairingRequestId {
        self.pairing_request_id
    }

    /// Returns the immutable Consumer identity allocated by user approval.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the fixed-order, length-prefixed bytes the Consumer must sign.
    #[must_use]
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    /// Returns the remaining request lifetime when approval completed.
    #[must_use]
    pub const fn valid_for(&self) -> Duration {
        self.valid_for
    }
}

impl Debug for BrokerPairingProofChallenge {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingProofChallenge")
            .field("pairing_request_id", &self.pairing_request_id)
            .field("consumer_id", &self.consumer_id)
            .field("transcript", &"<redacted>")
            .field("valid_for", &self.valid_for)
            .finish()
    }
}

/// Current process-local phase of a pending pairing request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerPairingRequestStatus {
    /// The local user has not approved or denied the request.
    AwaitingUserApproval,
    /// The user approved an identity and the Consumer must prove key possession.
    AwaitingProof,
}

/// Display-safe identity evidence for one pending Consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerPairingIdentityEvidence {
    pairing_key_fingerprint: ConsumerEvidenceFingerprint,
    executable_name: Option<String>,
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    code_signing_evidence: ConsumerCodeSigningEvidence,
    code_signature_fingerprint: Option<ConsumerEvidenceFingerprint>,
}

impl BrokerPairingIdentityEvidence {
    fn new(
        pairing_public_key: &[u8; PAIRING_PUBLIC_KEY_LENGTH],
        observed_identity: &ObservedConsumerIdentity,
    ) -> Self {
        let pairing_key_digest: [u8; 32] = Sha256::digest(pairing_public_key).into();
        Self {
            pairing_key_fingerprint: ConsumerEvidenceFingerprint::from_sha256_digest(
                &pairing_key_digest,
            ),
            executable_name: observed_identity.executable_name().map(ToOwned::to_owned),
            bundle_identifier: observed_identity.bundle_identifier().map(ToOwned::to_owned),
            team_identifier: observed_identity.team_identifier().map(ToOwned::to_owned),
            code_signing_evidence: observed_identity.code_signing_evidence(),
            code_signature_fingerprint: observed_identity.code_signature_fingerprint(),
        }
    }

    /// Returns the short SHA-256 fingerprint of the proposed pairing key.
    #[must_use]
    pub const fn pairing_key_fingerprint(&self) -> ConsumerEvidenceFingerprint {
        self.pairing_key_fingerprint
    }

    /// Returns the OS-observed executable basename when available.
    #[must_use]
    pub fn executable_name(&self) -> Option<&str> {
        self.executable_name.as_deref()
    }

    /// Returns the verified signing identifier when it is bundle-like.
    #[must_use]
    pub fn bundle_identifier(&self) -> Option<&str> {
        self.bundle_identifier.as_deref()
    }

    /// Returns the verified Apple team identifier when available.
    #[must_use]
    pub fn team_identifier(&self) -> Option<&str> {
        self.team_identifier.as_deref()
    }

    /// Returns the optional code-signing evidence classification.
    #[must_use]
    pub const fn code_signing_evidence(&self) -> ConsumerCodeSigningEvidence {
        self.code_signing_evidence
    }

    /// Returns a short fingerprint of verified code-signing evidence.
    #[must_use]
    pub const fn code_signature_fingerprint(&self) -> Option<ConsumerEvidenceFingerprint> {
        self.code_signature_fingerprint
    }
}

/// Path-free local-App projection of one pending pairing request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingRequestSnapshot {
    pairing_request_id: PairingRequestId,
    consumer_id: Option<ConsumerId>,
    comparison_code: PairingComparisonCode,
    identity_evidence: BrokerPairingIdentityEvidence,
    approved_label: Option<String>,
    status: BrokerPairingRequestStatus,
    remaining: Duration,
}

impl BrokerPairingRequestSnapshot {
    /// Returns the immutable request identity.
    #[must_use]
    pub const fn pairing_request_id(&self) -> PairingRequestId {
        self.pairing_request_id
    }

    /// Returns the Consumer identity only after explicit user approval.
    #[must_use]
    pub const fn consumer_id(&self) -> Option<ConsumerId> {
        self.consumer_id
    }

    /// Returns the human comparison code.
    #[must_use]
    pub const fn comparison_code(&self) -> PairingComparisonCode {
        self.comparison_code
    }

    /// Returns path-free identity evidence for trusted local presentation.
    #[must_use]
    pub const fn identity_evidence(&self) -> &BrokerPairingIdentityEvidence {
        &self.identity_evidence
    }

    /// Returns the user-controlled name only after approval.
    #[must_use]
    pub fn approved_label(&self) -> Option<&str> {
        self.approved_label.as_deref()
    }

    /// Returns the current pairing phase.
    #[must_use]
    pub const fn status(&self) -> BrokerPairingRequestStatus {
        self.status
    }

    /// Returns the request lifetime remaining at snapshot creation.
    #[must_use]
    pub const fn remaining(&self) -> Duration {
        self.remaining
    }
}

impl Debug for BrokerPairingRequestSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingRequestSnapshot")
            .field("pairing_request_id", &self.pairing_request_id)
            .field("consumer_id", &self.consumer_id)
            .field("comparison_code", &self.comparison_code)
            .field("identity_evidence", &self.identity_evidence)
            .field(
                "approved_label",
                &self.approved_label.as_ref().map(|_| "<redacted>"),
            )
            .field("status", &self.status)
            .field("remaining", &self.remaining)
            .finish()
    }
}

/// Result of verifying one approved Consumer pairing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerPairingCompletion {
    consumer_id: ConsumerId,
    newly_activated: bool,
    authorization_effect: BrokerPairingAuthorizationEffect,
}

impl BrokerPairingCompletion {
    /// Returns the one durable Consumer identity bound to the pairing key.
    #[must_use]
    pub const fn consumer_id(self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns whether this operation inserted the durable Consumer.
    #[must_use]
    pub const fn newly_activated(self) -> bool {
        self.newly_activated
    }

    /// Confirms that pairing did not create or modify credential authorization.
    #[must_use]
    pub const fn authorization_effect(self) -> BrokerPairingAuthorizationEffect {
        self.authorization_effect
    }
}

/// Credential-authorization effect of completing a Consumer pairing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerPairingAuthorizationEffect {
    /// Existing Access Rules and Use Grants were left unchanged.
    Unchanged,
}

/// Sanitized failure from the process-local Consumer pairing state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerPairingError {
    /// The public key or nonce is structurally invalid.
    InvalidProposal,
    /// The same cryptographic identity is already a durable Consumer.
    AlreadyPaired {
        /// Existing durable Consumer identity.
        consumer_id: ConsumerId,
    },
    /// The same cryptographic identity already has a pending request.
    AlreadyPending {
        /// Existing process-local request identity.
        pairing_request_id: PairingRequestId,
    },
    /// The process-local pending-request limit was reached.
    TooManyPending,
    /// The request does not exist or was already completed, denied, or consumed.
    RequestUnavailable,
    /// The local user must approve the request before proof can be submitted.
    AwaitingUserApproval,
    /// The request was already approved with a different local name.
    AlreadyApproved,
    /// The five-minute pairing request lifetime elapsed.
    Expired,
    /// The local approval contains an invalid Consumer name.
    InvalidApproval,
    /// The Ed25519 proof is invalid and the request was consumed.
    InvalidProof,
    /// The in-memory pairing registry cannot be accessed safely.
    StateUnavailable,
    /// Authenticated encrypted device state could not be read or updated.
    DeviceState(DeviceStateError),
}

impl Display for BrokerPairingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProposal => formatter.write_str("invalid Consumer pairing proposal"),
            Self::AlreadyPaired { .. } => {
                formatter.write_str("Consumer pairing identity is already active")
            }
            Self::AlreadyPending { .. } => {
                formatter.write_str("Consumer pairing identity is already pending")
            }
            Self::TooManyPending => formatter.write_str("too many Consumer pairings are pending"),
            Self::RequestUnavailable => {
                formatter.write_str("Consumer pairing request is unavailable")
            }
            Self::AwaitingUserApproval => {
                formatter.write_str("Consumer pairing is awaiting local user approval")
            }
            Self::AlreadyApproved => formatter.write_str("Consumer pairing was already approved"),
            Self::Expired => formatter.write_str("Consumer pairing request expired"),
            Self::InvalidApproval => formatter.write_str("invalid Consumer pairing approval"),
            Self::InvalidProof => formatter.write_str("invalid Consumer pairing proof"),
            Self::StateUnavailable => formatter.write_str("Consumer pairing state is unavailable"),
            Self::DeviceState(source) => {
                write!(formatter, "Consumer pairing state failed: {source}")
            }
        }
    }
}

impl std::error::Error for BrokerPairingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceState(source) => Some(source),
            _ => None,
        }
    }
}

impl From<DeviceStateError> for BrokerPairingError {
    fn from(source: DeviceStateError) -> Self {
        Self::DeviceState(source)
    }
}

#[derive(Clone)]
struct ApprovedPairing {
    consumer_id: ConsumerId,
    label: String,
    approved_at: StateTimestamp,
}

struct PendingPairing {
    pairing_request_id: PairingRequestId,
    pairing_public_key: [u8; PAIRING_PUBLIC_KEY_LENGTH],
    client_nonce: [u8; PAIRING_NONCE_LENGTH],
    server_nonce: [u8; PAIRING_NONCE_LENGTH],
    selected_protocol: BrokerProtocolVersion,
    comparison_code: PairingComparisonCode,
    observed_identity: ObservedConsumerIdentity,
    deadline: Instant,
    approval: Option<ApprovedPairing>,
}

impl PendingPairing {
    fn proof_challenge(&self, now: Instant) -> Option<BrokerPairingProofChallenge> {
        let approval = self.approval.as_ref()?;
        Some(BrokerPairingProofChallenge {
            pairing_request_id: self.pairing_request_id,
            consumer_id: approval.consumer_id,
            transcript: consumer_pairing_transcript(
                self.selected_protocol,
                self.pairing_request_id,
                approval.consumer_id,
                &self.pairing_public_key,
                &self.client_nonce,
                &self.server_nonce,
            ),
            valid_for: self.deadline.saturating_duration_since(now),
        })
    }

    fn snapshot(&self, now: Instant) -> BrokerPairingRequestSnapshot {
        let (consumer_id, approved_label, status) = self.approval.as_ref().map_or(
            (None, None, BrokerPairingRequestStatus::AwaitingUserApproval),
            |approval| {
                (
                    Some(approval.consumer_id),
                    Some(approval.label.clone()),
                    BrokerPairingRequestStatus::AwaitingProof,
                )
            },
        );
        BrokerPairingRequestSnapshot {
            pairing_request_id: self.pairing_request_id,
            consumer_id,
            comparison_code: self.comparison_code,
            identity_evidence: BrokerPairingIdentityEvidence::new(
                &self.pairing_public_key,
                &self.observed_identity,
            ),
            approved_label,
            status,
            remaining: self.deadline.saturating_duration_since(now),
        }
    }
}

/// Process-owned registry for short-lived Consumer pairing handshakes.
///
/// Pending requests intentionally live only in memory. A Broker restart
/// cancels them, while completed Consumers remain in encrypted device state.
#[derive(Default)]
pub struct BrokerPairingManager {
    requests: Mutex<BTreeMap<PairingRequestId, PendingPairing>>,
}

impl BrokerPairingManager {
    /// Creates an empty process-local pairing registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a five-minute pending request without granting any vault access.
    pub fn begin_pairing(
        &self,
        state: &DeviceStateStore,
        proposal: ConsumerPairingProposal,
        observed_identity: ObservedConsumerIdentity,
    ) -> Result<BrokerPairingChallenge, BrokerPairingError> {
        self.begin_pairing_at(state, proposal, observed_identity, Instant::now())
    }

    /// Starts a pairing or resumes the request already bound to the same key.
    ///
    /// This projection returns no label, vault metadata, authorization state,
    /// executable path, or secret. A resumed request still requires possession
    /// of the private pairing key before activation.
    pub fn begin_or_resume_pairing(
        &self,
        state: &DeviceStateStore,
        proposal: ConsumerPairingProposal,
        observed_identity: ObservedConsumerIdentity,
    ) -> Result<BrokerConsumerPairingProgress, BrokerPairingError> {
        let pairing_public_key = *proposal.pairing_public_key();
        match self.begin_pairing(state, proposal, observed_identity) {
            Ok(challenge) => {
                self.pending_progress_for_key(challenge.pairing_request_id(), &pairing_public_key)
            }
            Err(BrokerPairingError::AlreadyPaired { consumer_id }) => {
                Ok(BrokerConsumerPairingProgress::Active { consumer_id })
            }
            Err(BrokerPairingError::AlreadyPending { pairing_request_id }) => {
                self.pending_progress_for_key(pairing_request_id, &pairing_public_key)
            }
            Err(error) => Err(error),
        }
    }

    fn begin_pairing_at(
        &self,
        state: &DeviceStateStore,
        proposal: ConsumerPairingProposal,
        observed_identity: ObservedConsumerIdentity,
        now: Instant,
    ) -> Result<BrokerPairingChallenge, BrokerPairingError> {
        if let Some(consumer) =
            state.consumer_by_pairing_public_key(proposal.pairing_public_key())?
        {
            return Err(BrokerPairingError::AlreadyPaired {
                consumer_id: consumer.consumer_id(),
            });
        }

        let mut requests = self.lock_requests()?;
        requests.retain(|_, request| request.deadline > now);
        if let Some(request) = requests
            .values()
            .find(|request| request.pairing_public_key == proposal.pairing_public_key)
        {
            return Err(BrokerPairingError::AlreadyPending {
                pairing_request_id: request.pairing_request_id,
            });
        }
        if requests.len() >= MAX_PENDING_PAIRING_REQUESTS {
            return Err(BrokerPairingError::TooManyPending);
        }

        let pairing_request_id = PairingRequestId::generate();
        let mut server_nonce = [0_u8; PAIRING_NONCE_LENGTH];
        OsRng.fill_bytes(&mut server_nonce);
        let comparison_code = pairing_comparison_code(
            pairing_request_id,
            proposal.pairing_public_key(),
            proposal.client_nonce(),
            &server_nonce,
        );
        let deadline = now + PAIRING_REQUEST_TTL;
        let challenge = BrokerPairingChallenge {
            pairing_request_id,
            server_nonce,
            comparison_code,
            valid_for: PAIRING_REQUEST_TTL,
        };
        requests.insert(
            pairing_request_id,
            PendingPairing {
                pairing_request_id,
                pairing_public_key: proposal.pairing_public_key,
                client_nonce: proposal.client_nonce,
                server_nonce,
                selected_protocol: proposal.selected_protocol,
                comparison_code,
                observed_identity,
                deadline,
                approval: None,
            },
        );
        Ok(challenge)
    }

    /// Lists non-expired requests for presentation in the trusted local App.
    pub fn pending_requests(
        &self,
    ) -> Result<Vec<BrokerPairingRequestSnapshot>, BrokerPairingError> {
        self.pending_requests_at(Instant::now())
    }

    fn pending_requests_at(
        &self,
        now: Instant,
    ) -> Result<Vec<BrokerPairingRequestSnapshot>, BrokerPairingError> {
        let mut requests = self.lock_requests()?;
        requests.retain(|_, request| request.deadline > now);
        Ok(requests
            .values()
            .map(|request| request.snapshot(now))
            .collect())
    }

    /// Returns resumable Consumer-facing state only for the exact pairing key.
    pub fn pairing_progress(
        &self,
        state: &DeviceStateStore,
        pairing_request_id: PairingRequestId,
        pairing_public_key: &[u8; PAIRING_PUBLIC_KEY_LENGTH],
    ) -> Result<BrokerConsumerPairingProgress, BrokerPairingError> {
        if let Some(consumer) = state.consumer_by_pairing_public_key(pairing_public_key)? {
            return Ok(BrokerConsumerPairingProgress::Active {
                consumer_id: consumer.consumer_id(),
            });
        }
        self.pending_progress_for_key(pairing_request_id, pairing_public_key)
    }

    /// Applies explicit user approval and allocates the immutable Consumer ID.
    pub fn approve_pairing(
        &self,
        pairing_request_id: PairingRequestId,
        approval: BrokerPairingUserApproval,
    ) -> Result<BrokerPairingProofChallenge, BrokerPairingError> {
        self.approve_pairing_at(pairing_request_id, approval, Instant::now())
    }

    fn approve_pairing_at(
        &self,
        pairing_request_id: PairingRequestId,
        approval: BrokerPairingUserApproval,
        now: Instant,
    ) -> Result<BrokerPairingProofChallenge, BrokerPairingError> {
        let mut requests = self.lock_requests()?;
        let Some(request) = requests.get_mut(&pairing_request_id) else {
            return Err(BrokerPairingError::RequestUnavailable);
        };
        if request.deadline <= now {
            requests.remove(&pairing_request_id);
            return Err(BrokerPairingError::Expired);
        }
        if let Some(existing) = request.approval.as_ref() {
            if existing.label != approval.label {
                return Err(BrokerPairingError::AlreadyApproved);
            }
            return request
                .proof_challenge(now)
                .ok_or(BrokerPairingError::StateUnavailable);
        }

        let consumer_id = ConsumerId::generate();
        Consumer::with_id(
            consumer_id,
            request.pairing_public_key,
            approval.label.clone(),
            request.observed_identity.clone(),
            approval.approved_at,
        )
        .map_err(|_| BrokerPairingError::InvalidApproval)?;
        request.approval = Some(ApprovedPairing {
            consumer_id,
            label: approval.label,
            approved_at: approval.approved_at,
        });
        request
            .proof_challenge(now)
            .ok_or(BrokerPairingError::StateUnavailable)
    }

    /// Denies and consumes a pending pairing request.
    pub fn deny_pairing(
        &self,
        pairing_request_id: PairingRequestId,
    ) -> Result<(), BrokerPairingError> {
        self.deny_pairing_at(pairing_request_id, Instant::now())
    }

    fn deny_pairing_at(
        &self,
        pairing_request_id: PairingRequestId,
        now: Instant,
    ) -> Result<(), BrokerPairingError> {
        let mut requests = self.lock_requests()?;
        let Some(request) = requests.remove(&pairing_request_id) else {
            return Err(BrokerPairingError::RequestUnavailable);
        };
        if request.deadline <= now {
            return Err(BrokerPairingError::Expired);
        }
        Ok(())
    }

    /// Verifies one Ed25519 proof and activates exactly one durable Consumer.
    ///
    /// An invalid proof consumes the request, preventing replay. A device-state
    /// write failure leaves the already-approved request pending for retry.
    pub fn complete_pairing(
        &self,
        state: &DeviceStateStore,
        pairing_request_id: PairingRequestId,
        proof: [u8; PAIRING_PROOF_LENGTH],
    ) -> Result<BrokerPairingCompletion, BrokerPairingError> {
        self.complete_pairing_at(state, pairing_request_id, proof, Instant::now())
    }

    fn complete_pairing_at(
        &self,
        state: &DeviceStateStore,
        pairing_request_id: PairingRequestId,
        proof: [u8; PAIRING_PROOF_LENGTH],
        now: Instant,
    ) -> Result<BrokerPairingCompletion, BrokerPairingError> {
        let mut requests = self.lock_requests()?;
        let Some(request) = requests.get(&pairing_request_id) else {
            return Err(BrokerPairingError::RequestUnavailable);
        };
        if request.deadline <= now {
            requests.remove(&pairing_request_id);
            return Err(BrokerPairingError::Expired);
        }
        let Some(approval) = request.approval.as_ref() else {
            return Err(BrokerPairingError::AwaitingUserApproval);
        };
        let transcript = consumer_pairing_transcript(
            request.selected_protocol,
            request.pairing_request_id,
            approval.consumer_id,
            &request.pairing_public_key,
            &request.client_nonce,
            &request.server_nonce,
        );
        let verifying_key = VerifyingKey::from_bytes(&request.pairing_public_key)
            .map_err(|_| BrokerPairingError::InvalidProposal)?;
        let signature = Signature::from_bytes(&proof);
        if verifying_key
            .verify_strict(&transcript, &signature)
            .is_err()
        {
            requests.remove(&pairing_request_id);
            return Err(BrokerPairingError::InvalidProof);
        }

        let consumer = Consumer::with_id(
            approval.consumer_id,
            request.pairing_public_key,
            approval.label.clone(),
            request.observed_identity.clone(),
            approval.approved_at,
        )
        .map_err(|_| BrokerPairingError::InvalidApproval)?;
        match state.insert_consumer(&consumer) {
            Ok(()) => {
                requests.remove(&pairing_request_id);
                Ok(BrokerPairingCompletion {
                    consumer_id: consumer.consumer_id(),
                    newly_activated: true,
                    authorization_effect: BrokerPairingAuthorizationEffect::Unchanged,
                })
            }
            Err(DeviceStateError::Conflict) => {
                let Some(existing) =
                    state.consumer_by_pairing_public_key(consumer.pairing_public_key())?
                else {
                    return Err(BrokerPairingError::DeviceState(DeviceStateError::Conflict));
                };
                requests.remove(&pairing_request_id);
                Ok(BrokerPairingCompletion {
                    consumer_id: existing.consumer_id(),
                    newly_activated: false,
                    authorization_effect: BrokerPairingAuthorizationEffect::Unchanged,
                })
            }
            Err(source) => Err(BrokerPairingError::DeviceState(source)),
        }
    }

    /// Cancels every process-local pending request during Broker shutdown.
    pub fn cancel_all_pending(&self) -> Result<usize, BrokerPairingError> {
        let mut requests = self.lock_requests()?;
        let count = requests.len();
        requests.clear();
        Ok(count)
    }

    pub(crate) fn cancel_pending_for_consumer(
        &self,
        consumer_id: ConsumerId,
    ) -> Result<usize, BrokerPairingError> {
        let mut requests = self.lock_requests()?;
        let before = requests.len();
        requests.retain(|_, request| {
            request
                .approval
                .as_ref()
                .map(|approval| approval.consumer_id)
                != Some(consumer_id)
        });
        Ok(before.saturating_sub(requests.len()))
    }

    fn lock_requests(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<PairingRequestId, PendingPairing>>, BrokerPairingError>
    {
        self.requests
            .lock()
            .map_err(|_| BrokerPairingError::StateUnavailable)
    }

    fn pending_progress_for_key(
        &self,
        pairing_request_id: PairingRequestId,
        pairing_public_key: &[u8; PAIRING_PUBLIC_KEY_LENGTH],
    ) -> Result<BrokerConsumerPairingProgress, BrokerPairingError> {
        let now = Instant::now();
        let mut requests = self.lock_requests()?;
        let Some(request) = requests.get(&pairing_request_id) else {
            return Err(BrokerPairingError::RequestUnavailable);
        };
        if request.deadline <= now {
            requests.remove(&pairing_request_id);
            return Err(BrokerPairingError::Expired);
        }
        if &request.pairing_public_key != pairing_public_key {
            return Err(BrokerPairingError::RequestUnavailable);
        }
        let consumer_id = request
            .approval
            .as_ref()
            .map(|approval| approval.consumer_id);
        let status = if consumer_id.is_some() {
            BrokerPairingRequestStatus::AwaitingProof
        } else {
            BrokerPairingRequestStatus::AwaitingUserApproval
        };
        Ok(BrokerConsumerPairingProgress::Pending(
            BrokerConsumerPairingSnapshot {
                pairing_request_id,
                client_nonce: request.client_nonce,
                server_nonce: request.server_nonce,
                comparison_code: request.comparison_code,
                consumer_id,
                status,
                remaining: request.deadline.saturating_duration_since(now),
            },
        ))
    }
}

impl Debug for BrokerPairingManager {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let pending_count = self.requests.lock().map(|requests| requests.len()).ok();
        formatter
            .debug_struct("BrokerPairingManager")
            .field("pending_count", &pending_count)
            .finish_non_exhaustive()
    }
}

fn pairing_comparison_code(
    pairing_request_id: PairingRequestId,
    pairing_public_key: &[u8; PAIRING_PUBLIC_KEY_LENGTH],
    client_nonce: &[u8; PAIRING_NONCE_LENGTH],
    server_nonce: &[u8; PAIRING_NONCE_LENGTH],
) -> PairingComparisonCode {
    let mut material = Vec::new();
    append_length_prefixed(&mut material, PAIRING_COMPARISON_DOMAIN);
    append_length_prefixed(&mut material, pairing_request_id.as_bytes());
    append_length_prefixed(&mut material, pairing_public_key);
    append_length_prefixed(&mut material, client_nonce);
    append_length_prefixed(&mut material, server_nonce);
    let digest = Sha256::digest(&material);
    let mut code = [0_u8; 10];
    for (character_index, character) in code.iter_mut().enumerate() {
        let mut value = 0_u8;
        for bit_offset in 0..5 {
            let bit_index = character_index * 5 + bit_offset;
            let bit = (digest[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
            value = (value << 1) | bit;
        }
        *character = CROCKFORD_BASE32[usize::from(value)];
    }
    PairingComparisonCode(code)
}

/// Builds the fixed-order, length-prefixed Ed25519 pairing transcript.
#[must_use]
pub fn consumer_pairing_transcript(
    selected_protocol: BrokerProtocolVersion,
    pairing_request_id: PairingRequestId,
    consumer_id: ConsumerId,
    pairing_public_key: &[u8; PAIRING_PUBLIC_KEY_LENGTH],
    client_nonce: &[u8; PAIRING_NONCE_LENGTH],
    server_nonce: &[u8; PAIRING_NONCE_LENGTH],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(180);
    append_length_prefixed(&mut transcript, PAIRING_DOMAIN);
    let mut protocol = [0_u8; 4];
    protocol[..2].copy_from_slice(&selected_protocol.major().to_be_bytes());
    protocol[2..].copy_from_slice(&selected_protocol.minor().to_be_bytes());
    append_length_prefixed(&mut transcript, &protocol);
    append_length_prefixed(&mut transcript, pairing_request_id.as_bytes());
    append_length_prefixed(&mut transcript, consumer_id.as_bytes());
    append_length_prefixed(&mut transcript, pairing_public_key);
    append_length_prefixed(&mut transcript, client_nonce);
    append_length_prefixed(&mut transcript, server_nonce);
    transcript
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("pairing fields have bounded lengths");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{Signer, SigningKey};
    use psw_core::{CredentialId, SecretFieldId, VaultId};

    use super::*;
    use crate::device_key::DeviceRootKey;
    use crate::state_model::{
        AccessRule, AuthorizationTarget, Capability, CapabilityName, ConfirmationPolicy,
        CredentialFieldScope, GrantScope, RuleLifetime, UseGrant, VaultSessionId,
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
                "keptnear-pairing-{label}-{}-{nanos}-{sequence}",
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

    fn signing_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn proposal(
        signing_key: &SigningKey,
        nonce_byte: u8,
    ) -> Result<ConsumerPairingProposal, BrokerPairingError> {
        ConsumerPairingProposal::new(
            signing_key.verifying_key().to_bytes(),
            [nonce_byte; PAIRING_NONCE_LENGTH],
            BrokerProtocolVersion::current(),
        )
    }

    fn observed_identity() -> ObservedConsumerIdentity {
        ObservedConsumerIdentity::new(
            Some("codex".to_owned()),
            Some("com.openai.codex".to_owned()),
            None,
            Some([0x44; 32]),
        )
        .expect("observed identity")
    }

    #[test]
    fn pairing_requires_user_approval_and_valid_proof_before_activation() {
        let directory = TestStateDirectory::new("complete");
        let state = directory.initialize(11);
        let manager = BrokerPairingManager::new();
        let signing_key = signing_key(21);
        let now = Instant::now();

        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&signing_key, 31).expect("proposal"),
                observed_identity(),
                now,
            )
            .expect("pending request");
        assert_eq!(challenge.valid_for(), PAIRING_REQUEST_TTL);
        assert!(state.consumers().expect("Consumers").is_empty());
        assert_eq!(
            manager.complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                [0_u8; PAIRING_PROOF_LENGTH],
                now + Duration::from_secs(1),
            ),
            Err(BrokerPairingError::AwaitingUserApproval)
        );

        let snapshots = manager
            .pending_requests_at(now + Duration::from_secs(1))
            .expect("pending snapshots");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].status(),
            BrokerPairingRequestStatus::AwaitingUserApproval
        );
        assert_eq!(snapshots[0].consumer_id(), None);

        let proof_challenge = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Local Codex".to_owned(),
                    timestamp(100),
                ),
                now + Duration::from_secs(2),
            )
            .expect("approve pairing");
        let proof = signing_key.sign(proof_challenge.transcript()).to_bytes();
        let completion = manager
            .complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                proof,
                now + Duration::from_secs(3),
            )
            .expect("complete pairing");

        assert!(completion.newly_activated());
        assert_eq!(completion.consumer_id(), proof_challenge.consumer_id());
        assert_eq!(
            completion.authorization_effect(),
            BrokerPairingAuthorizationEffect::Unchanged
        );
        let consumers = state.consumers().expect("Consumers");
        assert_eq!(consumers.len(), 1);
        assert_eq!(consumers[0].consumer_id(), completion.consumer_id());
        assert!(state
            .access_rules_for_consumer(completion.consumer_id())
            .expect("Access Rules")
            .is_empty());
        assert!(state
            .use_grants_for_consumer(completion.consumer_id())
            .expect("Use Grants")
            .is_empty());
        assert!(manager
            .pending_requests_at(now + Duration::from_secs(4))
            .expect("pending snapshots")
            .is_empty());
        assert_eq!(
            manager.complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                proof,
                now + Duration::from_secs(4),
            ),
            Err(BrokerPairingError::RequestUnavailable)
        );
    }

    #[test]
    fn same_label_and_os_evidence_do_not_inherit_another_consumers_authorization() {
        let directory = TestStateDirectory::new("separate-authorization");
        let state = directory.initialize(20);
        let shared_identity = observed_identity();
        let existing_signing_key = signing_key(31);
        let existing = Consumer::new(
            existing_signing_key.verifying_key().to_bytes(),
            "Local tool".to_owned(),
            shared_identity.clone(),
            timestamp(800),
        )
        .expect("existing Consumer");
        state
            .insert_consumer(&existing)
            .expect("insert existing Consumer");
        let target = AuthorizationTarget::new(
            existing.consumer_id(),
            CredentialFieldScope::new(
                VaultId::generate(),
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::CredentialSearch),
        );
        let rule = AccessRule::new(
            target,
            ConfirmationPolicy::OncePerUnlockSession,
            RuleLifetime::Persistent,
            timestamp(810),
        )
        .expect("existing rule");
        state.insert_access_rule(&rule).expect("insert rule");
        let grant = UseGrant::new(
            target,
            Some(rule.access_rule_id()),
            VaultSessionId::generate(),
            GrantScope::UnlockSession,
            timestamp(820),
            timestamp(900),
        )
        .expect("existing grant");
        state.insert_use_grant(&grant).expect("insert grant");

        let new_signing_key = signing_key(32);
        let manager = BrokerPairingManager::new();
        let now = Instant::now();
        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&new_signing_key, 43).expect("proposal"),
                shared_identity,
                now,
            )
            .expect("separate pending pairing");
        let proof_challenge = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Local tool".to_owned(),
                    timestamp(830),
                ),
                now + Duration::from_secs(1),
            )
            .expect("separate approval");
        let completion = manager
            .complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                new_signing_key
                    .sign(proof_challenge.transcript())
                    .to_bytes(),
                now + Duration::from_secs(2),
            )
            .expect("separate completion");

        assert_ne!(completion.consumer_id(), existing.consumer_id());
        assert_eq!(
            completion.authorization_effect(),
            BrokerPairingAuthorizationEffect::Unchanged
        );
        assert!(state
            .access_rules_for_consumer(completion.consumer_id())
            .expect("new Consumer rules")
            .is_empty());
        assert!(state
            .use_grants_for_consumer(completion.consumer_id())
            .expect("new Consumer grants")
            .is_empty());
        assert_eq!(
            state
                .access_rules_for_consumer(existing.consumer_id())
                .expect("existing rules"),
            vec![rule]
        );
        assert_eq!(
            state
                .use_grants_for_consumer(existing.consumer_id())
                .expect("existing grants"),
            vec![grant]
        );
    }

    #[test]
    fn invalid_or_tampered_proof_consumes_the_request() {
        let directory = TestStateDirectory::new("invalid-proof");
        let state = directory.initialize(12);
        let manager = BrokerPairingManager::new();
        let consumer_signing_key = signing_key(22);
        let attacker = signing_key(23);
        let now = Instant::now();
        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&consumer_signing_key, 32).expect("proposal"),
                observed_identity(),
                now,
            )
            .expect("pending request");
        let proof_challenge = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Local tool".to_owned(),
                    timestamp(200),
                ),
                now + Duration::from_secs(1),
            )
            .expect("approve pairing");
        let mut tampered_transcript = proof_challenge.transcript().to_vec();
        let final_byte = tampered_transcript.last_mut().expect("transcript byte");
        *final_byte ^= 1;
        let invalid_proof = attacker.sign(&tampered_transcript).to_bytes();

        assert_eq!(
            manager.complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                invalid_proof,
                now + Duration::from_secs(2),
            ),
            Err(BrokerPairingError::InvalidProof)
        );
        assert!(state.consumers().expect("Consumers").is_empty());
        assert_eq!(
            manager.complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                consumer_signing_key
                    .sign(proof_challenge.transcript())
                    .to_bytes(),
                now + Duration::from_secs(3),
            ),
            Err(BrokerPairingError::RequestUnavailable)
        );
    }

    #[test]
    fn pairing_expires_at_the_five_minute_boundary() {
        let directory = TestStateDirectory::new("expiry");
        let state = directory.initialize(13);
        let manager = BrokerPairingManager::new();
        let signing_key = signing_key(24);
        let now = Instant::now();
        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&signing_key, 33).expect("proposal"),
                observed_identity(),
                now,
            )
            .expect("pending request");

        assert_eq!(
            manager.approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Expired tool".to_owned(),
                    timestamp(300),
                ),
                now + PAIRING_REQUEST_TTL,
            ),
            Err(BrokerPairingError::Expired)
        );
        assert_eq!(
            manager.approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Expired tool".to_owned(),
                    timestamp(300),
                ),
                now + PAIRING_REQUEST_TTL,
            ),
            Err(BrokerPairingError::RequestUnavailable)
        );
        assert!(state.consumers().expect("Consumers").is_empty());
    }

    #[test]
    fn invalid_proposals_and_denied_requests_never_create_consumers() {
        let directory = TestStateDirectory::new("invalid-and-denied");
        let state = directory.initialize(18);
        let manager = BrokerPairingManager::new();
        let signing_key = signing_key(29);
        let now = Instant::now();

        assert_eq!(
            ConsumerPairingProposal::new(
                [0_u8; PAIRING_PUBLIC_KEY_LENGTH],
                [0x61; PAIRING_NONCE_LENGTH],
                BrokerProtocolVersion::current(),
            ),
            Err(BrokerPairingError::InvalidProposal)
        );
        assert_eq!(
            ConsumerPairingProposal::new(
                signing_key.verifying_key().to_bytes(),
                [0_u8; PAIRING_NONCE_LENGTH],
                BrokerProtocolVersion::current(),
            ),
            Err(BrokerPairingError::InvalidProposal)
        );

        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&signing_key, 41).expect("proposal"),
                observed_identity(),
                now,
            )
            .expect("pending request");
        manager
            .deny_pairing_at(challenge.pairing_request_id(), now + Duration::from_secs(1))
            .expect("deny pairing");
        assert_eq!(
            manager.deny_pairing_at(challenge.pairing_request_id(), now + Duration::from_secs(2),),
            Err(BrokerPairingError::RequestUnavailable)
        );
        assert!(state.consumers().expect("Consumers").is_empty());
    }

    #[test]
    fn pairing_rejects_duplicate_and_excess_pending_identities() {
        let directory = TestStateDirectory::new("pending-bound");
        let state = directory.initialize(14);
        let manager = BrokerPairingManager::new();
        let now = Instant::now();
        let first_key = signing_key(25);
        let first = manager
            .begin_pairing_at(
                &state,
                proposal(&first_key, 34).expect("proposal"),
                observed_identity(),
                now,
            )
            .expect("first request");
        assert_eq!(
            manager.begin_pairing_at(
                &state,
                proposal(&first_key, 35).expect("duplicate proposal"),
                observed_identity(),
                now,
            ),
            Err(BrokerPairingError::AlreadyPending {
                pairing_request_id: first.pairing_request_id(),
            })
        );

        for index in 1..MAX_PENDING_PAIRING_REQUESTS {
            let byte = u8::try_from(index + 40).expect("test byte");
            let key = signing_key(byte);
            manager
                .begin_pairing_at(
                    &state,
                    proposal(&key, byte.wrapping_add(80)).expect("proposal"),
                    observed_identity(),
                    now,
                )
                .expect("bounded pending request");
        }
        let excess_key = signing_key(120);
        assert_eq!(
            manager.begin_pairing_at(
                &state,
                proposal(&excess_key, 121).expect("excess proposal"),
                observed_identity(),
                now,
            ),
            Err(BrokerPairingError::TooManyPending)
        );
        assert_eq!(
            manager.pending_requests_at(now).expect("pending").len(),
            MAX_PENDING_PAIRING_REQUESTS
        );
    }

    #[test]
    fn approved_consumer_id_is_stable_and_label_cannot_be_changed() {
        let directory = TestStateDirectory::new("approval");
        let state = directory.initialize(15);
        let manager = BrokerPairingManager::new();
        let signing_key = signing_key(26);
        let now = Instant::now();
        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&signing_key, 36).expect("proposal"),
                observed_identity(),
                now,
            )
            .expect("pending request");
        assert_eq!(
            manager.approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(String::new(), timestamp(400),),
                now + Duration::from_secs(1),
            ),
            Err(BrokerPairingError::InvalidApproval)
        );

        let first = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Approved name".to_owned(),
                    timestamp(401),
                ),
                now + Duration::from_secs(2),
            )
            .expect("first approval");
        let repeated = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Approved name".to_owned(),
                    timestamp(999),
                ),
                now + Duration::from_secs(3),
            )
            .expect("idempotent approval");
        assert_eq!(repeated.consumer_id(), first.consumer_id());
        assert_eq!(repeated.transcript(), first.transcript());
        assert_eq!(
            manager.approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Changed name".to_owned(),
                    timestamp(402),
                ),
                now + Duration::from_secs(4),
            ),
            Err(BrokerPairingError::AlreadyApproved)
        );
    }

    #[test]
    fn existing_pairing_key_maps_to_one_consumer_and_no_duplicate_row() {
        let directory = TestStateDirectory::new("existing");
        let state = directory.initialize(16);
        let manager = BrokerPairingManager::new();
        let signing_key = signing_key(27);
        let now = Instant::now();
        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&signing_key, 37).expect("proposal"),
                observed_identity(),
                now,
            )
            .expect("pending request");
        let proof_challenge = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Shared profile".to_owned(),
                    timestamp(500),
                ),
                now + Duration::from_secs(1),
            )
            .expect("approval");
        let completion = manager
            .complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                signing_key.sign(proof_challenge.transcript()).to_bytes(),
                now + Duration::from_secs(2),
            )
            .expect("completion");

        let restarted_manager = BrokerPairingManager::new();
        assert_eq!(
            restarted_manager.begin_pairing_at(
                &state,
                proposal(&signing_key, 38).expect("proposal"),
                observed_identity(),
                now + Duration::from_secs(3),
            ),
            Err(BrokerPairingError::AlreadyPaired {
                consumer_id: completion.consumer_id(),
            })
        );
        let duplicate = Consumer::new(
            signing_key.verifying_key().to_bytes(),
            "Duplicate".to_owned(),
            observed_identity(),
            timestamp(501),
        )
        .expect("duplicate Consumer");
        assert_eq!(
            state.insert_consumer(&duplicate),
            Err(DeviceStateError::Conflict)
        );
        assert_eq!(state.consumers().expect("Consumers").len(), 1);
    }

    #[test]
    fn pairing_accepts_unsigned_consumer_evidence_without_weakening_key_proof() {
        let directory = TestStateDirectory::new("unsigned");
        let state = directory.initialize(19);
        let manager = BrokerPairingManager::new();
        let signing_key = signing_key(30);
        let now = Instant::now();
        let challenge = manager
            .begin_pairing_at(
                &state,
                proposal(&signing_key, 42).expect("proposal"),
                ObservedConsumerIdentity::new(
                    Some("unsigned-adapter".to_owned()),
                    None,
                    None,
                    None,
                )
                .expect("unsigned evidence"),
                now,
            )
            .expect("pending request");
        let snapshot = manager
            .pending_requests_at(now)
            .expect("pending snapshots")
            .remove(0);
        assert_eq!(
            snapshot.identity_evidence().executable_name(),
            Some("unsigned-adapter")
        );
        assert_eq!(
            snapshot.identity_evidence().code_signing_evidence(),
            ConsumerCodeSigningEvidence::NoVerifiedSignature
        );
        assert_eq!(
            snapshot.identity_evidence().code_signature_fingerprint(),
            None
        );

        let proof_challenge = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                BrokerPairingUserApproval::after_user_approval(
                    "Unsigned local adapter".to_owned(),
                    timestamp(700),
                ),
                now + Duration::from_secs(1),
            )
            .expect("approval");
        manager
            .complete_pairing_at(
                &state,
                challenge.pairing_request_id(),
                signing_key.sign(proof_challenge.transcript()).to_bytes(),
                now + Duration::from_secs(2),
            )
            .expect("proof still required");
        let consumer = state
            .consumer(proof_challenge.consumer_id())
            .expect("Consumer query")
            .expect("Consumer");
        assert_eq!(
            consumer.observed_identity().code_signing_evidence(),
            ConsumerCodeSigningEvidence::NoVerifiedSignature
        );
    }

    #[test]
    fn canonical_code_and_transcript_are_deterministic() {
        let pairing_request_id =
            PairingRequestId::from_str("pairing_000102030405060708090a0b0c0d0e0f")
                .expect("request ID");
        let consumer_id =
            ConsumerId::from_str("consumer_101112131415161718191a1b1c1d1e1f").expect("Consumer ID");
        let public_key = [0x20_u8; PAIRING_PUBLIC_KEY_LENGTH];
        let client_nonce = [0x30_u8; PAIRING_NONCE_LENGTH];
        let server_nonce = [0x40_u8; PAIRING_NONCE_LENGTH];
        let protocol = BrokerProtocolVersion::new(1, 2).expect("protocol");
        let identity_evidence =
            BrokerPairingIdentityEvidence::new(&public_key, &observed_identity());

        assert_eq!(
            pairing_comparison_code(
                pairing_request_id,
                &public_key,
                &client_nonce,
                &server_nonce,
            )
            .as_str(),
            "NZ691C9PEQ"
        );
        assert_eq!(
            identity_evidence.pairing_key_fingerprint().to_string(),
            "85E7-EAC2-862F-1CBD"
        );
        assert_eq!(identity_evidence.executable_name(), Some("codex"));
        assert_eq!(
            identity_evidence.bundle_identifier(),
            Some("com.openai.codex")
        );
        assert_eq!(identity_evidence.team_identifier(), None);
        assert_eq!(
            identity_evidence.code_signing_evidence(),
            ConsumerCodeSigningEvidence::VerifiedWithoutTeamIdentifier
        );
        assert_eq!(
            identity_evidence
                .code_signature_fingerprint()
                .expect("code signature fingerprint")
                .to_string(),
            "4444-4444-4444-4444"
        );
        assert_eq!(
            hex::encode(consumer_pairing_transcript(
                protocol,
                pairing_request_id,
                consumer_id,
                &public_key,
                &client_nonce,
                &server_nonce,
            )),
            concat!(
                "000000134b6570744e6561722070616972696e67207631",
                "0000000400010002",
                "00000010000102030405060708090a0b0c0d0e0f",
                "00000010101112131415161718191a1b1c1d1e1f",
                "00000020",
                "2020202020202020202020202020202020202020202020202020202020202020",
                "00000020",
                "3030303030303030303030303030303030303030303030303030303030303030",
                "00000020",
                "4040404040404040404040404040404040404040404040404040404040404040",
            )
        );
    }

    #[test]
    fn debug_and_errors_redact_pairing_material_and_user_label() {
        let directory = TestStateDirectory::new("redaction");
        let state = directory.initialize(17);
        let manager = BrokerPairingManager::new();
        let signing_key = signing_key(28);
        let proposal = proposal(&signing_key, 39).expect("proposal");
        let public_key_hex = hex::encode(proposal.pairing_public_key());
        let client_nonce_hex = hex::encode(proposal.client_nonce());
        let proposal_debug = format!("{proposal:?}");
        assert!(!proposal_debug.contains(&public_key_hex));
        assert!(!proposal_debug.contains(&client_nonce_hex));

        let now = Instant::now();
        let challenge = manager
            .begin_pairing_at(&state, proposal, observed_identity(), now)
            .expect("pending request");
        let server_nonce_hex = hex::encode(challenge.server_nonce());
        assert!(!format!("{challenge:?}").contains(&server_nonce_hex));
        let approval = BrokerPairingUserApproval::after_user_approval(
            "private local label".to_owned(),
            timestamp(600),
        );
        assert!(!format!("{approval:?}").contains("private local label"));
        let proof_challenge = manager
            .approve_pairing_at(
                challenge.pairing_request_id(),
                approval,
                now + Duration::from_secs(1),
            )
            .expect("approval");
        assert!(
            !format!("{proof_challenge:?}").contains(&hex::encode(proof_challenge.transcript()))
        );
        let snapshot = manager
            .pending_requests_at(now + Duration::from_secs(2))
            .expect("snapshot")
            .remove(0);
        let snapshot_debug = format!("{snapshot:?}");
        assert!(!snapshot_debug.contains("private local label"));
        assert!(!snapshot_debug.contains(&public_key_hex));
        assert!(!snapshot_debug.contains(&hex::encode([0x44_u8; 32])));
        assert!(!BrokerPairingError::InvalidProof
            .to_string()
            .contains("private local label"));
    }
}
