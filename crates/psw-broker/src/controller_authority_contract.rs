use std::fmt::{Debug, Display, Formatter};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::human_control_protocol::{
    HumanControlProtocolVersion, HUMAN_CONTROL_PROTOCOL_NAME, HUMAN_CONTROL_SCHEMA_ID,
};

/// Stable identity of the version 1 human-controller authority contract.
pub const CONTROLLER_AUTHORITY_CONTRACT_ID: &str = "keptnear.controller-authority.v1";
/// Fixed signing algorithm for controller bootstrap and authentication.
pub const CONTROLLER_SIGNING_ALGORITHM: &str = "ed25519";
/// Fixed role bound into every controller proof.
pub const CONTROLLER_ROLE: &str = "human-controller";
/// Domain separator for first-authority bootstrap proofs.
pub const CONTROLLER_BOOTSTRAP_DOMAIN: &str = "KeptNear human controller bootstrap v1";
/// Domain separator for ordinary connection-authentication proofs.
pub const CONTROLLER_AUTHENTICATION_DOMAIN: &str = "KeptNear human controller auth v1";
/// Stable Data Protection Keychain generic-password service.
pub const CONTROLLER_KEYCHAIN_SERVICE: &str = "app.keptnear.human-controller-key.v1";
/// Stable primary controller-key Keychain account.
pub const CONTROLLER_KEYCHAIN_ACCOUNT: &str = "primary-v1";
/// Stable account for the non-secret controller-removal provenance marker.
pub const CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT: &str = "removal-pending-v1";
/// Fixed non-secret value stored while controller removal is incomplete.
pub const CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE: &[u8] = b"keptnear.controller-removal.v1";
/// Human-readable Keychain label. This is not part of item identity.
pub const CONTROLLER_KEYCHAIN_LABEL: &str = "KeptNear Human Controller key";
/// Access-group suffix shared only by the App and packaged Broker.
pub const CONTROLLER_KEYCHAIN_ACCESS_GROUP_SUFFIX: &str = "app.keptnear.human-controller";
/// Number of bytes in one Ed25519 private seed.
pub const CONTROLLER_SIGNING_SEED_LENGTH: usize = 32;
/// Number of bytes in one Ed25519 public key.
pub const CONTROLLER_PUBLIC_KEY_LENGTH: usize = 32;
/// Number of bytes in one Ed25519 signature.
pub const CONTROLLER_SIGNATURE_LENGTH: usize = 64;
/// Number of bytes in the SHA-256-derived controller identity.
pub const CONTROLLER_ID_LENGTH: usize = 32;
/// Number of bytes in each Broker instance or controller session identity.
pub const CONTROLLER_PROTOCOL_ID_LENGTH: usize = 16;
/// Number of bytes in each independently generated controller nonce.
pub const CONTROLLER_NONCE_LENGTH: usize = 32;
/// Required Apple application-identifier prefix length.
pub const CONTROLLER_SIGNING_PREFIX_LENGTH: usize = 10;
/// Maximum lifetime of one controller bootstrap or authentication challenge.
pub const CONTROLLER_CHALLENGE_TTL: Duration = Duration::from_secs(30);
/// Maximum live challenge count on one human-control connection.
pub const MAX_OUTSTANDING_CONTROLLER_CHALLENGES_PER_CONNECTION: usize = 1;
/// Maximum failed proofs for one controller identity in the failure window.
pub const MAX_CONTROLLER_FAILURES_PER_IDENTITY: usize = 5;
/// Maximum failed controller proofs across one Broker process in the failure window.
pub const MAX_CONTROLLER_FAILURES_GLOBALLY: usize = 64;
/// Process-local window used for controller proof rate limiting.
pub const CONTROLLER_FAILURE_WINDOW: Duration = Duration::from_secs(60);

const CONTROLLER_ID_DOMAIN: &[u8] = b"KeptNear human controller identity v1";

const _: () = assert!(CONTROLLER_SIGNING_SEED_LENGTH == 32);
const _: () = assert!(CONTROLLER_PUBLIC_KEY_LENGTH == 32);
const _: () = assert!(CONTROLLER_SIGNATURE_LENGTH == 64);
const _: () = assert!(CONTROLLER_CHALLENGE_TTL.as_secs() == 30);
const _: () = assert!(MAX_OUTSTANDING_CONTROLLER_CHALLENGES_PER_CONNECTION == 1);

/// Packaged executable principals allowed to declare the controller access group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerKeychainPrincipal {
    /// The KeptNear macOS application executable.
    App,
    /// The nested `keptnear-broker` LaunchAgent executable.
    Broker,
}

/// Complete principal set for the controller private-key access group.
pub const CONTROLLER_KEYCHAIN_PRINCIPALS: [ControllerKeychainPrincipal; 2] = [
    ControllerKeychainPrincipal::App,
    ControllerKeychainPrincipal::Broker,
];

/// Validated fully qualified Keychain access-group identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerKeychainAccessGroup(String);

impl ControllerKeychainAccessGroup {
    /// Builds `<signing-prefix>.app.keptnear.human-controller`.
    ///
    /// The signing prefix must be the exact ten-character Apple application-
    /// identifier prefix present in both activation-qualified signatures.
    pub fn from_signing_prefix(
        signing_prefix: &str,
    ) -> Result<Self, ControllerAuthorityContractError> {
        if signing_prefix.len() != CONTROLLER_SIGNING_PREFIX_LENGTH
            || !signing_prefix
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return Err(ControllerAuthorityContractError::InvalidSigningPrefix);
        }
        Ok(Self(format!(
            "{signing_prefix}.{CONTROLLER_KEYCHAIN_ACCESS_GROUP_SUFFIX}"
        )))
    }

    /// Returns the complete non-secret entitlement and query value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Frozen Data Protection Keychain behavior for the controller seed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerKeychainContract {
    data_protection_keychain: bool,
    synchronizable: bool,
    this_device_only: bool,
    create_only: bool,
    access_group_required_on_every_query: bool,
}

impl ControllerKeychainContract {
    /// Returns whether every operation must target the Data Protection Keychain.
    #[must_use]
    pub const fn uses_data_protection_keychain(self) -> bool {
        self.data_protection_keychain
    }

    /// Returns whether the controller item may synchronize through iCloud Keychain.
    #[must_use]
    pub const fn is_synchronizable(self) -> bool {
        self.synchronizable
    }

    /// Returns whether the accessibility class is device-bound.
    #[must_use]
    pub const fn is_this_device_only(self) -> bool {
        self.this_device_only
    }

    /// Returns whether first creation must use add-only duplicate rejection.
    #[must_use]
    pub const fn is_create_only(self) -> bool {
        self.create_only
    }

    /// Returns whether add, load, update, and delete must all name the access group.
    #[must_use]
    pub const fn requires_access_group_on_every_query(self) -> bool {
        self.access_group_required_on_every_query
    }
}

/// Immutable version 1 controller Keychain policy.
pub const CONTROLLER_KEYCHAIN_CONTRACT: ControllerKeychainContract = ControllerKeychainContract {
    data_protection_keychain: true,
    synchronizable: false,
    this_device_only: true,
    create_only: true,
    access_group_required_on_every_query: true,
};

/// Presence relationship between the shared Keychain seed and Broker trust record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAuthorityPresence {
    /// Neither the Keychain seed nor Broker public record exists.
    Absent,
    /// The Keychain seed exists but bootstrap did not commit the Broker record.
    KeyOnly,
    /// A protected removal marker exists, regardless of the remaining seed or record.
    RemovalPending,
    /// A Broker public record exists but the Keychain seed is missing.
    RecordOnly,
    /// Both sides exist and the derived identity and public key match exactly.
    CompleteMatching,
    /// Both sides exist but their identity or public key differs.
    CompleteMismatched,
}

/// Required behavior when explicit enable or repair inspects controller authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerEnableDisposition {
    /// Create one Keychain seed with add-only semantics, then prove bootstrap.
    CreateKeyThenBootstrap,
    /// Reuse the existing seed and resume bootstrap without generating a key.
    ResumeBootstrap,
    /// Preserve the complete authority and perform ordinary authentication.
    AuthenticateExisting,
    /// Refuse enablement and continue the already-started removal sequence only.
    ResumeRemovalOnly,
    /// Refuse activation until the incomplete authority is explicitly cleared.
    RejectIncompleteAuthority,
}

/// Returns the fail-closed enable behavior for one observed authority state.
#[must_use]
pub const fn controller_enable_disposition(
    presence: ControllerAuthorityPresence,
) -> ControllerEnableDisposition {
    match presence {
        ControllerAuthorityPresence::Absent => ControllerEnableDisposition::CreateKeyThenBootstrap,
        ControllerAuthorityPresence::KeyOnly => ControllerEnableDisposition::ResumeBootstrap,
        ControllerAuthorityPresence::CompleteMatching => {
            ControllerEnableDisposition::AuthenticateExisting
        }
        ControllerAuthorityPresence::RemovalPending => {
            ControllerEnableDisposition::ResumeRemovalOnly
        }
        ControllerAuthorityPresence::RecordOnly
        | ControllerAuthorityPresence::CompleteMismatched => {
            ControllerEnableDisposition::RejectIncompleteAuthority
        }
    }
}

/// Version 1 policy for changing the controller signing authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerRotationPolicy {
    /// Clear all device access data, verify both authority sides are absent,
    /// and bootstrap a fresh key only after a later explicit enable.
    ClearDeviceAccessThenBootstrap,
}

/// Frozen version 1 controller-key rotation policy.
pub const CONTROLLER_ROTATION_POLICY: ControllerRotationPolicy =
    ControllerRotationPolicy::ClearDeviceAccessThenBootstrap;

/// Required deletion ordering for a confirmed device-access clear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerRemovalOrder {
    /// Create the removal marker, remove the Broker record, delete the seed,
    /// verify both absent, and delete the marker last.
    MarkerThenBrokerRecordThenKeychainSeedThenMarker,
}

/// Frozen version 1 controller-authority removal order.
pub const CONTROLLER_REMOVAL_ORDER: ControllerRemovalOrder =
    ControllerRemovalOrder::MarkerThenBrokerRecordThenKeychainSeedThenMarker;

/// Exact bounded fields signed for bootstrap or ordinary authentication.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ControllerTranscriptFields {
    selected_protocol: HumanControlProtocolVersion,
    controller_id: [u8; CONTROLLER_ID_LENGTH],
    public_key: [u8; CONTROLLER_PUBLIC_KEY_LENGTH],
    broker_instance_id: [u8; CONTROLLER_PROTOCOL_ID_LENGTH],
    controller_session_id: [u8; CONTROLLER_PROTOCOL_ID_LENGTH],
    client_nonce: [u8; CONTROLLER_NONCE_LENGTH],
    broker_nonce: [u8; CONTROLLER_NONCE_LENGTH],
    monotonic_deadline_token: u64,
}

impl ControllerTranscriptFields {
    /// Creates validated transcript fields for one connection-bound challenge.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        selected_protocol: HumanControlProtocolVersion,
        controller_id: [u8; CONTROLLER_ID_LENGTH],
        public_key: [u8; CONTROLLER_PUBLIC_KEY_LENGTH],
        broker_instance_id: [u8; CONTROLLER_PROTOCOL_ID_LENGTH],
        controller_session_id: [u8; CONTROLLER_PROTOCOL_ID_LENGTH],
        client_nonce: [u8; CONTROLLER_NONCE_LENGTH],
        broker_nonce: [u8; CONTROLLER_NONCE_LENGTH],
        monotonic_deadline_token: u64,
    ) -> Result<Self, ControllerAuthorityContractError> {
        if controller_id != derive_controller_id(&public_key) {
            return Err(ControllerAuthorityContractError::ControllerIdentityMismatch);
        }
        if monotonic_deadline_token == 0 {
            return Err(ControllerAuthorityContractError::InvalidDeadlineToken);
        }
        Ok(Self {
            selected_protocol,
            controller_id,
            public_key,
            broker_instance_id,
            controller_session_id,
            client_nonce,
            broker_nonce,
            monotonic_deadline_token,
        })
    }
}

impl Debug for ControllerTranscriptFields {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerTranscriptFields")
            .field("selected_protocol", &self.selected_protocol)
            .field("controller_material", &"<redacted>")
            .finish()
    }
}

/// Sanitized validation failure for the controller-authority source contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAuthorityContractError {
    /// The artifact signing prefix is not ten uppercase ASCII alphanumerics.
    InvalidSigningPrefix,
    /// The supplied controller identity is not derived from the supplied public key.
    ControllerIdentityMismatch,
    /// The opaque Broker monotonic deadline token is zero.
    InvalidDeadlineToken,
}

impl Display for ControllerAuthorityContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSigningPrefix => "invalid controller signing prefix",
            Self::ControllerIdentityMismatch => "controller identity does not match public key",
            Self::InvalidDeadlineToken => "invalid controller deadline token",
        })
    }
}

impl std::error::Error for ControllerAuthorityContractError {}

/// Derives the stable controller identity from one Ed25519 public key.
#[must_use]
pub fn derive_controller_id(
    public_key: &[u8; CONTROLLER_PUBLIC_KEY_LENGTH],
) -> [u8; CONTROLLER_ID_LENGTH] {
    let mut input = Vec::with_capacity(CONTROLLER_ID_DOMAIN.len() + public_key.len() + 8);
    append_length_prefixed(&mut input, CONTROLLER_ID_DOMAIN);
    append_length_prefixed(&mut input, public_key);
    Sha256::digest(input).into()
}

/// Builds the fixed-order, length-prefixed Ed25519 bootstrap transcript.
#[must_use]
pub fn controller_bootstrap_transcript(fields: &ControllerTranscriptFields) -> Vec<u8> {
    controller_transcript(CONTROLLER_BOOTSTRAP_DOMAIN, fields)
}

/// Builds the fixed-order, length-prefixed Ed25519 authentication transcript.
#[must_use]
pub fn controller_authentication_transcript(fields: &ControllerTranscriptFields) -> Vec<u8> {
    controller_transcript(CONTROLLER_AUTHENTICATION_DOMAIN, fields)
}

fn controller_transcript(domain: &str, fields: &ControllerTranscriptFields) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(320);
    append_length_prefixed(&mut transcript, domain.as_bytes());
    append_length_prefixed(&mut transcript, CONTROLLER_AUTHORITY_CONTRACT_ID.as_bytes());
    append_length_prefixed(&mut transcript, HUMAN_CONTROL_PROTOCOL_NAME.as_bytes());
    let mut protocol = [0_u8; 4];
    protocol[..2].copy_from_slice(&fields.selected_protocol.major().to_be_bytes());
    protocol[2..].copy_from_slice(&fields.selected_protocol.minor().to_be_bytes());
    append_length_prefixed(&mut transcript, &protocol);
    append_length_prefixed(&mut transcript, HUMAN_CONTROL_SCHEMA_ID.as_bytes());
    append_length_prefixed(&mut transcript, CONTROLLER_SIGNING_ALGORITHM.as_bytes());
    append_length_prefixed(&mut transcript, CONTROLLER_ROLE.as_bytes());
    append_length_prefixed(&mut transcript, &fields.controller_id);
    append_length_prefixed(&mut transcript, &fields.public_key);
    append_length_prefixed(&mut transcript, &fields.broker_instance_id);
    append_length_prefixed(&mut transcript, &fields.controller_session_id);
    append_length_prefixed(&mut transcript, &fields.client_nonce);
    append_length_prefixed(&mut transcript, &fields.broker_nonce);
    append_length_prefixed(
        &mut transcript,
        &fields.monotonic_deadline_token.to_be_bytes(),
    );
    transcript
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("controller contract fields are bounded");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn transcript_fields(seed: u8) -> ControllerTranscriptFields {
        let public_key = SigningKey::from_bytes(&[seed; CONTROLLER_SIGNING_SEED_LENGTH])
            .verifying_key()
            .to_bytes();
        ControllerTranscriptFields::new(
            HumanControlProtocolVersion::current(),
            derive_controller_id(&public_key),
            public_key,
            [0x31; CONTROLLER_PROTOCOL_ID_LENGTH],
            [0x32; CONTROLLER_PROTOCOL_ID_LENGTH],
            [0x33; CONTROLLER_NONCE_LENGTH],
            [0x34; CONTROLLER_NONCE_LENGTH],
            9_876_543_210,
        )
        .expect("transcript fields")
    }

    fn decode_length_prefixed(mut transcript: &[u8]) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        while !transcript.is_empty() {
            let length =
                u32::from_be_bytes(transcript[..4].try_into().expect("length-prefix bytes"))
                    as usize;
            transcript = &transcript[4..];
            values.push(transcript[..length].to_vec());
            transcript = &transcript[length..];
        }
        values
    }

    #[test]
    fn keychain_contract_is_stable_shared_device_only_and_create_only() {
        assert_eq!(
            CONTROLLER_KEYCHAIN_SERVICE,
            "app.keptnear.human-controller-key.v1"
        );
        assert_eq!(CONTROLLER_KEYCHAIN_ACCOUNT, "primary-v1");
        assert_eq!(
            CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT,
            "removal-pending-v1"
        );
        assert_eq!(
            CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE,
            b"keptnear.controller-removal.v1"
        );
        assert_eq!(
            CONTROLLER_KEYCHAIN_PRINCIPALS,
            [
                ControllerKeychainPrincipal::App,
                ControllerKeychainPrincipal::Broker,
            ]
        );
        let access_group =
            ControllerKeychainAccessGroup::from_signing_prefix("AB12CD34EF").expect("access group");
        assert_eq!(
            access_group.as_str(),
            "AB12CD34EF.app.keptnear.human-controller"
        );
        for invalid in ["", "AB12CD34E", "ab12cd34ef", "AB12-CD34E", "AB12CD34EF."] {
            assert_eq!(
                ControllerKeychainAccessGroup::from_signing_prefix(invalid),
                Err(ControllerAuthorityContractError::InvalidSigningPrefix)
            );
        }
        assert!(CONTROLLER_KEYCHAIN_CONTRACT.uses_data_protection_keychain());
        assert!(!CONTROLLER_KEYCHAIN_CONTRACT.is_synchronizable());
        assert!(CONTROLLER_KEYCHAIN_CONTRACT.is_this_device_only());
        assert!(CONTROLLER_KEYCHAIN_CONTRACT.is_create_only());
        assert!(CONTROLLER_KEYCHAIN_CONTRACT.requires_access_group_on_every_query());
    }

    #[test]
    fn controller_identity_is_deterministic_public_and_domain_separated() {
        let first = SigningKey::from_bytes(&[0x41; CONTROLLER_SIGNING_SEED_LENGTH])
            .verifying_key()
            .to_bytes();
        let second = SigningKey::from_bytes(&[0x42; CONTROLLER_SIGNING_SEED_LENGTH])
            .verifying_key()
            .to_bytes();
        assert_eq!(derive_controller_id(&first), derive_controller_id(&first));
        assert_ne!(derive_controller_id(&first), derive_controller_id(&second));
        assert_ne!(derive_controller_id(&first), first);
    }

    #[test]
    fn transcripts_bind_every_fixed_field_and_separate_bootstrap_from_authentication() {
        let fields = transcript_fields(0x51);
        let bootstrap = controller_bootstrap_transcript(&fields);
        let authentication = controller_authentication_transcript(&fields);
        assert_ne!(bootstrap, authentication);

        let decoded = decode_length_prefixed(&authentication);
        assert_eq!(decoded.len(), 14);
        assert_eq!(decoded[0], CONTROLLER_AUTHENTICATION_DOMAIN.as_bytes());
        assert_eq!(decoded[1], CONTROLLER_AUTHORITY_CONTRACT_ID.as_bytes());
        assert_eq!(decoded[2], HUMAN_CONTROL_PROTOCOL_NAME.as_bytes());
        assert_eq!(decoded[3], [0, 1, 0, 0]);
        assert_eq!(decoded[4], HUMAN_CONTROL_SCHEMA_ID.as_bytes());
        assert_eq!(decoded[5], CONTROLLER_SIGNING_ALGORITHM.as_bytes());
        assert_eq!(decoded[6], CONTROLLER_ROLE.as_bytes());
        assert_eq!(decoded[7], fields.controller_id);
        assert_eq!(decoded[8], fields.public_key);
        assert_eq!(decoded[9], fields.broker_instance_id);
        assert_eq!(decoded[10], fields.controller_session_id);
        assert_eq!(decoded[11], fields.client_nonce);
        assert_eq!(decoded[12], fields.broker_nonce);
        assert_eq!(decoded[13], fields.monotonic_deadline_token.to_be_bytes());

        let signing_key = SigningKey::from_bytes(&[0x51; CONTROLLER_SIGNING_SEED_LENGTH]);
        let signature = signing_key.sign(&bootstrap);
        signing_key
            .verifying_key()
            .verify_strict(&bootstrap, &signature)
            .expect("bootstrap proof");
        assert!(signing_key
            .verifying_key()
            .verify_strict(&authentication, &signature)
            .is_err());
    }

    #[test]
    fn transcript_validation_rejects_mismatched_identity_and_zero_deadline() {
        let fields = transcript_fields(0x61);
        assert_eq!(
            ControllerTranscriptFields::new(
                fields.selected_protocol,
                [0_u8; CONTROLLER_ID_LENGTH],
                fields.public_key,
                fields.broker_instance_id,
                fields.controller_session_id,
                fields.client_nonce,
                fields.broker_nonce,
                fields.monotonic_deadline_token,
            ),
            Err(ControllerAuthorityContractError::ControllerIdentityMismatch)
        );
        assert_eq!(
            ControllerTranscriptFields::new(
                fields.selected_protocol,
                fields.controller_id,
                fields.public_key,
                fields.broker_instance_id,
                fields.controller_session_id,
                fields.client_nonce,
                fields.broker_nonce,
                0,
            ),
            Err(ControllerAuthorityContractError::InvalidDeadlineToken)
        );
        assert!(!format!("{fields:?}").contains(&hex::encode(fields.client_nonce)));
        assert!(!format!("{fields:?}").contains(&hex::encode(fields.public_key)));
    }

    #[test]
    fn lifecycle_reuses_partial_key_only_bootstrap_and_never_silently_rotates() {
        assert_eq!(
            controller_enable_disposition(ControllerAuthorityPresence::Absent),
            ControllerEnableDisposition::CreateKeyThenBootstrap
        );
        assert_eq!(
            controller_enable_disposition(ControllerAuthorityPresence::KeyOnly),
            ControllerEnableDisposition::ResumeBootstrap
        );
        assert_eq!(
            controller_enable_disposition(ControllerAuthorityPresence::CompleteMatching),
            ControllerEnableDisposition::AuthenticateExisting
        );
        assert_eq!(
            controller_enable_disposition(ControllerAuthorityPresence::RemovalPending),
            ControllerEnableDisposition::ResumeRemovalOnly
        );
        for incomplete in [
            ControllerAuthorityPresence::RecordOnly,
            ControllerAuthorityPresence::CompleteMismatched,
        ] {
            assert_eq!(
                controller_enable_disposition(incomplete),
                ControllerEnableDisposition::RejectIncompleteAuthority
            );
        }
        assert_eq!(
            CONTROLLER_ROTATION_POLICY,
            ControllerRotationPolicy::ClearDeviceAccessThenBootstrap
        );
        assert_eq!(
            CONTROLLER_REMOVAL_ORDER,
            ControllerRemovalOrder::MarkerThenBrokerRecordThenKeychainSeedThenMarker
        );
        assert_eq!(CONTROLLER_CHALLENGE_TTL, Duration::from_secs(30));
        assert_eq!(MAX_OUTSTANDING_CONTROLLER_CHALLENGES_PER_CONNECTION, 1);
        assert_eq!(MAX_CONTROLLER_FAILURES_PER_IDENTITY, 5);
        assert_eq!(MAX_CONTROLLER_FAILURES_GLOBALLY, 64);
        assert_eq!(CONTROLLER_FAILURE_WINDOW, Duration::from_secs(60));
    }
}
