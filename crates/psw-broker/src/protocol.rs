use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::str::FromStr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use psw_core::{CredentialId, SecretFieldId, SecretFieldKind, VaultId};
use rand_core::{OsRng, RngCore};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

use crate::authentication::{AUTHENTICATION_NONCE_LENGTH, AUTHENTICATION_PROOF_LENGTH};
use crate::capability_protocol::{
    BrokerAccessReceiptResponse, BrokerAccessRequest, BrokerAccessResponse,
    BrokerAccessSubmissionResponse, BrokerAccessWaitResponse, BrokerActiveGrantMetadata,
    BrokerCredentialMetadataResponse, BrokerCredentialOperationTarget,
    BrokerCredentialSearchRequest, BrokerCredentialSearchResponse, BrokerGrantRevokeRequest,
    BrokerGrantRevokeResponse, BrokerGrantStatusRequest, BrokerGrantStatusResponse,
    BrokerHttpCapabilityHeader, BrokerHttpCapabilityRequest, BrokerHttpCapabilityResponse,
    BrokerProcessCapabilityEnvironment, BrokerProcessCapabilityRequest,
    BrokerProcessCapabilityResponse,
};
use crate::http_request::BrokerHttpMethod;
use crate::pairing::{
    BrokerPairingRequestStatus, PairingComparisonCode, PAIRING_NONCE_LENGTH, PAIRING_PROOF_LENGTH,
    PAIRING_PUBLIC_KEY_LENGTH,
};
use crate::state_model::{
    ApprovalRequestId, ApprovalStatus, Capability, CapabilityName, ConsumerId,
    CredentialFieldScope, GrantScope, PairingRequestId, StateTimestamp, UsageProfileId, UseGrantId,
    VaultSessionId,
};

/// Canonical Broker protocol identity.
pub const BROKER_PROTOCOL_NAME: &str = "keptnear.broker";
/// Current Broker protocol major version.
pub const BROKER_PROTOCOL_MAJOR: u16 = 1;
/// Current Broker protocol minor version.
pub const BROKER_PROTOCOL_MINOR: u16 = 0;
/// Maximum accepted or emitted Broker frame payload.
pub const MAX_BROKER_FRAME_LENGTH: usize = 16 * 1024 * 1024;
/// Lower bound applied to the unauthenticated negotiation request.
pub const MAX_BROKER_HELLO_LENGTH: usize = 64 * 1024;

const PROTOCOL_ID_BYTE_LENGTH: usize = 16;
const PROTOCOL_ID_HEX_LENGTH: usize = PROTOCOL_ID_BYTE_LENGTH * 2;
const MAX_PROTOCOL_RANGES: usize = 16;
const MAX_CAPABILITY_OFFERS: usize = 32;
const MAX_CAPABILITY_VERSIONS: usize = 16;

/// Error returned for a non-canonical Broker protocol identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerProtocolIdParseError {
    expected_prefix: &'static str,
}

impl Display for BrokerProtocolIdParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid Broker identifier; expected {:?} followed by {} lowercase hexadecimal characters",
            self.expected_prefix, PROTOCOL_ID_HEX_LENGTH
        )
    }
}

impl std::error::Error for BrokerProtocolIdParseError {}

fn parse_protocol_id(
    value: &str,
    expected_prefix: &'static str,
) -> Result<[u8; PROTOCOL_ID_BYTE_LENGTH], BrokerProtocolIdParseError> {
    let invalid = || BrokerProtocolIdParseError { expected_prefix };
    let encoded = value.strip_prefix(expected_prefix).ok_or_else(invalid)?;
    if encoded.len() != PROTOCOL_ID_HEX_LENGTH
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }

    let mut bytes = [0_u8; PROTOCOL_ID_BYTE_LENGTH];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| invalid())?;
    Ok(bytes)
}

macro_rules! define_protocol_id {
    ($name:ident, $description:literal, $prefix:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; PROTOCOL_ID_BYTE_LENGTH]);

        impl $name {
            /// Generates a random identifier using the operating-system CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                let mut bytes = [0_u8; PROTOCOL_ID_BYTE_LENGTH];
                OsRng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Returns the 128-bit value backing the identifier.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; PROTOCOL_ID_BYTE_LENGTH] {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = BrokerProtocolIdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_protocol_id(value, $prefix).map(Self)
            }
        }
    };
}

define_protocol_id!(
    BrokerRequestId,
    "Immutable correlation identity of one Broker request.",
    "request_"
);
define_protocol_id!(
    BrokerInstanceId,
    "Ephemeral identity of one running Broker process instance.",
    "broker_instance_"
);
define_protocol_id!(
    BrokerSessionId,
    "Ephemeral identity of one authenticated Broker connection session.",
    "session_"
);

/// One exact Broker protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BrokerProtocolVersion {
    major: u16,
    minor: u16,
}

impl BrokerProtocolVersion {
    /// Creates a non-zero-major protocol version.
    pub fn new(major: u16, minor: u16) -> Result<Self, BrokerProtocolValidationError> {
        if major == 0 {
            return Err(BrokerProtocolValidationError::InvalidProtocolVersion);
        }
        Ok(Self { major, minor })
    }

    /// Returns the current server protocol version.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            major: BROKER_PROTOCOL_MAJOR,
            minor: BROKER_PROTOCOL_MINOR,
        }
    }

    /// Returns the major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// Inclusive client-supported minor range for one protocol major version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerProtocolVersionRange {
    major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
}

impl BrokerProtocolVersionRange {
    /// Creates a validated inclusive protocol range.
    pub fn new(
        major: u16,
        minimum_minor: u16,
        maximum_minor: u16,
    ) -> Result<Self, BrokerProtocolValidationError> {
        if major == 0 || minimum_minor > maximum_minor {
            return Err(BrokerProtocolValidationError::InvalidProtocolVersion);
        }
        Ok(Self {
            major,
            minimum_minor,
            maximum_minor,
        })
    }

    /// Returns the major version covered by the range.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the lowest supported minor version.
    #[must_use]
    pub const fn minimum_minor(self) -> u16 {
        self.minimum_minor
    }

    /// Returns the highest supported minor version.
    #[must_use]
    pub const fn maximum_minor(self) -> u16 {
        self.maximum_minor
    }

    fn contains(self, version: BrokerProtocolVersion) -> bool {
        self.major == version.major
            && self.minimum_minor <= version.minor
            && version.minor <= self.maximum_minor
    }

    fn highest_compatible(
        self,
        server_current: BrokerProtocolVersion,
    ) -> Option<BrokerProtocolVersion> {
        if self.major != server_current.major || self.minimum_minor > server_current.minor {
            return None;
        }
        Some(BrokerProtocolVersion {
            major: self.major,
            minor: self.maximum_minor.min(server_current.minor),
        })
    }
}

/// Sanitized validation failure for typed protocol input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerProtocolValidationError {
    /// A protocol version or range is structurally invalid.
    InvalidProtocolVersion,
    /// A capability list is empty, duplicated, unknown, or otherwise invalid.
    InvalidCapabilities,
    /// A request cannot be represented by the current protocol.
    InvalidRequest,
}

impl Display for BrokerProtocolValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::InvalidProtocolVersion => "invalid protocol version",
            Self::InvalidCapabilities => "invalid capability advertisement",
            Self::InvalidRequest => "invalid Broker request",
        };
        formatter.write_str(label)
    }
}

impl std::error::Error for BrokerProtocolValidationError {}

/// Capability versions advertised by one side of protocol negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerCapabilityVersions {
    capability_name: CapabilityName,
    versions: BTreeSet<u16>,
}

impl BrokerCapabilityVersions {
    /// Creates a validated, canonical capability-version set.
    pub fn new(
        capability_name: CapabilityName,
        versions: impl IntoIterator<Item = u16>,
    ) -> Result<Self, BrokerProtocolValidationError> {
        let versions = versions.into_iter().collect::<Vec<_>>();
        let canonical_versions = versions.iter().copied().collect::<BTreeSet<_>>();
        if versions.is_empty()
            || versions.len() > MAX_CAPABILITY_VERSIONS
            || canonical_versions.len() != versions.len()
            || canonical_versions.contains(&0)
        {
            return Err(BrokerProtocolValidationError::InvalidCapabilities);
        }
        Ok(Self {
            capability_name,
            versions: canonical_versions,
        })
    }

    /// Returns the capability name.
    #[must_use]
    pub const fn capability_name(&self) -> CapabilityName {
        self.capability_name
    }

    /// Returns supported versions in ascending canonical order.
    pub fn versions(&self) -> impl ExactSizeIterator<Item = u16> + '_ {
        self.versions.iter().copied()
    }
}

/// Server-side set of implemented capability versions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BrokerCapabilitySet {
    entries: BTreeMap<CapabilityName, BTreeSet<u16>>,
}

impl BrokerCapabilitySet {
    /// Creates an empty set that advertises no credential capability.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Creates the complete Broker capability set implemented by version 1.
    #[must_use]
    pub fn machine_credential_v1() -> Self {
        let mut capabilities = Self::empty();
        for name in [
            CapabilityName::CredentialSearch,
            CapabilityName::AccessRequest,
            CapabilityName::GrantStatus,
            CapabilityName::GrantRevoke,
            CapabilityName::HttpRequest,
            CapabilityName::ProcessRun,
        ] {
            capabilities.insert(Capability::v1(name));
        }
        capabilities
    }

    /// Inserts one implemented capability version.
    pub fn insert(&mut self, capability: Capability) {
        self.entries
            .entry(capability.name())
            .or_default()
            .insert(capability.version());
    }

    /// Returns whether no credential capability is implemented.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn negotiate(&self, offered: &[BrokerCapabilityVersions]) -> Vec<BrokerNegotiatedCapability> {
        offered
            .iter()
            .filter_map(|offer| {
                let server_versions = self.entries.get(&offer.capability_name)?;
                offer
                    .versions
                    .intersection(server_versions)
                    .max()
                    .copied()
                    .map(|version| BrokerNegotiatedCapability {
                        capability_name: offer.capability_name,
                        version,
                    })
            })
            .collect()
    }
}

/// One capability version selected during `hello`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerNegotiatedCapability {
    capability_name: CapabilityName,
    version: u16,
}

impl BrokerNegotiatedCapability {
    /// Returns the selected capability name.
    #[must_use]
    pub const fn capability_name(self) -> CapabilityName {
        self.capability_name
    }

    /// Returns the selected capability version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }
}

/// Initial protocol negotiation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerHelloRequest {
    protocol_versions: Vec<BrokerProtocolVersionRange>,
    capabilities: Vec<BrokerCapabilityVersions>,
}

impl BrokerHelloRequest {
    /// Creates a bounded, unambiguous protocol advertisement.
    pub fn new(
        protocol_versions: Vec<BrokerProtocolVersionRange>,
        capabilities: Vec<BrokerCapabilityVersions>,
    ) -> Result<Self, BrokerProtocolValidationError> {
        if protocol_versions.is_empty() || protocol_versions.len() > MAX_PROTOCOL_RANGES {
            return Err(BrokerProtocolValidationError::InvalidProtocolVersion);
        }
        let major_count = protocol_versions
            .iter()
            .map(|range| range.major)
            .collect::<BTreeSet<_>>()
            .len();
        if major_count != protocol_versions.len() {
            return Err(BrokerProtocolValidationError::InvalidProtocolVersion);
        }
        if capabilities.len() > MAX_CAPABILITY_OFFERS
            || capabilities
                .iter()
                .map(BrokerCapabilityVersions::capability_name)
                .collect::<BTreeSet<_>>()
                .len()
                != capabilities.len()
        {
            return Err(BrokerProtocolValidationError::InvalidCapabilities);
        }
        Ok(Self {
            protocol_versions,
            capabilities,
        })
    }

    /// Returns advertised protocol ranges.
    #[must_use]
    pub fn protocol_versions(&self) -> &[BrokerProtocolVersionRange] {
        &self.protocol_versions
    }

    /// Returns advertised capability versions.
    #[must_use]
    pub fn capabilities(&self) -> &[BrokerCapabilityVersions] {
        &self.capabilities
    }

    pub(crate) fn negotiate(
        &self,
        supported_capabilities: &BrokerCapabilitySet,
    ) -> Option<BrokerHelloResponse> {
        let selected_protocol = self
            .protocol_versions
            .iter()
            .filter_map(|range| range.highest_compatible(BrokerProtocolVersion::current()))
            .max()?;
        Some(BrokerHelloResponse {
            selected_protocol,
            capabilities: supported_capabilities.negotiate(&self.capabilities),
        })
    }
}

/// Starts or resumes pairing for one locally held Ed25519 identity.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingStartRequest {
    pairing_public_key: [u8; PAIRING_PUBLIC_KEY_LENGTH],
    client_nonce: [u8; PAIRING_NONCE_LENGTH],
}

impl BrokerPairingStartRequest {
    /// Creates a bounded pairing start request.
    #[must_use]
    pub const fn new(
        pairing_public_key: [u8; PAIRING_PUBLIC_KEY_LENGTH],
        client_nonce: [u8; PAIRING_NONCE_LENGTH],
    ) -> Self {
        Self {
            pairing_public_key,
            client_nonce,
        }
    }

    /// Returns the proposed Consumer public key.
    #[must_use]
    pub const fn pairing_public_key(&self) -> &[u8; PAIRING_PUBLIC_KEY_LENGTH] {
        &self.pairing_public_key
    }

    /// Returns the fresh Consumer pairing nonce.
    #[must_use]
    pub const fn client_nonce(&self) -> &[u8; PAIRING_NONCE_LENGTH] {
        &self.client_nonce
    }
}

impl Debug for BrokerPairingStartRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingStartRequest")
            .field("pairing_public_key", &"<redacted>")
            .field("client_nonce", &"<redacted>")
            .finish()
    }
}

/// Polls a pending pairing without exposing human-control-plane metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingStatusRequest {
    pairing_request_id: PairingRequestId,
    pairing_public_key: [u8; PAIRING_PUBLIC_KEY_LENGTH],
}

impl BrokerPairingStatusRequest {
    /// Creates a status request bound to the exact pairing public key.
    #[must_use]
    pub const fn new(
        pairing_request_id: PairingRequestId,
        pairing_public_key: [u8; PAIRING_PUBLIC_KEY_LENGTH],
    ) -> Self {
        Self {
            pairing_request_id,
            pairing_public_key,
        }
    }

    /// Returns the pending request identity.
    #[must_use]
    pub const fn pairing_request_id(&self) -> PairingRequestId {
        self.pairing_request_id
    }

    /// Returns the pairing key expected to own the request.
    #[must_use]
    pub const fn pairing_public_key(&self) -> &[u8; PAIRING_PUBLIC_KEY_LENGTH] {
        &self.pairing_public_key
    }
}

impl Debug for BrokerPairingStatusRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingStatusRequest")
            .field("pairing_request_id", &self.pairing_request_id)
            .field("pairing_public_key", &"<redacted>")
            .finish()
    }
}

/// Submits one Ed25519 proof for a locally approved pairing request.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingCompleteRequest {
    pairing_request_id: PairingRequestId,
    proof: [u8; PAIRING_PROOF_LENGTH],
}

impl BrokerPairingCompleteRequest {
    /// Creates a pairing proof request.
    #[must_use]
    pub const fn new(
        pairing_request_id: PairingRequestId,
        proof: [u8; PAIRING_PROOF_LENGTH],
    ) -> Self {
        Self {
            pairing_request_id,
            proof,
        }
    }

    /// Returns the approved pending request identity.
    #[must_use]
    pub const fn pairing_request_id(&self) -> PairingRequestId {
        self.pairing_request_id
    }

    /// Returns the fixed-size Ed25519 proof.
    #[must_use]
    pub const fn proof(&self) -> &[u8; PAIRING_PROOF_LENGTH] {
        &self.proof
    }
}

impl Debug for BrokerPairingCompleteRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingCompleteRequest")
            .field("pairing_request_id", &self.pairing_request_id)
            .field("proof", &"<redacted>")
            .finish()
    }
}

/// Requests a fresh challenge for an already paired Consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAuthenticationStartRequest {
    consumer_id: ConsumerId,
}

impl BrokerAuthenticationStartRequest {
    /// Creates an authentication start request.
    #[must_use]
    pub const fn new(consumer_id: ConsumerId) -> Self {
        Self { consumer_id }
    }

    /// Returns the immutable Consumer identity.
    #[must_use]
    pub const fn consumer_id(self) -> ConsumerId {
        self.consumer_id
    }
}

/// Submits a one-attempt Ed25519 proof for a connection challenge.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerAuthenticationCompleteRequest {
    session_id: BrokerSessionId,
    consumer_id: ConsumerId,
    proof: [u8; AUTHENTICATION_PROOF_LENGTH],
}

impl BrokerAuthenticationCompleteRequest {
    /// Creates an authentication proof request.
    #[must_use]
    pub const fn new(
        session_id: BrokerSessionId,
        consumer_id: ConsumerId,
        proof: [u8; AUTHENTICATION_PROOF_LENGTH],
    ) -> Self {
        Self {
            session_id,
            consumer_id,
            proof,
        }
    }

    /// Returns the challenged session identity.
    #[must_use]
    pub const fn session_id(&self) -> BrokerSessionId {
        self.session_id
    }

    /// Returns the Consumer expected to own the challenged session.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the fixed-size Ed25519 proof.
    #[must_use]
    pub const fn proof(&self) -> &[u8; AUTHENTICATION_PROOF_LENGTH] {
        &self.proof
    }
}

impl Debug for BrokerAuthenticationCompleteRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerAuthenticationCompleteRequest")
            .field("session_id", &self.session_id)
            .field("consumer_id", &self.consumer_id)
            .field("proof", &"<redacted>")
            .finish()
    }
}

/// Supported request bodies in the current dispatcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerRequest {
    /// Starts protocol compatibility negotiation.
    Hello(BrokerHelloRequest),
    /// Requests non-secret Broker process status after negotiation.
    Status,
    /// Starts or resumes device-local Consumer pairing.
    PairingStart(BrokerPairingStartRequest),
    /// Polls one pending pairing request.
    PairingStatus(BrokerPairingStatusRequest),
    /// Completes an approved Consumer pairing.
    PairingComplete(BrokerPairingCompleteRequest),
    /// Requests a fresh paired-Consumer authentication challenge.
    AuthenticationStart(BrokerAuthenticationStartRequest),
    /// Completes paired-Consumer authentication for this connection.
    AuthenticationComplete(BrokerAuthenticationCompleteRequest),
    /// Searches minimum metadata inside one already-authorized exact field scope.
    CredentialSearch(BrokerCredentialSearchRequest),
    /// Creates or coalesces one local access approval request.
    AccessRequest(BrokerAccessRequest),
    /// Returns one authenticated Consumer's Use Grant status.
    GrantStatus(BrokerGrantStatusRequest),
    /// Revokes one authenticated Consumer's Use Grant.
    GrantRevoke(BrokerGrantRevokeRequest),
    /// Executes one authorized HTTPS request inside the Broker.
    HttpRequest(BrokerHttpCapabilityRequest),
    /// Executes one authorized direct child process inside the Broker.
    ProcessRun(BrokerProcessCapabilityRequest),
}

impl BrokerRequest {
    /// Returns the negotiated capability required by a Consumer-scoped request.
    #[must_use]
    pub const fn required_capability(&self) -> Option<Capability> {
        let name = match self {
            Self::CredentialSearch(_) => CapabilityName::CredentialSearch,
            Self::AccessRequest(_) => CapabilityName::AccessRequest,
            Self::GrantStatus(_) => CapabilityName::GrantStatus,
            Self::GrantRevoke(_) => CapabilityName::GrantRevoke,
            Self::HttpRequest(_) => CapabilityName::HttpRequest,
            Self::ProcessRun(_) => CapabilityName::ProcessRun,
            Self::Hello(_)
            | Self::Status
            | Self::PairingStart(_)
            | Self::PairingStatus(_)
            | Self::PairingComplete(_)
            | Self::AuthenticationStart(_)
            | Self::AuthenticationComplete(_) => return None,
        };
        Some(Capability::v1(name))
    }
}

/// One decoded Broker request envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerRequestEnvelope {
    version: BrokerProtocolVersion,
    request_id: BrokerRequestId,
    request: BrokerRequest,
}

impl BrokerRequestEnvelope {
    /// Creates a typed request envelope.
    #[must_use]
    pub const fn new(
        version: BrokerProtocolVersion,
        request_id: BrokerRequestId,
        request: BrokerRequest,
    ) -> Self {
        Self {
            version,
            request_id,
            request,
        }
    }

    /// Returns the envelope protocol version.
    #[must_use]
    pub const fn version(&self) -> BrokerProtocolVersion {
        self.version
    }

    /// Returns the request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> BrokerRequestId {
        self.request_id
    }

    /// Returns the typed request body.
    #[must_use]
    pub const fn request(&self) -> &BrokerRequest {
        &self.request
    }
}

/// Successful `hello` negotiation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerHelloResponse {
    selected_protocol: BrokerProtocolVersion,
    capabilities: Vec<BrokerNegotiatedCapability>,
}

impl BrokerHelloResponse {
    /// Returns the selected protocol version.
    #[must_use]
    pub const fn selected_protocol(&self) -> BrokerProtocolVersion {
        self.selected_protocol
    }

    /// Returns mutually supported capability versions.
    #[must_use]
    pub fn capabilities(&self) -> &[BrokerNegotiatedCapability] {
        &self.capabilities
    }
}

/// Non-secret Broker process status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerStatusResponse {
    broker_instance_id: BrokerInstanceId,
}

impl BrokerStatusResponse {
    /// Creates status for one running process instance.
    #[must_use]
    pub const fn new(broker_instance_id: BrokerInstanceId) -> Self {
        Self { broker_instance_id }
    }

    /// Returns the ephemeral process instance identity.
    #[must_use]
    pub const fn broker_instance_id(self) -> BrokerInstanceId {
        self.broker_instance_id
    }
}

/// Consumer-facing state of an active or pending pairing identity.
#[derive(Clone, Eq, PartialEq)]
pub enum BrokerPairingProgressResponse {
    /// The pairing public key already belongs to an active Consumer.
    Active {
        /// Existing immutable Consumer identity.
        consumer_id: ConsumerId,
    },
    /// The pairing remains process-local and incomplete.
    Pending(BrokerPairingPendingResponse),
}

impl BrokerPairingProgressResponse {
    pub(crate) const fn active(consumer_id: ConsumerId) -> Self {
        Self::Active { consumer_id }
    }

    pub(crate) const fn pending(response: BrokerPairingPendingResponse) -> Self {
        Self::Pending(response)
    }
}

impl Debug for BrokerPairingProgressResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active { consumer_id } => formatter
                .debug_struct("Active")
                .field("consumer_id", consumer_id)
                .finish(),
            Self::Pending(pending) => formatter.debug_tuple("Pending").field(pending).finish(),
        }
    }
}

/// Resumable, non-authorizing state of one pending pairing.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerPairingPendingResponse {
    pairing_request_id: PairingRequestId,
    client_nonce: [u8; PAIRING_NONCE_LENGTH],
    server_nonce: [u8; PAIRING_NONCE_LENGTH],
    comparison_code: PairingComparisonCode,
    consumer_id: Option<ConsumerId>,
    status: BrokerPairingRequestStatus,
    valid_for_seconds: u64,
}

impl BrokerPairingPendingResponse {
    pub(crate) const fn new(
        pairing_request_id: PairingRequestId,
        client_nonce: [u8; PAIRING_NONCE_LENGTH],
        server_nonce: [u8; PAIRING_NONCE_LENGTH],
        comparison_code: PairingComparisonCode,
        consumer_id: Option<ConsumerId>,
        status: BrokerPairingRequestStatus,
        valid_for_seconds: u64,
    ) -> Self {
        Self {
            pairing_request_id,
            client_nonce,
            server_nonce,
            comparison_code,
            consumer_id,
            status,
            valid_for_seconds,
        }
    }

    /// Returns the immutable pending request identity.
    #[must_use]
    pub const fn pairing_request_id(&self) -> PairingRequestId {
        self.pairing_request_id
    }

    /// Returns the original client nonce bound into pairing.
    #[must_use]
    pub const fn client_nonce(&self) -> &[u8; PAIRING_NONCE_LENGTH] {
        &self.client_nonce
    }

    /// Returns the Broker nonce bound into pairing.
    #[must_use]
    pub const fn server_nonce(&self) -> &[u8; PAIRING_NONCE_LENGTH] {
        &self.server_nonce
    }

    /// Returns the human comparison code.
    #[must_use]
    pub const fn comparison_code(&self) -> PairingComparisonCode {
        self.comparison_code
    }

    /// Returns the approved Consumer identity only when proof is required.
    #[must_use]
    pub const fn consumer_id(&self) -> Option<ConsumerId> {
        self.consumer_id
    }

    /// Returns whether local approval or cryptographic proof is next.
    #[must_use]
    pub const fn status(&self) -> BrokerPairingRequestStatus {
        self.status
    }

    /// Returns a bounded remaining-lifetime projection.
    #[must_use]
    pub const fn valid_for_seconds(&self) -> u64 {
        self.valid_for_seconds
    }
}

impl Debug for BrokerPairingPendingResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerPairingPendingResponse")
            .field("pairing_request_id", &self.pairing_request_id)
            .field("client_nonce", &"<redacted>")
            .field("server_nonce", &"<redacted>")
            .field("comparison_code", &self.comparison_code)
            .field("consumer_id", &self.consumer_id)
            .field("status", &self.status)
            .field("valid_for_seconds", &self.valid_for_seconds)
            .finish()
    }
}

/// Result of activating one locally approved Consumer pairing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerPairingCompleteResponse {
    consumer_id: ConsumerId,
}

impl BrokerPairingCompleteResponse {
    pub(crate) const fn new(consumer_id: ConsumerId) -> Self {
        Self { consumer_id }
    }

    /// Returns the active immutable Consumer identity.
    #[must_use]
    pub const fn consumer_id(self) -> ConsumerId {
        self.consumer_id
    }
}

/// Fresh challenge for one paired Consumer connection.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerAuthenticationChallengeResponse {
    session_id: BrokerSessionId,
    consumer_id: ConsumerId,
    broker_nonce: [u8; AUTHENTICATION_NONCE_LENGTH],
    valid_for_seconds: u64,
}

impl BrokerAuthenticationChallengeResponse {
    pub(crate) const fn new(
        session_id: BrokerSessionId,
        consumer_id: ConsumerId,
        broker_nonce: [u8; AUTHENTICATION_NONCE_LENGTH],
        valid_for_seconds: u64,
    ) -> Self {
        Self {
            session_id,
            consumer_id,
            broker_nonce,
            valid_for_seconds,
        }
    }

    /// Returns the prospective connection session identity.
    #[must_use]
    pub const fn session_id(&self) -> BrokerSessionId {
        self.session_id
    }

    /// Returns the paired Consumer being challenged.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the fresh nonce bound into the proof transcript.
    #[must_use]
    pub const fn broker_nonce(&self) -> &[u8; AUTHENTICATION_NONCE_LENGTH] {
        &self.broker_nonce
    }

    /// Returns the fixed remaining lifetime at issue time.
    #[must_use]
    pub const fn valid_for_seconds(&self) -> u64 {
        self.valid_for_seconds
    }
}

impl Debug for BrokerAuthenticationChallengeResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerAuthenticationChallengeResponse")
            .field("session_id", &self.session_id)
            .field("consumer_id", &self.consumer_id)
            .field("broker_nonce", &"<redacted>")
            .field("valid_for_seconds", &self.valid_for_seconds)
            .finish()
    }
}

/// Result of authenticating one paired Consumer connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerAuthenticationResponse {
    session_id: BrokerSessionId,
    consumer_id: ConsumerId,
}

impl BrokerAuthenticationResponse {
    pub(crate) const fn new(session_id: BrokerSessionId, consumer_id: ConsumerId) -> Self {
        Self {
            session_id,
            consumer_id,
        }
    }

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

/// Stable, localizable Broker error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerErrorCode {
    /// Client and Broker have no mutually supported protocol.
    ProtocolIncompatible,
    /// A frame or JSON document is malformed.
    MalformedFrame,
    /// A frame exceeds the global or message-specific bound.
    OversizedFrame,
    /// Consumer authentication failed.
    AuthenticationFailed,
    /// The client has no approved pairing.
    PairingRequired,
    /// Pairing is waiting for a local decision.
    PairingPending,
    /// The Consumer was revoked.
    ConsumerRevoked,
    /// The target vault is locked.
    VaultLocked,
    /// A local approval is required.
    ApprovalRequired,
    /// A local approval remains pending.
    ApprovalPending,
    /// Authorization was denied.
    AccessDenied,
    /// A Use Grant expired.
    GrantExpired,
    /// The requested capability or version is unsupported.
    UnsupportedCapability,
    /// The request violates the current protocol contract.
    InvalidRequest,
    /// Machine access is globally paused.
    BrokerPaused,
    /// A bounded local rate limit was reached.
    RateLimited,
    /// The operation failed without exposing internal details.
    OperationFailed,
}

impl BrokerErrorCode {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolIncompatible => "protocol-incompatible",
            Self::MalformedFrame => "malformed-frame",
            Self::OversizedFrame => "oversized-frame",
            Self::AuthenticationFailed => "authentication-failed",
            Self::PairingRequired => "pairing-required",
            Self::PairingPending => "pairing-pending",
            Self::ConsumerRevoked => "consumer-revoked",
            Self::VaultLocked => "vault-locked",
            Self::ApprovalRequired => "approval-required",
            Self::ApprovalPending => "approval-pending",
            Self::AccessDenied => "access-denied",
            Self::GrantExpired => "grant-expired",
            Self::UnsupportedCapability => "unsupported-capability",
            Self::InvalidRequest => "invalid-request",
            Self::BrokerPaused => "broker-paused",
            Self::RateLimited => "rate-limited",
            Self::OperationFailed => "operation-failed",
        }
    }
}

impl FromStr for BrokerErrorCode {
    type Err = BrokerProtocolValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "protocol-incompatible" => Ok(Self::ProtocolIncompatible),
            "malformed-frame" => Ok(Self::MalformedFrame),
            "oversized-frame" => Ok(Self::OversizedFrame),
            "authentication-failed" => Ok(Self::AuthenticationFailed),
            "pairing-required" => Ok(Self::PairingRequired),
            "pairing-pending" => Ok(Self::PairingPending),
            "consumer-revoked" => Ok(Self::ConsumerRevoked),
            "vault-locked" => Ok(Self::VaultLocked),
            "approval-required" => Ok(Self::ApprovalRequired),
            "approval-pending" => Ok(Self::ApprovalPending),
            "access-denied" => Ok(Self::AccessDenied),
            "grant-expired" => Ok(Self::GrantExpired),
            "unsupported-capability" => Ok(Self::UnsupportedCapability),
            "invalid-request" => Ok(Self::InvalidRequest),
            "broker-paused" => Ok(Self::BrokerPaused),
            "rate-limited" => Ok(Self::RateLimited),
            "operation-failed" => Ok(Self::OperationFailed),
            _ => Err(BrokerProtocolValidationError::InvalidRequest),
        }
    }
}

/// Stable next action associated with a Broker error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerRequiredAction {
    /// Update a component to a compatible protocol.
    UpdateClient,
    /// Start the connection with `hello`.
    SendHello,
    /// Pair this local Consumer.
    PairConsumer,
    /// Wait for the pending pairing decision.
    WaitForPairing,
    /// Unlock the target vault in the human control plane.
    UnlockVault,
    /// Review an approval request.
    ApproveRequest,
    /// Wait for an existing approval decision.
    WaitForApproval,
    /// Retry after a bounded transient failure.
    RetryLater,
}

impl BrokerRequiredAction {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpdateClient => "update-client",
            Self::SendHello => "send-hello",
            Self::PairConsumer => "pair-consumer",
            Self::WaitForPairing => "wait-for-pairing",
            Self::UnlockVault => "unlock-vault",
            Self::ApproveRequest => "approve-request",
            Self::WaitForApproval => "wait-for-approval",
            Self::RetryLater => "retry-later",
        }
    }
}

impl FromStr for BrokerRequiredAction {
    type Err = BrokerProtocolValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "update-client" => Ok(Self::UpdateClient),
            "send-hello" => Ok(Self::SendHello),
            "pair-consumer" => Ok(Self::PairConsumer),
            "wait-for-pairing" => Ok(Self::WaitForPairing),
            "unlock-vault" => Ok(Self::UnlockVault),
            "approve-request" => Ok(Self::ApproveRequest),
            "wait-for-approval" => Ok(Self::WaitForApproval),
            "retry-later" => Ok(Self::RetryLater),
            _ => Err(BrokerProtocolValidationError::InvalidRequest),
        }
    }
}

/// Sanitized error returned over the Broker protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerProtocolError {
    error_code: BrokerErrorCode,
    retryable: bool,
    required_action: Option<BrokerRequiredAction>,
    approval_request_id: Option<ApprovalRequestId>,
}

impl BrokerProtocolError {
    /// Creates an error with no free-form or internal diagnostic text.
    #[must_use]
    pub const fn new(
        error_code: BrokerErrorCode,
        retryable: bool,
        required_action: Option<BrokerRequiredAction>,
        approval_request_id: Option<ApprovalRequestId>,
    ) -> Self {
        Self {
            error_code,
            retryable,
            required_action,
            approval_request_id,
        }
    }

    /// Returns the stable error code.
    #[must_use]
    pub const fn error_code(self) -> BrokerErrorCode {
        self.error_code
    }

    /// Returns whether retrying without a user action may succeed.
    #[must_use]
    pub const fn retryable(self) -> bool {
        self.retryable
    }

    /// Returns the optional localizable next action.
    #[must_use]
    pub const fn required_action(self) -> Option<BrokerRequiredAction> {
        self.required_action
    }

    /// Returns the optional asynchronous approval identity.
    #[must_use]
    pub const fn approval_request_id(self) -> Option<ApprovalRequestId> {
        self.approval_request_id
    }
}

/// Typed Broker response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerResponse {
    /// Successful compatibility negotiation.
    Hello(BrokerHelloResponse),
    /// Successful non-secret process status.
    Status(BrokerStatusResponse),
    /// Active or pending Consumer pairing progress.
    PairingProgress(BrokerPairingProgressResponse),
    /// Successful activation of an approved Consumer pairing.
    PairingComplete(BrokerPairingCompleteResponse),
    /// Fresh challenge for a paired Consumer.
    AuthenticationChallenge(BrokerAuthenticationChallengeResponse),
    /// Successful paired-Consumer connection authentication.
    Authenticated(BrokerAuthenticationResponse),
    /// Minimum metadata from one already-authorized exact field scope.
    CredentialSearch(BrokerCredentialSearchResponse),
    /// Consumer-safe asynchronous access-request receipt.
    AccessRequest(BrokerAccessResponse),
    /// Consumer-safe status of one Use Grant.
    GrantStatus(BrokerGrantStatusResponse),
    /// Result of one Consumer-scoped Use Grant revocation.
    GrantRevoke(BrokerGrantRevokeResponse),
    /// Bounded exact-secret-redacted HTTPS response.
    HttpRequest(BrokerHttpCapabilityResponse),
    /// Bounded exact-secret-redacted direct child-process response.
    ProcessRun(BrokerProcessCapabilityResponse),
    /// Sanitized stable error.
    Error(BrokerProtocolError),
}

/// One decoded Broker response envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerResponseEnvelope {
    version: BrokerProtocolVersion,
    request_id: BrokerRequestId,
    response: BrokerResponse,
}

impl BrokerResponseEnvelope {
    /// Creates a typed response envelope.
    #[must_use]
    pub const fn new(
        version: BrokerProtocolVersion,
        request_id: BrokerRequestId,
        response: BrokerResponse,
    ) -> Self {
        Self {
            version,
            request_id,
            response,
        }
    }

    /// Returns the response protocol version.
    #[must_use]
    pub const fn version(&self) -> BrokerProtocolVersion {
        self.version
    }

    /// Returns the correlated request identity.
    #[must_use]
    pub const fn request_id(&self) -> BrokerRequestId {
        self.request_id
    }

    /// Returns the typed response body.
    #[must_use]
    pub const fn response(&self) -> &BrokerResponse {
        &self.response
    }
}

/// Sanitized request-decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerRequestDecodeError {
    error_code: BrokerErrorCode,
    request_id: Option<BrokerRequestId>,
}

impl BrokerRequestDecodeError {
    /// Returns the stable wire error category.
    #[must_use]
    pub const fn error_code(self) -> BrokerErrorCode {
        self.error_code
    }

    /// Returns a request identity only when it was parsed canonically.
    #[must_use]
    pub const fn request_id(self) -> Option<BrokerRequestId> {
        self.request_id
    }
}

impl Display for BrokerRequestDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Broker request could not be decoded")
    }
}

impl std::error::Error for BrokerRequestDecodeError {}

/// Sanitized response-decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerResponseDecodeError;

impl Display for BrokerResponseDecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Broker response could not be decoded")
    }
}

impl std::error::Error for BrokerResponseDecodeError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelopeWire {
    protocol_name: String,
    protocol_major: u16,
    protocol_minor: u16,
    message_type: String,
    request_id: String,
    body: Value,
    #[serde(default)]
    extensions: Option<Map<String, Value>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolVersionRangeWire {
    major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityVersionsWire {
    capability_name: String,
    versions: Vec<u16>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelloRequestWire {
    protocol_versions: Vec<ProtocolVersionRangeWire>,
    capabilities: Vec<CapabilityVersionsWire>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyBodyWire {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingStartRequestWire {
    pairing_public_key: String,
    client_nonce: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingStatusRequestWire {
    pairing_request_id: String,
    pairing_public_key: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingCompleteRequestWire {
    pairing_request_id: String,
    proof: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationStartRequestWire {
    consumer_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationCompleteRequestWire {
    session_id: String,
    consumer_id: String,
    proof: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialOperationTargetWire {
    use_grant_id: String,
    vault_id: String,
    credential_id: String,
    secret_field_id: String,
    secret_kind: String,
    vault_session_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialSearchRequestWire {
    target: CredentialOperationTargetWire,
    query: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "request_kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AccessRequestWire {
    Exact {
        vault_id: String,
        credential_id: String,
        secret_field_id: String,
        capability_name: String,
        capability_version: u16,
    },
    Credential {
        vault_id: String,
        capability_name: String,
        capability_version: u16,
        description: String,
    },
    Status {
        approval_request_id: String,
    },
    Resume {
        approval_request_id: String,
    },
    Wait {
        approval_request_id: String,
        timeout_millis: u64,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantRequestWire {
    use_grant_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpHeaderWire {
    name: String,
    value: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpRequestWire {
    target: CredentialOperationTargetWire,
    usage_profile_id: String,
    method: String,
    url: String,
    headers: Vec<HttpHeaderWire>,
    body_base64: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessEnvironmentWire {
    name: String,
    value: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessRunRequestWire {
    target: CredentialOperationTargetWire,
    usage_profile_id: String,
    executable: String,
    arguments: Vec<String>,
    working_directory: Option<String>,
    environment: Vec<ProcessEnvironmentWire>,
    timeout_millis: u64,
}

#[derive(Serialize)]
struct RequestOutputWire<'a, T: Serialize> {
    protocol_name: &'static str,
    protocol_major: u16,
    protocol_minor: u16,
    message_type: &'static str,
    request_id: String,
    body: &'a T,
}

/// Encodes one canonical request JSON payload without frame bytes.
pub fn encode_broker_request(
    request: &BrokerRequestEnvelope,
) -> Result<Vec<u8>, BrokerProtocolValidationError> {
    let request_id = request.request_id.to_string();
    let encoded = match &request.request {
        BrokerRequest::Hello(hello) => {
            let body = HelloRequestWire {
                protocol_versions: hello
                    .protocol_versions
                    .iter()
                    .map(|range| ProtocolVersionRangeWire {
                        major: range.major,
                        minimum_minor: range.minimum_minor,
                        maximum_minor: range.maximum_minor,
                    })
                    .collect(),
                capabilities: hello
                    .capabilities
                    .iter()
                    .map(|capability| CapabilityVersionsWire {
                        capability_name: capability.capability_name.as_str().to_owned(),
                        versions: capability.versions().collect(),
                    })
                    .collect(),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "hello",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::Status => serde_json::to_vec(&RequestOutputWire {
            protocol_name: BROKER_PROTOCOL_NAME,
            protocol_major: request.version.major,
            protocol_minor: request.version.minor,
            message_type: "broker.status",
            request_id,
            body: &EmptyBodyWire {},
        }),
        BrokerRequest::PairingStart(pairing) => {
            let body = PairingStartRequestWire {
                pairing_public_key: hex::encode(pairing.pairing_public_key),
                client_nonce: hex::encode(pairing.client_nonce),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "consumer.pair.start",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::PairingStatus(pairing) => {
            let body = PairingStatusRequestWire {
                pairing_request_id: pairing.pairing_request_id.to_string(),
                pairing_public_key: hex::encode(pairing.pairing_public_key),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "consumer.pair.status",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::PairingComplete(pairing) => {
            let body = PairingCompleteRequestWire {
                pairing_request_id: pairing.pairing_request_id.to_string(),
                proof: hex::encode(pairing.proof),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "consumer.pair.complete",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::AuthenticationStart(authentication) => {
            let body = AuthenticationStartRequestWire {
                consumer_id: authentication.consumer_id.to_string(),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "consumer.auth.start",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::AuthenticationComplete(authentication) => {
            let body = AuthenticationCompleteRequestWire {
                session_id: authentication.session_id.to_string(),
                consumer_id: authentication.consumer_id.to_string(),
                proof: hex::encode(authentication.proof),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "consumer.auth.complete",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::CredentialSearch(search) => {
            let body = CredentialSearchRequestWire {
                target: credential_operation_target_wire(search.target()),
                query: search.query().to_owned(),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "credential.search",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::AccessRequest(access) => {
            let body = match access {
                BrokerAccessRequest::Exact {
                    field_scope,
                    capability,
                } => AccessRequestWire::Exact {
                    vault_id: field_scope.vault_id().to_string(),
                    credential_id: field_scope.credential_id().to_string(),
                    secret_field_id: field_scope.secret_field_id().to_string(),
                    capability_name: capability.name().as_str().to_owned(),
                    capability_version: capability.version(),
                },
                BrokerAccessRequest::Credential {
                    vault_id,
                    capability,
                    description,
                } => AccessRequestWire::Credential {
                    vault_id: vault_id.to_string(),
                    capability_name: capability.name().as_str().to_owned(),
                    capability_version: capability.version(),
                    description: description.clone(),
                },
                BrokerAccessRequest::Status {
                    approval_request_id,
                } => AccessRequestWire::Status {
                    approval_request_id: approval_request_id.to_string(),
                },
                BrokerAccessRequest::Resume {
                    approval_request_id,
                } => AccessRequestWire::Resume {
                    approval_request_id: approval_request_id.to_string(),
                },
                BrokerAccessRequest::Wait {
                    approval_request_id,
                    timeout,
                } => AccessRequestWire::Wait {
                    approval_request_id: approval_request_id.to_string(),
                    timeout_millis: u64::try_from(timeout.as_millis())
                        .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?,
                },
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "access.request",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::GrantStatus(status) => {
            let body = GrantRequestWire {
                use_grant_id: status.use_grant_id().to_string(),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "grant.status",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::GrantRevoke(revoke) => {
            let body = GrantRequestWire {
                use_grant_id: revoke.use_grant_id().to_string(),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "grant.revoke",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::HttpRequest(http) => {
            let body = HttpRequestWire {
                target: credential_operation_target_wire(http.target()),
                usage_profile_id: http.usage_profile_id().to_string(),
                method: http.method().as_str().to_owned(),
                url: http.url().to_owned(),
                headers: http
                    .headers()
                    .iter()
                    .map(|header| HttpHeaderWire {
                        name: header.name().to_owned(),
                        value: header.value().to_owned(),
                    })
                    .collect(),
                body_base64: BASE64_STANDARD.encode(http.body()),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "http.request",
                request_id,
                body: &body,
            })
        }
        BrokerRequest::ProcessRun(process) => {
            let body = ProcessRunRequestWire {
                target: credential_operation_target_wire(process.target()),
                usage_profile_id: process.usage_profile_id().to_string(),
                executable: process.executable().to_owned(),
                arguments: process.arguments().to_vec(),
                working_directory: process.working_directory().map(str::to_owned),
                environment: process
                    .environment()
                    .iter()
                    .map(|entry| ProcessEnvironmentWire {
                        name: entry.name().to_owned(),
                        value: entry.value().to_owned(),
                    })
                    .collect(),
                timeout_millis: process.timeout_millis(),
            };
            serde_json::to_vec(&RequestOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: request.version.major,
                protocol_minor: request.version.minor,
                message_type: "process.run",
                request_id,
                body: &body,
            })
        }
    }
    .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?;

    if encoded.len() > MAX_BROKER_FRAME_LENGTH {
        return Err(BrokerProtocolValidationError::InvalidRequest);
    }
    Ok(encoded)
}

fn credential_operation_target_wire(
    target: BrokerCredentialOperationTarget,
) -> CredentialOperationTargetWire {
    let field_scope = target.field_scope();
    CredentialOperationTargetWire {
        use_grant_id: target.use_grant_id().to_string(),
        vault_id: field_scope.vault_id().to_string(),
        credential_id: field_scope.credential_id().to_string(),
        secret_field_id: field_scope.secret_field_id().to_string(),
        secret_kind: target.secret_kind().as_str().to_owned(),
        vault_session_id: target.vault_session_id().to_string(),
    }
}

/// Decodes one strict request JSON payload without retaining source text.
pub fn decode_broker_request(
    payload: &[u8],
) -> Result<BrokerRequestEnvelope, BrokerRequestDecodeError> {
    let value = parse_unique_json(payload).map_err(|_| BrokerRequestDecodeError {
        error_code: BrokerErrorCode::MalformedFrame,
        request_id: None,
    })?;
    let wire: RequestEnvelopeWire =
        serde_json::from_value(value).map_err(|_| BrokerRequestDecodeError {
            error_code: BrokerErrorCode::InvalidRequest,
            request_id: None,
        })?;
    let request_id =
        BrokerRequestId::from_str(&wire.request_id).map_err(|_| BrokerRequestDecodeError {
            error_code: BrokerErrorCode::InvalidRequest,
            request_id: None,
        })?;

    if wire.protocol_name != BROKER_PROTOCOL_NAME {
        return Err(BrokerRequestDecodeError {
            error_code: BrokerErrorCode::ProtocolIncompatible,
            request_id: Some(request_id),
        });
    }
    let version =
        BrokerProtocolVersion::new(wire.protocol_major, wire.protocol_minor).map_err(|_| {
            BrokerRequestDecodeError {
                error_code: BrokerErrorCode::ProtocolIncompatible,
                request_id: Some(request_id),
            }
        })?;

    let request = match wire.message_type.as_str() {
        "hello" => {
            if payload.len() > MAX_BROKER_HELLO_LENGTH {
                return Err(BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::OversizedFrame,
                    request_id: Some(request_id),
                });
            }
            let body: HelloRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            let ranges = body
                .protocol_versions
                .into_iter()
                .map(|range| {
                    BrokerProtocolVersionRange::new(
                        range.major,
                        range.minimum_minor,
                        range.maximum_minor,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            let capabilities = body
                .capabilities
                .into_iter()
                .map(|capability| {
                    let capability_name = CapabilityName::from_str(&capability.capability_name)
                        .map_err(|_| BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::UnsupportedCapability,
                            request_id: Some(request_id),
                        })?;
                    BrokerCapabilityVersions::new(capability_name, capability.versions).map_err(
                        |_| BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let hello = BrokerHelloRequest::new(ranges, capabilities).map_err(|error| {
                BrokerRequestDecodeError {
                    error_code: match error {
                        BrokerProtocolValidationError::InvalidCapabilities => {
                            BrokerErrorCode::InvalidRequest
                        }
                        BrokerProtocolValidationError::InvalidProtocolVersion
                        | BrokerProtocolValidationError::InvalidRequest => {
                            BrokerErrorCode::InvalidRequest
                        }
                    },
                    request_id: Some(request_id),
                }
            })?;
            if !hello
                .protocol_versions
                .iter()
                .any(|range| range.contains(version))
            {
                return Err(BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                });
            }
            BrokerRequest::Hello(hello)
        }
        "broker.status" => {
            serde_json::from_value::<EmptyBodyWire>(wire.body).map_err(|_| {
                BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                }
            })?;
            BrokerRequest::Status
        }
        "consumer.pair.start" => {
            let body: PairingStartRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::PairingStart(BrokerPairingStartRequest::new(
                decode_fixed_hex(&body.pairing_public_key).map_err(|_| {
                    BrokerRequestDecodeError {
                        error_code: BrokerErrorCode::InvalidRequest,
                        request_id: Some(request_id),
                    }
                })?,
                decode_fixed_hex(&body.client_nonce).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            ))
        }
        "consumer.pair.status" => {
            let body: PairingStatusRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::PairingStatus(BrokerPairingStatusRequest::new(
                PairingRequestId::from_str(&body.pairing_request_id).map_err(|_| {
                    BrokerRequestDecodeError {
                        error_code: BrokerErrorCode::InvalidRequest,
                        request_id: Some(request_id),
                    }
                })?,
                decode_fixed_hex(&body.pairing_public_key).map_err(|_| {
                    BrokerRequestDecodeError {
                        error_code: BrokerErrorCode::InvalidRequest,
                        request_id: Some(request_id),
                    }
                })?,
            ))
        }
        "consumer.pair.complete" => {
            let body: PairingCompleteRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::PairingComplete(BrokerPairingCompleteRequest::new(
                PairingRequestId::from_str(&body.pairing_request_id).map_err(|_| {
                    BrokerRequestDecodeError {
                        error_code: BrokerErrorCode::InvalidRequest,
                        request_id: Some(request_id),
                    }
                })?,
                decode_fixed_hex(&body.proof).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            ))
        }
        "consumer.auth.start" => {
            let body: AuthenticationStartRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::AuthenticationStart(BrokerAuthenticationStartRequest::new(
                ConsumerId::from_str(&body.consumer_id).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            ))
        }
        "consumer.auth.complete" => {
            let body: AuthenticationCompleteRequestWire = serde_json::from_value(wire.body)
                .map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::AuthenticationComplete(BrokerAuthenticationCompleteRequest::new(
                BrokerSessionId::from_str(&body.session_id).map_err(|_| {
                    BrokerRequestDecodeError {
                        error_code: BrokerErrorCode::InvalidRequest,
                        request_id: Some(request_id),
                    }
                })?,
                ConsumerId::from_str(&body.consumer_id).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
                decode_fixed_hex(&body.proof).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            ))
        }
        "credential.search" => {
            let body: CredentialSearchRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::CredentialSearch(
                BrokerCredentialSearchRequest::new(
                    decode_credential_operation_target(body.target).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                    body.query,
                )
                .map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            )
        }
        "access.request" => {
            let body: AccessRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            let access = match body {
                AccessRequestWire::Exact {
                    vault_id,
                    credential_id,
                    secret_field_id,
                    capability_name,
                    capability_version,
                } => BrokerAccessRequest::exact(
                    CredentialFieldScope::new(
                        VaultId::from_str(&vault_id).map_err(|_| BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        })?,
                        CredentialId::from_str(&credential_id).map_err(|_| {
                            BrokerRequestDecodeError {
                                error_code: BrokerErrorCode::InvalidRequest,
                                request_id: Some(request_id),
                            }
                        })?,
                        SecretFieldId::from_str(&secret_field_id).map_err(|_| {
                            BrokerRequestDecodeError {
                                error_code: BrokerErrorCode::InvalidRequest,
                                request_id: Some(request_id),
                            }
                        })?,
                    ),
                    decode_capability(&capability_name, capability_version).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::UnsupportedCapability,
                            request_id: Some(request_id),
                        }
                    })?,
                ),
                AccessRequestWire::Credential {
                    vault_id,
                    capability_name,
                    capability_version,
                    description,
                } => BrokerAccessRequest::credential(
                    VaultId::from_str(&vault_id).map_err(|_| BrokerRequestDecodeError {
                        error_code: BrokerErrorCode::InvalidRequest,
                        request_id: Some(request_id),
                    })?,
                    decode_capability(&capability_name, capability_version).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::UnsupportedCapability,
                            request_id: Some(request_id),
                        }
                    })?,
                    description,
                ),
                AccessRequestWire::Status {
                    approval_request_id,
                } => Ok(BrokerAccessRequest::status(
                    ApprovalRequestId::from_str(&approval_request_id).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                )),
                AccessRequestWire::Resume {
                    approval_request_id,
                } => Ok(BrokerAccessRequest::resume(
                    ApprovalRequestId::from_str(&approval_request_id).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                )),
                AccessRequestWire::Wait {
                    approval_request_id,
                    timeout_millis,
                } => BrokerAccessRequest::wait(
                    ApprovalRequestId::from_str(&approval_request_id).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                    Duration::from_millis(timeout_millis),
                ),
            }
            .map_err(|_| BrokerRequestDecodeError {
                error_code: BrokerErrorCode::InvalidRequest,
                request_id: Some(request_id),
            })?;
            BrokerRequest::AccessRequest(access)
        }
        "grant.status" => {
            let body: GrantRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::GrantStatus(BrokerGrantStatusRequest::new(
                UseGrantId::from_str(&body.use_grant_id).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            ))
        }
        "grant.revoke" => {
            let body: GrantRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::GrantRevoke(BrokerGrantRevokeRequest::new(
                UseGrantId::from_str(&body.use_grant_id).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            ))
        }
        "http.request" => {
            let body: HttpRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            let headers = body
                .headers
                .into_iter()
                .map(|header| BrokerHttpCapabilityHeader::new(header.name, header.value))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::HttpRequest(
                BrokerHttpCapabilityRequest::new(
                    decode_credential_operation_target(body.target).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                    UsageProfileId::from_str(&body.usage_profile_id).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                    decode_http_method(&body.method).map_err(|_| BrokerRequestDecodeError {
                        error_code: BrokerErrorCode::InvalidRequest,
                        request_id: Some(request_id),
                    })?,
                    body.url,
                    headers,
                    BASE64_STANDARD.decode(body.body_base64).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                )
                .map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            )
        }
        "process.run" => {
            let body: ProcessRunRequestWire =
                serde_json::from_value(wire.body).map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            let environment = body
                .environment
                .into_iter()
                .map(|entry| BrokerProcessCapabilityEnvironment::new(entry.name, entry.value))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?;
            BrokerRequest::ProcessRun(
                BrokerProcessCapabilityRequest::new(
                    decode_credential_operation_target(body.target).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                    UsageProfileId::from_str(&body.usage_profile_id).map_err(|_| {
                        BrokerRequestDecodeError {
                            error_code: BrokerErrorCode::InvalidRequest,
                            request_id: Some(request_id),
                        }
                    })?,
                    body.executable,
                    body.arguments,
                    body.working_directory,
                    environment,
                    body.timeout_millis,
                )
                .map_err(|_| BrokerRequestDecodeError {
                    error_code: BrokerErrorCode::InvalidRequest,
                    request_id: Some(request_id),
                })?,
            )
        }
        _ => {
            return Err(BrokerRequestDecodeError {
                error_code: BrokerErrorCode::InvalidRequest,
                request_id: Some(request_id),
            });
        }
    };
    drop(wire.extensions);

    Ok(BrokerRequestEnvelope {
        version,
        request_id,
        request,
    })
}

fn decode_credential_operation_target(
    target: CredentialOperationTargetWire,
) -> Result<BrokerCredentialOperationTarget, BrokerProtocolValidationError> {
    Ok(BrokerCredentialOperationTarget::new(
        UseGrantId::from_str(&target.use_grant_id)
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?,
        CredentialFieldScope::new(
            VaultId::from_str(&target.vault_id)
                .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?,
            CredentialId::from_str(&target.credential_id)
                .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?,
            SecretFieldId::from_str(&target.secret_field_id)
                .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?,
        ),
        SecretFieldKind::from_str(&target.secret_kind)
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?,
        VaultSessionId::from_str(&target.vault_session_id)
            .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?,
    ))
}

fn decode_capability(
    name: &str,
    version: u16,
) -> Result<Capability, BrokerProtocolValidationError> {
    let name = CapabilityName::from_str(name)
        .map_err(|_| BrokerProtocolValidationError::InvalidCapabilities)?;
    Capability::new(name, version).map_err(|_| BrokerProtocolValidationError::InvalidCapabilities)
}

fn decode_http_method(method: &str) -> Result<BrokerHttpMethod, BrokerProtocolValidationError> {
    match method {
        "GET" => Ok(BrokerHttpMethod::Get),
        "HEAD" => Ok(BrokerHttpMethod::Head),
        "POST" => Ok(BrokerHttpMethod::Post),
        "PUT" => Ok(BrokerHttpMethod::Put),
        "PATCH" => Ok(BrokerHttpMethod::Patch),
        "DELETE" => Ok(BrokerHttpMethod::Delete),
        _ => Err(BrokerProtocolValidationError::InvalidRequest),
    }
}

#[derive(Serialize)]
struct ResponseOutputWire<'a, T: Serialize> {
    protocol_name: &'static str,
    protocol_major: u16,
    protocol_minor: u16,
    message_type: &'static str,
    request_id: String,
    result: &'a T,
}

#[derive(Serialize)]
struct ErrorResponseOutputWire<'a> {
    protocol_name: &'static str,
    protocol_major: u16,
    protocol_minor: u16,
    message_type: &'static str,
    request_id: String,
    error: &'a ErrorBodyWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NegotiatedCapabilityWire {
    capability_name: String,
    version: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelloResponseWire {
    selected_protocol: ProtocolVersionWire,
    capabilities: Vec<NegotiatedCapabilityWire>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolVersionWire {
    major: u16,
    minor: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusResponseWire {
    broker_instance_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", deny_unknown_fields)]
enum PairingProgressWire {
    #[serde(rename = "active")]
    Active { consumer_id: String },
    #[serde(rename = "awaiting-user-approval")]
    AwaitingUserApproval {
        pairing_request_id: String,
        client_nonce: String,
        server_nonce: String,
        comparison_code: String,
        valid_for_seconds: u64,
    },
    #[serde(rename = "awaiting-proof")]
    AwaitingProof {
        pairing_request_id: String,
        client_nonce: String,
        server_nonce: String,
        comparison_code: String,
        consumer_id: String,
        valid_for_seconds: u64,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairingCompleteResponseWire {
    consumer_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationChallengeResponseWire {
    session_id: String,
    consumer_id: String,
    broker_nonce: String,
    valid_for_seconds: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationResponseWire {
    session_id: String,
    consumer_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialFieldMetadataResponseWire {
    secret_field_id: String,
    role: String,
    label: Option<String>,
    kind: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialMetadataResponseWire {
    vault_id: String,
    credential_id: String,
    title: String,
    authorized_field: CredentialFieldMetadataResponseWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialSearchResponseWire {
    credential: Option<CredentialMetadataResponseWire>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result_kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AccessResponseWire {
    Submission {
        approval_request_id: String,
        status: String,
        expires_at_millis: i64,
        resolved_at_millis: Option<i64>,
        coalesced: bool,
    },
    Status {
        approval_request_id: String,
        status: String,
        expires_at_millis: i64,
        resolved_at_millis: Option<i64>,
    },
    Resume {
        approval_request_id: String,
        status: String,
        expires_at_millis: i64,
        resolved_at_millis: Option<i64>,
    },
    Wait {
        approval_request_id: String,
        status: String,
        expires_at_millis: i64,
        resolved_at_millis: Option<i64>,
        timed_out: bool,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveGrantResponseWire {
    use_grant_id: String,
    vault_id: String,
    credential_id: String,
    secret_field_id: String,
    capability_name: String,
    capability_version: u16,
    vault_session_id: String,
    scope: String,
    created_at_millis: i64,
    expires_at_millis: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantStatusResponseWire {
    status: String,
    active_grant: Option<ActiveGrantResponseWire>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantRevokeResponseWire {
    revoked: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpResponseWire {
    status_code: u16,
    body_base64: String,
    truncated: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessRunResponseWire {
    exit_code: Option<i32>,
    terminated_by_signal: bool,
    stdout_base64: String,
    stderr_base64: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ErrorBodyWire {
    error_code: String,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_request_id: Option<String>,
}

/// Encodes one canonical response JSON payload without frame bytes.
pub fn encode_broker_response(
    response: &BrokerResponseEnvelope,
) -> Result<Vec<u8>, BrokerProtocolValidationError> {
    let request_id = response.request_id.to_string();
    let encoded = match &response.response {
        BrokerResponse::Hello(hello) => {
            let result = HelloResponseWire {
                selected_protocol: ProtocolVersionWire {
                    major: hello.selected_protocol.major,
                    minor: hello.selected_protocol.minor,
                },
                capabilities: hello
                    .capabilities
                    .iter()
                    .map(|capability| NegotiatedCapabilityWire {
                        capability_name: capability.capability_name.as_str().to_owned(),
                        version: capability.version,
                    })
                    .collect(),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "hello.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::Status(status) => {
            let result = StatusResponseWire {
                broker_instance_id: status.broker_instance_id.to_string(),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "broker.status.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::PairingProgress(progress) => {
            let result = match progress {
                BrokerPairingProgressResponse::Active { consumer_id } => {
                    PairingProgressWire::Active {
                        consumer_id: consumer_id.to_string(),
                    }
                }
                BrokerPairingProgressResponse::Pending(pending) => {
                    let pairing_request_id = pending.pairing_request_id.to_string();
                    let client_nonce = hex::encode(pending.client_nonce);
                    let server_nonce = hex::encode(pending.server_nonce);
                    let comparison_code = pending.comparison_code.to_string();
                    match pending.status {
                        BrokerPairingRequestStatus::AwaitingUserApproval => {
                            PairingProgressWire::AwaitingUserApproval {
                                pairing_request_id,
                                client_nonce,
                                server_nonce,
                                comparison_code,
                                valid_for_seconds: pending.valid_for_seconds,
                            }
                        }
                        BrokerPairingRequestStatus::AwaitingProof => {
                            let consumer_id = pending
                                .consumer_id
                                .ok_or(BrokerProtocolValidationError::InvalidRequest)?;
                            PairingProgressWire::AwaitingProof {
                                pairing_request_id,
                                client_nonce,
                                server_nonce,
                                comparison_code,
                                consumer_id: consumer_id.to_string(),
                                valid_for_seconds: pending.valid_for_seconds,
                            }
                        }
                    }
                }
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "consumer.pair.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::PairingComplete(completion) => {
            let result = PairingCompleteResponseWire {
                consumer_id: completion.consumer_id.to_string(),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "consumer.pair.complete.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::AuthenticationChallenge(challenge) => {
            let result = AuthenticationChallengeResponseWire {
                session_id: challenge.session_id.to_string(),
                consumer_id: challenge.consumer_id.to_string(),
                broker_nonce: hex::encode(challenge.broker_nonce),
                valid_for_seconds: challenge.valid_for_seconds,
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "consumer.auth.challenge",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::Authenticated(authentication) => {
            let result = AuthenticationResponseWire {
                session_id: authentication.session_id.to_string(),
                consumer_id: authentication.consumer_id.to_string(),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "consumer.auth.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::CredentialSearch(search) => {
            let result = CredentialSearchResponseWire {
                credential: search.credential().map(credential_metadata_response_wire),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "credential.search.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::AccessRequest(access) => {
            let result = match access {
                BrokerAccessResponse::Submission(submission) => AccessResponseWire::Submission {
                    approval_request_id: submission.approval_request_id().to_string(),
                    status: submission.status().as_str().to_owned(),
                    expires_at_millis: submission.expires_at().unix_millis(),
                    resolved_at_millis: submission.resolved_at().map(StateTimestamp::unix_millis),
                    coalesced: submission.coalesced(),
                },
                BrokerAccessResponse::Status(receipt) => AccessResponseWire::Status {
                    approval_request_id: receipt.approval_request_id().to_string(),
                    status: receipt.status().as_str().to_owned(),
                    expires_at_millis: receipt.expires_at().unix_millis(),
                    resolved_at_millis: receipt.resolved_at().map(StateTimestamp::unix_millis),
                },
                BrokerAccessResponse::Resume(receipt) => AccessResponseWire::Resume {
                    approval_request_id: receipt.approval_request_id().to_string(),
                    status: receipt.status().as_str().to_owned(),
                    expires_at_millis: receipt.expires_at().unix_millis(),
                    resolved_at_millis: receipt.resolved_at().map(StateTimestamp::unix_millis),
                },
                BrokerAccessResponse::Wait(wait) => {
                    let receipt = wait.receipt();
                    AccessResponseWire::Wait {
                        approval_request_id: receipt.approval_request_id().to_string(),
                        status: receipt.status().as_str().to_owned(),
                        expires_at_millis: receipt.expires_at().unix_millis(),
                        resolved_at_millis: receipt.resolved_at().map(StateTimestamp::unix_millis),
                        timed_out: wait.timed_out(),
                    }
                }
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "access.request.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::GrantStatus(status) => {
            let result = GrantStatusResponseWire {
                status: status.status().as_str().to_owned(),
                active_grant: status.active_grant().map(active_grant_response_wire),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "grant.status.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::GrantRevoke(revoke) => {
            let result = GrantRevokeResponseWire {
                revoked: revoke.revoked(),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "grant.revoke.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::HttpRequest(http) => {
            let result = HttpResponseWire {
                status_code: http.status_code(),
                body_base64: BASE64_STANDARD.encode(http.body()),
                truncated: http.truncated(),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "http.request.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::ProcessRun(process) => {
            let result = ProcessRunResponseWire {
                exit_code: process.exit_code(),
                terminated_by_signal: process.terminated_by_signal(),
                stdout_base64: BASE64_STANDARD.encode(process.stdout()),
                stderr_base64: BASE64_STANDARD.encode(process.stderr()),
                stdout_truncated: process.stdout_truncated(),
                stderr_truncated: process.stderr_truncated(),
            };
            serde_json::to_vec(&ResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "process.run.result",
                request_id,
                result: &result,
            })
        }
        BrokerResponse::Error(error) => {
            let body = ErrorBodyWire {
                error_code: error.error_code.as_str().to_owned(),
                retryable: error.retryable,
                required_action: error
                    .required_action
                    .map(|action| action.as_str().to_owned()),
                approval_request_id: error
                    .approval_request_id
                    .map(|approval_id| approval_id.to_string()),
            };
            serde_json::to_vec(&ErrorResponseOutputWire {
                protocol_name: BROKER_PROTOCOL_NAME,
                protocol_major: response.version.major,
                protocol_minor: response.version.minor,
                message_type: "error",
                request_id,
                error: &body,
            })
        }
    }
    .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?;

    if encoded.len() > MAX_BROKER_FRAME_LENGTH {
        return Err(BrokerProtocolValidationError::InvalidRequest);
    }
    Ok(encoded)
}

fn credential_metadata_response_wire(
    metadata: &BrokerCredentialMetadataResponse,
) -> CredentialMetadataResponseWire {
    CredentialMetadataResponseWire {
        vault_id: metadata.vault_id().to_string(),
        credential_id: metadata.credential_id().to_string(),
        title: metadata.title().to_owned(),
        authorized_field: CredentialFieldMetadataResponseWire {
            secret_field_id: metadata.secret_field_id().to_string(),
            role: metadata.role().to_owned(),
            label: metadata.label().map(str::to_owned),
            kind: metadata.kind().as_str().to_owned(),
        },
    }
}

fn active_grant_response_wire(grant: BrokerActiveGrantMetadata) -> ActiveGrantResponseWire {
    let field_scope = grant.field_scope();
    ActiveGrantResponseWire {
        use_grant_id: grant.use_grant_id().to_string(),
        vault_id: field_scope.vault_id().to_string(),
        credential_id: field_scope.credential_id().to_string(),
        secret_field_id: field_scope.secret_field_id().to_string(),
        capability_name: grant.capability().name().as_str().to_owned(),
        capability_version: grant.capability().version(),
        vault_session_id: grant.vault_session_id().to_string(),
        scope: grant.scope().as_str().to_owned(),
        created_at_millis: grant.created_at().unix_millis(),
        expires_at_millis: grant.expires_at().unix_millis(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelopeWire {
    protocol_name: String,
    protocol_major: u16,
    protocol_minor: u16,
    message_type: String,
    request_id: String,
    result: Option<Value>,
    error: Option<Value>,
    #[serde(default)]
    extensions: Option<Map<String, Value>>,
}

/// Decodes one strict response JSON payload for future local adapters.
pub fn decode_broker_response(
    payload: &[u8],
) -> Result<BrokerResponseEnvelope, BrokerResponseDecodeError> {
    let value = parse_unique_json(payload).map_err(|_| BrokerResponseDecodeError)?;
    let wire: ResponseEnvelopeWire =
        serde_json::from_value(value).map_err(|_| BrokerResponseDecodeError)?;
    if wire.protocol_name != BROKER_PROTOCOL_NAME {
        return Err(BrokerResponseDecodeError);
    }
    let version = BrokerProtocolVersion::new(wire.protocol_major, wire.protocol_minor)
        .map_err(|_| BrokerResponseDecodeError)?;
    let request_id =
        BrokerRequestId::from_str(&wire.request_id).map_err(|_| BrokerResponseDecodeError)?;
    let response = match wire.message_type.as_str() {
        "hello.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: HelloResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            let selected_protocol = BrokerProtocolVersion::new(
                result.selected_protocol.major,
                result.selected_protocol.minor,
            )
            .map_err(|_| BrokerResponseDecodeError)?;
            let capabilities = result
                .capabilities
                .into_iter()
                .map(|capability| {
                    let capability_name = CapabilityName::from_str(&capability.capability_name)
                        .map_err(|_| BrokerResponseDecodeError)?;
                    if capability.version == 0 {
                        return Err(BrokerResponseDecodeError);
                    }
                    Ok(BrokerNegotiatedCapability {
                        capability_name,
                        version: capability.version,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if capabilities.len() > MAX_CAPABILITY_OFFERS
                || capabilities
                    .iter()
                    .map(|capability| capability.capability_name)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != capabilities.len()
            {
                return Err(BrokerResponseDecodeError);
            }
            BrokerResponse::Hello(BrokerHelloResponse {
                selected_protocol,
                capabilities,
            })
        }
        "broker.status.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: StatusResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            BrokerResponse::Status(BrokerStatusResponse {
                broker_instance_id: BrokerInstanceId::from_str(&result.broker_instance_id)
                    .map_err(|_| BrokerResponseDecodeError)?,
            })
        }
        "consumer.pair.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: PairingProgressWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            let progress = match result {
                PairingProgressWire::Active { consumer_id } => {
                    BrokerPairingProgressResponse::active(
                        ConsumerId::from_str(&consumer_id)
                            .map_err(|_| BrokerResponseDecodeError)?,
                    )
                }
                PairingProgressWire::AwaitingUserApproval {
                    pairing_request_id,
                    client_nonce,
                    server_nonce,
                    comparison_code,
                    valid_for_seconds,
                } => {
                    if valid_for_seconds == 0 {
                        return Err(BrokerResponseDecodeError);
                    }
                    BrokerPairingProgressResponse::pending(BrokerPairingPendingResponse::new(
                        PairingRequestId::from_str(&pairing_request_id)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        decode_fixed_hex(&client_nonce).map_err(|_| BrokerResponseDecodeError)?,
                        decode_fixed_hex(&server_nonce).map_err(|_| BrokerResponseDecodeError)?,
                        PairingComparisonCode::from_ascii(&comparison_code)
                            .ok_or(BrokerResponseDecodeError)?,
                        None,
                        BrokerPairingRequestStatus::AwaitingUserApproval,
                        valid_for_seconds,
                    ))
                }
                PairingProgressWire::AwaitingProof {
                    pairing_request_id,
                    client_nonce,
                    server_nonce,
                    comparison_code,
                    consumer_id,
                    valid_for_seconds,
                } => {
                    if valid_for_seconds == 0 {
                        return Err(BrokerResponseDecodeError);
                    }
                    BrokerPairingProgressResponse::pending(BrokerPairingPendingResponse::new(
                        PairingRequestId::from_str(&pairing_request_id)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        decode_fixed_hex(&client_nonce).map_err(|_| BrokerResponseDecodeError)?,
                        decode_fixed_hex(&server_nonce).map_err(|_| BrokerResponseDecodeError)?,
                        PairingComparisonCode::from_ascii(&comparison_code)
                            .ok_or(BrokerResponseDecodeError)?,
                        Some(
                            ConsumerId::from_str(&consumer_id)
                                .map_err(|_| BrokerResponseDecodeError)?,
                        ),
                        BrokerPairingRequestStatus::AwaitingProof,
                        valid_for_seconds,
                    ))
                }
            };
            BrokerResponse::PairingProgress(progress)
        }
        "consumer.pair.complete.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: PairingCompleteResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            BrokerResponse::PairingComplete(BrokerPairingCompleteResponse::new(
                ConsumerId::from_str(&result.consumer_id).map_err(|_| BrokerResponseDecodeError)?,
            ))
        }
        "consumer.auth.challenge" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: AuthenticationChallengeResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            if result.valid_for_seconds == 0 {
                return Err(BrokerResponseDecodeError);
            }
            BrokerResponse::AuthenticationChallenge(BrokerAuthenticationChallengeResponse::new(
                BrokerSessionId::from_str(&result.session_id)
                    .map_err(|_| BrokerResponseDecodeError)?,
                ConsumerId::from_str(&result.consumer_id).map_err(|_| BrokerResponseDecodeError)?,
                decode_fixed_hex(&result.broker_nonce).map_err(|_| BrokerResponseDecodeError)?,
                result.valid_for_seconds,
            ))
        }
        "consumer.auth.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: AuthenticationResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            BrokerResponse::Authenticated(BrokerAuthenticationResponse::new(
                BrokerSessionId::from_str(&result.session_id)
                    .map_err(|_| BrokerResponseDecodeError)?,
                ConsumerId::from_str(&result.consumer_id).map_err(|_| BrokerResponseDecodeError)?,
            ))
        }
        "credential.search.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: CredentialSearchResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            let credential = result
                .credential
                .map(|metadata| {
                    Ok::<_, BrokerResponseDecodeError>(
                        BrokerCredentialMetadataResponse::from_protocol(
                            VaultId::from_str(&metadata.vault_id)
                                .map_err(|_| BrokerResponseDecodeError)?,
                            CredentialId::from_str(&metadata.credential_id)
                                .map_err(|_| BrokerResponseDecodeError)?,
                            metadata.title,
                            SecretFieldId::from_str(&metadata.authorized_field.secret_field_id)
                                .map_err(|_| BrokerResponseDecodeError)?,
                            metadata.authorized_field.role,
                            metadata.authorized_field.label,
                            SecretFieldKind::from_str(&metadata.authorized_field.kind)
                                .map_err(|_| BrokerResponseDecodeError)?,
                        ),
                    )
                })
                .transpose()?;
            BrokerResponse::CredentialSearch(BrokerCredentialSearchResponse::from_protocol(
                credential,
            ))
        }
        "access.request.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: AccessResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            let access = match result {
                AccessResponseWire::Submission {
                    approval_request_id,
                    status,
                    expires_at_millis,
                    resolved_at_millis,
                    coalesced,
                } => {
                    let (status, resolved_at) = decode_access_status(&status, resolved_at_millis)?;
                    BrokerAccessResponse::Submission(BrokerAccessSubmissionResponse::from_protocol(
                        ApprovalRequestId::from_str(&approval_request_id)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        status,
                        StateTimestamp::from_unix_millis(expires_at_millis)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        resolved_at,
                        coalesced,
                    ))
                }
                AccessResponseWire::Status {
                    approval_request_id,
                    status,
                    expires_at_millis,
                    resolved_at_millis,
                } => BrokerAccessResponse::Status(decode_access_receipt(
                    &approval_request_id,
                    &status,
                    expires_at_millis,
                    resolved_at_millis,
                )?),
                AccessResponseWire::Resume {
                    approval_request_id,
                    status,
                    expires_at_millis,
                    resolved_at_millis,
                } => BrokerAccessResponse::Resume(decode_access_receipt(
                    &approval_request_id,
                    &status,
                    expires_at_millis,
                    resolved_at_millis,
                )?),
                AccessResponseWire::Wait {
                    approval_request_id,
                    status,
                    expires_at_millis,
                    resolved_at_millis,
                    timed_out,
                } => {
                    let receipt = decode_access_receipt(
                        &approval_request_id,
                        &status,
                        expires_at_millis,
                        resolved_at_millis,
                    )?;
                    if (receipt.status() == ApprovalStatus::Pending) != timed_out {
                        return Err(BrokerResponseDecodeError);
                    }
                    BrokerAccessResponse::Wait(BrokerAccessWaitResponse::from_protocol(
                        receipt, timed_out,
                    ))
                }
            };
            BrokerResponse::AccessRequest(access)
        }
        "grant.status.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: GrantStatusResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            let response = match (result.status.as_str(), result.active_grant) {
                ("active", Some(grant)) => {
                    let created_at = StateTimestamp::from_unix_millis(grant.created_at_millis)
                        .map_err(|_| BrokerResponseDecodeError)?;
                    let expires_at = StateTimestamp::from_unix_millis(grant.expires_at_millis)
                        .map_err(|_| BrokerResponseDecodeError)?;
                    if expires_at <= created_at {
                        return Err(BrokerResponseDecodeError);
                    }
                    BrokerGrantStatusResponse::active(BrokerActiveGrantMetadata::from_protocol(
                        UseGrantId::from_str(&grant.use_grant_id)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        CredentialFieldScope::new(
                            VaultId::from_str(&grant.vault_id)
                                .map_err(|_| BrokerResponseDecodeError)?,
                            CredentialId::from_str(&grant.credential_id)
                                .map_err(|_| BrokerResponseDecodeError)?,
                            SecretFieldId::from_str(&grant.secret_field_id)
                                .map_err(|_| BrokerResponseDecodeError)?,
                        ),
                        decode_capability(&grant.capability_name, grant.capability_version)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        VaultSessionId::from_str(&grant.vault_session_id)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        GrantScope::from_str(&grant.scope)
                            .map_err(|_| BrokerResponseDecodeError)?,
                        created_at,
                        expires_at,
                    ))
                }
                ("expired", None) => BrokerGrantStatusResponse::expired(),
                ("unavailable", None) => BrokerGrantStatusResponse::unavailable(),
                _ => return Err(BrokerResponseDecodeError),
            };
            BrokerResponse::GrantStatus(response)
        }
        "grant.revoke.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: GrantRevokeResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            BrokerResponse::GrantRevoke(BrokerGrantRevokeResponse::new(result.revoked))
        }
        "http.request.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: HttpResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            if !(100..=599).contains(&result.status_code) {
                return Err(BrokerResponseDecodeError);
            }
            BrokerResponse::HttpRequest(BrokerHttpCapabilityResponse::from_protocol(
                result.status_code,
                BASE64_STANDARD
                    .decode(result.body_base64)
                    .map_err(|_| BrokerResponseDecodeError)?,
                result.truncated,
            ))
        }
        "process.run.result" => {
            if wire.error.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let result: ProcessRunResponseWire =
                serde_json::from_value(wire.result.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            BrokerResponse::ProcessRun(BrokerProcessCapabilityResponse::from_protocol(
                result.exit_code,
                result.terminated_by_signal,
                BASE64_STANDARD
                    .decode(result.stdout_base64)
                    .map_err(|_| BrokerResponseDecodeError)?,
                BASE64_STANDARD
                    .decode(result.stderr_base64)
                    .map_err(|_| BrokerResponseDecodeError)?,
                result.stdout_truncated,
                result.stderr_truncated,
            ))
        }
        "error" => {
            if wire.result.is_some() {
                return Err(BrokerResponseDecodeError);
            }
            let error: ErrorBodyWire =
                serde_json::from_value(wire.error.ok_or(BrokerResponseDecodeError)?)
                    .map_err(|_| BrokerResponseDecodeError)?;
            BrokerResponse::Error(BrokerProtocolError {
                error_code: BrokerErrorCode::from_str(&error.error_code)
                    .map_err(|_| BrokerResponseDecodeError)?,
                retryable: error.retryable,
                required_action: error
                    .required_action
                    .map(|action| BrokerRequiredAction::from_str(&action))
                    .transpose()
                    .map_err(|_| BrokerResponseDecodeError)?,
                approval_request_id: error
                    .approval_request_id
                    .map(|approval_id| ApprovalRequestId::from_str(&approval_id))
                    .transpose()
                    .map_err(|_| BrokerResponseDecodeError)?,
            })
        }
        _ => return Err(BrokerResponseDecodeError),
    };
    drop(wire.extensions);

    Ok(BrokerResponseEnvelope {
        version,
        request_id,
        response,
    })
}

fn decode_access_status(
    status: &str,
    resolved_at_millis: Option<i64>,
) -> Result<(ApprovalStatus, Option<StateTimestamp>), BrokerResponseDecodeError> {
    let status = ApprovalStatus::from_str(status).map_err(|_| BrokerResponseDecodeError)?;
    let resolved_at = resolved_at_millis
        .map(StateTimestamp::from_unix_millis)
        .transpose()
        .map_err(|_| BrokerResponseDecodeError)?;
    if (status == ApprovalStatus::Pending) != resolved_at.is_none() {
        return Err(BrokerResponseDecodeError);
    }
    Ok((status, resolved_at))
}

fn decode_access_receipt(
    approval_request_id: &str,
    status: &str,
    expires_at_millis: i64,
    resolved_at_millis: Option<i64>,
) -> Result<BrokerAccessReceiptResponse, BrokerResponseDecodeError> {
    let (status, resolved_at) = decode_access_status(status, resolved_at_millis)?;
    Ok(BrokerAccessReceiptResponse::from_protocol(
        ApprovalRequestId::from_str(approval_request_id).map_err(|_| BrokerResponseDecodeError)?,
        status,
        StateTimestamp::from_unix_millis(expires_at_millis)
            .map_err(|_| BrokerResponseDecodeError)?,
        resolved_at,
    ))
}

fn decode_fixed_hex<const LENGTH: usize>(
    value: &str,
) -> Result<[u8; LENGTH], BrokerProtocolValidationError> {
    if value.len() != LENGTH * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BrokerProtocolValidationError::InvalidRequest);
    }
    let mut decoded = [0_u8; LENGTH];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| BrokerProtocolValidationError::InvalidRequest)?;
    Ok(decoded)
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, UniqueJsonValue(value))) = object.next_entry::<String, _>()? {
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate object key"));
            }
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn parse_unique_json(payload: &[u8]) -> Result<Value, ()> {
    serde_json::from_slice::<UniqueJsonValue>(payload)
        .map(|value| value.0)
        .map_err(|_| ())
}

/// Sanitized category returned by the length-prefixed frame codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerFrameError {
    /// The frame length is zero.
    Empty,
    /// The declared frame length exceeds the 16 MiB bound.
    Oversized,
    /// The stream ended in the middle of a frame.
    Truncated,
    /// A local stream read failed.
    Read,
    /// A local stream write failed.
    Write,
}

impl Display for BrokerFrameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Empty => "empty Broker frame",
            Self::Oversized => "oversized Broker frame",
            Self::Truncated => "truncated Broker frame",
            Self::Read => "Broker frame read failed",
            Self::Write => "Broker frame write failed",
        };
        formatter.write_str(label)
    }
}

impl std::error::Error for BrokerFrameError {}

fn read_exact_or_eof(reader: &mut impl Read, buffer: &mut [u8]) -> Result<bool, BrokerFrameError> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => return Err(BrokerFrameError::Truncated),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BrokerFrameError::Read),
        }
    }
    Ok(true)
}

/// Reads one four-byte big-endian length-prefixed frame.
///
/// The length bound is checked before allocating the payload buffer.
pub fn read_broker_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, BrokerFrameError> {
    let mut header = [0_u8; 4];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(BrokerFrameError::Empty);
    }
    if length > MAX_BROKER_FRAME_LENGTH {
        return Err(BrokerFrameError::Oversized);
    }

    let mut payload = vec![0_u8; length];
    if !read_exact_or_eof(reader, &mut payload)? {
        return Err(BrokerFrameError::Truncated);
    }
    Ok(Some(payload))
}

/// Writes one four-byte big-endian length-prefixed frame.
pub fn write_broker_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), BrokerFrameError> {
    if payload.is_empty() {
        return Err(BrokerFrameError::Empty);
    }
    if payload.len() > MAX_BROKER_FRAME_LENGTH {
        return Err(BrokerFrameError::Oversized);
    }
    let length = u32::try_from(payload.len()).map_err(|_| BrokerFrameError::Oversized)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .map_err(|_| BrokerFrameError::Write)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn hello_request() -> BrokerRequestEnvelope {
        BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    vec![BrokerProtocolVersionRange::new(1, 0, 2).expect("range")],
                    vec![
                        BrokerCapabilityVersions::new(CapabilityName::CredentialSearch, [1, 2])
                            .expect("capabilities"),
                    ],
                )
                .expect("hello"),
            ),
        )
    }

    #[test]
    fn request_process_and_session_ids_are_canonical_and_kind_separated() {
        let request = BrokerRequestId::generate();
        let instance = BrokerInstanceId::generate();
        let session = BrokerSessionId::generate();
        assert_eq!(
            BrokerRequestId::from_str(&request.to_string()).expect("request"),
            request
        );
        assert_eq!(
            BrokerInstanceId::from_str(&instance.to_string()).expect("instance"),
            instance
        );
        assert_eq!(
            BrokerSessionId::from_str(&session.to_string()).expect("session"),
            session
        );
        assert!(BrokerRequestId::from_str(&instance.to_string()).is_err());
        assert!(BrokerRequestId::from_str(&session.to_string()).is_err());
        assert!(BrokerRequestId::from_str("request_ABCDEF").is_err());
    }

    #[test]
    fn request_codec_round_trips_hello_and_status() {
        let hello = hello_request();
        let payload = encode_broker_request(&hello).expect("encode");
        assert_eq!(decode_broker_request(&payload).expect("decode"), hello);

        let status = BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Status,
        );
        let payload = encode_broker_request(&status).expect("encode");
        assert_eq!(decode_broker_request(&payload).expect("decode"), status);
    }

    #[test]
    fn request_codec_round_trips_pairing_and_authentication_without_debug_material() {
        let pairing_request_id = PairingRequestId::generate();
        let session_id = BrokerSessionId::generate();
        let consumer_id = ConsumerId::generate();
        let public_key = [0x31; PAIRING_PUBLIC_KEY_LENGTH];
        let client_nonce = [0x32; PAIRING_NONCE_LENGTH];
        let pairing_proof = [0x33; PAIRING_PROOF_LENGTH];
        let authentication_proof = [0x34; AUTHENTICATION_PROOF_LENGTH];
        let requests = [
            BrokerRequest::PairingStart(BrokerPairingStartRequest::new(public_key, client_nonce)),
            BrokerRequest::PairingStatus(BrokerPairingStatusRequest::new(
                pairing_request_id,
                public_key,
            )),
            BrokerRequest::PairingComplete(BrokerPairingCompleteRequest::new(
                pairing_request_id,
                pairing_proof,
            )),
            BrokerRequest::AuthenticationStart(BrokerAuthenticationStartRequest::new(consumer_id)),
            BrokerRequest::AuthenticationComplete(BrokerAuthenticationCompleteRequest::new(
                session_id,
                consumer_id,
                authentication_proof,
            )),
        ];

        for request in requests {
            let envelope = BrokerRequestEnvelope::new(
                BrokerProtocolVersion::current(),
                BrokerRequestId::generate(),
                request,
            );
            let payload = encode_broker_request(&envelope).expect("encode");
            assert_eq!(decode_broker_request(&payload).expect("decode"), envelope);
            let debug = format!("{envelope:?}");
            assert!(!debug.contains(&hex::encode(public_key)));
            assert!(!debug.contains(&hex::encode(client_nonce)));
            assert!(!debug.contains(&hex::encode(pairing_proof)));
            assert!(!debug.contains(&hex::encode(authentication_proof)));
        }
    }

    #[test]
    fn capability_request_codec_round_trips_all_six_capabilities_and_access_lifecycle() {
        let marker = "KN_CAPABILITY_REQUEST_MARKER";
        let approval_request_id = ApprovalRequestId::generate();
        let field_scope = CredentialFieldScope::new(
            VaultId::generate(),
            CredentialId::generate(),
            SecretFieldId::generate(),
        );
        let operation = BrokerCredentialOperationTarget::new(
            UseGrantId::generate(),
            field_scope,
            SecretFieldKind::ApiToken,
            VaultSessionId::generate(),
        );
        let requests = vec![
            BrokerRequest::CredentialSearch(
                BrokerCredentialSearchRequest::new(operation, marker.to_owned()).expect("search"),
            ),
            BrokerRequest::AccessRequest(
                BrokerAccessRequest::credential(
                    field_scope.vault_id(),
                    Capability::v1(CapabilityName::HttpRequest),
                    marker.to_owned(),
                )
                .expect("access"),
            ),
            BrokerRequest::AccessRequest(BrokerAccessRequest::status(approval_request_id)),
            BrokerRequest::AccessRequest(BrokerAccessRequest::resume(approval_request_id)),
            BrokerRequest::AccessRequest(
                BrokerAccessRequest::wait(approval_request_id, Duration::from_millis(25))
                    .expect("wait"),
            ),
            BrokerRequest::GrantStatus(BrokerGrantStatusRequest::new(UseGrantId::generate())),
            BrokerRequest::GrantRevoke(BrokerGrantRevokeRequest::new(UseGrantId::generate())),
            BrokerRequest::HttpRequest(
                BrokerHttpCapabilityRequest::new(
                    operation,
                    UsageProfileId::generate(),
                    BrokerHttpMethod::Post,
                    format!("https://example.com/{marker}"),
                    vec![BrokerHttpCapabilityHeader::new(
                        "X-KeptNear-Test".to_owned(),
                        marker.to_owned(),
                    )
                    .expect("header")],
                    marker.as_bytes().to_vec(),
                )
                .expect("HTTP"),
            ),
            BrokerRequest::ProcessRun(
                BrokerProcessCapabilityRequest::new(
                    operation,
                    UsageProfileId::generate(),
                    "/usr/bin/printf".to_owned(),
                    vec![marker.to_owned()],
                    Some("/tmp".to_owned()),
                    vec![BrokerProcessCapabilityEnvironment::new(
                        "KEPTNEAR_TEST".to_owned(),
                        marker.to_owned(),
                    )
                    .expect("environment")],
                    1_000,
                )
                .expect("process"),
            ),
        ];

        for request in requests {
            let envelope = BrokerRequestEnvelope::new(
                BrokerProtocolVersion::current(),
                BrokerRequestId::generate(),
                request,
            );
            let payload = encode_broker_request(&envelope).expect("encode");
            assert_eq!(decode_broker_request(&payload).expect("decode"), envelope);
            assert!(!format!("{envelope:?}").contains(marker));
        }
    }

    #[test]
    fn request_codec_rejects_duplicate_keys_at_every_depth() {
        let request_id = BrokerRequestId::generate();
        let top_level = format!(
            r#"{{"protocol_name":"{BROKER_PROTOCOL_NAME}","protocol_name":"{BROKER_PROTOCOL_NAME}","protocol_major":1,"protocol_minor":0,"message_type":"broker.status","request_id":"{request_id}","body":{{}}}}"#
        );
        assert_eq!(
            decode_broker_request(top_level.as_bytes())
                .expect_err("duplicate")
                .error_code(),
            BrokerErrorCode::MalformedFrame
        );

        let nested = format!(
            r#"{{"protocol_name":"{BROKER_PROTOCOL_NAME}","protocol_major":1,"protocol_minor":0,"message_type":"broker.status","request_id":"{request_id}","body":{{"x":1,"x":2}}}}"#
        );
        assert_eq!(
            decode_broker_request(nested.as_bytes())
                .expect_err("duplicate")
                .error_code(),
            BrokerErrorCode::MalformedFrame
        );
    }

    #[test]
    fn request_codec_rejects_invalid_utf8_unknown_fields_messages_and_capabilities() {
        assert_eq!(
            decode_broker_request(&[0xff])
                .expect_err("UTF-8")
                .error_code(),
            BrokerErrorCode::MalformedFrame
        );

        let request_id = BrokerRequestId::generate();
        let unknown_field = format!(
            r#"{{"protocol_name":"{BROKER_PROTOCOL_NAME}","protocol_major":1,"protocol_minor":0,"message_type":"broker.status","request_id":"{request_id}","body":{{}},"secret":"marker"}}"#
        );
        assert_eq!(
            decode_broker_request(unknown_field.as_bytes())
                .expect_err("field")
                .error_code(),
            BrokerErrorCode::InvalidRequest
        );

        let unknown_message = format!(
            r#"{{"protocol_name":"{BROKER_PROTOCOL_NAME}","protocol_major":1,"protocol_minor":0,"message_type":"secret.get","request_id":"{request_id}","body":{{}}}}"#
        );
        let error = decode_broker_request(unknown_message.as_bytes()).expect_err("message");
        assert_eq!(error.error_code(), BrokerErrorCode::InvalidRequest);
        assert_eq!(error.request_id(), Some(request_id));

        let unknown_capability = format!(
            r#"{{"protocol_name":"{BROKER_PROTOCOL_NAME}","protocol_major":1,"protocol_minor":0,"message_type":"hello","request_id":"{request_id}","body":{{"protocol_versions":[{{"major":1,"minimum_minor":0,"maximum_minor":0}}],"capabilities":[{{"capability_name":"secret.get","versions":[1]}}]}}}}"#
        );
        assert_eq!(
            decode_broker_request(unknown_capability.as_bytes())
                .expect_err("capability")
                .error_code(),
            BrokerErrorCode::UnsupportedCapability
        );
    }

    #[test]
    fn hello_validation_rejects_ambiguous_or_unbounded_advertisements() {
        let duplicate_major = BrokerHelloRequest::new(
            vec![
                BrokerProtocolVersionRange::new(1, 0, 0).expect("range"),
                BrokerProtocolVersionRange::new(1, 1, 1).expect("range"),
            ],
            vec![],
        );
        assert_eq!(
            duplicate_major,
            Err(BrokerProtocolValidationError::InvalidProtocolVersion)
        );

        assert_eq!(
            BrokerCapabilityVersions::new(CapabilityName::CredentialSearch, []),
            Err(BrokerProtocolValidationError::InvalidCapabilities)
        );
        assert_eq!(
            BrokerCapabilityVersions::new(CapabilityName::CredentialSearch, [0]),
            Err(BrokerProtocolValidationError::InvalidCapabilities)
        );
        assert_eq!(
            BrokerCapabilityVersions::new(CapabilityName::CredentialSearch, [1, 1]),
            Err(BrokerProtocolValidationError::InvalidCapabilities)
        );
    }

    #[test]
    fn minor_negotiation_selects_the_highest_mutually_supported_version() {
        let range = BrokerProtocolVersionRange::new(1, 1, 3).expect("range");
        assert_eq!(
            range.highest_compatible(BrokerProtocolVersion::new(1, 5).expect("version")),
            Some(BrokerProtocolVersion::new(1, 3).expect("version"))
        );
        assert_eq!(
            range.highest_compatible(BrokerProtocolVersion::new(1, 2).expect("version")),
            Some(BrokerProtocolVersion::new(1, 2).expect("version"))
        );
        assert_eq!(
            range.highest_compatible(BrokerProtocolVersion::new(1, 0).expect("version")),
            None
        );
    }

    #[test]
    fn hello_selects_current_protocol_and_highest_common_capability() {
        let BrokerRequest::Hello(hello) = hello_request().request else {
            panic!("hello request");
        };
        let mut supported = BrokerCapabilitySet::empty();
        supported.insert(Capability::v1(CapabilityName::CredentialSearch));
        let negotiated = hello.negotiate(&supported).expect("compatible");
        assert_eq!(
            negotiated.selected_protocol(),
            BrokerProtocolVersion::current()
        );
        assert_eq!(
            negotiated.capabilities(),
            &[BrokerNegotiatedCapability {
                capability_name: CapabilityName::CredentialSearch,
                version: 1,
            }]
        );
    }

    #[test]
    fn response_codec_round_trips_every_current_response_shape() {
        let request_id = BrokerRequestId::generate();
        let pairing_request_id = PairingRequestId::generate();
        let consumer_id = ConsumerId::generate();
        let session_id = BrokerSessionId::generate();
        let field_scope = CredentialFieldScope::new(
            VaultId::generate(),
            CredentialId::generate(),
            SecretFieldId::generate(),
        );
        let created_at = StateTimestamp::from_unix_millis(100).expect("time");
        let resolved_at = StateTimestamp::from_unix_millis(500).expect("time");
        let expires_at = StateTimestamp::from_unix_millis(1_000).expect("time");
        let approval_request_id = ApprovalRequestId::generate();
        let responses = vec![
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::Hello(BrokerHelloResponse {
                    selected_protocol: BrokerProtocolVersion::current(),
                    capabilities: vec![],
                }),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::Status(BrokerStatusResponse::new(BrokerInstanceId::generate())),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::PairingProgress(BrokerPairingProgressResponse::pending(
                    BrokerPairingPendingResponse::new(
                        pairing_request_id,
                        [0x41; PAIRING_NONCE_LENGTH],
                        [0x42; PAIRING_NONCE_LENGTH],
                        PairingComparisonCode::from_ascii("0123456789").expect("code"),
                        Some(consumer_id),
                        BrokerPairingRequestStatus::AwaitingProof,
                        120,
                    ),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::PairingProgress(BrokerPairingProgressResponse::active(consumer_id)),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::PairingComplete(BrokerPairingCompleteResponse::new(consumer_id)),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::AuthenticationChallenge(
                    BrokerAuthenticationChallengeResponse::new(
                        session_id,
                        consumer_id,
                        [0x43; AUTHENTICATION_NONCE_LENGTH],
                        30,
                    ),
                ),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::Authenticated(BrokerAuthenticationResponse::new(
                    session_id,
                    consumer_id,
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::Error(BrokerProtocolError::new(
                    BrokerErrorCode::ApprovalPending,
                    true,
                    Some(BrokerRequiredAction::WaitForApproval),
                    Some(ApprovalRequestId::generate()),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::CredentialSearch(BrokerCredentialSearchResponse::from_protocol(
                    Some(BrokerCredentialMetadataResponse::from_protocol(
                        field_scope.vault_id(),
                        field_scope.credential_id(),
                        "Private title".to_owned(),
                        field_scope.secret_field_id(),
                        "token".to_owned(),
                        Some("Release token".to_owned()),
                        SecretFieldKind::ApiToken,
                    )),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::AccessRequest(BrokerAccessResponse::Submission(
                    BrokerAccessSubmissionResponse::from_protocol(
                        approval_request_id,
                        ApprovalStatus::Pending,
                        expires_at,
                        None,
                        false,
                    ),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::AccessRequest(BrokerAccessResponse::Status(
                    BrokerAccessReceiptResponse::from_protocol(
                        approval_request_id,
                        ApprovalStatus::Pending,
                        expires_at,
                        None,
                    ),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::AccessRequest(BrokerAccessResponse::Resume(
                    BrokerAccessReceiptResponse::from_protocol(
                        approval_request_id,
                        ApprovalStatus::Approved,
                        expires_at,
                        Some(resolved_at),
                    ),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::AccessRequest(BrokerAccessResponse::Wait(
                    BrokerAccessWaitResponse::from_protocol(
                        BrokerAccessReceiptResponse::from_protocol(
                            approval_request_id,
                            ApprovalStatus::Pending,
                            expires_at,
                            None,
                        ),
                        true,
                    ),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::GrantStatus(BrokerGrantStatusResponse::active(
                    BrokerActiveGrantMetadata::from_protocol(
                        UseGrantId::generate(),
                        field_scope,
                        Capability::v1(CapabilityName::ProcessRun),
                        VaultSessionId::generate(),
                        GrantScope::UnlockSession,
                        created_at,
                        expires_at,
                    ),
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::GrantRevoke(BrokerGrantRevokeResponse::new(true)),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::HttpRequest(BrokerHttpCapabilityResponse::from_protocol(
                    200,
                    b"private HTTP output".to_vec(),
                    false,
                )),
            ),
            BrokerResponseEnvelope::new(
                BrokerProtocolVersion::current(),
                request_id,
                BrokerResponse::ProcessRun(BrokerProcessCapabilityResponse::from_protocol(
                    Some(0),
                    false,
                    b"private stdout".to_vec(),
                    b"private stderr".to_vec(),
                    false,
                    false,
                )),
            ),
        ];

        for response in responses {
            let payload = encode_broker_response(&response).expect("encode");
            assert_eq!(decode_broker_response(&payload).expect("decode"), response);
            let debug = format!("{response:?}");
            for marker in [
                "Private title",
                "Release token",
                "private HTTP output",
                "private stdout",
                "private stderr",
            ] {
                assert!(!debug.contains(marker));
            }
        }
    }

    #[test]
    fn response_codec_rejects_duplicate_negotiated_capabilities() {
        let request_id = BrokerRequestId::generate();
        let payload = format!(
            r#"{{"protocol_name":"{BROKER_PROTOCOL_NAME}","protocol_major":1,"protocol_minor":0,"message_type":"hello.result","request_id":"{request_id}","result":{{"selected_protocol":{{"major":1,"minor":0}},"capabilities":[{{"capability_name":"credential.search","version":1}},{{"capability_name":"credential.search","version":1}}]}}}}"#
        );
        assert_eq!(
            decode_broker_response(payload.as_bytes()),
            Err(BrokerResponseDecodeError)
        );
    }

    #[test]
    fn frame_codec_round_trips_and_rejects_invalid_lengths() {
        let mut encoded = Vec::new();
        write_broker_frame(&mut encoded, b"payload").expect("write");
        assert_eq!(
            read_broker_frame(&mut Cursor::new(encoded)).expect("read"),
            Some(b"payload".to_vec())
        );
        assert_eq!(
            read_broker_frame(&mut Cursor::new(Vec::<u8>::new())).expect("EOF"),
            None
        );
        assert_eq!(
            read_broker_frame(&mut Cursor::new(0_u32.to_be_bytes())),
            Err(BrokerFrameError::Empty)
        );
        assert_eq!(
            read_broker_frame(&mut Cursor::new(
                ((MAX_BROKER_FRAME_LENGTH + 1) as u32).to_be_bytes()
            )),
            Err(BrokerFrameError::Oversized)
        );
        assert_eq!(
            read_broker_frame(&mut Cursor::new([0, 0, 0, 5, 1, 2])),
            Err(BrokerFrameError::Truncated)
        );
    }
}
