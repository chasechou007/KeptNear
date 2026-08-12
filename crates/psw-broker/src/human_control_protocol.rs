use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Canonical identity of the App-to-Broker human-control protocol.
pub const HUMAN_CONTROL_PROTOCOL_NAME: &str = "keptnear.human-control";
/// Current human-control protocol major version.
pub const HUMAN_CONTROL_PROTOCOL_MAJOR: u16 = 1;
/// Current human-control protocol minor version.
pub const HUMAN_CONTROL_PROTOCOL_MINOR: u16 = 0;
/// Immutable schema identity for the complete version 1 operation catalog.
pub const HUMAN_CONTROL_SCHEMA_ID: &str = "keptnear.human-control.schema.v1";
/// Fixed decision accepted by `pending.deny`.
pub const HUMAN_CONTROL_DENY_DECISION: &str = "deny";
/// Fixed destructive scope accepted by `consumer.revoke`.
pub const HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE: &str = "consumer-and-authorization";
/// Fixed reason accepted by the graceful `shutdown` operation.
pub const HUMAN_CONTROL_SHUTDOWN_REASON: &str = "controller-request";
/// Maximum accepted or emitted framed human-control payload.
pub const MAX_HUMAN_CONTROL_FRAME_LENGTH: usize = 1024 * 1024;
/// Maximum unauthenticated negotiation request or response.
pub const MAX_HUMAN_CONTROL_HELLO_LENGTH: usize = 16 * 1024;
/// Maximum controller challenge, proof, or lease message.
pub const MAX_HUMAN_CONTROL_AUTH_LENGTH: usize = 64 * 1024;
/// Maximum request containing one Vault unlock credential.
pub const MAX_HUMAN_CONTROL_UNLOCK_LENGTH: usize = 128 * 1024;
/// Maximum ordinary authenticated metadata request.
pub const MAX_HUMAN_CONTROL_REQUEST_LENGTH: usize = 64 * 1024;
/// Maximum secret-free metadata response.
pub const MAX_HUMAN_CONTROL_RESPONSE_LENGTH: usize = MAX_HUMAN_CONTROL_FRAME_LENGTH;
/// Maximum decoded bytes accepted for one master password or local unlock value.
pub const MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES: usize = 64 * 1024;
/// Maximum entries in one human-control collection response.
pub const MAX_HUMAN_CONTROL_COLLECTION_ITEMS: usize = 256;
/// Maximum audit events returned or exported in one human-control response.
pub const MAX_HUMAN_CONTROL_AUDIT_EVENTS: usize = 256;
/// Maximum protocol version ranges accepted during negotiation.
pub const MAX_HUMAN_CONTROL_VERSION_RANGES: usize = 8;
/// Maximum schema identities accepted during negotiation.
pub const MAX_HUMAN_CONTROL_SCHEMA_IDS: usize = 8;
/// Maximum bytes accepted for one negotiation role or schema identity.
pub const MAX_HUMAN_CONTROL_NEGOTIATION_ID_BYTES: usize = 128;
/// Maximum UTF-8 bytes accepted for one human-control label or technical name.
pub const MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES: usize = 128;
/// Maximum outstanding audit-clear tickets retained on one controller connection.
pub const MAX_HUMAN_CONTROL_AUDIT_CLEAR_CONFIRMATIONS: usize = 16;

const _: () = assert!(MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES < MAX_HUMAN_CONTROL_UNLOCK_LENGTH);
const _: () = assert!(MAX_HUMAN_CONTROL_COLLECTION_ITEMS <= 256);
const _: () = assert!(MAX_HUMAN_CONTROL_AUDIT_EVENTS <= MAX_HUMAN_CONTROL_COLLECTION_ITEMS);
const _: () = assert!(MAX_HUMAN_CONTROL_AUDIT_CLEAR_CONFIRMATIONS <= 16);

/// Sanitized validation failure for the frozen human-control contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlProtocolValidationError {
    /// A version or inclusive version range is structurally invalid.
    InvalidProtocolVersion,
    /// A version offer is empty, ambiguous, duplicated, or unbounded.
    InvalidVersionOffer,
    /// An operation is outside the frozen catalog.
    InvalidOperation,
    /// A failure code or required action is outside the frozen catalog.
    InvalidFixedValue,
}

impl Display for HumanControlProtocolValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProtocolVersion => "invalid human-control protocol version",
            Self::InvalidVersionOffer => "invalid human-control version offer",
            Self::InvalidOperation => "invalid human-control operation",
            Self::InvalidFixedValue => "invalid human-control fixed value",
        })
    }
}

impl std::error::Error for HumanControlProtocolValidationError {}

/// One exact human-control protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HumanControlProtocolVersion {
    major: u16,
    minor: u16,
}

impl HumanControlProtocolVersion {
    /// Creates a non-zero-major protocol version.
    pub fn new(major: u16, minor: u16) -> Result<Self, HumanControlProtocolValidationError> {
        if major == 0 {
            return Err(HumanControlProtocolValidationError::InvalidProtocolVersion);
        }
        Ok(Self { major, minor })
    }

    /// Returns the current server protocol version.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            major: HUMAN_CONTROL_PROTOCOL_MAJOR,
            minor: HUMAN_CONTROL_PROTOCOL_MINOR,
        }
    }

    /// Returns the protocol major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the protocol minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

impl Display for HumanControlProtocolVersion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for HumanControlProtocolVersion {
    type Err = HumanControlProtocolValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (major, minor) = value
            .split_once('.')
            .ok_or(HumanControlProtocolValidationError::InvalidProtocolVersion)?;
        if major.is_empty()
            || minor.is_empty()
            || (major.len() > 1 && major.starts_with('0'))
            || (minor.len() > 1 && minor.starts_with('0'))
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(HumanControlProtocolValidationError::InvalidProtocolVersion);
        }
        Self::new(
            major
                .parse()
                .map_err(|_| HumanControlProtocolValidationError::InvalidProtocolVersion)?,
            minor
                .parse()
                .map_err(|_| HumanControlProtocolValidationError::InvalidProtocolVersion)?,
        )
    }
}

impl Serialize for HumanControlProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HumanControlProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// Inclusive client-supported minor range for one human-control major version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanControlProtocolVersionRange {
    major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
}

impl HumanControlProtocolVersionRange {
    /// Creates one validated inclusive version range.
    pub fn new(
        major: u16,
        minimum_minor: u16,
        maximum_minor: u16,
    ) -> Result<Self, HumanControlProtocolValidationError> {
        if major == 0 || minimum_minor > maximum_minor {
            return Err(HumanControlProtocolValidationError::InvalidProtocolVersion);
        }
        Ok(Self {
            major,
            minimum_minor,
            maximum_minor,
        })
    }

    /// Returns the covered major version.
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

    fn highest_compatible(
        self,
        server_current: HumanControlProtocolVersion,
    ) -> Option<HumanControlProtocolVersion> {
        if self.major != server_current.major || self.minimum_minor > server_current.minor {
            return None;
        }
        Some(HumanControlProtocolVersion {
            major: self.major,
            minor: self.maximum_minor.min(server_current.minor),
        })
    }
}

/// Canonical bounded protocol ranges offered by one App controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlVersionOffer {
    role: String,
    ranges: Vec<HumanControlProtocolVersionRange>,
    schema_ids: Vec<String>,
}

impl HumanControlVersionOffer {
    /// Creates a bounded offer that retains every compatibility constraint.
    pub fn new(
        role: impl Into<String>,
        ranges: impl IntoIterator<Item = HumanControlProtocolVersionRange>,
        schema_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, HumanControlProtocolValidationError> {
        let role = role.into();
        let mut ranges = ranges.into_iter().collect::<Vec<_>>();
        let schema_ids = schema_ids.into_iter().collect::<Vec<_>>();
        if !valid_negotiation_identity(&role)
            || ranges.is_empty()
            || ranges.len() > MAX_HUMAN_CONTROL_VERSION_RANGES
            || schema_ids.is_empty()
            || schema_ids.len() > MAX_HUMAN_CONTROL_SCHEMA_IDS
            || schema_ids
                .iter()
                .any(|schema_id| !valid_negotiation_identity(schema_id))
        {
            return Err(HumanControlProtocolValidationError::InvalidVersionOffer);
        }
        let majors = ranges
            .iter()
            .map(|range| range.major)
            .collect::<BTreeSet<_>>();
        if majors.len() != ranges.len() {
            return Err(HumanControlProtocolValidationError::InvalidVersionOffer);
        }
        if schema_ids.iter().collect::<BTreeSet<_>>().len() != schema_ids.len() {
            return Err(HumanControlProtocolValidationError::InvalidVersionOffer);
        }
        ranges.sort_by_key(|range| range.major);
        Ok(Self {
            role,
            ranges,
            schema_ids,
        })
    }

    /// Returns the exact offered controller role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns offered ranges in ascending major-version order.
    #[must_use]
    pub fn ranges(&self) -> &[HumanControlProtocolVersionRange] {
        &self.ranges
    }

    /// Returns the bounded schema identities offered by the controller.
    #[must_use]
    pub fn schema_ids(&self) -> &[String] {
        &self.schema_ids
    }

    /// Selects the highest compatible version implemented by this Broker.
    #[must_use]
    pub fn negotiate_current(&self) -> Option<HumanControlProtocolVersion> {
        self.ranges
            .iter()
            .filter_map(|range| range.highest_compatible(HumanControlProtocolVersion::current()))
            .max()
    }
}

fn valid_negotiation_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HUMAN_CONTROL_NEGOTIATION_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Authentication state required before one operation may be dispatched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlAuthenticationRequirement {
    /// The operation is the initial protocol negotiation.
    None,
    /// Protocol negotiation must be complete, but controller proof is in progress.
    Negotiated,
    /// A live authenticated controller session and lease are required.
    Authenticated,
}

/// Secret-bearing class accepted by one request schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlRequestSecretClass {
    /// The schema accepts no controller proof or Vault unlock credential.
    None,
    /// The schema contains bounded controller authentication material.
    ControllerAuthentication,
    /// The schema contains one bounded Vault unlock credential.
    VaultUnlockCredential,
}

/// Result secrecy guaranteed by every version 1 operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlResultSecrecy {
    /// The result contains only bounded metadata or a fixed control receipt.
    SecretFree,
}

/// Closed request-body schema identifiers for version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlRequestSchema {
    /// Protocol version offer.
    Hello,
    /// Controller identity and challenge request.
    ControllerChallenge,
    /// Controller proof and negotiated transcript identity.
    ControllerProof,
    /// Existing authenticated session and lease renewal.
    ControllerLease,
    /// Empty object.
    Empty,
    /// Boolean Machine Access Pause transition.
    PauseUpdate,
    /// Vault identity plus exactly one bounded unlock credential kind.
    VaultUnlock,
    /// Vault identity only.
    VaultIdentity,
    /// Pending request identity and fixed decision.
    PendingDecision,
    /// Pairing request identity and bounded human label.
    PairingApproval,
    /// Pending unlock identity and expected Vault identity.
    UnlockApproval,
    /// Pending credential request identity.
    CredentialReview,
    /// Pending request plus exact selected Credential and Secret Field identities.
    CredentialSelection,
    /// Exact selected field, capability, confirmation policy, and rule lifetime.
    CredentialAuthorization,
    /// One Vault identity for authorization inventory.
    AuthorizationSnapshot,
    /// One Consumer identity.
    ConsumerIdentity,
    /// Consumer identity plus optional bounded executable-name hint.
    UsageProfileCatalog,
    /// Consumer identity, template identity, label, and typed technical field.
    UsageProfileCreate,
    /// Consumer and Usage Profile identities.
    UsageProfileRemove,
    /// Consumer, Vault, Credential, and Secret Field identities.
    FieldAccessRevoke,
    /// Consumer and Use Grant identities.
    GrantRevoke,
    /// Consumer identity and explicit revocation scope.
    ConsumerRevoke,
    /// Bounded audit filter, cursor, and page limit.
    AuditPage,
    /// Explicit bounded audit selection and confirmation identity.
    AuditClear,
    /// Bounded audit filter and export limit.
    AuditExport,
    /// Expected component and protocol identity for repair coordination.
    RepairPrepare,
    /// Fixed graceful-shutdown reason.
    Shutdown,
}

/// Closed response-body schema identifiers for version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlResponseSchema {
    /// Selected version, schema identity, Broker instance, and operation catalog.
    Hello,
    /// Controller challenge transcript fields without a private key.
    ControllerChallenge,
    /// Authenticated controller session and bounded lease expiry.
    ControllerAuthenticated,
    /// Renewed bounded lease expiry.
    ControllerLease,
    /// Component, protected-state category, pause, and Vault lock readiness.
    Readiness,
    /// Current Machine Access Pause state.
    PauseState,
    /// Vault identity, lock state, and optional session identity.
    VaultState,
    /// Bounded pending Pairing, unlock, and credential request metadata.
    PendingQueue,
    /// Fixed decision outcome and affected stable identities.
    DecisionReceipt,
    /// Bounded human-only credential and field candidate metadata.
    CredentialReview,
    /// Secret-free authorization inventory for one Vault.
    AuthorizationSnapshot,
    /// Secret-free Consumer, Rule, Grant, Profile, and recent audit metadata.
    ConsumerDetail,
    /// Bounded provider-neutral Usage Profile templates and recommendation.
    UsageProfileCatalog,
    /// One created Usage Profile metadata projection.
    UsageProfile,
    /// Fixed removal outcome.
    RemovalReceipt,
    /// Fixed revocation counts and stable affected identities.
    RevocationSummary,
    /// Bounded secret-free audit page.
    AuditPage,
    /// Fixed audit clear summary.
    AuditClearSummary,
    /// Versioned bounded secret-free audit export.
    AuditExport,
    /// Fixed repair readiness and shutdown requirements.
    RepairReadiness,
    /// Fixed graceful-shutdown receipt.
    ShutdownReceipt,
}

/// Closed human-control operations introduced by protocol version 1.0.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HumanControlOperation {
    /// Negotiate the protocol and complete operation catalog.
    Hello,
    /// Request a fresh controller authentication challenge.
    ControllerChallenge,
    /// Prove controller-key possession for this connection.
    ControllerAuthenticate,
    /// Renew the authenticated App controller lease.
    ControllerLeaseRenew,
    /// Read authenticated Broker and protected-state readiness.
    ReadinessGet,
    /// Change the accepted Machine Access Pause gate.
    MachineAccessPauseSet,
    /// Unlock one machine Vault session with bounded secret input.
    VaultUnlock,
    /// Lock one machine Vault session.
    VaultLock,
    /// List pending local human decisions.
    PendingList,
    /// Deny one pending local decision.
    PendingDeny,
    /// Approve one pending Consumer pairing identity.
    PairingApprove,
    /// Approve one pending machine Vault unlock request.
    UnlockApprove,
    /// Review bounded candidates for one pending credential request.
    CredentialReview,
    /// Allow one exact pending credential request once.
    CredentialAllowOnce,
    /// Create one exact persistent Access Rule from a pending request.
    CredentialAuthorize,
    /// Read one Vault's secret-free authorization inventory.
    AuthorizationSnapshot,
    /// Read one Consumer's secret-free management detail.
    ConsumerDetail,
    /// Read provider-neutral Usage Profile templates for one Consumer.
    UsageProfileCatalog,
    /// Create one declarative Usage Profile.
    UsageProfileCreate,
    /// Remove one declarative Usage Profile.
    UsageProfileRemove,
    /// Revoke one Consumer's exact field authorization boundary.
    FieldAccessRevoke,
    /// Revoke one Consumer-owned Use Grant.
    GrantRevoke,
    /// Revoke one Consumer and its future access.
    ConsumerRevoke,
    /// Revoke all Apps & Tools authorization while preserving human Vault data.
    AllAccessRevoke,
    /// Read a bounded secret-free audit page.
    AuditList,
    /// Clear one explicitly confirmed bounded audit selection.
    AuditClear,
    /// Export a bounded versioned secret-free audit projection.
    AuditExport,
    /// Lock and quiesce machine state for an App-managed repair.
    RepairPrepare,
    /// Gracefully lock sessions, invalidate live Grants, and stop the Broker.
    Shutdown,
}

impl HumanControlOperation {
    /// Returns the canonical wire operation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::ControllerChallenge => "controller.challenge",
            Self::ControllerAuthenticate => "controller.authenticate",
            Self::ControllerLeaseRenew => "controller.lease.renew",
            Self::ReadinessGet => "readiness.get",
            Self::MachineAccessPauseSet => "machine-access.pause.set",
            Self::VaultUnlock => "vault.unlock",
            Self::VaultLock => "vault.lock",
            Self::PendingList => "pending.list",
            Self::PendingDeny => "pending.deny",
            Self::PairingApprove => "pairing.approve",
            Self::UnlockApprove => "unlock.approve",
            Self::CredentialReview => "credential.review",
            Self::CredentialAllowOnce => "credential.allow-once",
            Self::CredentialAuthorize => "credential.authorize",
            Self::AuthorizationSnapshot => "authorization.snapshot",
            Self::ConsumerDetail => "consumer.detail",
            Self::UsageProfileCatalog => "usage-profile.catalog",
            Self::UsageProfileCreate => "usage-profile.create",
            Self::UsageProfileRemove => "usage-profile.remove",
            Self::FieldAccessRevoke => "access.field.revoke",
            Self::GrantRevoke => "grant.revoke",
            Self::ConsumerRevoke => "consumer.revoke",
            Self::AllAccessRevoke => "access.all.revoke",
            Self::AuditList => "audit.list",
            Self::AuditClear => "audit.clear",
            Self::AuditExport => "audit.export",
            Self::RepairPrepare => "repair.prepare",
            Self::Shutdown => "shutdown",
        }
    }

    /// Returns the complete frozen contract for this operation.
    #[must_use]
    pub fn contract(self) -> &'static HumanControlOperationContract {
        HUMAN_CONTROL_OPERATION_CONTRACTS
            .iter()
            .find(|contract| contract.operation == self)
            .expect("every human-control operation has one static contract")
    }
}

impl Display for HumanControlOperation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HumanControlOperation {
    type Err = HumanControlProtocolValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        HUMAN_CONTROL_OPERATION_CONTRACTS
            .iter()
            .find(|contract| contract.operation.as_str() == value)
            .map(|contract| contract.operation)
            .ok_or(HumanControlProtocolValidationError::InvalidOperation)
    }
}

/// One immutable operation-to-schema mapping in the version 1 catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanControlOperationContract {
    operation: HumanControlOperation,
    introduced_minor: u16,
    authentication: HumanControlAuthenticationRequirement,
    request_schema: HumanControlRequestSchema,
    response_schema: HumanControlResponseSchema,
    request_secret_class: HumanControlRequestSecretClass,
    result_secrecy: HumanControlResultSecrecy,
    maximum_request_length: usize,
    maximum_response_length: usize,
}

impl HumanControlOperationContract {
    /// Returns the operation identity.
    #[must_use]
    pub const fn operation(self) -> HumanControlOperation {
        self.operation
    }

    /// Returns the protocol minor version that introduced the operation.
    #[must_use]
    pub const fn introduced_minor(self) -> u16 {
        self.introduced_minor
    }

    /// Returns the required connection authentication state.
    #[must_use]
    pub const fn authentication(self) -> HumanControlAuthenticationRequirement {
        self.authentication
    }

    /// Returns the exact closed request schema identifier.
    #[must_use]
    pub const fn request_schema(self) -> HumanControlRequestSchema {
        self.request_schema
    }

    /// Returns the exact closed response schema identifier.
    #[must_use]
    pub const fn response_schema(self) -> HumanControlResponseSchema {
        self.response_schema
    }

    /// Returns the only secret-bearing input class accepted by the schema.
    #[must_use]
    pub const fn request_secret_class(self) -> HumanControlRequestSecretClass {
        self.request_secret_class
    }

    /// Returns the required result secrecy.
    #[must_use]
    pub const fn result_secrecy(self) -> HumanControlResultSecrecy {
        self.result_secrecy
    }

    /// Returns the operation-specific encoded request bound.
    #[must_use]
    pub const fn maximum_request_length(self) -> usize {
        self.maximum_request_length
    }

    /// Returns the operation-specific encoded response bound.
    #[must_use]
    pub const fn maximum_response_length(self) -> usize {
        self.maximum_response_length
    }
}

const fn contract(
    operation: HumanControlOperation,
    authentication: HumanControlAuthenticationRequirement,
    request_schema: HumanControlRequestSchema,
    response_schema: HumanControlResponseSchema,
    request_secret_class: HumanControlRequestSecretClass,
    maximum_request_length: usize,
    maximum_response_length: usize,
) -> HumanControlOperationContract {
    HumanControlOperationContract {
        operation,
        introduced_minor: 0,
        authentication,
        request_schema,
        response_schema,
        request_secret_class,
        result_secrecy: HumanControlResultSecrecy::SecretFree,
        maximum_request_length,
        maximum_response_length,
    }
}

/// Complete ordered operation catalog for human-control protocol version 1.0.
pub const HUMAN_CONTROL_OPERATION_CONTRACTS: [HumanControlOperationContract; 29] = [
    contract(
        HumanControlOperation::Hello,
        HumanControlAuthenticationRequirement::None,
        HumanControlRequestSchema::Hello,
        HumanControlResponseSchema::Hello,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_HELLO_LENGTH,
        MAX_HUMAN_CONTROL_HELLO_LENGTH,
    ),
    contract(
        HumanControlOperation::ControllerChallenge,
        HumanControlAuthenticationRequirement::Negotiated,
        HumanControlRequestSchema::ControllerChallenge,
        HumanControlResponseSchema::ControllerChallenge,
        HumanControlRequestSecretClass::ControllerAuthentication,
        MAX_HUMAN_CONTROL_AUTH_LENGTH,
        MAX_HUMAN_CONTROL_AUTH_LENGTH,
    ),
    contract(
        HumanControlOperation::ControllerAuthenticate,
        HumanControlAuthenticationRequirement::Negotiated,
        HumanControlRequestSchema::ControllerProof,
        HumanControlResponseSchema::ControllerAuthenticated,
        HumanControlRequestSecretClass::ControllerAuthentication,
        MAX_HUMAN_CONTROL_AUTH_LENGTH,
        MAX_HUMAN_CONTROL_AUTH_LENGTH,
    ),
    contract(
        HumanControlOperation::ControllerLeaseRenew,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::ControllerLease,
        HumanControlResponseSchema::ControllerLease,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_AUTH_LENGTH,
        MAX_HUMAN_CONTROL_AUTH_LENGTH,
    ),
    contract(
        HumanControlOperation::ReadinessGet,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::Empty,
        HumanControlResponseSchema::Readiness,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::MachineAccessPauseSet,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::PauseUpdate,
        HumanControlResponseSchema::PauseState,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::VaultUnlock,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::VaultUnlock,
        HumanControlResponseSchema::VaultState,
        HumanControlRequestSecretClass::VaultUnlockCredential,
        MAX_HUMAN_CONTROL_UNLOCK_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::VaultLock,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::VaultIdentity,
        HumanControlResponseSchema::VaultState,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::PendingList,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::Empty,
        HumanControlResponseSchema::PendingQueue,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::PendingDeny,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::PendingDecision,
        HumanControlResponseSchema::DecisionReceipt,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::PairingApprove,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::PairingApproval,
        HumanControlResponseSchema::DecisionReceipt,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::UnlockApprove,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::UnlockApproval,
        HumanControlResponseSchema::DecisionReceipt,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::CredentialReview,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::CredentialReview,
        HumanControlResponseSchema::CredentialReview,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::CredentialAllowOnce,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::CredentialSelection,
        HumanControlResponseSchema::DecisionReceipt,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::CredentialAuthorize,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::CredentialAuthorization,
        HumanControlResponseSchema::DecisionReceipt,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::AuthorizationSnapshot,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::AuthorizationSnapshot,
        HumanControlResponseSchema::AuthorizationSnapshot,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::ConsumerDetail,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::ConsumerIdentity,
        HumanControlResponseSchema::ConsumerDetail,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::UsageProfileCatalog,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::UsageProfileCatalog,
        HumanControlResponseSchema::UsageProfileCatalog,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::UsageProfileCreate,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::UsageProfileCreate,
        HumanControlResponseSchema::UsageProfile,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::UsageProfileRemove,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::UsageProfileRemove,
        HumanControlResponseSchema::RemovalReceipt,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::FieldAccessRevoke,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::FieldAccessRevoke,
        HumanControlResponseSchema::RevocationSummary,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::GrantRevoke,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::GrantRevoke,
        HumanControlResponseSchema::RevocationSummary,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::ConsumerRevoke,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::ConsumerRevoke,
        HumanControlResponseSchema::RevocationSummary,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::AllAccessRevoke,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::Empty,
        HumanControlResponseSchema::RevocationSummary,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::AuditList,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::AuditPage,
        HumanControlResponseSchema::AuditPage,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::AuditClear,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::AuditClear,
        HumanControlResponseSchema::AuditClearSummary,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::AuditExport,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::AuditExport,
        HumanControlResponseSchema::AuditExport,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::RepairPrepare,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::RepairPrepare,
        HumanControlResponseSchema::RepairReadiness,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
    contract(
        HumanControlOperation::Shutdown,
        HumanControlAuthenticationRequirement::Authenticated,
        HumanControlRequestSchema::Shutdown,
        HumanControlResponseSchema::ShutdownReceipt,
        HumanControlRequestSecretClass::None,
        MAX_HUMAN_CONTROL_REQUEST_LENGTH,
        MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
    ),
];

/// Stable localizable failure codes returned by the human-control protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlFailureCode {
    /// App and Broker have no mutually supported protocol version.
    ProtocolIncompatible,
    /// The frame or closed JSON document is malformed.
    MalformedFrame,
    /// The global or operation-specific message bound was exceeded.
    OversizedFrame,
    /// The connection has not completed `hello`.
    NegotiationRequired,
    /// Controller authentication is required for this operation.
    AuthenticationRequired,
    /// Controller proof failed without further detail.
    AuthenticationFailed,
    /// A nonce, proof, session, or deadline was replayed.
    ReplayRejected,
    /// Controller authority is absent, incomplete, or unavailable.
    ControllerUnavailable,
    /// The operation is unknown or unavailable in the negotiated version.
    UnsupportedOperation,
    /// The request violates its closed schema.
    InvalidRequest,
    /// The target machine Vault is locked.
    VaultLocked,
    /// Vault unlock failed without reflecting credential material.
    UnlockFailed,
    /// The named pending request is not available to the controller.
    RequestUnavailable,
    /// Current state changed and the operation cannot be applied safely.
    Conflict,
    /// Protected device state cannot be read safely.
    ProtectedStateUnavailable,
    /// Component, protocol, socket, or service state requires repair.
    RepairRequired,
    /// A bounded local attempt rate was exceeded.
    RateLimited,
    /// The operation failed without exposing internal details.
    OperationFailed,
}

impl HumanControlFailureCode {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolIncompatible => "protocol-incompatible",
            Self::MalformedFrame => "malformed-frame",
            Self::OversizedFrame => "oversized-frame",
            Self::NegotiationRequired => "negotiation-required",
            Self::AuthenticationRequired => "authentication-required",
            Self::AuthenticationFailed => "authentication-failed",
            Self::ReplayRejected => "replay-rejected",
            Self::ControllerUnavailable => "controller-unavailable",
            Self::UnsupportedOperation => "unsupported-operation",
            Self::InvalidRequest => "invalid-request",
            Self::VaultLocked => "vault-locked",
            Self::UnlockFailed => "unlock-failed",
            Self::RequestUnavailable => "request-unavailable",
            Self::Conflict => "conflict",
            Self::ProtectedStateUnavailable => "protected-state-unavailable",
            Self::RepairRequired => "repair-required",
            Self::RateLimited => "rate-limited",
            Self::OperationFailed => "operation-failed",
        }
    }
}

impl FromStr for HumanControlFailureCode {
    type Err = HumanControlProtocolValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        for code in HUMAN_CONTROL_FAILURE_CODES {
            if code.as_str() == value {
                return Ok(code);
            }
        }
        Err(HumanControlProtocolValidationError::InvalidFixedValue)
    }
}

/// Complete fixed failure-code catalog for protocol version 1.
pub const HUMAN_CONTROL_FAILURE_CODES: [HumanControlFailureCode; 18] = [
    HumanControlFailureCode::ProtocolIncompatible,
    HumanControlFailureCode::MalformedFrame,
    HumanControlFailureCode::OversizedFrame,
    HumanControlFailureCode::NegotiationRequired,
    HumanControlFailureCode::AuthenticationRequired,
    HumanControlFailureCode::AuthenticationFailed,
    HumanControlFailureCode::ReplayRejected,
    HumanControlFailureCode::ControllerUnavailable,
    HumanControlFailureCode::UnsupportedOperation,
    HumanControlFailureCode::InvalidRequest,
    HumanControlFailureCode::VaultLocked,
    HumanControlFailureCode::UnlockFailed,
    HumanControlFailureCode::RequestUnavailable,
    HumanControlFailureCode::Conflict,
    HumanControlFailureCode::ProtectedStateUnavailable,
    HumanControlFailureCode::RepairRequired,
    HumanControlFailureCode::RateLimited,
    HumanControlFailureCode::OperationFailed,
];

/// Stable next actions associated with fixed human-control failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlRequiredAction {
    /// Update the App or Broker to a compatible version.
    UpdateComponent,
    /// Start the connection with protocol negotiation.
    SendHello,
    /// Prove the dedicated controller identity.
    AuthenticateController,
    /// Establish a fresh controller session after expiry or restart.
    Reauthenticate,
    /// Unlock the target machine Vault from the human App.
    UnlockVault,
    /// Review a pending local decision.
    ReviewRequest,
    /// Retry after a bounded transient failure.
    RetryLater,
    /// Run the explicit App-managed repair flow.
    RepairService,
    /// Disable machine access without changing portable Vaults.
    DisableMachineAccess,
}

impl HumanControlRequiredAction {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpdateComponent => "update-component",
            Self::SendHello => "send-hello",
            Self::AuthenticateController => "authenticate-controller",
            Self::Reauthenticate => "reauthenticate",
            Self::UnlockVault => "unlock-vault",
            Self::ReviewRequest => "review-request",
            Self::RetryLater => "retry-later",
            Self::RepairService => "repair-service",
            Self::DisableMachineAccess => "disable-machine-access",
        }
    }
}

impl FromStr for HumanControlRequiredAction {
    type Err = HumanControlProtocolValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        for action in HUMAN_CONTROL_REQUIRED_ACTIONS {
            if action.as_str() == value {
                return Ok(action);
            }
        }
        Err(HumanControlProtocolValidationError::InvalidFixedValue)
    }
}

/// Complete fixed recovery-action catalog for protocol version 1.
pub const HUMAN_CONTROL_REQUIRED_ACTIONS: [HumanControlRequiredAction; 9] = [
    HumanControlRequiredAction::UpdateComponent,
    HumanControlRequiredAction::SendHello,
    HumanControlRequiredAction::AuthenticateController,
    HumanControlRequiredAction::Reauthenticate,
    HumanControlRequiredAction::UnlockVault,
    HumanControlRequiredAction::ReviewRequest,
    HumanControlRequiredAction::RetryLater,
    HumanControlRequiredAction::RepairService,
    HumanControlRequiredAction::DisableMachineAccess,
];

/// Fixed failure response with no free-form diagnostic or reflected request data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanControlProtocolFailure {
    code: HumanControlFailureCode,
    retryable: bool,
    required_action: Option<HumanControlRequiredAction>,
}

impl HumanControlProtocolFailure {
    /// Creates one fixed failure response.
    #[must_use]
    pub const fn new(
        code: HumanControlFailureCode,
        retryable: bool,
        required_action: Option<HumanControlRequiredAction>,
    ) -> Self {
        Self {
            code,
            retryable,
            required_action,
        }
    }

    /// Returns the fixed failure code.
    #[must_use]
    pub const fn code(self) -> HumanControlFailureCode {
        self.code
    }

    /// Returns whether a retry without another user decision may succeed.
    #[must_use]
    pub const fn retryable(self) -> bool {
        self.retryable
    }

    /// Returns the optional localizable recovery action.
    #[must_use]
    pub const fn required_action(self) -> Option<HumanControlRequiredAction> {
        self.required_action
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HumanControlFixture {
        schema: String,
        protocol: HumanControlFixtureProtocol,
        operations: Vec<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HumanControlFixtureProtocol {
        name: String,
        major: u16,
        minor: u16,
    }

    fn machine_access_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/machine-access")
            .join(name)
    }

    #[test]
    fn version_offer_is_canonical_bounded_and_negotiates_only_current_major() {
        let offer = HumanControlVersionOffer::new(
            "human-controller",
            [
                HumanControlProtocolVersionRange::new(2, 0, 4).expect("future range"),
                HumanControlProtocolVersionRange::new(1, 0, 7).expect("current range"),
            ],
            [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
        )
        .expect("canonical offer");
        assert_eq!(offer.role(), "human-controller");
        assert_eq!(offer.schema_ids(), [HUMAN_CONTROL_SCHEMA_ID]);
        assert_eq!(offer.ranges()[0].major(), 1);
        assert_eq!(
            offer.negotiate_current(),
            Some(HumanControlProtocolVersion::current())
        );

        let future_only = HumanControlVersionOffer::new(
            "human-controller",
            [HumanControlProtocolVersionRange::new(2, 0, 0).expect("future range")],
            [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
        )
        .expect("bounded offer");
        assert_eq!(future_only.negotiate_current(), None);
        assert_eq!(
            HumanControlVersionOffer::new(
                "human-controller",
                [
                    HumanControlProtocolVersionRange::new(1, 0, 0).expect("range"),
                    HumanControlProtocolVersionRange::new(1, 1, 1).expect("duplicate major"),
                ],
                [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
            ),
            Err(HumanControlProtocolValidationError::InvalidVersionOffer)
        );
        assert_eq!(
            HumanControlProtocolVersionRange::new(1, 2, 1),
            Err(HumanControlProtocolValidationError::InvalidProtocolVersion)
        );
    }

    #[test]
    fn protocol_version_string_is_strict_and_canonical() {
        assert_eq!(HumanControlProtocolVersion::current().to_string(), "1.0");
        assert_eq!("1.0".parse(), Ok(HumanControlProtocolVersion::current()));
        for invalid in ["", "1", "1.", ".0", "01.0", "1.00", "0.1", "1.-1"] {
            assert!(invalid.parse::<HumanControlProtocolVersion>().is_err());
        }
    }

    #[test]
    fn sanitized_protocol_fixture_accepts_v1_and_rejects_future_major() {
        let read = |name| {
            serde_json::from_slice::<HumanControlFixture>(
                &std::fs::read(machine_access_fixture(name)).expect("read protocol fixture"),
            )
            .expect("parse protocol fixture")
        };
        let current = read("human-control-v1.json");
        assert_eq!(current.schema, "keptnear.fixture.human-control.v1");
        assert_eq!(current.protocol.name, HUMAN_CONTROL_PROTOCOL_NAME);
        assert_eq!(
            HumanControlProtocolVersion::new(current.protocol.major, current.protocol.minor),
            Ok(HumanControlProtocolVersion::current())
        );
        let fixture_operations = current
            .operations
            .iter()
            .map(|value| {
                value
                    .parse::<HumanControlOperation>()
                    .expect("known operation")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fixture_operations,
            HUMAN_CONTROL_OPERATION_CONTRACTS
                .iter()
                .map(|contract| contract.operation())
                .collect::<Vec<_>>()
        );

        let future = read("human-control-future.json");
        let offer = HumanControlVersionOffer::new(
            "human-controller",
            [HumanControlProtocolVersionRange::new(
                future.protocol.major,
                future.protocol.minor,
                future.protocol.minor,
            )
            .expect("future range")],
            ["keptnear.human-control.schema.v2".to_owned()],
        )
        .expect("future offer");
        assert_eq!(offer.negotiate_current(), None);
    }

    #[test]
    fn operation_catalog_is_exact_unique_and_rejects_consumer_capabilities() {
        let expected = [
            "hello",
            "controller.challenge",
            "controller.authenticate",
            "controller.lease.renew",
            "readiness.get",
            "machine-access.pause.set",
            "vault.unlock",
            "vault.lock",
            "pending.list",
            "pending.deny",
            "pairing.approve",
            "unlock.approve",
            "credential.review",
            "credential.allow-once",
            "credential.authorize",
            "authorization.snapshot",
            "consumer.detail",
            "usage-profile.catalog",
            "usage-profile.create",
            "usage-profile.remove",
            "access.field.revoke",
            "grant.revoke",
            "consumer.revoke",
            "access.all.revoke",
            "audit.list",
            "audit.clear",
            "audit.export",
            "repair.prepare",
            "shutdown",
        ];
        let actual = HUMAN_CONTROL_OPERATION_CONTRACTS
            .iter()
            .map(|contract| contract.operation().as_str())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            actual.iter().copied().collect::<BTreeSet<_>>().len(),
            actual.len()
        );
        for name in expected {
            let operation = name
                .parse::<HumanControlOperation>()
                .expect("known operation");
            assert_eq!(operation.as_str(), name);
            assert_eq!(operation.contract().introduced_minor(), 0);
        }
        for forbidden in [
            "credential.search",
            "access.request",
            "grant.status",
            "http.request",
            "process.run",
            "secret.get",
            "vault.export",
        ] {
            assert_eq!(
                forbidden.parse::<HumanControlOperation>(),
                Err(HumanControlProtocolValidationError::InvalidOperation)
            );
        }
    }

    #[test]
    fn operation_authentication_and_message_bounds_are_fail_closed() {
        assert_eq!(
            HumanControlOperation::Hello.contract().authentication(),
            HumanControlAuthenticationRequirement::None
        );
        for operation in [
            HumanControlOperation::ControllerChallenge,
            HumanControlOperation::ControllerAuthenticate,
        ] {
            assert_eq!(
                operation.contract().authentication(),
                HumanControlAuthenticationRequirement::Negotiated
            );
        }
        for contract in &HUMAN_CONTROL_OPERATION_CONTRACTS[3..] {
            assert_eq!(
                contract.authentication(),
                HumanControlAuthenticationRequirement::Authenticated
            );
        }
        for contract in HUMAN_CONTROL_OPERATION_CONTRACTS {
            assert!(contract.maximum_request_length() <= MAX_HUMAN_CONTROL_FRAME_LENGTH);
            assert!(contract.maximum_response_length() <= MAX_HUMAN_CONTROL_FRAME_LENGTH);
            assert_ne!(contract.maximum_request_length(), 0);
            assert_ne!(contract.maximum_response_length(), 0);
        }
    }

    #[test]
    fn only_vault_unlock_accepts_unlock_material_and_every_result_is_secret_free() {
        let credential_operations = HUMAN_CONTROL_OPERATION_CONTRACTS
            .iter()
            .filter(|contract| {
                contract.request_secret_class()
                    == HumanControlRequestSecretClass::VaultUnlockCredential
            })
            .map(|contract| contract.operation())
            .collect::<Vec<_>>();
        assert_eq!(credential_operations, [HumanControlOperation::VaultUnlock]);

        let authentication_operations = HUMAN_CONTROL_OPERATION_CONTRACTS
            .iter()
            .filter(|contract| {
                contract.request_secret_class()
                    == HumanControlRequestSecretClass::ControllerAuthentication
            })
            .map(|contract| contract.operation())
            .collect::<Vec<_>>();
        assert_eq!(
            authentication_operations,
            [
                HumanControlOperation::ControllerChallenge,
                HumanControlOperation::ControllerAuthenticate,
            ]
        );
        assert!(HUMAN_CONTROL_OPERATION_CONTRACTS.iter().all(|contract| {
            contract.result_secrecy() == HumanControlResultSecrecy::SecretFree
        }));
    }

    #[test]
    fn fixed_failure_catalog_has_no_free_form_or_reflected_value() {
        let names = HUMAN_CONTROL_FAILURE_CODES
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names.iter().copied().collect::<BTreeSet<_>>().len(),
            names.len()
        );
        for code in HUMAN_CONTROL_FAILURE_CODES {
            assert_eq!(code.as_str().parse::<HumanControlFailureCode>(), Ok(code));
        }
        assert_eq!(
            "private-marker".parse::<HumanControlFailureCode>(),
            Err(HumanControlProtocolValidationError::InvalidFixedValue)
        );
        for action in HUMAN_CONTROL_REQUIRED_ACTIONS {
            assert_eq!(
                action.as_str().parse::<HumanControlRequiredAction>(),
                Ok(action)
            );
        }
        assert_eq!(
            "private-marker".parse::<HumanControlRequiredAction>(),
            Err(HumanControlProtocolValidationError::InvalidFixedValue)
        );
        let failure = HumanControlProtocolFailure::new(
            HumanControlFailureCode::AuthenticationFailed,
            false,
            Some(HumanControlRequiredAction::AuthenticateController),
        );
        let debug = format!("{failure:?}");
        assert!(debug.contains("AuthenticationFailed"));
        assert!(!debug.contains("private-marker"));
        assert_eq!(
            failure.code(),
            HumanControlFailureCode::AuthenticationFailed
        );
        assert!(!failure.retryable());
        assert_eq!(
            failure.required_action(),
            Some(HumanControlRequiredAction::AuthenticateController)
        );
    }
}
