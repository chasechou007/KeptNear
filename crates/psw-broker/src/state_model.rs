use std::fmt::{Display, Formatter};
use std::str::FromStr;

use psw_core::{CredentialId, SecretFieldId, VaultId};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

const LOCAL_ID_BYTE_LENGTH: usize = 16;
const LOCAL_ID_HEX_LENGTH: usize = LOCAL_ID_BYTE_LENGTH * 2;
const CONSUMER_LABEL_MAX_BYTES: usize = 128;
const PROFILE_LABEL_MAX_BYTES: usize = 128;
const EXECUTABLE_NAME_MAX_BYTES: usize = 128;
const BUNDLE_IDENTIFIER_MAX_BYTES: usize = 255;
const TEAM_IDENTIFIER_MAX_BYTES: usize = 64;
const VARIABLE_NAME_MAX_BYTES: usize = 128;
const HEADER_NAME_MAX_BYTES: usize = 128;
const CONSUMER_EVIDENCE_FINGERPRINT_LENGTH: usize = 8;

/// Current JSON schema version for declarative Usage Profile definitions.
pub const CURRENT_USAGE_PROFILE_DEFINITION_VERSION: u16 = 1;
/// Maximum encoded size of one declarative Usage Profile definition.
pub const MAX_USAGE_PROFILE_DEFINITION_BYTES: usize = 2_048;

/// Error returned when a Broker-local stable identifier is not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalIdParseError {
    expected_prefix: &'static str,
}

impl LocalIdParseError {
    const fn new(expected_prefix: &'static str) -> Self {
        Self { expected_prefix }
    }
}

impl Display for LocalIdParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid local identifier; expected {:?} followed by {} lowercase hexadecimal characters",
            self.expected_prefix, LOCAL_ID_HEX_LENGTH
        )
    }
}

impl std::error::Error for LocalIdParseError {}

fn parse_local_id(
    value: &str,
    expected_prefix: &'static str,
) -> Result<[u8; LOCAL_ID_BYTE_LENGTH], LocalIdParseError> {
    let invalid = || LocalIdParseError::new(expected_prefix);
    let encoded = value.strip_prefix(expected_prefix).ok_or_else(invalid)?;
    if encoded.len() != LOCAL_ID_HEX_LENGTH
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }

    let mut bytes = [0_u8; LOCAL_ID_BYTE_LENGTH];
    hex::decode_to_slice(encoded, &mut bytes).map_err(|_| invalid())?;
    Ok(bytes)
}

macro_rules! define_local_id {
    ($name:ident, $description:literal, $prefix:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; LOCAL_ID_BYTE_LENGTH]);

        impl $name {
            /// Generates a random identifier using the operating-system CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                let mut bytes = [0_u8; LOCAL_ID_BYTE_LENGTH];
                OsRng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Returns the 128-bit value backing the identifier.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; LOCAL_ID_BYTE_LENGTH] {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = LocalIdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_local_id(value, $prefix).map(Self)
            }
        }
    };
}

define_local_id!(
    ConsumerId,
    "Immutable identity of one paired machine Consumer.",
    "consumer_"
);
define_local_id!(
    PairingRequestId,
    "Immutable identity of one short-lived Consumer pairing request.",
    "pairing_"
);
define_local_id!(
    AccessRuleId,
    "Immutable identity of one persistent Consumer access rule.",
    "access_rule_"
);
define_local_id!(
    UseGrantId,
    "Immutable identity of one bounded credential-use grant.",
    "use_grant_"
);
define_local_id!(
    UsageProfileId,
    "Immutable identity of one device-local declarative Usage Profile.",
    "usage_profile_"
);
define_local_id!(
    ApprovalRequestId,
    "Immutable identity of one asynchronous local approval request.",
    "approval_"
);
define_local_id!(
    AuditEventId,
    "Immutable identity of one encrypted device-local audit event.",
    "audit_event_"
);
define_local_id!(
    VaultSessionId,
    "Immutable identity of one in-memory unlocked vault session.",
    "vault_session_"
);

/// A non-negative Unix timestamp expressed in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StateTimestamp(i64);

impl StateTimestamp {
    /// Creates a timestamp after validating its canonical range.
    pub fn from_unix_millis(value: i64) -> Result<Self, DeviceStateValidationError> {
        if value < 0 {
            return Err(DeviceStateValidationError::new(
                "timestamp must be non-negative",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the Unix timestamp in milliseconds.
    #[must_use]
    pub const fn unix_millis(self) -> i64 {
        self.0
    }
}

/// A sanitized structural validation error for device-local state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceStateValidationError {
    reason: &'static str,
}

impl DeviceStateValidationError {
    pub(crate) const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Returns a value-free explanation of the invalid structure.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }
}

impl Display for DeviceStateValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid device state: {}", self.reason)
    }
}

impl std::error::Error for DeviceStateValidationError {}

/// Error returned for an unknown canonical device-state enum value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceStateValueParseError {
    expected: &'static str,
}

impl DeviceStateValueParseError {
    const fn new(expected: &'static str) -> Self {
        Self { expected }
    }
}

impl Display for DeviceStateValueParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid device-state value; expected {}",
            self.expected
        )
    }
}

impl std::error::Error for DeviceStateValueParseError {}

macro_rules! define_string_enum {
    (
        $name:ident,
        $description:literal,
        $expected:literal,
        { $($variant:ident => $serialized:literal),+ $(,)? }
    ) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum $name {
            $(
                #[doc = "A supported canonical value."]
                $variant,
            )+
        }

        impl $name {
            /// Returns the canonical storage and protocol value.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $serialized),+
                }
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = DeviceStateValueParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($serialized => Ok(Self::$variant),)+
                    _ => Err(DeviceStateValueParseError::new($expected)),
                }
            }
        }
    };
}

define_string_enum!(
    CapabilityName,
    "Versioned Broker capability name stored in rules, grants, approvals, and audit.",
    "a supported Broker capability",
    {
        CredentialSearch => "credential.search",
        AccessRequest => "access.request",
        GrantStatus => "grant.status",
        GrantRevoke => "grant.revoke",
        HttpRequest => "http.request",
        ProcessRun => "process.run",
    }
);

define_string_enum!(
    ConfirmationPolicy,
    "Persistent Access Rule confirmation policy.",
    "a supported confirmation policy",
    {
        EveryUse => "every-use",
        OncePerUnlockSession => "once-per-unlock-session",
        AutomaticWhileUnlocked => "automatic-while-unlocked",
    }
);

define_string_enum!(
    GrantScope,
    "Bound on operations authorized by a Use Grant.",
    "a supported grant scope",
    {
        OneOperation => "one-operation",
        UnlockSession => "unlock-session",
    }
);

define_string_enum!(
    ApprovalKind,
    "Human decision represented by an asynchronous approval.",
    "a supported approval kind",
    {
        Pairing => "pairing",
        Unlock => "unlock",
        Access => "access",
        CredentialAccess => "credential-access",
    }
);

define_string_enum!(
    ApprovalStatus,
    "Current state of an asynchronous approval request.",
    "a supported approval status",
    {
        Pending => "pending",
        Approved => "approved",
        Denied => "denied",
        Expired => "expired",
        Cancelled => "cancelled",
    }
);

define_string_enum!(
    AuditEventKind,
    "Security decision category recorded in local audit.",
    "a supported audit event kind",
    {
        Pairing => "pairing",
        Authorization => "authorization",
        Grant => "grant",
        CredentialUse => "credential-use",
        Pause => "pause",
        Revocation => "revocation",
    }
);

define_string_enum!(
    AuditDecision,
    "Non-secret outcome recorded for an audit event.",
    "a supported audit decision",
    {
        Allowed => "allowed",
        Denied => "denied",
        Pending => "pending",
        Revoked => "revoked",
        Paused => "paused",
        Resumed => "resumed",
        Failed => "failed",
    }
);

define_string_enum!(
    ConfirmationMethod,
    "Non-secret method that authorized or denied an audited decision.",
    "a supported confirmation method",
    {
        None => "none",
        UserApproval => "user-approval",
        MasterPassword => "master-password",
        LocalAuthentication => "local-authentication",
        PersistentRule => "persistent-rule",
    }
);

/// A capability name paired with its independent version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Capability {
    name: CapabilityName,
    version: u16,
}

impl Capability {
    /// Creates a versioned capability reference.
    pub fn new(name: CapabilityName, version: u16) -> Result<Self, DeviceStateValidationError> {
        if version == 0 {
            return Err(DeviceStateValidationError::new(
                "capability version must be non-zero",
            ));
        }
        Ok(Self { name, version })
    }

    /// Creates a version-one capability reference.
    #[must_use]
    pub const fn v1(name: CapabilityName) -> Self {
        Self { name, version: 1 }
    }

    /// Returns the capability name.
    #[must_use]
    pub const fn name(self) -> CapabilityName {
        self.name
    }

    /// Returns the capability version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }
}

/// Short display fingerprint for cryptographic Consumer evidence.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConsumerEvidenceFingerprint([u8; CONSUMER_EVIDENCE_FINGERPRINT_LENGTH]);

impl ConsumerEvidenceFingerprint {
    pub(crate) fn from_sha256_digest(digest: &[u8; 32]) -> Self {
        let mut fingerprint = [0_u8; CONSUMER_EVIDENCE_FINGERPRINT_LENGTH];
        fingerprint.copy_from_slice(&digest[..CONSUMER_EVIDENCE_FINGERPRINT_LENGTH]);
        Self(fingerprint)
    }

    /// Returns the first 64 bits of the underlying SHA-256 evidence digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONSUMER_EVIDENCE_FINGERPRINT_LENGTH] {
        &self.0
    }
}

impl Display for ConsumerEvidenceFingerprint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 && index % 2 == 0 {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for ConsumerEvidenceFingerprint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ConsumerEvidenceFingerprint")
            .field(&self.to_string())
            .finish()
    }
}

/// Display state for optional operating-system code-signing evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerCodeSigningEvidence {
    /// No verified code-signing evidence was available.
    NoVerifiedSignature,
    /// The running code verified but did not carry an Apple team identifier.
    VerifiedWithoutTeamIdentifier,
    /// The running code verified and carried an Apple team identifier.
    VerifiedWithTeamIdentifier,
}

/// Bounded operating-system evidence observed during Consumer pairing.
///
/// This structure cannot hold a full executable path. It is supporting
/// evidence only and is never the Consumer's protocol identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservedConsumerIdentity {
    executable_name: Option<String>,
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    code_signature_digest: Option<[u8; 32]>,
}

impl ObservedConsumerIdentity {
    /// Creates bounded, path-free supporting identity evidence.
    pub fn new(
        executable_name: Option<String>,
        bundle_identifier: Option<String>,
        team_identifier: Option<String>,
        code_signature_digest: Option<[u8; 32]>,
    ) -> Result<Self, DeviceStateValidationError> {
        if let Some(value) = executable_name.as_deref() {
            validate_bounded_text(
                value,
                EXECUTABLE_NAME_MAX_BYTES,
                "executable name is empty",
                "executable name is too long",
            )?;
            if value.contains('/') || value.contains('\\') {
                return Err(DeviceStateValidationError::new(
                    "executable evidence must not contain a path",
                ));
            }
        }
        if let Some(value) = bundle_identifier.as_deref() {
            validate_identifier_text(
                value,
                BUNDLE_IDENTIFIER_MAX_BYTES,
                "bundle identifier is invalid",
            )?;
        }
        if let Some(value) = team_identifier.as_deref() {
            validate_identifier_text(
                value,
                TEAM_IDENTIFIER_MAX_BYTES,
                "team identifier is invalid",
            )?;
        }

        Ok(Self {
            executable_name,
            bundle_identifier,
            team_identifier,
            code_signature_digest,
        })
    }

    /// Returns the observed executable basename.
    #[must_use]
    pub fn executable_name(&self) -> Option<&str> {
        self.executable_name.as_deref()
    }

    /// Returns the observed bundle identifier.
    #[must_use]
    pub fn bundle_identifier(&self) -> Option<&str> {
        self.bundle_identifier.as_deref()
    }

    /// Returns the observed Apple team identifier when available.
    #[must_use]
    pub fn team_identifier(&self) -> Option<&str> {
        self.team_identifier.as_deref()
    }

    /// Returns the observed code-signature digest when available.
    #[must_use]
    pub const fn code_signature_digest(&self) -> Option<&[u8; 32]> {
        self.code_signature_digest.as_ref()
    }

    /// Returns a display-safe classification without requiring Apple signing.
    #[must_use]
    pub const fn code_signing_evidence(&self) -> ConsumerCodeSigningEvidence {
        match (self.code_signature_digest, self.team_identifier.as_ref()) {
            (Some(_), Some(_)) => ConsumerCodeSigningEvidence::VerifiedWithTeamIdentifier,
            (Some(_), None) => ConsumerCodeSigningEvidence::VerifiedWithoutTeamIdentifier,
            (None, _) => ConsumerCodeSigningEvidence::NoVerifiedSignature,
        }
    }

    /// Returns a short display fingerprint of verified code-signing evidence.
    #[must_use]
    pub fn code_signature_fingerprint(&self) -> Option<ConsumerEvidenceFingerprint> {
        self.code_signature_digest
            .as_ref()
            .map(ConsumerEvidenceFingerprint::from_sha256_digest)
    }
}

/// One approved, device-local machine Consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Consumer {
    consumer_id: ConsumerId,
    pairing_public_key: [u8; 32],
    label: String,
    observed_identity: ObservedConsumerIdentity,
    created_at: StateTimestamp,
}

impl Consumer {
    /// Creates a Consumer with a random immutable identity.
    pub fn new(
        pairing_public_key: [u8; 32],
        label: String,
        observed_identity: ObservedConsumerIdentity,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        Self::with_id(
            ConsumerId::generate(),
            pairing_public_key,
            label,
            observed_identity,
            created_at,
        )
    }

    /// Restores a Consumer with a previously allocated identity.
    pub fn with_id(
        consumer_id: ConsumerId,
        pairing_public_key: [u8; 32],
        label: String,
        observed_identity: ObservedConsumerIdentity,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        validate_bounded_text(
            &label,
            CONSUMER_LABEL_MAX_BYTES,
            "Consumer label is empty",
            "Consumer label is too long",
        )?;
        if pairing_public_key.iter().all(|byte| *byte == 0) {
            return Err(DeviceStateValidationError::new(
                "Consumer public key must not be all zero",
            ));
        }
        Ok(Self {
            consumer_id,
            pairing_public_key,
            label,
            observed_identity,
            created_at,
        })
    }

    /// Returns the immutable Consumer identity.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the Consumer pairing public key.
    #[must_use]
    pub const fn pairing_public_key(&self) -> &[u8; 32] {
        &self.pairing_public_key
    }

    /// Returns the user-controlled local label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns bounded supporting operating-system evidence.
    #[must_use]
    pub const fn observed_identity(&self) -> &ObservedConsumerIdentity {
        &self.observed_identity
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }
}

/// Stable credential and secret-field scope used by authorization state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CredentialFieldScope {
    vault_id: VaultId,
    credential_id: CredentialId,
    secret_field_id: SecretFieldId,
}

impl CredentialFieldScope {
    /// Creates one exact vault, credential, and secret-field scope.
    #[must_use]
    pub const fn new(
        vault_id: VaultId,
        credential_id: CredentialId,
        secret_field_id: SecretFieldId,
    ) -> Self {
        Self {
            vault_id,
            credential_id,
            secret_field_id,
        }
    }

    /// Returns the immutable vault identity.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Returns the immutable credential identity.
    #[must_use]
    pub const fn credential_id(self) -> CredentialId {
        self.credential_id
    }

    /// Returns the immutable secret-field identity.
    #[must_use]
    pub const fn secret_field_id(self) -> SecretFieldId {
        self.secret_field_id
    }
}

/// Exact Consumer, field, and capability authorization target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorizationTarget {
    consumer_id: ConsumerId,
    field_scope: CredentialFieldScope,
    capability: Capability,
}

impl AuthorizationTarget {
    /// Creates an exact authorization target.
    #[must_use]
    pub const fn new(
        consumer_id: ConsumerId,
        field_scope: CredentialFieldScope,
        capability: Capability,
    ) -> Self {
        Self {
            consumer_id,
            field_scope,
            capability,
        }
    }

    /// Returns the Consumer identity.
    #[must_use]
    pub const fn consumer_id(self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the credential field scope.
    #[must_use]
    pub const fn field_scope(self) -> CredentialFieldScope {
        self.field_scope
    }

    /// Returns the versioned capability.
    #[must_use]
    pub const fn capability(self) -> Capability {
        self.capability
    }
}

/// Expiry boundary for a persistent Access Rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleLifetime {
    /// The rule remains until explicit revocation.
    Persistent,
    /// The rule expires at an absolute timestamp.
    Until(StateTimestamp),
}

/// One persistent field-scoped Consumer authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRule {
    access_rule_id: AccessRuleId,
    target: AuthorizationTarget,
    confirmation_policy: ConfirmationPolicy,
    lifetime: RuleLifetime,
    created_at: StateTimestamp,
}

impl AccessRule {
    /// Creates an Access Rule with a random immutable identity.
    pub fn new(
        target: AuthorizationTarget,
        confirmation_policy: ConfirmationPolicy,
        lifetime: RuleLifetime,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        Self::with_id(
            AccessRuleId::generate(),
            target,
            confirmation_policy,
            lifetime,
            created_at,
        )
    }

    /// Restores an Access Rule with a previously allocated identity.
    pub fn with_id(
        access_rule_id: AccessRuleId,
        target: AuthorizationTarget,
        confirmation_policy: ConfirmationPolicy,
        lifetime: RuleLifetime,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        if matches!(lifetime, RuleLifetime::Until(expires_at) if expires_at <= created_at) {
            return Err(DeviceStateValidationError::new(
                "Access Rule expiry must follow creation",
            ));
        }
        Ok(Self {
            access_rule_id,
            target,
            confirmation_policy,
            lifetime,
            created_at,
        })
    }

    /// Returns the immutable Access Rule identity.
    #[must_use]
    pub const fn access_rule_id(&self) -> AccessRuleId {
        self.access_rule_id
    }

    /// Returns the exact authorization target.
    #[must_use]
    pub const fn target(&self) -> AuthorizationTarget {
        self.target
    }

    /// Returns the confirmation policy.
    #[must_use]
    pub const fn confirmation_policy(&self) -> ConfirmationPolicy {
        self.confirmation_policy
    }

    /// Returns the rule lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> RuleLifetime {
        self.lifetime
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }

    /// Returns whether this rule is active at the supplied wall-clock boundary.
    #[must_use]
    pub fn is_active_at(&self, evaluated_at: StateTimestamp) -> bool {
        match self.lifetime {
            RuleLifetime::Persistent => true,
            RuleLifetime::Until(expires_at) => {
                evaluated_at >= self.created_at && evaluated_at < expires_at
            }
        }
    }
}

/// One bounded authorization to perform a credential operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UseGrant {
    use_grant_id: UseGrantId,
    target: AuthorizationTarget,
    source_rule_id: Option<AccessRuleId>,
    vault_session_id: VaultSessionId,
    scope: GrantScope,
    created_at: StateTimestamp,
    expires_at: StateTimestamp,
}

impl UseGrant {
    /// Creates a Use Grant with a random immutable identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: AuthorizationTarget,
        source_rule_id: Option<AccessRuleId>,
        vault_session_id: VaultSessionId,
        scope: GrantScope,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        Self::with_id(
            UseGrantId::generate(),
            target,
            source_rule_id,
            vault_session_id,
            scope,
            created_at,
            expires_at,
        )
    }

    /// Restores a Use Grant with a previously allocated identity.
    #[allow(clippy::too_many_arguments)]
    pub fn with_id(
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        source_rule_id: Option<AccessRuleId>,
        vault_session_id: VaultSessionId,
        scope: GrantScope,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        if expires_at <= created_at {
            return Err(DeviceStateValidationError::new(
                "Use Grant expiry must follow creation",
            ));
        }
        Ok(Self {
            use_grant_id,
            target,
            source_rule_id,
            vault_session_id,
            scope,
            created_at,
            expires_at,
        })
    }

    /// Returns the immutable Use Grant identity.
    #[must_use]
    pub const fn use_grant_id(&self) -> UseGrantId {
        self.use_grant_id
    }

    /// Returns the exact authorization target.
    #[must_use]
    pub const fn target(&self) -> AuthorizationTarget {
        self.target
    }

    /// Returns the persistent rule that authorized this grant, if any.
    #[must_use]
    pub const fn source_rule_id(&self) -> Option<AccessRuleId> {
        self.source_rule_id
    }

    /// Returns the unlocked vault session that bounds this grant.
    #[must_use]
    pub const fn vault_session_id(&self) -> VaultSessionId {
        self.vault_session_id
    }

    /// Returns the operation-count scope.
    #[must_use]
    pub const fn scope(&self) -> GrantScope {
        self.scope
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }

    /// Returns the absolute expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> StateTimestamp {
        self.expires_at
    }

    /// Returns whether this grant is active at the supplied wall-clock boundary.
    #[must_use]
    pub fn is_active_at(&self, evaluated_at: StateTimestamp) -> bool {
        evaluated_at >= self.created_at && evaluated_at < self.expires_at
    }
}

/// Declarative, non-script secret placement stored by a Usage Profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "placement", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UsagePlacement {
    /// Place a secret in one child-only environment variable.
    ProcessEnvironment {
        /// Environment variable receiving the secret.
        variable_name: String,
    },
    /// Write only the secret to child standard input.
    ProcessStdin {
        /// Whether to append one newline after the secret.
        append_newline: bool,
    },
    /// Write the secret through an anonymous inherited descriptor.
    ProcessFileDescriptor {
        /// Optional child environment variable receiving the descriptor reference.
        reference_variable_name: Option<String>,
        /// Whether the reference uses `/dev/fd/<n>` instead of the numeric descriptor.
        render_dev_fd_path: bool,
    },
    /// Place a fixed Bearer value in the HTTP Authorization header.
    HttpBearerAuthorization {},
    /// Place a secret directly in one named HTTP header.
    HttpHeader {
        /// Header name receiving the secret value.
        header_name: String,
    },
}

impl UsagePlacement {
    fn validate(&self, capability: Capability) -> Result<(), DeviceStateValidationError> {
        match self {
            Self::ProcessEnvironment { variable_name } => {
                validate_variable_name(variable_name)?;
                validate_process_capability(capability)
            }
            Self::ProcessStdin { .. } => validate_process_capability(capability),
            Self::ProcessFileDescriptor {
                reference_variable_name,
                ..
            } => {
                if let Some(variable_name) = reference_variable_name {
                    validate_variable_name(variable_name)?;
                }
                validate_process_capability(capability)
            }
            Self::HttpBearerAuthorization {} => validate_http_capability(capability),
            Self::HttpHeader { header_name } => {
                validate_header_name(header_name)?;
                validate_http_capability(capability)
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UsageProfileCapabilityWire {
    name: String,
    version: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UsageProfileDefinitionWire {
    definition_version: u16,
    capability: UsageProfileCapabilityWire,
    secret_placement: UsagePlacement,
}

/// A versioned, declarative Usage Profile definition with no executable content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageProfileDefinition {
    capability: Capability,
    placement: UsagePlacement,
}

impl UsageProfileDefinition {
    /// Creates a definition after validating the capability and placement.
    pub fn new(
        capability: Capability,
        placement: UsagePlacement,
    ) -> Result<Self, DeviceStateValidationError> {
        placement.validate(capability)?;
        Ok(Self {
            capability,
            placement,
        })
    }

    /// Decodes a bounded versioned JSON definition and rejects unknown fields.
    pub fn from_json(encoded: &str) -> Result<Self, DeviceStateValidationError> {
        if encoded.is_empty() || encoded.len() > MAX_USAGE_PROFILE_DEFINITION_BYTES {
            return Err(DeviceStateValidationError::new(
                "Usage Profile definition size is invalid",
            ));
        }
        let wire: UsageProfileDefinitionWire = serde_json::from_str(encoded).map_err(|_| {
            DeviceStateValidationError::new("Usage Profile definition JSON is invalid")
        })?;
        if wire.definition_version != CURRENT_USAGE_PROFILE_DEFINITION_VERSION {
            return Err(DeviceStateValidationError::new(
                "Usage Profile definition version is unsupported",
            ));
        }
        let capability_name = wire.capability.name.parse().map_err(|_| {
            DeviceStateValidationError::new("Usage Profile capability is unsupported")
        })?;
        let capability = Capability::new(capability_name, wire.capability.version)?;
        Self::new(capability, wire.secret_placement)
    }

    /// Encodes the bounded canonical JSON definition.
    pub fn to_json(&self) -> Result<String, DeviceStateValidationError> {
        let wire = UsageProfileDefinitionWire {
            definition_version: CURRENT_USAGE_PROFILE_DEFINITION_VERSION,
            capability: UsageProfileCapabilityWire {
                name: self.capability.name().as_str().to_owned(),
                version: self.capability.version(),
            },
            secret_placement: self.placement.clone(),
        };
        let encoded = serde_json::to_string(&wire).map_err(|_| {
            DeviceStateValidationError::new("Usage Profile definition could not be encoded")
        })?;
        if encoded.len() > MAX_USAGE_PROFILE_DEFINITION_BYTES {
            return Err(DeviceStateValidationError::new(
                "Usage Profile definition size is invalid",
            ));
        }
        Ok(encoded)
    }

    /// Returns the current definition schema version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        CURRENT_USAGE_PROFILE_DEFINITION_VERSION
    }

    /// Returns the operation capability configured by the definition.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the typed secret-placement declaration.
    #[must_use]
    pub const fn placement(&self) -> &UsagePlacement {
        &self.placement
    }
}

/// One device-local declarative Usage Profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageProfile {
    usage_profile_id: UsageProfileId,
    consumer_id: ConsumerId,
    label: String,
    definition: UsageProfileDefinition,
    created_at: StateTimestamp,
}

impl UsageProfile {
    /// Creates a Usage Profile with a random immutable identity.
    pub fn new(
        consumer_id: ConsumerId,
        label: String,
        capability: Capability,
        placement: UsagePlacement,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        Self::from_definition(
            consumer_id,
            label,
            UsageProfileDefinition::new(capability, placement)?,
            created_at,
        )
    }

    /// Creates a Usage Profile from a validated declarative definition.
    pub fn from_definition(
        consumer_id: ConsumerId,
        label: String,
        definition: UsageProfileDefinition,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        Self::with_id_and_definition(
            UsageProfileId::generate(),
            consumer_id,
            label,
            definition,
            created_at,
        )
    }

    /// Restores a Usage Profile with a previously allocated identity.
    pub fn with_id(
        usage_profile_id: UsageProfileId,
        consumer_id: ConsumerId,
        label: String,
        capability: Capability,
        placement: UsagePlacement,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        Self::with_id_and_definition(
            usage_profile_id,
            consumer_id,
            label,
            UsageProfileDefinition::new(capability, placement)?,
            created_at,
        )
    }

    /// Restores a Usage Profile from a validated declarative definition.
    pub fn with_id_and_definition(
        usage_profile_id: UsageProfileId,
        consumer_id: ConsumerId,
        label: String,
        definition: UsageProfileDefinition,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        validate_bounded_text(
            &label,
            PROFILE_LABEL_MAX_BYTES,
            "Usage Profile label is empty",
            "Usage Profile label is too long",
        )?;
        Ok(Self {
            usage_profile_id,
            consumer_id,
            label,
            definition,
            created_at,
        })
    }

    /// Returns the immutable Usage Profile identity.
    #[must_use]
    pub const fn usage_profile_id(&self) -> UsageProfileId {
        self.usage_profile_id
    }

    /// Returns the Consumer that owns this local profile.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        self.consumer_id
    }

    /// Returns the user-controlled local label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the capability configured by the profile.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.definition.capability()
    }

    /// Returns the declarative placement definition.
    #[must_use]
    pub const fn placement(&self) -> &UsagePlacement {
        self.definition.placement()
    }

    /// Returns the complete versioned declarative definition.
    #[must_use]
    pub const fn definition(&self) -> &UsageProfileDefinition {
        &self.definition
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }
}

/// Secret-free subject of an asynchronous approval request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalSubject {
    /// Pair one proposed Consumer public key.
    Pairing {
        /// Immutable identity proposed for the Consumer.
        consumer_id: ConsumerId,
        /// Public key whose private half remains with the Consumer.
        pairing_public_key: [u8; 32],
        /// Bounded path-free operating-system evidence.
        observed_identity: ObservedConsumerIdentity,
    },
    /// Unlock one vault for a requesting Consumer.
    Unlock {
        /// Consumer waiting for the unlock.
        consumer_id: ConsumerId,
        /// Vault that must be unlocked.
        vault_id: VaultId,
    },
    /// Authorize one exact credential field and capability.
    Access {
        /// Exact field-scoped authorization target.
        target: AuthorizationTarget,
    },
    /// Match a previously unauthorized Credential in the human control plane.
    CredentialAccess {
        /// Paired Consumer waiting for a selection.
        consumer_id: ConsumerId,
        /// Vault in which the human will match candidates.
        vault_id: VaultId,
        /// Field-scoped capability requested after selection.
        capability: Capability,
    },
}

impl ApprovalSubject {
    /// Returns the approval kind.
    #[must_use]
    pub const fn kind(&self) -> ApprovalKind {
        match self {
            Self::Pairing { .. } => ApprovalKind::Pairing,
            Self::Unlock { .. } => ApprovalKind::Unlock,
            Self::Access { .. } => ApprovalKind::Access,
            Self::CredentialAccess { .. } => ApprovalKind::CredentialAccess,
        }
    }

    /// Returns an authorization target only for an explicit access decision.
    #[must_use]
    pub const fn access_target(&self) -> Option<AuthorizationTarget> {
        match self {
            Self::Access { target } => Some(*target),
            Self::Pairing { .. } | Self::Unlock { .. } | Self::CredentialAccess { .. } => None,
        }
    }

    /// Returns the Consumer waiting for this decision.
    #[must_use]
    pub const fn consumer_id(&self) -> ConsumerId {
        match self {
            Self::Pairing { consumer_id, .. }
            | Self::Unlock { consumer_id, .. }
            | Self::CredentialAccess { consumer_id, .. } => *consumer_id,
            Self::Access { target } => target.consumer_id(),
        }
    }

    fn validate(&self) -> Result<(), DeviceStateValidationError> {
        if let Self::Pairing {
            pairing_public_key, ..
        } = self
        {
            if pairing_public_key.iter().all(|byte| *byte == 0) {
                return Err(DeviceStateValidationError::new(
                    "pairing approval public key must not be all zero",
                ));
            }
        }
        Ok(())
    }
}

/// One stable asynchronous approval request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequest {
    approval_request_id: ApprovalRequestId,
    subject: ApprovalSubject,
    coalescing_digest: [u8; 32],
    status: ApprovalStatus,
    created_at: StateTimestamp,
    expires_at: StateTimestamp,
    resolved_at: Option<StateTimestamp>,
}

impl ApprovalRequest {
    /// Creates a pending approval with a random immutable identity.
    pub fn pending(
        subject: ApprovalSubject,
        coalescing_digest: [u8; 32],
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
    ) -> Result<Self, DeviceStateValidationError> {
        Self::with_id(
            ApprovalRequestId::generate(),
            subject,
            coalescing_digest,
            ApprovalStatus::Pending,
            created_at,
            expires_at,
            None,
        )
    }

    /// Restores an approval with a previously allocated identity and state.
    #[allow(clippy::too_many_arguments)]
    pub fn with_id(
        approval_request_id: ApprovalRequestId,
        subject: ApprovalSubject,
        coalescing_digest: [u8; 32],
        status: ApprovalStatus,
        created_at: StateTimestamp,
        expires_at: StateTimestamp,
        resolved_at: Option<StateTimestamp>,
    ) -> Result<Self, DeviceStateValidationError> {
        subject.validate()?;
        if coalescing_digest.iter().all(|byte| *byte == 0) {
            return Err(DeviceStateValidationError::new(
                "approval coalescing digest must not be all zero",
            ));
        }
        if expires_at <= created_at {
            return Err(DeviceStateValidationError::new(
                "approval expiry must follow creation",
            ));
        }
        match (status, resolved_at) {
            (ApprovalStatus::Pending, None) => {}
            (ApprovalStatus::Pending, Some(_)) => {
                return Err(DeviceStateValidationError::new(
                    "pending approval must not have a resolution timestamp",
                ));
            }
            (_, Some(value)) if value >= created_at => {}
            (_, Some(_)) => {
                return Err(DeviceStateValidationError::new(
                    "approval resolution must not precede creation",
                ));
            }
            (_, None) => {
                return Err(DeviceStateValidationError::new(
                    "resolved approval requires a resolution timestamp",
                ));
            }
        }
        Ok(Self {
            approval_request_id,
            subject,
            coalescing_digest,
            status,
            created_at,
            expires_at,
            resolved_at,
        })
    }

    /// Returns the immutable approval identity.
    #[must_use]
    pub const fn approval_request_id(&self) -> ApprovalRequestId {
        self.approval_request_id
    }

    /// Returns the secret-free approval subject.
    #[must_use]
    pub const fn subject(&self) -> &ApprovalSubject {
        &self.subject
    }

    /// Returns the keyed request-equivalence digest.
    #[must_use]
    pub const fn coalescing_digest(&self) -> &[u8; 32] {
        &self.coalescing_digest
    }

    /// Returns the current approval status.
    #[must_use]
    pub const fn status(&self) -> ApprovalStatus {
        self.status
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> StateTimestamp {
        self.created_at
    }

    /// Returns the bounded expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> StateTimestamp {
        self.expires_at
    }

    /// Returns the resolution timestamp for a terminal request.
    #[must_use]
    pub const fn resolved_at(&self) -> Option<StateTimestamp> {
        self.resolved_at
    }
}

/// Stable identities attributable to a local audit event.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditScope {
    consumer_id: Option<ConsumerId>,
    field_scope: Option<CredentialFieldScope>,
    capability: Option<Capability>,
    use_grant_id: Option<UseGrantId>,
}

impl AuditScope {
    /// Creates a scope from stable identities only.
    #[must_use]
    pub const fn new(
        consumer_id: Option<ConsumerId>,
        field_scope: Option<CredentialFieldScope>,
        capability: Option<Capability>,
        use_grant_id: Option<UseGrantId>,
    ) -> Self {
        Self {
            consumer_id,
            field_scope,
            capability,
            use_grant_id,
        }
    }

    /// Returns the Consumer identity when attributable.
    #[must_use]
    pub const fn consumer_id(self) -> Option<ConsumerId> {
        self.consumer_id
    }

    /// Returns the exact field scope when attributable.
    #[must_use]
    pub const fn field_scope(self) -> Option<CredentialFieldScope> {
        self.field_scope
    }

    /// Returns the capability when attributable.
    #[must_use]
    pub const fn capability(self) -> Option<Capability> {
        self.capability
    }

    /// Returns the Use Grant identity when attributable.
    #[must_use]
    pub const fn use_grant_id(self) -> Option<UseGrantId> {
        self.use_grant_id
    }
}

/// One immutable, secret-free audit event stored in the encrypted database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    audit_event_id: AuditEventId,
    occurred_at: StateTimestamp,
    kind: AuditEventKind,
    scope: AuditScope,
    decision: AuditDecision,
    confirmation_method: ConfirmationMethod,
}

impl AuditEvent {
    /// Creates an audit event with a random immutable identity.
    #[must_use]
    pub fn new(
        occurred_at: StateTimestamp,
        kind: AuditEventKind,
        scope: AuditScope,
        decision: AuditDecision,
        confirmation_method: ConfirmationMethod,
    ) -> Self {
        Self::with_id(
            AuditEventId::generate(),
            occurred_at,
            kind,
            scope,
            decision,
            confirmation_method,
        )
    }

    /// Restores an audit event with a previously allocated identity.
    #[must_use]
    pub const fn with_id(
        audit_event_id: AuditEventId,
        occurred_at: StateTimestamp,
        kind: AuditEventKind,
        scope: AuditScope,
        decision: AuditDecision,
        confirmation_method: ConfirmationMethod,
    ) -> Self {
        Self {
            audit_event_id,
            occurred_at,
            kind,
            scope,
            decision,
            confirmation_method,
        }
    }

    /// Returns the immutable audit event identity.
    #[must_use]
    pub const fn audit_event_id(&self) -> AuditEventId {
        self.audit_event_id
    }

    /// Returns the event timestamp.
    #[must_use]
    pub const fn occurred_at(&self) -> StateTimestamp {
        self.occurred_at
    }

    /// Returns the event category.
    #[must_use]
    pub const fn kind(&self) -> AuditEventKind {
        self.kind
    }

    /// Returns stable attributable identities.
    #[must_use]
    pub const fn scope(&self) -> AuditScope {
        self.scope
    }

    /// Returns the non-secret decision.
    #[must_use]
    pub const fn decision(&self) -> AuditDecision {
        self.decision
    }

    /// Returns the non-secret confirmation method.
    #[must_use]
    pub const fn confirmation_method(&self) -> ConfirmationMethod {
        self.confirmation_method
    }
}

fn validate_bounded_text(
    value: &str,
    max_bytes: usize,
    empty_reason: &'static str,
    length_reason: &'static str,
) -> Result<(), DeviceStateValidationError> {
    if value.trim().is_empty() {
        return Err(DeviceStateValidationError::new(empty_reason));
    }
    if value.len() > max_bytes {
        return Err(DeviceStateValidationError::new(length_reason));
    }
    if value.chars().any(char::is_control) {
        return Err(DeviceStateValidationError::new(
            "device-state text contains control characters",
        ));
    }
    Ok(())
}

fn validate_identifier_text(
    value: &str,
    max_bytes: usize,
    reason: &'static str,
) -> Result<(), DeviceStateValidationError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(DeviceStateValidationError::new(reason));
    }
    Ok(())
}

fn validate_variable_name(value: &str) -> Result<(), DeviceStateValidationError> {
    if value.is_empty() || value.len() > VARIABLE_NAME_MAX_BYTES {
        return Err(DeviceStateValidationError::new(
            "environment variable name is invalid",
        ));
    }
    let mut bytes = value.bytes();
    let first = bytes.next().expect("non-empty checked");
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(DeviceStateValidationError::new(
            "environment variable name is invalid",
        ));
    }
    Ok(())
}

fn validate_header_name(value: &str) -> Result<(), DeviceStateValidationError> {
    if value.is_empty()
        || value.len() > HEADER_NAME_MAX_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(DeviceStateValidationError::new(
            "HTTP header name is invalid",
        ));
    }
    Ok(())
}

fn validate_process_capability(capability: Capability) -> Result<(), DeviceStateValidationError> {
    if capability.name() != CapabilityName::ProcessRun {
        return Err(DeviceStateValidationError::new(
            "process placement requires process.run",
        ));
    }
    Ok(())
}

fn validate_http_capability(capability: Capability) -> Result<(), DeviceStateValidationError> {
    if capability.name() != CapabilityName::HttpRequest {
        return Err(DeviceStateValidationError::new(
            "HTTP placement requires http.request",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn local_ids_are_canonical_and_kind_separated() {
        let consumer: ConsumerId = format!("consumer_{SAMPLE_HEX}")
            .parse()
            .expect("parse Consumer ID");
        assert_eq!(consumer.to_string(), format!("consumer_{SAMPLE_HEX}"));
        assert!(format!("access_rule_{SAMPLE_HEX}")
            .parse::<ConsumerId>()
            .is_err());
        assert!(format!("consumer_{}", SAMPLE_HEX.to_ascii_uppercase())
            .parse::<ConsumerId>()
            .is_err());
        assert_ne!(ConsumerId::generate(), ConsumerId::generate());
    }

    #[test]
    fn whole_vault_export_is_not_a_machine_capability() {
        assert_eq!(
            [
                CapabilityName::CredentialSearch,
                CapabilityName::AccessRequest,
                CapabilityName::GrantStatus,
                CapabilityName::GrantRevoke,
                CapabilityName::HttpRequest,
                CapabilityName::ProcessRun,
            ]
            .map(CapabilityName::as_str),
            [
                "credential.search",
                "access.request",
                "grant.status",
                "grant.revoke",
                "http.request",
                "process.run",
            ]
        );
        for rejected in [
            "vault.export",
            "credential.export",
            "secret.export",
            "plaintext.export",
        ] {
            assert!(rejected.parse::<CapabilityName>().is_err());
        }
    }

    #[test]
    fn observed_identity_rejects_paths_and_unbounded_values() {
        assert!(ObservedConsumerIdentity::new(
            Some("/Applications/Tool.app/Contents/MacOS/tool".to_owned()),
            None,
            None,
            None,
        )
        .is_err());
        assert!(ObservedConsumerIdentity::new(
            Some("tool".to_owned()),
            Some("com.example.tool".to_owned()),
            Some("TEAM123".to_owned()),
            Some([7_u8; 32]),
        )
        .is_ok());
    }

    #[test]
    fn observed_identity_presents_optional_signing_evidence_without_requiring_it() {
        let unsigned =
            ObservedConsumerIdentity::new(Some("local-tool".to_owned()), None, None, None)
                .expect("unsigned evidence");
        assert_eq!(
            unsigned.code_signing_evidence(),
            ConsumerCodeSigningEvidence::NoVerifiedSignature
        );
        assert_eq!(unsigned.code_signature_fingerprint(), None);

        let local = ObservedConsumerIdentity::new(
            Some("local-tool".to_owned()),
            None,
            None,
            Some([0xab; 32]),
        )
        .expect("local signing evidence");
        assert_eq!(
            local.code_signing_evidence(),
            ConsumerCodeSigningEvidence::VerifiedWithoutTeamIdentifier
        );
        assert_eq!(
            local
                .code_signature_fingerprint()
                .expect("signature fingerprint")
                .to_string(),
            "ABAB-ABAB-ABAB-ABAB"
        );

        let team = ObservedConsumerIdentity::new(
            Some("signed-tool".to_owned()),
            Some("com.example.tool".to_owned()),
            Some("TEAM123".to_owned()),
            Some([0xcd; 32]),
        )
        .expect("team signing evidence");
        assert_eq!(
            team.code_signing_evidence(),
            ConsumerCodeSigningEvidence::VerifiedWithTeamIdentifier
        );
    }

    #[test]
    fn usage_profiles_accept_only_typed_capability_compatible_placements() {
        let consumer_id = ConsumerId::generate();
        let created_at = StateTimestamp::from_unix_millis(10).expect("timestamp");
        let process = UsageProfile::new(
            consumer_id,
            "CLI token".to_owned(),
            Capability::v1(CapabilityName::ProcessRun),
            UsagePlacement::ProcessEnvironment {
                variable_name: "TOOL_TOKEN".to_owned(),
            },
            created_at,
        )
        .expect("process profile");
        assert_eq!(process.capability().name(), CapabilityName::ProcessRun);
        assert_eq!(
            process.definition().version(),
            CURRENT_USAGE_PROFILE_DEFINITION_VERSION
        );

        assert!(UsageProfile::new(
            consumer_id,
            "Wrong channel".to_owned(),
            Capability::v1(CapabilityName::HttpRequest),
            UsagePlacement::ProcessEnvironment {
                variable_name: "TOOL_TOKEN".to_owned(),
            },
            created_at,
        )
        .is_err());
        assert!(UsageProfile::new(
            consumer_id,
            "Invalid variable".to_owned(),
            Capability::v1(CapabilityName::ProcessRun),
            UsagePlacement::ProcessEnvironment {
                variable_name: "BAD-NAME".to_owned(),
            },
            created_at,
        )
        .is_err());
    }

    #[test]
    fn usage_profile_definitions_round_trip_every_typed_placement() {
        let cases = [
            (
                Capability::v1(CapabilityName::ProcessRun),
                UsagePlacement::ProcessEnvironment {
                    variable_name: "GH_TOKEN".to_owned(),
                },
                r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"}}"#,
            ),
            (
                Capability::v1(CapabilityName::ProcessRun),
                UsagePlacement::ProcessStdin {
                    append_newline: true,
                },
                r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-stdin","append_newline":true}}"#,
            ),
            (
                Capability::v1(CapabilityName::ProcessRun),
                UsagePlacement::ProcessFileDescriptor {
                    reference_variable_name: Some("TOKEN_FD".to_owned()),
                    render_dev_fd_path: true,
                },
                r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-file-descriptor","reference_variable_name":"TOKEN_FD","render_dev_fd_path":true}}"#,
            ),
            (
                Capability::v1(CapabilityName::HttpRequest),
                UsagePlacement::HttpBearerAuthorization {},
                r#"{"definition_version":1,"capability":{"name":"http.request","version":1},"secret_placement":{"placement":"http-bearer-authorization"}}"#,
            ),
            (
                Capability::v1(CapabilityName::HttpRequest),
                UsagePlacement::HttpHeader {
                    header_name: "X-API-Key".to_owned(),
                },
                r#"{"definition_version":1,"capability":{"name":"http.request","version":1},"secret_placement":{"placement":"http-header","header_name":"X-API-Key"}}"#,
            ),
        ];

        for (capability, placement, expected_json) in cases {
            let definition =
                UsageProfileDefinition::new(capability, placement).expect("valid definition");
            let encoded = definition.to_json().expect("encode definition");
            assert_eq!(encoded, expected_json);
            assert!(encoded.len() <= MAX_USAGE_PROFILE_DEFINITION_BYTES);
            assert_eq!(
                UsageProfileDefinition::from_json(&encoded).expect("decode definition"),
                definition
            );
        }
    }

    #[test]
    fn usage_profile_definition_json_rejects_executable_and_secret_fields() {
        let rejected = [
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"},"script":"DO_NOT_ECHO_MARKER"}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1,"command":"tool"},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN","shell":"zsh"}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-stdin","append_newline":false,"arguments":["--token"]}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-file-descriptor","reference_variable_name":null,"render_dev_fd_path":false,"executable":"/bin/tool"}}"#,
            r#"{"definition_version":1,"capability":{"name":"http.request","version":1},"secret_placement":{"placement":"http-bearer-authorization","secret_value":"token"}}"#,
            r#"{"definition_version":1,"capability":{"name":"http.request","version":1},"secret_placement":{"placement":"http-header","header_name":"X-API-Key","placeholder":"${SECRET}"}}"#,
            r#"{"definition_version":1,"capability":{"name":"http.request","version":1},"secret_placement":{"placement":"http-header","header_name":"X-API-Key","url":"https://example.invalid"}}"#,
        ];

        for encoded in rejected {
            let error = UsageProfileDefinition::from_json(encoded)
                .expect_err("executable or secret-bearing field must fail");
            assert!(!error.to_string().contains("DO_NOT_ECHO_MARKER"));
            assert!(!error.to_string().contains("${SECRET}"));
        }
    }

    #[test]
    fn usage_profile_definition_json_rejects_invalid_structure_and_versions() {
        let rejected = [
            r#"{"definition_version":2,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"}}"#,
            r#"{"definition_version":1,"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"}}"#,
            r#"{"definition_version":1,"capability":{"name":"unknown","version":1},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":0},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"}}"#,
            r#"{"definition_version":1,"capability":{"name":"http.request","version":1},"secret_placement":{"placement":"process-environment","variable_name":"GH_TOKEN"}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"http-bearer-authorization"}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"process-environment","variable_name":"BAD-NAME"}}"#,
            r#"{"definition_version":1,"capability":{"name":"http.request","version":1},"secret_placement":{"placement":"http-header","header_name":"Bad Header"}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1},"secret_placement":{"placement":"unknown"}}"#,
            r#"{"definition_version":1,"capability":{"name":"process.run","version":1}}"#,
            r#"not-json"#,
        ];

        for encoded in rejected {
            assert!(
                UsageProfileDefinition::from_json(encoded).is_err(),
                "invalid definition was accepted"
            );
        }

        let oversized = " ".repeat(MAX_USAGE_PROFILE_DEFINITION_BYTES + 1);
        assert!(UsageProfileDefinition::from_json(&oversized).is_err());
    }

    #[test]
    fn rule_grant_and_approval_time_bounds_fail_closed() {
        let created_at = StateTimestamp::from_unix_millis(100).expect("timestamp");
        let expires_at = StateTimestamp::from_unix_millis(100).expect("timestamp");
        let target = sample_target();

        assert!(AccessRule::new(
            target,
            ConfirmationPolicy::EveryUse,
            RuleLifetime::Until(expires_at),
            created_at,
        )
        .is_err());
        assert!(UseGrant::new(
            target,
            None,
            VaultSessionId::generate(),
            GrantScope::OneOperation,
            created_at,
            expires_at,
        )
        .is_err());
        assert!(ApprovalRequest::pending(
            ApprovalSubject::Access { target },
            [9_u8; 32],
            created_at,
            expires_at,
        )
        .is_err());
    }

    #[test]
    fn pairing_and_unlock_approvals_cannot_project_credential_authorization() {
        let consumer_id = ConsumerId::generate();
        let pairing = ApprovalSubject::Pairing {
            consumer_id,
            pairing_public_key: [7_u8; 32],
            observed_identity: ObservedConsumerIdentity::default(),
        };
        let unlock = ApprovalSubject::Unlock {
            consumer_id,
            vault_id: VaultId::generate(),
        };
        let target = sample_target();
        let access = ApprovalSubject::Access { target };

        assert_eq!(pairing.kind(), ApprovalKind::Pairing);
        assert_eq!(pairing.access_target(), None);
        assert_eq!(unlock.kind(), ApprovalKind::Unlock);
        assert_eq!(unlock.access_target(), None);
        assert_eq!(access.kind(), ApprovalKind::Access);
        assert_eq!(access.access_target(), Some(target));
    }

    #[test]
    fn model_has_no_arbitrary_secret_or_path_payload_fields() {
        let source = include_str!("state_model.rs");
        for forbidden in [
            concat!("secret_", "value:"),
            concat!("credential_", "title:"),
            concat!("master_", "password:"),
            concat!("recovery_", "key:"),
            concat!("request_", "body:"),
            concat!("request_", "url:"),
            concat!("response_", "body:"),
            concat!("command_", "arguments:"),
            concat!("standard_", "output:"),
            concat!("standard_", "error:"),
            concat!("executable_", "path:"),
            concat!("vault_", "path:"),
        ] {
            assert!(
                !source.contains(forbidden),
                "state model added forbidden field {forbidden}"
            );
        }
    }

    fn sample_target() -> AuthorizationTarget {
        AuthorizationTarget::new(
            ConsumerId::generate(),
            CredentialFieldScope::new(
                VaultId::generate(),
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::ProcessRun),
        )
    }
}
