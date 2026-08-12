use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use psw_core::{CredentialId, SecretBytes, SecretFieldId, VaultId};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    bundled_usage_profile_template, ApprovalRequestId, AuditDecision, AuditEventId, AuditEventKind,
    BrokerAuditCursor, BrokerAuditFilter, BrokerCredentialCandidateSelection, BrokerInstanceId,
    BrokerPairingUserApproval, BrokerPendingRequestId, BundledUsageProfileTemplateId, Capability,
    CapabilityName, ConfirmationPolicy, ConsumerId, ControllerAuthenticationProof,
    ControllerChallengeRequest, ControllerDeadline, ControllerId, ControllerNonce,
    ControllerSessionId, ControllerSignature, CredentialFieldScope,
    HumanControlAuditConfirmationId, HumanControlOperation, HumanControlProtocolVersion,
    HumanControlProtocolVersionRange, HumanControlRequest, HumanControlRequestId,
    HumanControlVaultUnlockCredential, HumanControlVersionOffer, PackagedComponent,
    PairingRequestId, RuleLifetime, StateTimestamp, UsageProfileId, UseGrantId,
    HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE, HUMAN_CONTROL_DENY_DECISION, HUMAN_CONTROL_PROTOCOL_NAME,
    HUMAN_CONTROL_SHUTDOWN_REASON, MAX_HUMAN_CONTROL_AUDIT_EVENTS, MAX_HUMAN_CONTROL_FRAME_LENGTH,
    MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES, MAX_HUMAN_CONTROL_SCHEMA_IDS,
    MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES, MAX_HUMAN_CONTROL_VERSION_RANGES,
};

const LOCAL_UNLOCK_MATERIAL_LENGTH: usize = 32;

/// Fixed wire-validation failure that never reflects request bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanControlWireError {
    /// Frame length is zero.
    Empty,
    /// Frame or operation-specific request exceeds its fixed bound.
    Oversized,
    /// Stream ended before the declared frame was complete.
    Truncated,
    /// Local stream read failed.
    Read,
    /// Local stream write or flush failed.
    Write,
    /// JSON, envelope, operation, schema, or body fields are invalid.
    Malformed,
    /// Protocol identity or version is unsupported.
    Incompatible,
}

impl Display for HumanControlWireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "human-control frame is empty",
            Self::Oversized => "human-control frame is oversized",
            Self::Truncated => "human-control frame is truncated",
            Self::Read => "human-control frame read failed",
            Self::Write => "human-control frame write failed",
            Self::Malformed => "human-control frame is malformed",
            Self::Incompatible => "human-control frame version is incompatible",
        })
    }
}

impl std::error::Error for HumanControlWireError {}

/// Validated frozen request envelope whose body has the exact operation field set.
#[derive(Eq, PartialEq)]
pub struct HumanControlWireEnvelope {
    request_id: HumanControlRequestId,
    version: HumanControlProtocolVersion,
    operation: HumanControlOperation,
    body: serde_json::Map<String, Value>,
}

impl Debug for HumanControlWireEnvelope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanControlWireEnvelope")
            .field("request_id", &self.request_id)
            .field("version", &self.version)
            .field("operation", &self.operation)
            .field("body", &"<redacted>")
            .finish()
    }
}

impl Drop for HumanControlWireEnvelope {
    fn drop(&mut self) {
        for value in self.body.values_mut() {
            zeroize_json_strings(value);
        }
    }
}

struct ZeroizingJsonObject(serde_json::Map<String, Value>);

impl Drop for ZeroizingJsonObject {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            zeroize_json_strings(value);
        }
    }
}

/// Owned bounded frame payload that clears its bytes when released.
pub struct HumanControlFrame {
    payload: Zeroizing<Vec<u8>>,
}

impl HumanControlFrame {
    /// Returns the immutable payload for parsing or framed transport output.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.payload
    }
}

impl From<Vec<u8>> for HumanControlFrame {
    fn from(payload: Vec<u8>) -> Self {
        Self {
            payload: Zeroizing::new(payload),
        }
    }
}

impl Debug for HumanControlFrame {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanControlFrame")
            .field("length", &self.payload.len())
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl Zeroize for HumanControlFrame {
    fn zeroize(&mut self) {
        self.payload.zeroize();
    }
}

impl HumanControlWireEnvelope {
    /// Returns the immutable request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> HumanControlRequestId {
        self.request_id
    }

    /// Returns the exact protocol version declared by the request.
    #[must_use]
    pub const fn version(&self) -> HumanControlProtocolVersion {
        self.version
    }

    /// Returns the only operation selected by the untrusted frame.
    #[must_use]
    pub const fn operation(&self) -> HumanControlOperation {
        self.operation
    }

    /// Reconstructs the one typed dispatcher request selected by this validated envelope.
    ///
    /// `observed_at` is Broker-owned local context. It records when a pairing approval was
    /// observed and is never accepted from the untrusted frame.
    pub fn to_typed_request(
        &self,
        observed_at: StateTimestamp,
    ) -> Result<HumanControlRequest, HumanControlWireError> {
        let body = &self.body;
        let request = match self.operation {
            HumanControlOperation::Hello => HumanControlRequest::Hello(decode_version_offer(body)?),
            HumanControlOperation::ControllerChallenge => {
                HumanControlRequest::ControllerChallenge(ControllerChallengeRequest::new(
                    parse_field(body, "controllerId")?,
                    parse_field(body, "clientNonce")?,
                ))
            }
            HumanControlOperation::ControllerAuthenticate => {
                let signature = decode_controller_signature(body, "proof")?;
                HumanControlRequest::ControllerAuthenticate(
                    ControllerAuthenticationProof::from_validated_wire_bindings(
                        parse_field(body, "brokerInstanceId")?,
                        parse_field(body, "controllerId")?,
                        parse_field(body, "controllerSessionId")?,
                        parse_field(body, "clientNonce")?,
                        parse_field(body, "brokerNonce")?,
                        parse_field(body, "deadline")?,
                        signature,
                    ),
                )
            }
            HumanControlOperation::ControllerLeaseRenew => {
                HumanControlRequest::ControllerLeaseRenew {
                    controller_session_id: parse_field(body, "controllerSessionId")?,
                    broker_instance_id: parse_field(body, "brokerInstanceId")?,
                }
            }
            HumanControlOperation::ReadinessGet => HumanControlRequest::ReadinessGet,
            HumanControlOperation::MachineAccessPauseSet => {
                HumanControlRequest::MachineAccessPauseSet {
                    paused: required_bool(body, "paused")?,
                }
            }
            HumanControlOperation::VaultUnlock => HumanControlRequest::VaultUnlock {
                vault_id: parse_field(body, "vaultId")?,
                credential: decode_unlock_credential(value_field(body, "credential")?)?,
            },
            HumanControlOperation::VaultLock => HumanControlRequest::VaultLock {
                vault_id: parse_field(body, "vaultId")?,
            },
            HumanControlOperation::PendingList => HumanControlRequest::PendingList,
            HumanControlOperation::PendingDeny => HumanControlRequest::PendingDeny {
                request_id: decode_pending_request_id(value_string(body, "pendingRequestId")?)?,
                decision: value_string(body, "decision")?.to_owned(),
            },
            HumanControlOperation::PairingApprove => HumanControlRequest::PairingApprove {
                request_id: parse_field(body, "pendingRequestId")?,
                approval: BrokerPairingUserApproval::after_user_approval(
                    value_string(body, "label")?.to_owned(),
                    observed_at,
                ),
            },
            HumanControlOperation::UnlockApprove => HumanControlRequest::UnlockApprove {
                request_id: parse_field(body, "pendingRequestId")?,
                vault_id: parse_field(body, "vaultId")?,
            },
            HumanControlOperation::CredentialReview => HumanControlRequest::CredentialReview {
                request_id: parse_field(body, "pendingRequestId")?,
            },
            HumanControlOperation::CredentialAllowOnce => {
                HumanControlRequest::CredentialAllowOnce {
                    request_id: parse_field(body, "pendingRequestId")?,
                    selection: decode_credential_selection(body)?,
                }
            }
            HumanControlOperation::CredentialAuthorize => {
                HumanControlRequest::CredentialAuthorize {
                    request_id: parse_field(body, "pendingRequestId")?,
                    selection: decode_credential_selection(body)?,
                    confirmation_policy: parse_field(body, "confirmationPolicy")?,
                    rule_lifetime: decode_rule_lifetime(value_field(body, "ruleLifetime")?)?,
                    capability: decode_capability(value_field(body, "capability")?)?,
                }
            }
            HumanControlOperation::AuthorizationSnapshot => {
                HumanControlRequest::AuthorizationSnapshot {
                    vault_id: parse_field(body, "vaultId")?,
                }
            }
            HumanControlOperation::ConsumerDetail => HumanControlRequest::ConsumerDetail {
                consumer_id: parse_field(body, "consumerId")?,
            },
            HumanControlOperation::UsageProfileCatalog => {
                HumanControlRequest::UsageProfileCatalog {
                    consumer_id: parse_field(body, "consumerId")?,
                    executable_name_hint: optional_owned_string(body, "executableName")?,
                }
            }
            HumanControlOperation::UsageProfileCreate => {
                let template_id = parse_field(body, "templateId")?;
                let technical_field = nullable_string(body, "technicalField")?;
                let definition = bundled_usage_profile_template(template_id)
                    .ok_or(HumanControlWireError::Malformed)?
                    .instantiate(technical_field)
                    .map_err(|_| HumanControlWireError::Malformed)?;
                HumanControlRequest::UsageProfileCreate {
                    consumer_id: parse_field(body, "consumerId")?,
                    label: value_string(body, "label")?.to_owned(),
                    definition,
                }
            }
            HumanControlOperation::UsageProfileRemove => HumanControlRequest::UsageProfileRemove {
                consumer_id: parse_field(body, "consumerId")?,
                usage_profile_id: parse_field(body, "usageProfileId")?,
            },
            HumanControlOperation::FieldAccessRevoke => HumanControlRequest::FieldAccessRevoke {
                consumer_id: parse_field(body, "consumerId")?,
                field_scope: decode_field_scope(body)?,
            },
            HumanControlOperation::GrantRevoke => HumanControlRequest::GrantRevoke {
                consumer_id: parse_field(body, "consumerId")?,
                use_grant_id: parse_field(body, "useGrantId")?,
            },
            HumanControlOperation::ConsumerRevoke => HumanControlRequest::ConsumerRevoke {
                consumer_id: parse_field(body, "consumerId")?,
                scope: value_string(body, "scope")?.to_owned(),
            },
            HumanControlOperation::AllAccessRevoke => HumanControlRequest::AllAccessRevoke,
            HumanControlOperation::AuditList => HumanControlRequest::AuditList {
                filter: decode_audit_filter(value_field(body, "filter")?)?,
                cursor: body.get("cursor").map(decode_audit_cursor).transpose()?,
                limit: decode_audit_limit(body, "limit")?,
            },
            HumanControlOperation::AuditClear => HumanControlRequest::AuditClear {
                filter: decode_audit_filter(value_field(body, "selection")?)?,
                confirmation_id: parse_field(body, "confirmationId")?,
            },
            HumanControlOperation::AuditExport => HumanControlRequest::AuditExport {
                filter: decode_audit_filter(value_field(body, "filter")?)?,
                limit: decode_audit_limit(body, "limit")?,
            },
            HumanControlOperation::RepairPrepare => HumanControlRequest::RepairPrepare {
                expected_component: decode_packaged_component(body, "expectedComponent")?,
                expected_protocol: decode_protocol_version(value_field(body, "expectedProtocol")?)?,
            },
            HumanControlOperation::Shutdown => HumanControlRequest::Shutdown {
                reason: value_string(body, "reason")?.to_owned(),
            },
        };
        debug_assert_eq!(request.operation(), self.operation);
        Ok(request)
    }
}

#[derive(Clone, Copy)]
enum HumanControlWireVersionExpectation {
    InitialHello { broker: HumanControlProtocolVersion },
    Negotiated(HumanControlProtocolVersion),
}

/// Validates an initial Hello using current-major minor-version compatibility.
pub fn decode_human_control_hello_wire_envelope(
    payload: impl Into<HumanControlFrame>,
) -> Result<HumanControlWireEnvelope, HumanControlWireError> {
    decode_human_control_wire_envelope_with_expectation(
        payload,
        HumanControlWireVersionExpectation::InitialHello {
            broker: HumanControlProtocolVersion::current(),
        },
    )
}

/// Validates one post-Hello request against the exact version selected for its connection.
pub fn decode_human_control_wire_envelope(
    payload: impl Into<HumanControlFrame>,
    selected_protocol: HumanControlProtocolVersion,
) -> Result<HumanControlWireEnvelope, HumanControlWireError> {
    decode_human_control_wire_envelope_with_expectation(
        payload,
        HumanControlWireVersionExpectation::Negotiated(selected_protocol),
    )
}

fn decode_human_control_wire_envelope_with_expectation(
    payload: impl Into<HumanControlFrame>,
    expectation: HumanControlWireVersionExpectation,
) -> Result<HumanControlWireEnvelope, HumanControlWireError> {
    let payload = payload.into();
    if payload.as_bytes().is_empty() {
        return Err(HumanControlWireError::Empty);
    }
    if payload.as_bytes().len() > MAX_HUMAN_CONTROL_FRAME_LENGTH {
        return Err(HumanControlWireError::Oversized);
    }
    let value = crate::protocol::parse_unique_json(payload.as_bytes())
        .map_err(|_| HumanControlWireError::Malformed)?;
    let Value::Object(envelope) = value else {
        let mut value = value;
        zeroize_json_strings(&mut value);
        return Err(HumanControlWireError::Malformed);
    };
    let mut envelope = ZeroizingJsonObject(envelope);
    if envelope.0.len() != 5 {
        return Err(HumanControlWireError::Malformed);
    }
    if take_string(&mut envelope.0, "protocol")? != HUMAN_CONTROL_PROTOCOL_NAME {
        return Err(HumanControlWireError::Incompatible);
    }
    let version = take_version(&mut envelope.0)?;
    let request_id = HumanControlRequestId::from_str(&take_string(&mut envelope.0, "requestId")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let operation = HumanControlOperation::from_str(&take_string(&mut envelope.0, "operation")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let compatible = match expectation {
        HumanControlWireVersionExpectation::InitialHello { broker } => {
            operation == HumanControlOperation::Hello && version.is_supported_by(broker)
        }
        HumanControlWireVersionExpectation::Negotiated(selected) => version == selected,
    };
    if !compatible {
        return Err(HumanControlWireError::Incompatible);
    }
    let Some(Value::Object(body)) = envelope.0.remove("body") else {
        return Err(HumanControlWireError::Malformed);
    };
    if !envelope.0.is_empty() {
        return Err(HumanControlWireError::Malformed);
    }
    let mut body = ZeroizingJsonObject(body);
    if payload.as_bytes().len() > operation.contract().maximum_request_length() {
        return Err(HumanControlWireError::Oversized);
    }
    validate_body_keys(operation, &body.0)?;
    validate_body_values(operation, &body.0)?;
    Ok(HumanControlWireEnvelope {
        request_id,
        version,
        operation,
        body: std::mem::take(&mut body.0),
    })
}

fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_strings(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_strings(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn decode_version_offer(
    body: &serde_json::Map<String, Value>,
) -> Result<HumanControlVersionOffer, HumanControlWireError> {
    let ranges = value_field(body, "protocolVersions")?
        .as_array()
        .ok_or(HumanControlWireError::Malformed)?
        .iter()
        .map(|value| {
            let range = value.as_object().ok_or(HumanControlWireError::Malformed)?;
            HumanControlProtocolVersionRange::new(
                u16_field(range, "major")?,
                u16_field(range, "minimumMinor")?,
                u16_field(range, "maximumMinor")?,
            )
            .map_err(|_| HumanControlWireError::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let schema_ids = value_field(body, "schemaIds")?
        .as_array()
        .ok_or(HumanControlWireError::Malformed)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or(HumanControlWireError::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    HumanControlVersionOffer::new(value_string(body, "role")?, ranges, schema_ids)
        .map_err(|_| HumanControlWireError::Malformed)
}

fn decode_controller_signature(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<ControllerSignature, HumanControlWireError> {
    let mut decoded = BASE64_STANDARD
        .decode(value_string(body, key)?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let mut bytes = [0_u8; crate::CONTROLLER_SIGNATURE_LENGTH];
    if decoded.len() != bytes.len() {
        decoded.zeroize();
        return Err(HumanControlWireError::Malformed);
    }
    bytes.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(ControllerSignature::from_bytes(bytes))
}

fn decode_unlock_credential(
    value: &Value,
) -> Result<HumanControlVaultUnlockCredential, HumanControlWireError> {
    let credential = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    let decoded = BASE64_STANDARD
        .decode(value_string(credential, "valueBase64")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let secret = SecretBytes::new(decoded);
    match value_string(credential, "kind")? {
        "master-password" => Ok(HumanControlVaultUnlockCredential::MasterPassword(secret)),
        "local-material" => Ok(HumanControlVaultUnlockCredential::LocalMaterial(secret)),
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn decode_pending_request_id(value: &str) -> Result<BrokerPendingRequestId, HumanControlWireError> {
    if let Ok(request_id) = value.parse::<PairingRequestId>() {
        Ok(BrokerPendingRequestId::Pairing(request_id))
    } else {
        value
            .parse::<ApprovalRequestId>()
            .map(BrokerPendingRequestId::Approval)
            .map_err(|_| HumanControlWireError::Malformed)
    }
}

fn decode_credential_selection(
    body: &serde_json::Map<String, Value>,
) -> Result<BrokerCredentialCandidateSelection, HumanControlWireError> {
    Ok(BrokerCredentialCandidateSelection::new(
        parse_field(body, "credentialId")?,
        parse_field(body, "secretFieldId")?,
    ))
}

fn decode_capability(value: &Value) -> Result<Capability, HumanControlWireError> {
    let capability = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    Capability::new(
        parse_field(capability, "name")?,
        u16_field(capability, "version")?,
    )
    .map_err(|_| HumanControlWireError::Malformed)
}

fn decode_rule_lifetime(value: &Value) -> Result<RuleLifetime, HumanControlWireError> {
    let lifetime = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    match value_string(lifetime, "kind")? {
        "persistent" => Ok(RuleLifetime::Persistent),
        "until" => Ok(RuleLifetime::Until(decode_timestamp(timestamp_field(
            lifetime,
            "expiresAtMs",
        )?)?)),
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn decode_field_scope(
    body: &serde_json::Map<String, Value>,
) -> Result<CredentialFieldScope, HumanControlWireError> {
    Ok(CredentialFieldScope::new(
        parse_field(body, "vaultId")?,
        parse_field(body, "credentialId")?,
        parse_field(body, "secretFieldId")?,
    ))
}

fn decode_audit_filter(value: &Value) -> Result<BrokerAuditFilter, HumanControlWireError> {
    let body = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    let mut filter = BrokerAuditFilter::all();
    if let Some(event_kind) = optional_parse_field::<AuditEventKind>(body, "eventKind")? {
        filter = filter.with_event_kind(event_kind);
    }
    if let Some(decision) = optional_parse_field::<AuditDecision>(body, "decision")? {
        filter = filter.with_decision(decision);
    }
    if let Some(consumer_id) = optional_parse_field::<ConsumerId>(body, "consumerId")? {
        filter = filter.with_consumer(consumer_id);
    }
    if let Some(vault_id) = optional_parse_field::<VaultId>(body, "vaultId")? {
        filter = filter.with_vault(vault_id);
    }
    if let Some(field_scope) = body.get("fieldScope") {
        filter = filter.with_field_scope(decode_field_scope(
            field_scope
                .as_object()
                .ok_or(HumanControlWireError::Malformed)?,
        )?);
    }
    if let Some(capability) = body.get("capability") {
        filter = filter.with_capability(decode_capability(capability)?);
    }
    if let Some(timestamp) = optional_timestamp_field(body, "occurredAtOrAfterMs")? {
        filter = filter.occurring_at_or_after(decode_timestamp(timestamp)?);
    }
    if let Some(timestamp) = optional_timestamp_field(body, "occurredBeforeMs")? {
        filter = filter.occurring_before(decode_timestamp(timestamp)?);
    }
    Ok(filter)
}

fn decode_audit_cursor(value: &Value) -> Result<BrokerAuditCursor, HumanControlWireError> {
    let cursor = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    Ok(BrokerAuditCursor::from_validated_wire_bindings(
        decode_timestamp(timestamp_field(cursor, "occurredAtMs")?)?,
        parse_field(cursor, "auditEventId")?,
    ))
}

fn decode_audit_limit(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<usize, HumanControlWireError> {
    value_field(body, key)?
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (1..=MAX_HUMAN_CONTROL_AUDIT_EVENTS).contains(value))
        .ok_or(HumanControlWireError::Malformed)
}

fn decode_packaged_component(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<PackagedComponent, HumanControlWireError> {
    match value_string(body, key)? {
        "macos-app" => Ok(PackagedComponent::MacOsApp),
        "broker" => Ok(PackagedComponent::Broker),
        "mcp-adapter" => Ok(PackagedComponent::McpAdapter),
        "cli" => Ok(PackagedComponent::Cli),
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn decode_protocol_version(
    value: &Value,
) -> Result<HumanControlProtocolVersion, HumanControlWireError> {
    let version = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    HumanControlProtocolVersion::new(u16_field(version, "major")?, u16_field(version, "minor")?)
        .map_err(|_| HumanControlWireError::Malformed)
}

fn decode_timestamp(value: i64) -> Result<StateTimestamp, HumanControlWireError> {
    StateTimestamp::from_unix_millis(value).map_err(|_| HumanControlWireError::Malformed)
}

fn required_bool(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<bool, HumanControlWireError> {
    value_field(body, key)?
        .as_bool()
        .ok_or(HumanControlWireError::Malformed)
}

fn optional_owned_string(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, HumanControlWireError> {
    body.get(key)
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or(HumanControlWireError::Malformed)
        })
        .transpose()
}

fn nullable_string<'a>(
    body: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, HumanControlWireError> {
    let value = value_field(body, key)?;
    if value.is_null() {
        Ok(None)
    } else {
        value
            .as_str()
            .map(Some)
            .ok_or(HumanControlWireError::Malformed)
    }
}

fn validate_body_values(
    operation: HumanControlOperation,
    body: &serde_json::Map<String, Value>,
) -> Result<(), HumanControlWireError> {
    match operation {
        HumanControlOperation::Hello => validate_hello(body),
        HumanControlOperation::ControllerChallenge => {
            parse_field::<ControllerId>(body, "controllerId")?;
            parse_field::<ControllerNonce>(body, "clientNonce")?;
            Ok(())
        }
        HumanControlOperation::ControllerAuthenticate => {
            parse_field::<ControllerId>(body, "controllerId")?;
            parse_field::<ControllerSessionId>(body, "controllerSessionId")?;
            parse_field::<BrokerInstanceId>(body, "brokerInstanceId")?;
            parse_field::<ControllerNonce>(body, "clientNonce")?;
            parse_field::<ControllerNonce>(body, "brokerNonce")?;
            parse_field::<ControllerDeadline>(body, "deadline")?;
            validate_base64_field(
                body,
                "proof",
                Some(crate::CONTROLLER_SIGNATURE_LENGTH),
                false,
            )
        }
        HumanControlOperation::ControllerLeaseRenew => {
            parse_field::<ControllerSessionId>(body, "controllerSessionId")?;
            parse_field::<BrokerInstanceId>(body, "brokerInstanceId")?;
            Ok(())
        }
        HumanControlOperation::ReadinessGet
        | HumanControlOperation::PendingList
        | HumanControlOperation::AllAccessRevoke => Ok(()),
        HumanControlOperation::MachineAccessPauseSet => bool_field(body, "paused"),
        HumanControlOperation::VaultUnlock => {
            parse_field::<VaultId>(body, "vaultId")?;
            validate_unlock_credential(value_field(body, "credential")?)
        }
        HumanControlOperation::VaultLock | HumanControlOperation::AuthorizationSnapshot => {
            parse_field::<VaultId>(body, "vaultId")?;
            Ok(())
        }
        HumanControlOperation::PendingDeny => {
            validate_pending_id(value_string(body, "pendingRequestId")?)?;
            fixed_string(body, "decision", HUMAN_CONTROL_DENY_DECISION)
        }
        HumanControlOperation::PairingApprove => {
            parse_field::<PairingRequestId>(body, "pendingRequestId")?;
            bounded_text_field(body, "label", MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES, false)
        }
        HumanControlOperation::UnlockApprove | HumanControlOperation::CredentialReview => {
            parse_field::<ApprovalRequestId>(body, "pendingRequestId")?;
            if operation == HumanControlOperation::UnlockApprove {
                parse_field::<VaultId>(body, "vaultId")?;
            }
            Ok(())
        }
        HumanControlOperation::CredentialAllowOnce => validate_credential_selection(body),
        HumanControlOperation::CredentialAuthorize => {
            validate_credential_selection(body)?;
            validate_capability(value_field(body, "capability")?)?;
            value_string(body, "confirmationPolicy")?
                .parse::<ConfirmationPolicy>()
                .map_err(|_| HumanControlWireError::Malformed)?;
            validate_rule_lifetime(value_field(body, "ruleLifetime")?)
        }
        HumanControlOperation::ConsumerDetail => {
            parse_field::<ConsumerId>(body, "consumerId")?;
            Ok(())
        }
        HumanControlOperation::ConsumerRevoke => {
            parse_field::<ConsumerId>(body, "consumerId")?;
            fixed_string(body, "scope", HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE)
        }
        HumanControlOperation::UsageProfileCatalog => {
            parse_field::<ConsumerId>(body, "consumerId")?;
            optional_bounded_text_field(body, "executableName", MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES)
        }
        HumanControlOperation::UsageProfileCreate => {
            parse_field::<ConsumerId>(body, "consumerId")?;
            let template_id = parse_field::<BundledUsageProfileTemplateId>(body, "templateId")?;
            bounded_text_field(body, "label", MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES, false)?;
            nullable_bounded_text_field(
                body,
                "technicalField",
                MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES,
            )?;
            let technical_field = value_field(body, "technicalField")?.as_str();
            bundled_usage_profile_template(template_id)
                .ok_or(HumanControlWireError::Malformed)?
                .instantiate(technical_field)
                .map(|_| ())
                .map_err(|_| HumanControlWireError::Malformed)
        }
        HumanControlOperation::UsageProfileRemove => {
            parse_field::<ConsumerId>(body, "consumerId")?;
            parse_field::<UsageProfileId>(body, "usageProfileId")?;
            Ok(())
        }
        HumanControlOperation::FieldAccessRevoke => {
            parse_field::<ConsumerId>(body, "consumerId")?;
            validate_field_scope(body)
        }
        HumanControlOperation::GrantRevoke => {
            parse_field::<ConsumerId>(body, "consumerId")?;
            parse_field::<UseGrantId>(body, "useGrantId")?;
            Ok(())
        }
        HumanControlOperation::AuditList => {
            validate_audit_filter(value_field(body, "filter")?)?;
            audit_limit(body, "limit")?;
            if let Some(cursor) = body.get("cursor") {
                validate_audit_cursor(cursor)?;
            }
            Ok(())
        }
        HumanControlOperation::AuditClear => {
            validate_audit_filter(value_field(body, "selection")?)?;
            parse_field::<HumanControlAuditConfirmationId>(body, "confirmationId")?;
            Ok(())
        }
        HumanControlOperation::AuditExport => {
            validate_audit_filter(value_field(body, "filter")?)?;
            audit_limit(body, "limit")
        }
        HumanControlOperation::RepairPrepare => {
            validate_packaged_component(body, "expectedComponent")?;
            let version = value_field(body, "expectedProtocol")?
                .as_object()
                .ok_or(HumanControlWireError::Malformed)?;
            validate_exact_keys(version, &["major", "minor"], &[])?;
            HumanControlProtocolVersion::new(
                u16_field(version, "major")?,
                u16_field(version, "minor")?,
            )
            .map(|_| ())
            .map_err(|_| HumanControlWireError::Malformed)
        }
        HumanControlOperation::Shutdown => {
            fixed_string(body, "reason", HUMAN_CONTROL_SHUTDOWN_REASON)
        }
    }
}

fn validate_hello(body: &serde_json::Map<String, Value>) -> Result<(), HumanControlWireError> {
    if !valid_negotiation_identity(value_string(body, "role")?) {
        return Err(HumanControlWireError::Malformed);
    }
    let ranges = value_field(body, "protocolVersions")?
        .as_array()
        .ok_or(HumanControlWireError::Malformed)?;
    if ranges.is_empty() || ranges.len() > MAX_HUMAN_CONTROL_VERSION_RANGES {
        return Err(HumanControlWireError::Malformed);
    }
    let mut majors = BTreeSet::new();
    for range in ranges {
        let range = range.as_object().ok_or(HumanControlWireError::Malformed)?;
        validate_exact_keys(range, &["major", "minimumMinor", "maximumMinor"], &[])?;
        let major = u16_field(range, "major")?;
        let minimum = u16_field(range, "minimumMinor")?;
        let maximum = u16_field(range, "maximumMinor")?;
        if major == 0 || minimum > maximum || !majors.insert(major) {
            return Err(HumanControlWireError::Malformed);
        }
    }
    let schemas = value_field(body, "schemaIds")?
        .as_array()
        .ok_or(HumanControlWireError::Malformed)?;
    if schemas.is_empty() || schemas.len() > MAX_HUMAN_CONTROL_SCHEMA_IDS {
        return Err(HumanControlWireError::Malformed);
    }
    let mut unique = BTreeSet::new();
    for schema in schemas {
        let schema = schema.as_str().ok_or(HumanControlWireError::Malformed)?;
        if !valid_negotiation_identity(schema) || !unique.insert(schema) {
            return Err(HumanControlWireError::Malformed);
        }
    }
    Ok(())
}

fn valid_negotiation_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn validate_unlock_credential(value: &Value) -> Result<(), HumanControlWireError> {
    let credential = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    validate_exact_keys(credential, &["kind", "valueBase64"], &[])?;
    match value_string(credential, "kind")? {
        "master-password" => validate_base64_field(
            credential,
            "valueBase64",
            Some(MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES),
            true,
        ),
        "local-material" => validate_base64_field(
            credential,
            "valueBase64",
            Some(LOCAL_UNLOCK_MATERIAL_LENGTH),
            false,
        ),
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn validate_base64_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
    expected_or_maximum: Option<usize>,
    maximum_not_exact: bool,
) -> Result<(), HumanControlWireError> {
    let encoded = value_string(body, key)?;
    let encoded_bound = expected_or_maximum
        .unwrap_or(MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES)
        .saturating_add(2)
        / 3
        * 4;
    if encoded.len() > encoded_bound.saturating_add(4) {
        return Err(HumanControlWireError::Oversized);
    }
    let mut decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let decoded_oversized =
        maximum_not_exact && expected_or_maximum.is_some_and(|bound| decoded.len() > bound);
    let mut reencoded = BASE64_STANDARD.encode(&decoded);
    let canonical = reencoded == encoded;
    reencoded.zeroize();
    let valid = !decoded.is_empty()
        && canonical
        && expected_or_maximum.is_none_or(|bound| {
            maximum_not_exact && decoded.len() <= bound || decoded.len() == bound
        });
    decoded.zeroize();
    if decoded_oversized {
        Err(HumanControlWireError::Oversized)
    } else if valid {
        Ok(())
    } else {
        Err(HumanControlWireError::Malformed)
    }
}

fn validate_credential_selection(
    body: &serde_json::Map<String, Value>,
) -> Result<(), HumanControlWireError> {
    parse_field::<ApprovalRequestId>(body, "pendingRequestId")?;
    parse_field::<CredentialId>(body, "credentialId")?;
    parse_field::<SecretFieldId>(body, "secretFieldId")?;
    Ok(())
}

fn validate_field_scope(
    body: &serde_json::Map<String, Value>,
) -> Result<(), HumanControlWireError> {
    parse_field::<VaultId>(body, "vaultId")?;
    parse_field::<CredentialId>(body, "credentialId")?;
    parse_field::<SecretFieldId>(body, "secretFieldId")?;
    Ok(())
}

fn validate_capability(value: &Value) -> Result<(), HumanControlWireError> {
    let capability = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    validate_exact_keys(capability, &["name", "version"], &[])?;
    value_string(capability, "name")?
        .parse::<CapabilityName>()
        .map_err(|_| HumanControlWireError::Malformed)?;
    if u16_field(capability, "version")? == 0 {
        return Err(HumanControlWireError::Malformed);
    }
    Ok(())
}

fn validate_rule_lifetime(value: &Value) -> Result<(), HumanControlWireError> {
    let lifetime = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    match value_string(lifetime, "kind")? {
        "persistent" => validate_exact_keys(lifetime, &["kind"], &[]),
        "until" => {
            validate_exact_keys(lifetime, &["kind", "expiresAtMs"], &[])?;
            timestamp_field(lifetime, "expiresAtMs").map(|_| ())
        }
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn validate_audit_filter(value: &Value) -> Result<(), HumanControlWireError> {
    let filter = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    validate_exact_keys(
        filter,
        &[],
        &[
            "eventKind",
            "decision",
            "consumerId",
            "vaultId",
            "fieldScope",
            "capability",
            "occurredAtOrAfterMs",
            "occurredBeforeMs",
        ],
    )?;
    if let Some(value) = filter.get("eventKind") {
        value
            .as_str()
            .ok_or(HumanControlWireError::Malformed)?
            .parse::<AuditEventKind>()
            .map_err(|_| HumanControlWireError::Malformed)?;
    }
    if let Some(value) = filter.get("decision") {
        value
            .as_str()
            .ok_or(HumanControlWireError::Malformed)?
            .parse::<AuditDecision>()
            .map_err(|_| HumanControlWireError::Malformed)?;
    }
    optional_parse_field::<ConsumerId>(filter, "consumerId")?;
    let vault_id = optional_parse_field::<VaultId>(filter, "vaultId")?;
    let field_vault = if let Some(value) = filter.get("fieldScope") {
        let scope = value.as_object().ok_or(HumanControlWireError::Malformed)?;
        validate_exact_keys(scope, &["vaultId", "credentialId", "secretFieldId"], &[])?;
        let vault = parse_field::<VaultId>(scope, "vaultId")?;
        parse_field::<CredentialId>(scope, "credentialId")?;
        parse_field::<SecretFieldId>(scope, "secretFieldId")?;
        Some(vault)
    } else {
        None
    };
    if matches!((vault_id, field_vault), (Some(left), Some(right)) if left != right) {
        return Err(HumanControlWireError::Malformed);
    }
    if let Some(value) = filter.get("capability") {
        validate_capability(value)?;
    }
    let start = optional_timestamp_field(filter, "occurredAtOrAfterMs")?;
    let end = optional_timestamp_field(filter, "occurredBeforeMs")?;
    if matches!((start, end), (Some(start), Some(end)) if start >= end) {
        return Err(HumanControlWireError::Malformed);
    }
    Ok(())
}

fn validate_audit_cursor(value: &Value) -> Result<(), HumanControlWireError> {
    let cursor = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    validate_exact_keys(cursor, &["occurredAtMs", "auditEventId"], &[])?;
    timestamp_field(cursor, "occurredAtMs")?;
    parse_field::<AuditEventId>(cursor, "auditEventId")?;
    Ok(())
}

fn validate_pending_id(value: &str) -> Result<(), HumanControlWireError> {
    if value.parse::<PairingRequestId>().is_ok() || value.parse::<ApprovalRequestId>().is_ok() {
        Ok(())
    } else {
        Err(HumanControlWireError::Malformed)
    }
}

fn validate_exact_keys(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), HumanControlWireError> {
    let accepted = required
        .iter()
        .chain(optional)
        .copied()
        .collect::<BTreeSet<_>>();
    if required.iter().any(|key| !object.contains_key(*key))
        || object.keys().any(|key| !accepted.contains(key.as_str()))
    {
        Err(HumanControlWireError::Malformed)
    } else {
        Ok(())
    }
}

fn value_field<'a>(
    body: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a Value, HumanControlWireError> {
    body.get(key).ok_or(HumanControlWireError::Malformed)
}

fn value_string<'a>(
    body: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, HumanControlWireError> {
    value_field(body, key)?
        .as_str()
        .ok_or(HumanControlWireError::Malformed)
}

fn parse_field<T: FromStr>(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<T, HumanControlWireError> {
    value_string(body, key)?
        .parse()
        .map_err(|_| HumanControlWireError::Malformed)
}

fn optional_parse_field<T: FromStr>(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<T>, HumanControlWireError> {
    body.get(key)
        .map(|value| {
            value
                .as_str()
                .ok_or(HumanControlWireError::Malformed)?
                .parse()
                .map_err(|_| HumanControlWireError::Malformed)
        })
        .transpose()
}

fn bool_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), HumanControlWireError> {
    value_field(body, key)?
        .as_bool()
        .map(|_| ())
        .ok_or(HumanControlWireError::Malformed)
}

fn validate_packaged_component(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), HumanControlWireError> {
    match value_string(body, key)? {
        "macos-app" | "broker" | "mcp-adapter" | "cli" => Ok(()),
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn u16_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<u16, HumanControlWireError> {
    value_field(body, key)?
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(HumanControlWireError::Malformed)
}

fn timestamp_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<i64, HumanControlWireError> {
    value_field(body, key)?
        .as_i64()
        .filter(|value| *value >= 0)
        .ok_or(HumanControlWireError::Malformed)
}

fn optional_timestamp_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, HumanControlWireError> {
    body.get(key)
        .map(|_| timestamp_field(body, key))
        .transpose()
}

fn bounded_text_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), HumanControlWireError> {
    let value = value_string(body, key)?;
    if value.len() > maximum || (!allow_empty && value.trim().is_empty()) {
        Err(HumanControlWireError::Malformed)
    } else {
        Ok(())
    }
}

fn optional_bounded_text_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<(), HumanControlWireError> {
    match body.get(key) {
        Some(_) => bounded_text_field(body, key, maximum, true),
        None => Ok(()),
    }
}

fn nullable_bounded_text_field(
    body: &serde_json::Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<(), HumanControlWireError> {
    if value_field(body, key)?.is_null() {
        Ok(())
    } else {
        bounded_text_field(body, key, maximum, false)
    }
}

fn fixed_string(
    body: &serde_json::Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), HumanControlWireError> {
    if value_string(body, key)? == expected {
        Ok(())
    } else {
        Err(HumanControlWireError::Malformed)
    }
}

fn audit_limit(
    body: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), HumanControlWireError> {
    let limit = value_field(body, key)?
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(HumanControlWireError::Malformed)?;
    if (1..=MAX_HUMAN_CONTROL_AUDIT_EVENTS).contains(&limit) {
        Ok(())
    } else {
        Err(HumanControlWireError::Malformed)
    }
}

fn take_string(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, HumanControlWireError> {
    match object.remove(key) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn take_version(
    object: &mut serde_json::Map<String, Value>,
) -> Result<HumanControlProtocolVersion, HumanControlWireError> {
    let Some(Value::Object(version)) = object.remove("version") else {
        return Err(HumanControlWireError::Malformed);
    };
    if version.len() != 2 {
        return Err(HumanControlWireError::Malformed);
    }
    let major = version
        .get("major")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(HumanControlWireError::Malformed)?;
    let minor = version
        .get("minor")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(HumanControlWireError::Malformed)?;
    HumanControlProtocolVersion::new(major, minor).map_err(|_| HumanControlWireError::Malformed)
}

fn validate_body_keys(
    operation: HumanControlOperation,
    body: &serde_json::Map<String, Value>,
) -> Result<(), HumanControlWireError> {
    let (required, optional): (&[&str], &[&str]) = match operation {
        HumanControlOperation::Hello => (&["role", "protocolVersions", "schemaIds"], &[]),
        HumanControlOperation::ControllerChallenge => (&["controllerId", "clientNonce"], &[]),
        HumanControlOperation::ControllerAuthenticate => (
            &[
                "controllerId",
                "controllerSessionId",
                "brokerInstanceId",
                "clientNonce",
                "brokerNonce",
                "deadline",
                "proof",
            ],
            &[],
        ),
        HumanControlOperation::ControllerLeaseRenew => {
            (&["controllerSessionId", "brokerInstanceId"], &[])
        }
        HumanControlOperation::ReadinessGet
        | HumanControlOperation::PendingList
        | HumanControlOperation::AllAccessRevoke => (&[], &[]),
        HumanControlOperation::MachineAccessPauseSet => (&["paused"], &[]),
        HumanControlOperation::VaultUnlock => (&["vaultId", "credential"], &[]),
        HumanControlOperation::VaultLock | HumanControlOperation::AuthorizationSnapshot => {
            (&["vaultId"], &[])
        }
        HumanControlOperation::PendingDeny => (&["pendingRequestId", "decision"], &[]),
        HumanControlOperation::PairingApprove => (&["pendingRequestId", "label"], &[]),
        HumanControlOperation::UnlockApprove => (&["pendingRequestId", "vaultId"], &[]),
        HumanControlOperation::CredentialReview => (&["pendingRequestId"], &[]),
        HumanControlOperation::CredentialAllowOnce => {
            (&["pendingRequestId", "credentialId", "secretFieldId"], &[])
        }
        HumanControlOperation::CredentialAuthorize => (
            &[
                "pendingRequestId",
                "credentialId",
                "secretFieldId",
                "capability",
                "confirmationPolicy",
                "ruleLifetime",
            ],
            &[],
        ),
        HumanControlOperation::ConsumerDetail => (&["consumerId"], &[]),
        HumanControlOperation::ConsumerRevoke => (&["consumerId", "scope"], &[]),
        HumanControlOperation::UsageProfileCatalog => (&["consumerId"], &["executableName"]),
        HumanControlOperation::UsageProfileCreate => (
            &["consumerId", "templateId", "label", "technicalField"],
            &[],
        ),
        HumanControlOperation::UsageProfileRemove => (&["consumerId", "usageProfileId"], &[]),
        HumanControlOperation::FieldAccessRevoke => (
            &["consumerId", "vaultId", "credentialId", "secretFieldId"],
            &[],
        ),
        HumanControlOperation::GrantRevoke => (&["consumerId", "useGrantId"], &[]),
        HumanControlOperation::AuditList => (&["filter", "limit"], &["cursor"]),
        HumanControlOperation::AuditClear => (&["selection", "confirmationId"], &[]),
        HumanControlOperation::AuditExport => (&["filter", "limit"], &[]),
        HumanControlOperation::RepairPrepare => (&["expectedComponent", "expectedProtocol"], &[]),
        HumanControlOperation::Shutdown => (&["reason"], &[]),
    };
    let accepted = required
        .iter()
        .chain(optional)
        .copied()
        .collect::<BTreeSet<_>>();
    if required.iter().any(|key| !body.contains_key(*key))
        || body.keys().any(|key| !accepted.contains(key.as_str()))
    {
        return Err(HumanControlWireError::Malformed);
    }
    Ok(())
}

/// Reads one bounded big-endian length-prefixed human-control frame.
pub fn read_human_control_frame(
    reader: &mut impl Read,
) -> Result<Option<HumanControlFrame>, HumanControlWireError> {
    let mut length = [0_u8; 4];
    let mut read = 0;
    while read < length.len() {
        match reader.read(&mut length[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err(HumanControlWireError::Truncated),
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(HumanControlWireError::Read),
        }
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(HumanControlWireError::Empty);
    }
    if length > MAX_HUMAN_CONTROL_FRAME_LENGTH {
        return Err(HumanControlWireError::Oversized);
    }
    let mut payload = HumanControlFrame::from(vec![0_u8; length]);
    reader
        .read_exact(payload.payload.as_mut_slice())
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => HumanControlWireError::Truncated,
            _ => HumanControlWireError::Read,
        })?;
    Ok(Some(payload))
}

/// Writes and flushes one bounded big-endian length-prefixed frame.
pub fn write_human_control_frame(
    writer: &mut impl Write,
    payload: &[u8],
) -> Result<(), HumanControlWireError> {
    if payload.is_empty() {
        return Err(HumanControlWireError::Empty);
    }
    let length = u32::try_from(payload.len()).map_err(|_| HumanControlWireError::Oversized)?;
    if payload.len() > MAX_HUMAN_CONTROL_FRAME_LENGTH {
        return Err(HumanControlWireError::Oversized);
    }
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(|_| HumanControlWireError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_current(
        payload: impl Into<HumanControlFrame>,
    ) -> Result<HumanControlWireEnvelope, HumanControlWireError> {
        decode_human_control_wire_envelope(payload, HumanControlProtocolVersion::current())
    }

    fn request(operation: &str, body: &str) -> Vec<u8> {
        format!(
            "{{\"protocol\":\"{HUMAN_CONTROL_PROTOCOL_NAME}\",\"version\":{{\"major\":1,\"minor\":0}},\"requestId\":\"control_request_11111111111111111111111111111111\",\"operation\":\"{operation}\",\"body\":{body}}}"
        )
        .into_bytes()
    }

    fn request_value(operation: &str, body: Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "protocol": HUMAN_CONTROL_PROTOCOL_NAME,
            "version": {"major": 1, "minor": 0},
            "requestId": "control_request_11111111111111111111111111111111",
            "operation": operation,
            "body": body,
        }))
        .expect("request JSON")
    }

    #[test]
    fn frozen_envelope_accepts_known_operation_and_rejects_capabilities_or_unknown_fields() {
        let readiness = decode_current(request("readiness.get", "{}")).expect("readiness envelope");
        assert_eq!(readiness.operation(), HumanControlOperation::ReadinessGet);
        assert_eq!(readiness.version(), HumanControlProtocolVersion::current());
        assert!(matches!(
            readiness
                .to_typed_request(StateTimestamp::from_unix_millis(1).expect("timestamp"))
                .expect("typed readiness"),
            HumanControlRequest::ReadinessGet
        ));

        for operation in [
            "credential.search",
            "access.request",
            "http.request",
            "process.run",
        ] {
            assert_eq!(
                decode_current(request(operation, "{}")),
                Err(HumanControlWireError::Malformed)
            );
        }
        assert_eq!(
            decode_current(request(
                "machine-access.pause.set",
                "{\"paused\":true,\"unexpected\":false}"
            )),
            Err(HumanControlWireError::Malformed)
        );
    }

    #[test]
    fn duplicate_keys_future_version_and_incomplete_body_fail_closed() {
        let duplicate = request("audit.list", "{\"filter\":{},\"filter\":{},\"limit\":10}");
        assert_eq!(
            decode_current(duplicate),
            Err(HumanControlWireError::Malformed)
        );
        let future = String::from_utf8(request("readiness.get", "{}"))
            .expect("utf8")
            .replace("\"major\":1", "\"major\":2");
        assert_eq!(
            decode_current(future.into_bytes()),
            Err(HumanControlWireError::Incompatible)
        );
        assert_eq!(
            decode_current(request(
                "credential.allow-once",
                "{\"pendingRequestId\":\"approval_x\",\"credentialId\":\"credential_x\"}"
            )),
            Err(HumanControlWireError::Malformed)
        );

        let marker = "seeded-private-input-marker";
        let malformed = request("readiness.get", &format!("{{\"unexpected\":\"{marker}\"}}"));
        let error = decode_current(malformed).expect_err("private input must fail closed");
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
    }

    #[test]
    fn hello_accepts_compatible_minor_but_post_hello_frames_match_selected_exactly() {
        let future_broker = HumanControlProtocolVersion::new(1, 7).expect("future broker");
        let selected = HumanControlProtocolVersion::new(1, 0).expect("selected protocol");
        let hello = decode_human_control_wire_envelope_with_expectation(
            request(
                "hello",
                "{\"role\":\"human-controller\",\"protocolVersions\":[{\"major\":1,\"minimumMinor\":0,\"maximumMinor\":0}],\"schemaIds\":[\"keptnear.human-control.schema.v1\"]}",
            ),
            HumanControlWireVersionExpectation::InitialHello {
                broker: future_broker,
            },
        )
        .expect("compatible hello envelope");
        assert_eq!(hello.version(), selected);

        assert!(
            decode_human_control_wire_envelope(request("readiness.get", "{}"), selected,).is_ok()
        );
        assert_eq!(
            decode_human_control_wire_envelope(request("readiness.get", "{}"), future_broker,),
            Err(HumanControlWireError::Incompatible)
        );
        assert_eq!(
            decode_human_control_wire_envelope_with_expectation(
                request("readiness.get", "{}"),
                HumanControlWireVersionExpectation::InitialHello {
                    broker: future_broker,
                },
            ),
            Err(HumanControlWireError::Incompatible)
        );
    }

    #[test]
    fn operation_values_and_nested_objects_are_closed_and_canonical() {
        let vault_id = VaultId::generate();
        let valid_unlock = request(
            "vault.unlock",
            &format!(
                "{{\"vaultId\":\"{vault_id}\",\"credential\":{{\"kind\":\"local-material\",\"valueBase64\":\"{}\"}}}}",
                BASE64_STANDARD.encode([0x22; LOCAL_UNLOCK_MATERIAL_LENGTH])
            ),
        );
        assert!(decode_current(valid_unlock).is_ok());

        for malformed in [
            request("machine-access.pause.set", "{\"paused\":\"true\"}"),
            request(
                "vault.unlock",
                &format!(
                    "{{\"vaultId\":\"{vault_id}\",\"credential\":{{\"kind\":\"local-material\",\"valueBase64\":\"{}\",\"source\":\"keychain\"}}}}",
                    BASE64_STANDARD.encode([0x22; LOCAL_UNLOCK_MATERIAL_LENGTH])
                ),
            ),
            request(
                "vault.unlock",
                &format!(
                    "{{\"vaultId\":\"{vault_id}\",\"credential\":{{\"kind\":\"local-material\",\"valueBase64\":\"{}\"}}}}",
                    BASE64_STANDARD.encode([0x22; LOCAL_UNLOCK_MATERIAL_LENGTH - 1])
                ),
            ),
            request(
                "vault.unlock",
                &format!(
                    "{{\"vaultId\":\"{vault_id}\",\"credential\":{{\"kind\":\"local-material\",\"valueBase64\":\"{}\"}}}}",
                    BASE64_STANDARD
                        .encode([0x22; LOCAL_UNLOCK_MATERIAL_LENGTH])
                        .trim_end_matches('=')
                ),
            ),
            request(
                "audit.list",
                "{\"filter\":{\"eventKind\":\"authorization\",\"unknown\":true},\"limit\":10}",
            ),
            request(
                "audit.list",
                "{\"filter\":{},\"limit\":0}",
            ),
            request(
                "consumer.detail",
                "{\"consumerId\":\"consumer_ABCDEFABCDEFABCDEFABCDEFABCDEFAB\"}",
            ),
        ] {
            assert_eq!(
                decode_current(malformed),
                Err(HumanControlWireError::Malformed)
            );
        }

        let stale_repair = request(
            "repair.prepare",
            "{\"expectedComponent\":\"broker\",\"expectedProtocol\":{\"major\":2,\"minor\":0}}",
        );
        assert!(decode_current(stale_repair).is_ok());
        let mismatched_component = request(
            "repair.prepare",
            "{\"expectedComponent\":\"macos-app\",\"expectedProtocol\":{\"major\":1,\"minor\":0}}",
        );
        assert!(decode_current(mismatched_component).is_ok());
        for malformed in [
            request(
                "repair.prepare",
                "{\"expectedComponent\":\"broker\",\"expectedProtocol\":{\"major\":0,\"minor\":0}}",
            ),
            request(
                "repair.prepare",
                "{\"expectedComponent\":\"broker\",\"expectedProtocol\":{\"major\":2,\"minor\":0,\"patch\":1}}",
            ),
            request(
                "repair.prepare",
                "{\"expectedComponent\":\"broker\",\"expectedProtocol\":{\"major\":\"2\",\"minor\":0}}",
            ),
            request(
                "repair.prepare",
                "{\"expectedComponent\":\"unknown\",\"expectedProtocol\":{\"major\":1,\"minor\":0}}",
            ),
        ] {
            assert_eq!(
                decode_current(malformed),
                Err(HumanControlWireError::Malformed)
            );
        }
    }

    #[test]
    fn structurally_valid_hello_identity_mismatches_reach_negotiation() {
        for (body, expected_role, expected_schema) in [
            (
                "{\"role\":\"consumer\",\"protocolVersions\":[{\"major\":1,\"minimumMinor\":0,\"maximumMinor\":0}],\"schemaIds\":[\"keptnear.human-control.schema.v1\"]}",
                "consumer",
                "keptnear.human-control.schema.v1",
            ),
            (
                "{\"role\":\"human-controller\",\"protocolVersions\":[{\"major\":1,\"minimumMinor\":0,\"maximumMinor\":0}],\"schemaIds\":[\"keptnear.human-control.schema.v2\"]}",
                "human-controller",
                "keptnear.human-control.schema.v2",
            ),
        ] {
            let envelope = decode_human_control_hello_wire_envelope(request("hello", body))
                .expect("structurally valid hello");
            let typed = envelope
                .to_typed_request(StateTimestamp::from_unix_millis(10).expect("timestamp"))
                .expect("typed hello");
            let HumanControlRequest::Hello(offer) = typed else {
                panic!("hello operation must reconstruct a hello request");
            };
            assert_eq!(offer.role(), expected_role);
            assert_eq!(offer.schema_ids(), &[expected_schema.to_owned()]);
        }
        for malformed in [
            "{\"role\":\"\",\"protocolVersions\":[{\"major\":1,\"minimumMinor\":0,\"maximumMinor\":0}],\"schemaIds\":[\"keptnear.human-control.schema.v1\"]}",
            "{\"role\":\"human controller\",\"protocolVersions\":[{\"major\":1,\"minimumMinor\":0,\"maximumMinor\":0}],\"schemaIds\":[\"keptnear.human-control.schema.v1\"]}",
            "{\"role\":\"human-controller\",\"protocolVersions\":[{\"major\":1,\"minimumMinor\":0,\"maximumMinor\":0}],\"schemaIds\":[\"keptnear.human-control.schema.v2\",\"keptnear.human-control.schema.v2\"]}",
        ] {
            assert_eq!(
                decode_human_control_hello_wire_envelope(request("hello", malformed)),
                Err(HumanControlWireError::Malformed)
            );
        }
    }

    #[test]
    fn validated_audit_cursor_reconstructs_the_typed_continuation_position() {
        let event_id = AuditEventId::generate();
        let payload = request(
            "audit.list",
            &format!(
                "{{\"filter\":{{}},\"cursor\":{{\"occurredAtMs\":42,\"auditEventId\":\"{event_id}\"}},\"limit\":17}}"
            ),
        );
        let envelope = decode_current(payload).expect("audit envelope");
        let typed = envelope
            .to_typed_request(StateTimestamp::from_unix_millis(100).expect("timestamp"))
            .expect("typed audit request");
        let HumanControlRequest::AuditList {
            filter,
            cursor: Some(cursor),
            limit,
        } = typed
        else {
            panic!("audit.list must retain its validated cursor");
        };
        assert_eq!(filter, BrokerAuditFilter::all());
        assert_eq!(cursor.occurred_at().unix_millis(), 42);
        assert_eq!(cursor.audit_event_id(), event_id);
        assert_eq!(limit, 17);
    }

    #[test]
    fn every_frozen_operation_reconstructs_exactly_one_typed_request() {
        let controller_id = format!("controller_{}", "11".repeat(32));
        let controller_session_id = ControllerSessionId::generate().to_string();
        let broker_instance_id = BrokerInstanceId::generate().to_string();
        let client_nonce = ControllerNonce::generate().to_string();
        let broker_nonce = ControllerNonce::generate().to_string();
        let vault_id = VaultId::generate().to_string();
        let credential_id = CredentialId::generate().to_string();
        let secret_field_id = SecretFieldId::generate().to_string();
        let pairing_id = PairingRequestId::generate().to_string();
        let approval_id = ApprovalRequestId::generate().to_string();
        let consumer_id = ConsumerId::generate().to_string();
        let usage_profile_id = UsageProfileId::generate().to_string();
        let use_grant_id = UseGrantId::generate().to_string();
        let audit_event_id = AuditEventId::generate().to_string();
        let confirmation_id = HumanControlAuditConfirmationId::generate().to_string();
        let selection = || {
            serde_json::json!({
                "pendingRequestId": approval_id,
                "credentialId": credential_id,
                "secretFieldId": secret_field_id,
            })
        };
        let operations = vec![
            (
                "hello",
                serde_json::json!({
                    "role": "human-controller",
                    "protocolVersions": [{"major": 1, "minimumMinor": 0, "maximumMinor": 0}],
                    "schemaIds": ["keptnear.human-control.schema.v1"],
                }),
            ),
            (
                "controller.challenge",
                serde_json::json!({"controllerId": controller_id, "clientNonce": client_nonce}),
            ),
            (
                "controller.authenticate",
                serde_json::json!({
                    "controllerId": controller_id,
                    "controllerSessionId": controller_session_id,
                    "brokerInstanceId": broker_instance_id,
                    "clientNonce": client_nonce,
                    "brokerNonce": broker_nonce,
                    "deadline": "controller_deadline_1",
                    "proof": BASE64_STANDARD.encode([0x31; crate::CONTROLLER_SIGNATURE_LENGTH]),
                }),
            ),
            (
                "controller.lease.renew",
                serde_json::json!({
                    "controllerSessionId": controller_session_id,
                    "brokerInstanceId": broker_instance_id,
                }),
            ),
            ("readiness.get", serde_json::json!({})),
            (
                "machine-access.pause.set",
                serde_json::json!({"paused": true}),
            ),
            (
                "vault.unlock",
                serde_json::json!({
                    "vaultId": vault_id,
                    "credential": {
                        "kind": "local-material",
                        "valueBase64": BASE64_STANDARD.encode([0x42; LOCAL_UNLOCK_MATERIAL_LENGTH]),
                    },
                }),
            ),
            ("vault.lock", serde_json::json!({"vaultId": vault_id})),
            ("pending.list", serde_json::json!({})),
            (
                "pending.deny",
                serde_json::json!({"pendingRequestId": approval_id, "decision": "deny"}),
            ),
            (
                "pairing.approve",
                serde_json::json!({"pendingRequestId": pairing_id, "label": "Local Tool"}),
            ),
            (
                "unlock.approve",
                serde_json::json!({"pendingRequestId": approval_id, "vaultId": vault_id}),
            ),
            (
                "credential.review",
                serde_json::json!({"pendingRequestId": approval_id}),
            ),
            ("credential.allow-once", selection()),
            ("credential.authorize", {
                let mut body = selection();
                let object = body.as_object_mut().expect("selection object");
                object.insert(
                    "capability".to_owned(),
                    serde_json::json!({"name": "http.request", "version": 1}),
                );
                object.insert(
                    "confirmationPolicy".to_owned(),
                    Value::String("every-use".to_owned()),
                );
                object.insert(
                    "ruleLifetime".to_owned(),
                    serde_json::json!({"kind": "persistent"}),
                );
                body
            }),
            (
                "authorization.snapshot",
                serde_json::json!({"vaultId": vault_id}),
            ),
            (
                "consumer.detail",
                serde_json::json!({"consumerId": consumer_id}),
            ),
            (
                "usage-profile.catalog",
                serde_json::json!({"consumerId": consumer_id, "executableName": "gh"}),
            ),
            (
                "usage-profile.create",
                serde_json::json!({
                    "consumerId": consumer_id,
                    "templateId": "http-bearer-authorization",
                    "label": "GitHub API",
                    "technicalField": null,
                }),
            ),
            (
                "usage-profile.remove",
                serde_json::json!({
                    "consumerId": consumer_id,
                    "usageProfileId": usage_profile_id,
                }),
            ),
            (
                "access.field.revoke",
                serde_json::json!({
                    "consumerId": consumer_id,
                    "vaultId": vault_id,
                    "credentialId": credential_id,
                    "secretFieldId": secret_field_id,
                }),
            ),
            (
                "grant.revoke",
                serde_json::json!({"consumerId": consumer_id, "useGrantId": use_grant_id}),
            ),
            (
                "consumer.revoke",
                serde_json::json!({
                    "consumerId": consumer_id,
                    "scope": HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE,
                }),
            ),
            ("access.all.revoke", serde_json::json!({})),
            (
                "audit.list",
                serde_json::json!({
                    "filter": {},
                    "cursor": {"occurredAtMs": 42, "auditEventId": audit_event_id},
                    "limit": 17,
                }),
            ),
            (
                "audit.clear",
                serde_json::json!({"selection": {}, "confirmationId": confirmation_id}),
            ),
            (
                "audit.export",
                serde_json::json!({"filter": {}, "limit": 17}),
            ),
            (
                "repair.prepare",
                serde_json::json!({
                    "expectedComponent": "broker",
                    "expectedProtocol": {"major": 1, "minor": 0},
                }),
            ),
            (
                "shutdown",
                serde_json::json!({"reason": HUMAN_CONTROL_SHUTDOWN_REASON}),
            ),
        ];
        assert_eq!(operations.len(), 29);
        let observed_at = StateTimestamp::from_unix_millis(100).expect("timestamp");
        for (operation, body) in operations {
            let envelope = decode_current(request_value(operation, body))
                .unwrap_or_else(|error| panic!("{operation} envelope failed: {error}"));
            let typed = envelope
                .to_typed_request(observed_at)
                .unwrap_or_else(|error| panic!("{operation} typed request failed: {error}"));
            assert_eq!(typed.operation(), envelope.operation(), "{operation}");
        }
    }

    #[test]
    fn unlock_base64_is_bounded_before_and_after_decoding() {
        let vault_id = VaultId::generate();
        let oversized =
            BASE64_STANDARD.encode(vec![0x44; MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES + 1]);
        let payload = request(
            "vault.unlock",
            &format!(
                "{{\"vaultId\":\"{vault_id}\",\"credential\":{{\"kind\":\"master-password\",\"valueBase64\":\"{oversized}\"}}}}"
            ),
        );
        assert_eq!(
            decode_current(payload),
            Err(HumanControlWireError::Oversized)
        );
    }

    #[test]
    fn validated_envelope_debug_never_reflects_unlock_material() {
        let marker = "seeded-wire-unlock-secret-marker";
        let payload = request(
            "vault.unlock",
            &format!(
                "{{\"vaultId\":\"{}\",\"credential\":{{\"kind\":\"master-password\",\"valueBase64\":\"{}\"}}}}",
                VaultId::generate(),
                BASE64_STANDARD.encode(marker)
            ),
        );
        let envelope = decode_current(payload).expect("unlock envelope");
        let debug = format!("{envelope:?}");
        assert!(!debug.contains(marker));
        assert!(!debug.contains(&BASE64_STANDARD.encode(marker)));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn frame_codec_round_trips_and_rejects_empty_truncated_and_oversized_lengths() {
        let payload = request("pending.list", "{}");
        let mut frame = Vec::new();
        write_human_control_frame(&mut frame, &payload).expect("write frame");
        let mut read = read_human_control_frame(&mut frame.as_slice())
            .expect("read frame")
            .expect("payload");
        assert_eq!(read.as_bytes(), payload);
        assert!(!format!("{read:?}").contains("pending.list"));
        read.zeroize();
        assert!(read.as_bytes().iter().all(|byte| *byte == 0));
        assert!(matches!(
            read_human_control_frame(&mut [0, 0, 0, 0].as_slice()),
            Err(HumanControlWireError::Empty)
        ));
        assert!(matches!(
            read_human_control_frame(&mut [0, 0, 0, 3, b'{'].as_slice()),
            Err(HumanControlWireError::Truncated)
        ));
        let oversized = u32::try_from(MAX_HUMAN_CONTROL_FRAME_LENGTH + 1)
            .expect("length")
            .to_be_bytes();
        assert!(matches!(
            read_human_control_frame(&mut oversized.as_slice()),
            Err(HumanControlWireError::Oversized)
        ));
    }
}
