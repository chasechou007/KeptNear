use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use psw_core::{CredentialId, SecretFieldId, VaultId};
use serde_json::Value;
use zeroize::Zeroize;

use crate::{
    bundled_usage_profile_template, ApprovalRequestId, AuditDecision, AuditEventId, AuditEventKind,
    BrokerInstanceId, BundledUsageProfileTemplateId, CapabilityName, ConfirmationPolicy,
    ConsumerId, ControllerDeadline, ControllerId, ControllerNonce, ControllerSessionId,
    HumanControlAuditConfirmationId, HumanControlOperation, HumanControlProtocolVersion,
    HumanControlRequestId, PairingRequestId, UsageProfileId, UseGrantId,
    HUMAN_CONTROL_CONSUMER_REVOKE_SCOPE, HUMAN_CONTROL_DENY_DECISION, HUMAN_CONTROL_PROTOCOL_NAME,
    HUMAN_CONTROL_SCHEMA_ID, HUMAN_CONTROL_SHUTDOWN_REASON, MAX_HUMAN_CONTROL_AUDIT_EVENTS,
    MAX_HUMAN_CONTROL_FRAME_LENGTH, MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES,
    MAX_HUMAN_CONTROL_SCHEMA_IDS, MAX_HUMAN_CONTROL_UNLOCK_CREDENTIAL_BYTES,
    MAX_HUMAN_CONTROL_VERSION_RANGES,
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

    /// Returns the validated closed body for typed value decoding.
    #[must_use]
    pub const fn body(&self) -> &serde_json::Map<String, Value> {
        &self.body
    }
}

/// Validates one complete frozen JSON payload with duplicate-key rejection at every depth.
pub fn decode_human_control_wire_envelope(
    payload: &[u8],
) -> Result<HumanControlWireEnvelope, HumanControlWireError> {
    if payload.is_empty() {
        return Err(HumanControlWireError::Empty);
    }
    if payload.len() > MAX_HUMAN_CONTROL_FRAME_LENGTH {
        return Err(HumanControlWireError::Oversized);
    }
    let value = crate::protocol::parse_unique_json(payload)
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
    if version != HumanControlProtocolVersion::current() {
        return Err(HumanControlWireError::Incompatible);
    }
    let request_id = HumanControlRequestId::from_str(&take_string(&mut envelope.0, "requestId")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let operation = HumanControlOperation::from_str(&take_string(&mut envelope.0, "operation")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let Some(Value::Object(body)) = envelope.0.remove("body") else {
        return Err(HumanControlWireError::Malformed);
    };
    if !envelope.0.is_empty() {
        return Err(HumanControlWireError::Malformed);
    }
    let mut body = ZeroizingJsonObject(body);
    if payload.len() > operation.contract().maximum_request_length() {
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
    if value_string(body, "role")? != crate::CONTROLLER_ROLE {
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
    if !unique.contains(HUMAN_CONTROL_SCHEMA_ID) {
        return Err(HumanControlWireError::Malformed);
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
) -> Result<Option<Vec<u8>>, HumanControlWireError> {
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
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
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

    fn request(operation: &str, body: &str) -> Vec<u8> {
        format!(
            "{{\"protocol\":\"{HUMAN_CONTROL_PROTOCOL_NAME}\",\"version\":{{\"major\":1,\"minor\":0}},\"requestId\":\"control_request_11111111111111111111111111111111\",\"operation\":\"{operation}\",\"body\":{body}}}"
        )
        .into_bytes()
    }

    #[test]
    fn frozen_envelope_accepts_known_operation_and_rejects_capabilities_or_unknown_fields() {
        let readiness = decode_human_control_wire_envelope(&request("readiness.get", "{}"))
            .expect("readiness envelope");
        assert_eq!(readiness.operation(), HumanControlOperation::ReadinessGet);
        assert_eq!(readiness.version(), HumanControlProtocolVersion::current());
        assert!(readiness.body().is_empty());

        for operation in [
            "credential.search",
            "access.request",
            "http.request",
            "process.run",
        ] {
            assert_eq!(
                decode_human_control_wire_envelope(&request(operation, "{}")),
                Err(HumanControlWireError::Malformed)
            );
        }
        assert_eq!(
            decode_human_control_wire_envelope(&request(
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
            decode_human_control_wire_envelope(&duplicate),
            Err(HumanControlWireError::Malformed)
        );
        let future = String::from_utf8(request("readiness.get", "{}"))
            .expect("utf8")
            .replace("\"major\":1", "\"major\":2");
        assert_eq!(
            decode_human_control_wire_envelope(future.as_bytes()),
            Err(HumanControlWireError::Incompatible)
        );
        assert_eq!(
            decode_human_control_wire_envelope(&request(
                "credential.allow-once",
                "{\"pendingRequestId\":\"approval_x\",\"credentialId\":\"credential_x\"}"
            )),
            Err(HumanControlWireError::Malformed)
        );

        let marker = "seeded-private-input-marker";
        let malformed = request("readiness.get", &format!("{{\"unexpected\":\"{marker}\"}}"));
        let error = decode_human_control_wire_envelope(&malformed)
            .expect_err("private input must fail closed");
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
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
        assert!(decode_human_control_wire_envelope(&valid_unlock).is_ok());

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
                decode_human_control_wire_envelope(&malformed),
                Err(HumanControlWireError::Malformed)
            );
        }

        let stale_repair = request(
            "repair.prepare",
            "{\"expectedComponent\":\"broker\",\"expectedProtocol\":{\"major\":2,\"minor\":0}}",
        );
        assert!(decode_human_control_wire_envelope(&stale_repair).is_ok());
        let mismatched_component = request(
            "repair.prepare",
            "{\"expectedComponent\":\"macos-app\",\"expectedProtocol\":{\"major\":1,\"minor\":0}}",
        );
        assert!(decode_human_control_wire_envelope(&mismatched_component).is_ok());
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
                decode_human_control_wire_envelope(&malformed),
                Err(HumanControlWireError::Malformed)
            );
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
            decode_human_control_wire_envelope(&payload),
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
        let envelope = decode_human_control_wire_envelope(&payload).expect("unlock envelope");
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
        assert_eq!(
            read_human_control_frame(&mut frame.as_slice()).expect("read frame"),
            Some(payload)
        );
        assert_eq!(
            read_human_control_frame(&mut [0, 0, 0, 0].as_slice()),
            Err(HumanControlWireError::Empty)
        );
        assert_eq!(
            read_human_control_frame(&mut [0, 0, 0, 3, b'{'].as_slice()),
            Err(HumanControlWireError::Truncated)
        );
        let oversized = u32::try_from(MAX_HUMAN_CONTROL_FRAME_LENGTH + 1)
            .expect("length")
            .to_be_bytes();
        assert_eq!(
            read_human_control_frame(&mut oversized.as_slice()),
            Err(HumanControlWireError::Oversized)
        );
    }
}
