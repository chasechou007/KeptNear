use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};
use std::str::FromStr;

use serde_json::Value;

use crate::{
    HumanControlOperation, HumanControlProtocolVersion, HumanControlRequestId,
    HUMAN_CONTROL_PROTOCOL_NAME, MAX_HUMAN_CONTROL_FRAME_LENGTH,
};

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanControlWireEnvelope {
    request_id: HumanControlRequestId,
    version: HumanControlProtocolVersion,
    operation: HumanControlOperation,
    body: serde_json::Map<String, Value>,
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
    let mut envelope = value
        .as_object()
        .cloned()
        .ok_or(HumanControlWireError::Malformed)?;
    if envelope.len() != 5 {
        return Err(HumanControlWireError::Malformed);
    }
    if take_string(&mut envelope, "protocol")? != HUMAN_CONTROL_PROTOCOL_NAME {
        return Err(HumanControlWireError::Incompatible);
    }
    let version = take_version(&mut envelope)?;
    if version != HumanControlProtocolVersion::current() {
        return Err(HumanControlWireError::Incompatible);
    }
    let request_id = HumanControlRequestId::from_str(&take_string(&mut envelope, "requestId")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let operation = HumanControlOperation::from_str(&take_string(&mut envelope, "operation")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let body = envelope
        .remove("body")
        .and_then(|body| body.as_object().cloned())
        .ok_or(HumanControlWireError::Malformed)?;
    if !envelope.is_empty() {
        return Err(HumanControlWireError::Malformed);
    }
    if payload.len() > operation.contract().maximum_request_length() {
        return Err(HumanControlWireError::Oversized);
    }
    validate_body_keys(operation, &body)?;
    Ok(HumanControlWireEnvelope {
        request_id,
        version,
        operation,
        body,
    })
}

fn take_string(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, HumanControlWireError> {
    object
        .remove(key)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(HumanControlWireError::Malformed)
}

fn take_version(
    object: &mut serde_json::Map<String, Value>,
) -> Result<HumanControlProtocolVersion, HumanControlWireError> {
    let version = object
        .remove("version")
        .and_then(|value| value.as_object().cloned())
        .ok_or(HumanControlWireError::Malformed)?;
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
