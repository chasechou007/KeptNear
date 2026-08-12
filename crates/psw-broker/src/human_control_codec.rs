use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use zeroize::Zeroize;

use crate::human_control_dispatcher::{
    HumanControlAuthorizationSnapshot, HumanControlConsumerDetail,
};
use crate::{
    AuditEvent, BrokerAuditFilter, BrokerConsumerAuditSummary, BrokerConsumerIdentityEvidence,
    BrokerConsumerSummary, BrokerFieldGrantSummary, BrokerPendingRequestId,
    BrokerPendingRequestKind, BrokerProtectedStateCategory, BrokerRevocationKind,
    BrokerUsageProfileSummary, BrokerVaultLockState, BrokerVaultSessionSnapshot, Capability,
    ConsumerCodeSigningEvidence, ControllerAuthenticationChallenge, ControllerAuthenticationMode,
    ControllerId, ControllerNonce, ControllerSessionId, CredentialFieldScope,
    HumanControlCredentialCandidate, HumanControlCredentialReview, HumanControlFailureCode,
    HumanControlFrame, HumanControlOperation, HumanControlPendingRequest,
    HumanControlProtocolFailure, HumanControlProtocolVersion, HumanControlRequest,
    HumanControlRequestId, HumanControlRequiredAction, HumanControlResponse,
    HumanControlResponseSchema, HumanControlSecretFieldCandidate, HumanControlUsageProfileCatalog,
    HumanControlVaultUnlockCredential, HumanControlWireError, RuleLifetime, StateTimestamp,
    UsagePlacement, UsageProfile, UsageProfileDefinition, UsageProfileTemplateTechnicalField,
    HUMAN_CONTROL_PROTOCOL_NAME, HUMAN_CONTROL_SCHEMA_ID, MAX_HUMAN_CONTROL_AUDIT_EVENTS,
    MAX_HUMAN_CONTROL_COLLECTION_ITEMS, MAX_HUMAN_CONTROL_FRAME_LENGTH,
    MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES, MAX_HUMAN_CONTROL_RESPONSE_LENGTH,
};

/// Validated success response received by a Human Control client.
pub struct HumanControlSuccessEnvelope {
    request_id: HumanControlRequestId,
    version: HumanControlProtocolVersion,
    operation: HumanControlOperation,
    result: Map<String, Value>,
}

impl HumanControlSuccessEnvelope {
    /// Returns the matching request identity.
    #[must_use]
    pub const fn request_id(&self) -> HumanControlRequestId {
        self.request_id
    }

    /// Returns the exact selected protocol version.
    #[must_use]
    pub const fn version(&self) -> HumanControlProtocolVersion {
        self.version
    }

    /// Returns the operation whose response schema was validated.
    #[must_use]
    pub const fn operation(&self) -> HumanControlOperation {
        self.operation
    }

    /// Reconstructs a validated controller challenge for transcript signing.
    pub fn controller_challenge(
        &self,
    ) -> Result<ControllerAuthenticationChallenge, HumanControlWireError> {
        if self.operation != HumanControlOperation::ControllerChallenge {
            return Err(HumanControlWireError::Malformed);
        }
        let mode = ControllerAuthenticationMode::from_wire(string(&self.result, "mode")?)
            .map_err(|_| HumanControlWireError::Malformed)?;
        let protocol = protocol_version(object(&self.result, "protocol")?)?;
        let public_key = fixed_base64::<32>(string(&self.result, "publicKeyBase64")?)?;
        ControllerAuthenticationChallenge::from_validated_wire_bindings(
            mode,
            protocol,
            parse(&self.result, "brokerInstanceId")?,
            parse(&self.result, "controllerId")?,
            public_key,
            parse(&self.result, "controllerSessionId")?,
            parse(&self.result, "clientNonce")?,
            parse(&self.result, "brokerNonce")?,
            parse(&self.result, "deadline")?,
        )
        .map_err(|_| HumanControlWireError::Malformed)
    }

    /// Returns the selected protocol, schema, and Broker instance from `hello`.
    pub fn hello_selection(
        &self,
    ) -> Result<(HumanControlProtocolVersion, &str, crate::BrokerInstanceId), HumanControlWireError>
    {
        if self.operation != HumanControlOperation::Hello {
            return Err(HumanControlWireError::Malformed);
        }
        Ok((
            protocol_version(object(&self.result, "protocol")?)?,
            string(&self.result, "schema")?,
            parse(&self.result, "brokerInstanceId")?,
        ))
    }

    /// Returns the authenticated controller and session identities.
    pub fn authenticated_session(
        &self,
    ) -> Result<(ControllerId, ControllerSessionId, u64), HumanControlWireError> {
        if self.operation != HumanControlOperation::ControllerAuthenticate {
            return Err(HumanControlWireError::Malformed);
        }
        Ok((
            parse(&self.result, "controllerId")?,
            parse(&self.result, "controllerSessionId")?,
            unsigned(&self.result, "leaseDurationMs")?,
        ))
    }

    /// Verifies that `hello` returned the exact complete operation catalog.
    #[must_use]
    pub fn has_complete_operation_catalog(&self) -> bool {
        if self.operation != HumanControlOperation::Hello {
            return false;
        }
        let Some(operations) = self.result.get("operations").and_then(Value::as_array) else {
            return false;
        };
        operations.len() == crate::HUMAN_CONTROL_OPERATION_CONTRACTS.len()
            && crate::HUMAN_CONTROL_OPERATION_CONTRACTS
                .iter()
                .zip(operations)
                .all(|(contract, value)| value.as_str() == Some(contract.operation().as_str()))
    }

    /// Returns the validated lease session and duration receipt.
    pub fn controller_lease(&self) -> Result<(ControllerSessionId, u64), HumanControlWireError> {
        if self.operation != HumanControlOperation::ControllerLeaseRenew {
            return Err(HumanControlWireError::Malformed);
        }
        Ok((
            parse(&self.result, "controllerSessionId")?,
            unsigned(&self.result, "leaseDurationMs")?,
        ))
    }

    /// Returns the validated secret-free result JSON for later typed App projection.
    #[must_use]
    pub fn result(&self) -> &Map<String, Value> {
        &self.result
    }
}

impl Debug for HumanControlSuccessEnvelope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanControlSuccessEnvelope")
            .field("request_id", &self.request_id)
            .field("version", &self.version)
            .field("operation", &self.operation)
            .field("result", &"<validated-secret-free>")
            .finish()
    }
}

impl Drop for HumanControlSuccessEnvelope {
    fn drop(&mut self) {
        for value in self.result.values_mut() {
            zeroize_json_strings(value);
        }
    }
}

/// Successful or fixed-failure Human Control response.
#[derive(Debug)]
pub enum HumanControlClientResponse {
    /// A response body validated against the operation's closed schema.
    Success(HumanControlSuccessEnvelope),
    /// A fixed response with no free-form or reflected input.
    Failure(HumanControlProtocolFailure),
}

struct ZeroizingJsonObject(Map<String, Value>);

impl Zeroize for ZeroizingJsonObject {
    fn zeroize(&mut self) {
        for value in self.0.values_mut() {
            zeroize_json_strings(value);
        }
    }
}

impl Drop for ZeroizingJsonObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Encodes one typed Human Control request under the exact selected version.
pub fn encode_human_control_request(
    request_id: HumanControlRequestId,
    version: HumanControlProtocolVersion,
    request: &HumanControlRequest,
) -> Result<HumanControlFrame, HumanControlWireError> {
    let operation = request.operation();
    let envelope = request_envelope(request_id, version, request)?;
    let payload = serde_json::to_vec(&envelope.0).map_err(|_| HumanControlWireError::Malformed)?;
    if payload.len() > MAX_HUMAN_CONTROL_FRAME_LENGTH
        || payload.len() > operation.contract().maximum_request_length()
    {
        return Err(HumanControlWireError::Oversized);
    }
    Ok(HumanControlFrame::from(payload))
}

fn request_envelope(
    request_id: HumanControlRequestId,
    version: HumanControlProtocolVersion,
    request: &HumanControlRequest,
) -> Result<ZeroizingJsonObject, HumanControlWireError> {
    let mut envelope = Map::new();
    envelope.insert(
        "protocol".to_owned(),
        Value::String(HUMAN_CONTROL_PROTOCOL_NAME.to_owned()),
    );
    envelope.insert("version".to_owned(), version_value(version));
    envelope.insert(
        "requestId".to_owned(),
        Value::String(request_id.to_string()),
    );
    envelope.insert(
        "operation".to_owned(),
        Value::String(request.operation().as_str().to_owned()),
    );
    envelope.insert("body".to_owned(), encode_request_body(request)?);
    Ok(ZeroizingJsonObject(envelope))
}

/// Encodes one successful dispatcher response with a matching request identity.
pub fn encode_human_control_response(
    request_id: HumanControlRequestId,
    version: HumanControlProtocolVersion,
    operation: HumanControlOperation,
    response: &HumanControlResponse,
) -> Result<Vec<u8>, HumanControlWireError> {
    if response_schema(response) != operation.contract().response_schema() {
        return Err(HumanControlWireError::Malformed);
    }
    let result = encode_response_body(response)?;
    validate_response_body(operation.contract().response_schema(), &result)?;
    let payload = serde_json::to_vec(&json!({
        "protocol": HUMAN_CONTROL_PROTOCOL_NAME,
        "version": version_value(version),
        "requestId": request_id.to_string(),
        "result": result,
    }))
    .map_err(|_| HumanControlWireError::Malformed)?;
    if payload.len() > MAX_HUMAN_CONTROL_FRAME_LENGTH
        || payload.len() > operation.contract().maximum_response_length()
    {
        return Err(HumanControlWireError::Oversized);
    }
    Ok(payload)
}

/// Encodes one fixed dispatcher failure with no diagnostic string.
pub fn encode_human_control_failure(
    request_id: HumanControlRequestId,
    version: HumanControlProtocolVersion,
    failure: HumanControlProtocolFailure,
) -> Result<Vec<u8>, HumanControlWireError> {
    let error = json!({
        "code": failure.code().as_str(),
        "retryable": failure.retryable(),
        "requiredAction": failure.required_action().map(HumanControlRequiredAction::as_str),
    });
    let payload = serde_json::to_vec(&json!({
        "protocol": HUMAN_CONTROL_PROTOCOL_NAME,
        "version": version_value(version),
        "requestId": request_id.to_string(),
        "error": error,
    }))
    .map_err(|_| HumanControlWireError::Malformed)?;
    if payload.len() > MAX_HUMAN_CONTROL_FRAME_LENGTH {
        return Err(HumanControlWireError::Oversized);
    }
    Ok(payload)
}

/// Decodes one response against its exact request, version, and operation.
pub fn decode_human_control_response(
    payload: &[u8],
    expected_request_id: HumanControlRequestId,
    expected_version: HumanControlProtocolVersion,
    expected_operation: HumanControlOperation,
) -> Result<HumanControlClientResponse, HumanControlWireError> {
    if payload.is_empty() {
        return Err(HumanControlWireError::Empty);
    }
    if payload.len() > MAX_HUMAN_CONTROL_FRAME_LENGTH
        || payload.len() > expected_operation.contract().maximum_response_length()
    {
        return Err(HumanControlWireError::Oversized);
    }
    let value = crate::protocol::parse_unique_json(payload)
        .map_err(|_| HumanControlWireError::Malformed)?;
    let Value::Object(mut envelope) = value else {
        return Err(HumanControlWireError::Malformed);
    };
    if envelope.len() != 4
        || remove_string(&mut envelope, "protocol")? != HUMAN_CONTROL_PROTOCOL_NAME
        || remove_version(&mut envelope)? != expected_version
        || HumanControlRequestId::from_str(&remove_string(&mut envelope, "requestId")?)
            .map_err(|_| HumanControlWireError::Malformed)?
            != expected_request_id
    {
        return Err(HumanControlWireError::Incompatible);
    }
    match (envelope.remove("result"), envelope.remove("error")) {
        (Some(Value::Object(result)), None) if envelope.is_empty() => {
            validate_response_body(expected_operation.contract().response_schema(), &result)?;
            validate_selected_response_bindings(expected_operation, expected_version, &result)?;
            Ok(HumanControlClientResponse::Success(
                HumanControlSuccessEnvelope {
                    request_id: expected_request_id,
                    version: expected_version,
                    operation: expected_operation,
                    result,
                },
            ))
        }
        (None, Some(Value::Object(error))) if envelope.is_empty() => {
            exact_keys(&error, &["code", "retryable", "requiredAction"])?;
            let code = HumanControlFailureCode::from_str(string(&error, "code")?)
                .map_err(|_| HumanControlWireError::Malformed)?;
            let retryable = boolean(&error, "retryable")?;
            let required_action = match error.get("requiredAction") {
                Some(Value::Null) => None,
                Some(Value::String(value)) => Some(
                    HumanControlRequiredAction::from_str(value)
                        .map_err(|_| HumanControlWireError::Malformed)?,
                ),
                _ => return Err(HumanControlWireError::Malformed),
            };
            Ok(HumanControlClientResponse::Failure(
                HumanControlProtocolFailure::new(code, retryable, required_action),
            ))
        }
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn encode_request_body(request: &HumanControlRequest) -> Result<Value, HumanControlWireError> {
    Ok(match request {
        HumanControlRequest::Hello(offer) => json!({
            "role": offer.role(),
            "protocolVersions": offer.ranges().iter().map(|range| json!({
                "major": range.major(),
                "minimumMinor": range.minimum_minor(),
                "maximumMinor": range.maximum_minor(),
            })).collect::<Vec<_>>(),
            "schemaIds": offer.schema_ids(),
        }),
        HumanControlRequest::ControllerChallenge(request) => json!({
            "controllerId": request.controller_id().to_string(),
            "clientNonce": request.client_nonce().to_string(),
        }),
        HumanControlRequest::ControllerAuthenticate(proof) => json!({
            "brokerInstanceId": proof.broker_instance_id().to_string(),
            "controllerId": proof.controller_id().to_string(),
            "controllerSessionId": proof.session_id().to_string(),
            "clientNonce": proof.client_nonce().to_string(),
            "brokerNonce": proof.broker_nonce().to_string(),
            "deadline": proof.deadline().to_string(),
            "proof": BASE64_STANDARD.encode(proof.signature().as_bytes()),
        }),
        HumanControlRequest::ControllerLeaseRenew {
            controller_session_id,
            broker_instance_id,
        } => json!({
            "controllerSessionId": controller_session_id.to_string(),
            "brokerInstanceId": broker_instance_id.to_string(),
        }),
        HumanControlRequest::ReadinessGet
        | HumanControlRequest::PendingList
        | HumanControlRequest::AllAccessRevoke => json!({}),
        HumanControlRequest::MachineAccessPauseSet { paused } => json!({"paused": paused}),
        HumanControlRequest::VaultUnlock {
            vault_id,
            credential,
        } => {
            let (kind, value) = match credential {
                HumanControlVaultUnlockCredential::MasterPassword(value) => {
                    ("master-password", value.expose())
                }
                HumanControlVaultUnlockCredential::LocalMaterial(value) => {
                    ("local-material", value.expose())
                }
            };
            json!({
                "vaultId": vault_id.to_string(),
                "credential": {"kind": kind, "valueBase64": BASE64_STANDARD.encode(value)},
            })
        }
        HumanControlRequest::VaultLock { vault_id }
        | HumanControlRequest::AuthorizationSnapshot { vault_id } => {
            json!({"vaultId": vault_id.to_string()})
        }
        HumanControlRequest::PendingDeny {
            request_id,
            decision,
        } => json!({
            "pendingRequestId": pending_request_id(*request_id),
            "decision": decision,
        }),
        HumanControlRequest::PairingApprove {
            request_id,
            approval,
        } => json!({
            "pendingRequestId": request_id.to_string(),
            "label": approval.label(),
        }),
        HumanControlRequest::UnlockApprove {
            request_id,
            vault_id,
        } => json!({
            "pendingRequestId": request_id.to_string(),
            "vaultId": vault_id.to_string(),
        }),
        HumanControlRequest::CredentialReview { request_id } => {
            json!({"pendingRequestId": request_id.to_string()})
        }
        HumanControlRequest::CredentialAllowOnce {
            request_id,
            selection,
        } => json!({
            "pendingRequestId": request_id.to_string(),
            "credentialId": selection.credential_id().to_string(),
            "secretFieldId": selection.secret_field_id().to_string(),
        }),
        HumanControlRequest::CredentialAuthorize {
            request_id,
            selection,
            confirmation_policy,
            rule_lifetime,
            capability,
        } => json!({
            "pendingRequestId": request_id.to_string(),
            "credentialId": selection.credential_id().to_string(),
            "secretFieldId": selection.secret_field_id().to_string(),
            "confirmationPolicy": confirmation_policy.as_str(),
            "ruleLifetime": lifetime_value(*rule_lifetime),
            "capability": capability_value(*capability),
        }),
        HumanControlRequest::ConsumerDetail { consumer_id } => {
            json!({"consumerId": consumer_id.to_string()})
        }
        HumanControlRequest::UsageProfileCatalog {
            consumer_id,
            executable_name_hint,
        } => {
            let mut body = Map::from_iter([(
                "consumerId".to_owned(),
                Value::String(consumer_id.to_string()),
            )]);
            if let Some(executable_name) = executable_name_hint {
                body.insert(
                    "executableName".to_owned(),
                    Value::String(executable_name.clone()),
                );
            }
            Value::Object(body)
        }
        HumanControlRequest::UsageProfileCreate {
            consumer_id,
            label,
            definition,
        } => {
            let (template_id, technical_field) = template_from_definition(definition)?;
            json!({
                "consumerId": consumer_id.to_string(),
                "templateId": template_id,
                "label": label,
                "technicalField": technical_field,
            })
        }
        HumanControlRequest::UsageProfileRemove {
            consumer_id,
            usage_profile_id,
        } => json!({
            "consumerId": consumer_id.to_string(),
            "usageProfileId": usage_profile_id.to_string(),
        }),
        HumanControlRequest::FieldAccessRevoke {
            consumer_id,
            field_scope,
        } => {
            let mut value = field_scope_value(*field_scope);
            value.as_object_mut().expect("field scope object").insert(
                "consumerId".to_owned(),
                Value::String(consumer_id.to_string()),
            );
            value
        }
        HumanControlRequest::GrantRevoke {
            consumer_id,
            use_grant_id,
        } => json!({
            "consumerId": consumer_id.to_string(),
            "useGrantId": use_grant_id.to_string(),
        }),
        HumanControlRequest::ConsumerRevoke { consumer_id, scope } => json!({
            "consumerId": consumer_id.to_string(),
            "scope": scope,
        }),
        HumanControlRequest::AuditList {
            filter,
            cursor,
            limit,
        } => {
            let mut body = Map::from_iter([
                ("filter".to_owned(), audit_filter_value(*filter)),
                ("limit".to_owned(), json!(limit)),
            ]);
            if let Some(cursor) = cursor {
                body.insert("cursor".to_owned(), audit_cursor_value(*cursor));
            }
            Value::Object(body)
        }
        HumanControlRequest::AuditClear {
            filter,
            confirmation_id,
        } => json!({
            "selection": audit_filter_value(*filter),
            "confirmationId": confirmation_id.to_string(),
        }),
        HumanControlRequest::AuditExport { filter, limit } => json!({
            "filter": audit_filter_value(*filter),
            "limit": limit,
        }),
        HumanControlRequest::RepairPrepare {
            expected_component,
            expected_protocol,
        } => json!({
            "expectedComponent": expected_component,
            "expectedProtocol": version_value(*expected_protocol),
        }),
        HumanControlRequest::Shutdown { reason } => json!({"reason": reason}),
    })
}

fn response_schema(response: &HumanControlResponse) -> HumanControlResponseSchema {
    match response {
        HumanControlResponse::Hello { .. } => HumanControlResponseSchema::Hello,
        HumanControlResponse::ControllerChallenge(_) => {
            HumanControlResponseSchema::ControllerChallenge
        }
        HumanControlResponse::ControllerAuthenticated { .. } => {
            HumanControlResponseSchema::ControllerAuthenticated
        }
        HumanControlResponse::ControllerLease { .. } => HumanControlResponseSchema::ControllerLease,
        HumanControlResponse::Readiness(_) => HumanControlResponseSchema::Readiness,
        HumanControlResponse::PauseState { .. } => HumanControlResponseSchema::PauseState,
        HumanControlResponse::VaultState(_) => HumanControlResponseSchema::VaultState,
        HumanControlResponse::PendingQueue(_) => HumanControlResponseSchema::PendingQueue,
        HumanControlResponse::DecisionReceipt { .. } => HumanControlResponseSchema::DecisionReceipt,
        HumanControlResponse::CredentialReview(_) => HumanControlResponseSchema::CredentialReview,
        HumanControlResponse::AuthorizationSnapshot(_) => {
            HumanControlResponseSchema::AuthorizationSnapshot
        }
        HumanControlResponse::ConsumerDetail(_) => HumanControlResponseSchema::ConsumerDetail,
        HumanControlResponse::UsageProfileCatalog(_) => {
            HumanControlResponseSchema::UsageProfileCatalog
        }
        HumanControlResponse::UsageProfile(_) => HumanControlResponseSchema::UsageProfile,
        HumanControlResponse::RemovalReceipt { .. } => HumanControlResponseSchema::RemovalReceipt,
        HumanControlResponse::RevocationSummary(_) => HumanControlResponseSchema::RevocationSummary,
        HumanControlResponse::AuditPage(_) => HumanControlResponseSchema::AuditPage,
        HumanControlResponse::AuditClearSummary(_) => HumanControlResponseSchema::AuditClearSummary,
        HumanControlResponse::AuditExport(_) => HumanControlResponseSchema::AuditExport,
        HumanControlResponse::RepairReadiness(_) => HumanControlResponseSchema::RepairReadiness,
        HumanControlResponse::ShutdownReceipt(_) => HumanControlResponseSchema::ShutdownReceipt,
    }
}

fn encode_response_body(
    response: &HumanControlResponse,
) -> Result<Map<String, Value>, HumanControlWireError> {
    let value = match response {
        HumanControlResponse::Hello {
            protocol,
            schema,
            broker_instance_id,
            limits,
            operations,
        } => json!({
            "protocol": version_value(*protocol),
            "schema": schema,
            "brokerInstanceId": broker_instance_id.to_string(),
            "limits": {
                "maximumFrameLength": limits.maximum_frame_length(),
                "maximumCollectionItems": limits.maximum_collection_items(),
                "maximumAuditEvents": limits.maximum_audit_events(),
                "maximumInputTextBytes": limits.maximum_input_text_bytes(),
            },
            "operations": operations.iter().map(|operation| operation.as_str()).collect::<Vec<_>>(),
        }),
        HumanControlResponse::ControllerChallenge(challenge) => json!({
            "mode": challenge.mode().as_str(),
            "protocol": version_value(challenge.protocol()),
            "brokerInstanceId": challenge.broker_instance_id().to_string(),
            "controllerId": challenge.controller_id().to_string(),
            "publicKeyBase64": BASE64_STANDARD.encode(challenge.public_key()),
            "controllerSessionId": challenge.session_id().to_string(),
            "clientNonce": challenge.client_nonce().to_string(),
            "brokerNonce": challenge.broker_nonce().to_string(),
            "deadline": challenge.deadline().to_string(),
        }),
        HumanControlResponse::ControllerAuthenticated {
            controller_id,
            session_id,
            lease_duration_millis,
        } => json!({
            "controllerId": controller_id.to_string(),
            "controllerSessionId": session_id.to_string(),
            "leaseDurationMs": lease_duration_millis,
        }),
        HumanControlResponse::ControllerLease {
            session_id,
            lease_duration_millis,
        } => json!({
            "controllerSessionId": session_id.to_string(),
            "leaseDurationMs": lease_duration_millis,
        }),
        HumanControlResponse::Readiness(readiness) => json!({
            "component": readiness.component(),
            "humanControlProtocol": version_value(readiness.human_control_protocol()),
            "humanControlSchema": readiness.human_control_schema(),
            "protectedState": protected_state(readiness.protected_state()),
            "machineAccessPaused": readiness.machine_access_paused(),
            "vaults": readiness.vaults().iter().copied().map(vault_state_value).collect::<Vec<_>>(),
            "vaultsTruncated": readiness.vaults_truncated(),
        }),
        HumanControlResponse::PauseState { paused } => json!({"paused": paused}),
        HumanControlResponse::VaultState(snapshot) => vault_state_value(*snapshot),
        HumanControlResponse::PendingQueue(requests) => json!({
            "requests": requests.iter().map(pending_value).collect::<Vec<_>>()
        }),
        HumanControlResponse::DecisionReceipt { changed } => json!({"changed": changed}),
        HumanControlResponse::CredentialReview(review) => credential_review_value(review),
        HumanControlResponse::AuthorizationSnapshot(snapshot) => authorization_value(snapshot),
        HumanControlResponse::ConsumerDetail(detail) => consumer_detail_value(detail),
        HumanControlResponse::UsageProfileCatalog(catalog) => usage_catalog_value(catalog),
        HumanControlResponse::UsageProfile(profile) => usage_profile_value(profile),
        HumanControlResponse::RemovalReceipt { removed } => json!({"removed": removed}),
        HumanControlResponse::RevocationSummary(summary) => json!({
            "kind": revocation_kind(summary.kind()),
            "consumersRemoved": summary.consumers_removed(),
            "accessRulesRemoved": summary.access_rules_removed(),
            "useGrantsRemoved": summary.use_grants_removed(),
            "usageProfilesRemoved": summary.usage_profiles_removed(),
            "approvalsRemoved": summary.approvals_removed(),
            "pendingPairingsCancelled": summary.pending_pairings_cancelled(),
            "credentialContextsDiscarded": summary.credential_contexts_discarded(),
        }),
        HumanControlResponse::AuditPage(page) => json!({
            "events": page.page().events().iter().map(audit_event_value).collect::<Vec<_>>(),
            "nextCursor": page.page().next_cursor().map(audit_cursor_value),
            "clearConfirmationId": page.clear_confirmation_id().to_string(),
        }),
        HumanControlResponse::AuditClearSummary(summary) => json!({
            "removedEvents": summary.removed_events(),
            "remainingEvents": summary.remaining_events(),
        }),
        HumanControlResponse::AuditExport(export) => json!({
            "documentJson": export.as_str(),
            "eventCount": export.event_count(),
        }),
        HumanControlResponse::RepairReadiness(summary)
        | HumanControlResponse::ShutdownReceipt(summary) => json!({
            "lockEventsProcessed": summary.lock_events_processed(),
            "useGrantsRemoved": summary.use_grants_removed(),
            "invalidatedAllUseGrants": summary.invalidated_all_use_grants(),
        }),
    };
    value
        .as_object()
        .cloned()
        .ok_or(HumanControlWireError::Malformed)
}

fn validate_response_body(
    schema: HumanControlResponseSchema,
    body: &Map<String, Value>,
) -> Result<(), HumanControlWireError> {
    let keys: &[&str] = match schema {
        HumanControlResponseSchema::Hello => &[
            "protocol",
            "schema",
            "brokerInstanceId",
            "limits",
            "operations",
        ],
        HumanControlResponseSchema::ControllerChallenge => &[
            "mode",
            "protocol",
            "brokerInstanceId",
            "controllerId",
            "publicKeyBase64",
            "controllerSessionId",
            "clientNonce",
            "brokerNonce",
            "deadline",
        ],
        HumanControlResponseSchema::ControllerAuthenticated => {
            &["controllerId", "controllerSessionId", "leaseDurationMs"]
        }
        HumanControlResponseSchema::ControllerLease => &["controllerSessionId", "leaseDurationMs"],
        HumanControlResponseSchema::Readiness => &[
            "component",
            "humanControlProtocol",
            "humanControlSchema",
            "protectedState",
            "machineAccessPaused",
            "vaults",
            "vaultsTruncated",
        ],
        HumanControlResponseSchema::PauseState => &["paused"],
        HumanControlResponseSchema::VaultState => &["vaultId", "lockState", "vaultSessionId"],
        HumanControlResponseSchema::PendingQueue => &["requests"],
        HumanControlResponseSchema::DecisionReceipt => &["changed"],
        HumanControlResponseSchema::CredentialReview => &[
            "consumerId",
            "vaultId",
            "capability",
            "candidates",
            "truncated",
        ],
        HumanControlResponseSchema::AuthorizationSnapshot => &[
            "paused",
            "authorizedCredentialIds",
            "consumers",
            "authorizedCredentialsTruncated",
            "consumersTruncated",
        ],
        HumanControlResponseSchema::ConsumerDetail => &[
            "consumer",
            "fieldGrants",
            "usageProfiles",
            "recentAuditEvents",
            "fieldGrantsTruncated",
            "usageProfilesTruncated",
        ],
        HumanControlResponseSchema::UsageProfileCatalog => {
            &["consumerId", "templates", "recommendation"]
        }
        HumanControlResponseSchema::UsageProfile => &[
            "usageProfileId",
            "consumerId",
            "label",
            "definition",
            "createdAtMs",
        ],
        HumanControlResponseSchema::RemovalReceipt => &["removed"],
        HumanControlResponseSchema::RevocationSummary => &[
            "kind",
            "consumersRemoved",
            "accessRulesRemoved",
            "useGrantsRemoved",
            "usageProfilesRemoved",
            "approvalsRemoved",
            "pendingPairingsCancelled",
            "credentialContextsDiscarded",
        ],
        HumanControlResponseSchema::AuditPage => &["events", "nextCursor", "clearConfirmationId"],
        HumanControlResponseSchema::AuditClearSummary => &["removedEvents", "remainingEvents"],
        HumanControlResponseSchema::AuditExport => &["documentJson", "eventCount"],
        HumanControlResponseSchema::RepairReadiness
        | HumanControlResponseSchema::ShutdownReceipt => &[
            "lockEventsProcessed",
            "useGrantsRemoved",
            "invalidatedAllUseGrants",
        ],
    };
    exact_keys(body, keys)?;
    validate_response_values(schema, body)
}

fn validate_response_values(
    schema: HumanControlResponseSchema,
    body: &Map<String, Value>,
) -> Result<(), HumanControlWireError> {
    match schema {
        HumanControlResponseSchema::Hello => {
            let limits = object(body, "limits")?;
            protocol_version(object(body, "protocol")?)?;
            parse::<crate::BrokerInstanceId>(body, "brokerInstanceId")?;
            exact_keys(
                limits,
                &[
                    "maximumFrameLength",
                    "maximumCollectionItems",
                    "maximumAuditEvents",
                    "maximumInputTextBytes",
                ],
            )?;
            for key in [
                "maximumFrameLength",
                "maximumCollectionItems",
                "maximumAuditEvents",
                "maximumInputTextBytes",
            ] {
                unsigned(limits, key)?;
            }
            if unsigned(limits, "maximumFrameLength")?
                != u64::try_from(MAX_HUMAN_CONTROL_FRAME_LENGTH)
                    .map_err(|_| HumanControlWireError::Malformed)?
                || unsigned(limits, "maximumCollectionItems")?
                    != u64::try_from(MAX_HUMAN_CONTROL_COLLECTION_ITEMS)
                        .map_err(|_| HumanControlWireError::Malformed)?
                || unsigned(limits, "maximumAuditEvents")?
                    != u64::try_from(MAX_HUMAN_CONTROL_AUDIT_EVENTS)
                        .map_err(|_| HumanControlWireError::Malformed)?
                || unsigned(limits, "maximumInputTextBytes")?
                    != u64::try_from(MAX_HUMAN_CONTROL_INPUT_TEXT_BYTES)
                        .map_err(|_| HumanControlWireError::Malformed)?
                || string(body, "schema")? != HUMAN_CONTROL_SCHEMA_ID
            {
                return Err(HumanControlWireError::Malformed);
            }
            let operations = array(body, "operations")?;
            if operations.len() != crate::HUMAN_CONTROL_OPERATION_CONTRACTS.len()
                || crate::HUMAN_CONTROL_OPERATION_CONTRACTS
                    .iter()
                    .zip(operations)
                    .any(|(contract, value)| value.as_str() != Some(contract.operation().as_str()))
            {
                return Err(HumanControlWireError::Malformed);
            }
        }
        HumanControlResponseSchema::ControllerChallenge => {
            ControllerAuthenticationMode::from_wire(string(body, "mode")?)
                .map_err(|_| HumanControlWireError::Malformed)?;
            protocol_version(object(body, "protocol")?)?;
            parse::<crate::BrokerInstanceId>(body, "brokerInstanceId")?;
            parse::<ControllerId>(body, "controllerId")?;
            parse::<ControllerSessionId>(body, "controllerSessionId")?;
            parse::<ControllerNonce>(body, "clientNonce")?;
            parse::<ControllerNonce>(body, "brokerNonce")?;
            parse::<crate::ControllerDeadline>(body, "deadline")?;
            fixed_base64::<32>(string(body, "publicKeyBase64")?)?;
        }
        HumanControlResponseSchema::ControllerAuthenticated => {
            parse::<ControllerId>(body, "controllerId")?;
            parse::<ControllerSessionId>(body, "controllerSessionId")?;
            positive(unsigned(body, "leaseDurationMs")?)?;
        }
        HumanControlResponseSchema::ControllerLease => {
            parse::<ControllerSessionId>(body, "controllerSessionId")?;
            positive(unsigned(body, "leaseDurationMs")?)?;
        }
        HumanControlResponseSchema::Readiness => {
            let _: crate::ComponentMetadata = serde_json::from_value(
                body.get("component")
                    .cloned()
                    .ok_or(HumanControlWireError::Malformed)?,
            )
            .map_err(|_| HumanControlWireError::Malformed)?;
            protocol_version(object(body, "humanControlProtocol")?)?;
            if string(body, "protectedState")? != "authenticated" {
                return Err(HumanControlWireError::Malformed);
            }
            string(body, "humanControlSchema")?;
            boolean(body, "machineAccessPaused")?;
            boolean(body, "vaultsTruncated")?;
            bounded_array(body, "vaults")?
                .iter()
                .try_for_each(validate_vault_state)?;
        }
        HumanControlResponseSchema::PauseState => {
            boolean(body, "paused")?;
        }
        HumanControlResponseSchema::VaultState => {
            validate_vault_state(&Value::Object(body.clone()))?
        }
        HumanControlResponseSchema::PendingQueue => {
            bounded_array(body, "requests")?
                .iter()
                .try_for_each(validate_pending)?;
        }
        HumanControlResponseSchema::DecisionReceipt => {
            boolean(body, "changed")?;
        }
        HumanControlResponseSchema::CredentialReview => validate_credential_review(body)?,
        HumanControlResponseSchema::AuthorizationSnapshot => validate_authorization(body)?,
        HumanControlResponseSchema::ConsumerDetail => validate_consumer_detail(body)?,
        HumanControlResponseSchema::UsageProfileCatalog => validate_usage_catalog(body)?,
        HumanControlResponseSchema::UsageProfile => validate_usage_profile(body)?,
        HumanControlResponseSchema::RemovalReceipt => {
            boolean(body, "removed")?;
        }
        HumanControlResponseSchema::RevocationSummary => {
            match string(body, "kind")? {
                "use-grant" | "consumer-field" | "consumer" | "global" => {}
                _ => return Err(HumanControlWireError::Malformed),
            }
            for key in [
                "consumersRemoved",
                "accessRulesRemoved",
                "useGrantsRemoved",
                "usageProfilesRemoved",
                "approvalsRemoved",
                "pendingPairingsCancelled",
                "credentialContextsDiscarded",
            ] {
                unsigned(body, key)?;
            }
        }
        HumanControlResponseSchema::AuditPage => {
            bounded_array(body, "events")?
                .iter()
                .try_for_each(validate_audit_event)?;
            nullable_object(body, "nextCursor")?
                .map(validate_cursor)
                .transpose()?;
            parse::<crate::HumanControlAuditConfirmationId>(body, "clearConfirmationId")?;
        }
        HumanControlResponseSchema::AuditClearSummary => {
            unsigned(body, "removedEvents")?;
            unsigned(body, "remainingEvents")?;
        }
        HumanControlResponseSchema::AuditExport => {
            let document = string(body, "documentJson")?;
            if document.len() > MAX_HUMAN_CONTROL_RESPONSE_LENGTH
                || serde_json::from_str::<Value>(document).is_err()
            {
                return Err(HumanControlWireError::Malformed);
            }
            let count = unsigned(body, "eventCount")?;
            if count as usize > MAX_HUMAN_CONTROL_COLLECTION_ITEMS {
                return Err(HumanControlWireError::Malformed);
            }
        }
        HumanControlResponseSchema::RepairReadiness
        | HumanControlResponseSchema::ShutdownReceipt => {
            unsigned(body, "lockEventsProcessed")?;
            unsigned(body, "useGrantsRemoved")?;
            boolean(body, "invalidatedAllUseGrants")?;
        }
    }
    Ok(())
}

fn validate_selected_response_bindings(
    operation: HumanControlOperation,
    selected: HumanControlProtocolVersion,
    body: &Map<String, Value>,
) -> Result<(), HumanControlWireError> {
    match operation.contract().response_schema() {
        HumanControlResponseSchema::Hello => {
            if protocol_version(object(body, "protocol")?)? != selected {
                return Err(HumanControlWireError::Incompatible);
            }
        }
        HumanControlResponseSchema::ControllerChallenge => {
            if protocol_version(object(body, "protocol")?)? != selected {
                return Err(HumanControlWireError::Incompatible);
            }
        }
        HumanControlResponseSchema::Readiness => {
            if protocol_version(object(body, "humanControlProtocol")?)? != selected
                || string(body, "humanControlSchema")? != HUMAN_CONTROL_SCHEMA_ID
            {
                return Err(HumanControlWireError::Incompatible);
            }
        }
        _ => {}
    }
    Ok(())
}

fn pending_request_id(id: BrokerPendingRequestId) -> String {
    match id {
        BrokerPendingRequestId::Pairing(id) => id.to_string(),
        BrokerPendingRequestId::Approval(id) => id.to_string(),
    }
}

fn pending_kind(kind: BrokerPendingRequestKind) -> &'static str {
    match kind {
        BrokerPendingRequestKind::Pairing => "pairing",
        BrokerPendingRequestKind::Unlock => "unlock",
        BrokerPendingRequestKind::Access => "access",
        BrokerPendingRequestKind::CredentialAccess => "credential-access",
    }
}

fn pending_value(request: &HumanControlPendingRequest) -> Value {
    json!({
        "pendingRequestId": pending_request_id(request.request_id),
        "kind": pending_kind(request.kind),
        "consumerId": request.consumer_id.map(|value| value.to_string()),
        "identityEvidence": request.identity_evidence.as_ref().map(identity_evidence_value),
        "pairingComparisonCode": request.pairing_comparison_code.map(|value| value.to_string()),
        "pairingKeyFingerprint": request.pairing_key_fingerprint.map(|value| value.to_string()),
        "pairingRemainingMs": request.pairing_remaining_millis,
        "vaultId": request.vault_id.map(|value| value.to_string()),
        "fieldScope": request.field_scope.map(field_scope_value),
        "capability": request.capability.map(capability_value),
        "createdAtMs": request.created_at.map(StateTimestamp::unix_millis),
        "expiresAtMs": request.expires_at.map(StateTimestamp::unix_millis),
    })
}

fn credential_review_value(review: &HumanControlCredentialReview) -> Value {
    json!({
        "consumerId": review.consumer_id.to_string(),
        "vaultId": review.vault_id.to_string(),
        "capability": capability_value(review.capability),
        "candidates": review.candidates.iter().map(credential_candidate_value).collect::<Vec<_>>(),
        "truncated": review.truncated,
    })
}

fn credential_candidate_value(candidate: &HumanControlCredentialCandidate) -> Value {
    json!({
        "vaultId": candidate.vault_id.to_string(),
        "credentialId": candidate.credential_id.to_string(),
        "title": candidate.title,
        "templateId": candidate.template_id,
        "tags": candidate.tags,
        "favorite": candidate.favorite,
        "secretFields": candidate.secret_fields.iter().map(secret_field_candidate_value).collect::<Vec<_>>(),
    })
}

fn secret_field_candidate_value(candidate: &HumanControlSecretFieldCandidate) -> Value {
    json!({
        "secretFieldId": candidate.secret_field_id.to_string(),
        "role": candidate.role,
        "label": candidate.label,
        "kind": candidate.kind.as_str(),
    })
}

fn authorization_value(snapshot: &HumanControlAuthorizationSnapshot) -> Value {
    json!({
        "paused": snapshot.paused,
        "authorizedCredentialIds": snapshot.authorized_credential_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "consumers": snapshot.consumers.iter().map(consumer_summary_value).collect::<Vec<_>>(),
        "authorizedCredentialsTruncated": snapshot.authorized_credentials_truncated,
        "consumersTruncated": snapshot.consumers_truncated,
    })
}

fn consumer_detail_value(detail: &HumanControlConsumerDetail) -> Value {
    json!({
        "consumer": consumer_summary_value(&detail.consumer),
        "fieldGrants": detail.field_grants.iter().map(field_grant_value).collect::<Vec<_>>(),
        "usageProfiles": detail.usage_profiles.iter().map(usage_profile_summary_value).collect::<Vec<_>>(),
        "recentAuditEvents": detail.recent_audit_events.iter().map(consumer_audit_value).collect::<Vec<_>>(),
        "fieldGrantsTruncated": detail.field_grants_truncated,
        "usageProfilesTruncated": detail.usage_profiles_truncated,
    })
}

fn usage_catalog_value(catalog: &HumanControlUsageProfileCatalog) -> Value {
    json!({
        "consumerId": catalog.consumer_id.to_string(),
        "templates": catalog.templates.iter().map(|template| json!({
            "templateId": template.id().as_str(),
            "capability": capability_value(template.capability()),
            "technicalField": technical_field_value(template.technical_field()),
        })).collect::<Vec<_>>(),
        "recommendation": catalog.recommendation.map(|recommendation| json!({
            "recommendationId": recommendation.id().as_str(),
            "templateId": recommendation.template_id().as_str(),
            "technicalName": recommendation.technical_name(),
        })),
    })
}

fn technical_field_value(field: UsageProfileTemplateTechnicalField) -> Value {
    match field {
        UsageProfileTemplateTechnicalField::None => json!({"kind": "none"}),
        UsageProfileTemplateTechnicalField::HttpHeaderName { suggested_value } => {
            json!({"kind": "http-header-name", "suggestedValue": suggested_value})
        }
        UsageProfileTemplateTechnicalField::EnvironmentVariableName => {
            json!({"kind": "environment-variable-name"})
        }
    }
}

fn usage_profile_value(profile: &UsageProfile) -> Value {
    json!({
        "usageProfileId": profile.usage_profile_id().to_string(),
        "consumerId": profile.consumer_id().to_string(),
        "label": profile.label(),
        "definition": serde_json::from_str::<Value>(&profile.definition().to_json().expect("validated definition encodes")).expect("validated definition JSON"),
        "createdAtMs": profile.created_at().unix_millis(),
    })
}

fn usage_profile_summary_value(profile: &BrokerUsageProfileSummary) -> Value {
    json!({
        "usageProfileId": profile.usage_profile_id().to_string(),
        "label": profile.label(),
        "capability": capability_value(profile.capability()),
        "placement": profile.placement(),
        "createdAtMs": profile.created_at().unix_millis(),
    })
}

fn consumer_summary_value(consumer: &BrokerConsumerSummary) -> Value {
    json!({
        "consumerId": consumer.consumer_id().to_string(),
        "label": consumer.label(),
        "identityEvidence": identity_evidence_value(consumer.identity_evidence()),
        "accessRuleCount": consumer.access_rule_count(),
        "usageProfileCount": consumer.usage_profile_count(),
        "createdAtMs": consumer.created_at().unix_millis(),
    })
}

fn identity_evidence_value(evidence: &BrokerConsumerIdentityEvidence) -> Value {
    json!({
        "executableName": evidence.executable_name(),
        "bundleIdentifier": evidence.bundle_identifier(),
        "teamIdentifier": evidence.team_identifier(),
        "codeSigningEvidence": signing_evidence(evidence.code_signing_evidence()),
        "codeSignatureFingerprint": evidence.code_signature_fingerprint().map(|value| value.to_string()),
    })
}

fn field_grant_value(grant: &BrokerFieldGrantSummary) -> Value {
    json!({
        "accessRuleId": grant.access_rule_id().to_string(),
        "fieldScope": field_scope_value(grant.field_scope()),
        "capability": capability_value(grant.capability()),
        "confirmationPolicy": grant.confirmation_policy().as_str(),
        "lifetime": lifetime_value(grant.lifetime()),
        "createdAtMs": grant.created_at().unix_millis(),
        "active": grant.active(),
    })
}

fn consumer_audit_value(event: &BrokerConsumerAuditSummary) -> Value {
    json!({
        "auditEventId": event.audit_event_id().to_string(),
        "occurredAtMs": event.occurred_at().unix_millis(),
        "kind": event.kind().as_str(),
        "fieldScope": event.field_scope().map(field_scope_value),
        "capability": event.capability().map(capability_value),
        "decision": event.decision().as_str(),
        "confirmationMethod": event.confirmation_method().as_str(),
    })
}

fn audit_event_value(event: &AuditEvent) -> Value {
    let scope = event.scope();
    json!({
        "auditEventId": event.audit_event_id().to_string(),
        "occurredAtMs": event.occurred_at().unix_millis(),
        "kind": event.kind().as_str(),
        "consumerId": scope.consumer_id().map(|value| value.to_string()),
        "fieldScope": scope.field_scope().map(field_scope_value),
        "capability": scope.capability().map(capability_value),
        "useGrantId": scope.use_grant_id().map(|value| value.to_string()),
        "decision": event.decision().as_str(),
        "confirmationMethod": event.confirmation_method().as_str(),
    })
}

fn vault_state_value(snapshot: BrokerVaultSessionSnapshot) -> Value {
    json!({
        "vaultId": snapshot.vault_id().to_string(),
        "lockState": match snapshot.lock_state() { BrokerVaultLockState::Locked => "locked", BrokerVaultLockState::Unlocking => "unlocking", BrokerVaultLockState::Unlocked => "unlocked" },
        "vaultSessionId": snapshot.vault_session_id().map(|value| value.to_string()),
    })
}

fn protected_state(state: BrokerProtectedStateCategory) -> &'static str {
    match state {
        BrokerProtectedStateCategory::Authenticated => "authenticated",
    }
}

fn revocation_kind(kind: BrokerRevocationKind) -> &'static str {
    match kind {
        BrokerRevocationKind::UseGrant => "use-grant",
        BrokerRevocationKind::ConsumerField => "consumer-field",
        BrokerRevocationKind::Consumer => "consumer",
        BrokerRevocationKind::Global => "global",
    }
}

fn signing_evidence(value: ConsumerCodeSigningEvidence) -> &'static str {
    match value {
        ConsumerCodeSigningEvidence::NoVerifiedSignature => "no-verified-signature",
        ConsumerCodeSigningEvidence::VerifiedWithoutTeamIdentifier => {
            "verified-without-team-identifier"
        }
        ConsumerCodeSigningEvidence::VerifiedWithTeamIdentifier => "verified-with-team-identifier",
    }
}

fn template_from_definition(
    definition: &UsageProfileDefinition,
) -> Result<(&'static str, Option<&str>), HumanControlWireError> {
    match definition.placement() {
        UsagePlacement::HttpBearerAuthorization {} => Ok(("http-bearer-authorization", None)),
        UsagePlacement::HttpHeader { header_name } => {
            Ok(("http-api-key-header", Some(header_name)))
        }
        UsagePlacement::ProcessEnvironment { variable_name } => {
            Ok(("cli-environment-variable", Some(variable_name)))
        }
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn capability_value(capability: Capability) -> Value {
    json!({"name": capability.name().as_str(), "version": capability.version()})
}
fn field_scope_value(scope: CredentialFieldScope) -> Value {
    json!({"vaultId": scope.vault_id().to_string(), "credentialId": scope.credential_id().to_string(), "secretFieldId": scope.secret_field_id().to_string()})
}
fn lifetime_value(lifetime: RuleLifetime) -> Value {
    match lifetime {
        RuleLifetime::Persistent => json!({"kind": "persistent"}),
        RuleLifetime::Until(value) => json!({"kind": "until", "expiresAtMs": value.unix_millis()}),
    }
}
fn version_value(version: HumanControlProtocolVersion) -> Value {
    json!({"major": version.major(), "minor": version.minor()})
}

fn audit_filter_value(filter: BrokerAuditFilter) -> Value {
    let mut body = Map::new();
    if let Some(value) = filter.event_kind() {
        body.insert(
            "eventKind".to_owned(),
            Value::String(value.as_str().to_owned()),
        );
    }
    if let Some(value) = filter.decision() {
        body.insert(
            "decision".to_owned(),
            Value::String(value.as_str().to_owned()),
        );
    }
    if let Some(value) = filter.consumer_id() {
        body.insert("consumerId".to_owned(), Value::String(value.to_string()));
    }
    if let Some(value) = filter.vault_id() {
        body.insert("vaultId".to_owned(), Value::String(value.to_string()));
    }
    if let Some(value) = filter.field_scope() {
        body.insert("fieldScope".to_owned(), field_scope_value(value));
    }
    if let Some(value) = filter.capability() {
        body.insert("capability".to_owned(), capability_value(value));
    }
    if let Some(value) = filter.occurred_at_or_after() {
        body.insert("occurredAtOrAfterMs".to_owned(), json!(value.unix_millis()));
    }
    if let Some(value) = filter.occurred_before() {
        body.insert("occurredBeforeMs".to_owned(), json!(value.unix_millis()));
    }
    Value::Object(body)
}

fn audit_cursor_value(cursor: crate::BrokerAuditCursor) -> Value {
    json!({"occurredAtMs": cursor.occurred_at().unix_millis(), "auditEventId": cursor.audit_event_id().to_string()})
}

fn validate_vault_state(value: &Value) -> Result<(), HumanControlWireError> {
    let body = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    exact_keys(body, &["vaultId", "lockState", "vaultSessionId"])?;
    parse::<crate::VaultId>(body, "vaultId")?;
    match string(body, "lockState")? {
        "locked" | "unlocking" | "unlocked" => {}
        _ => return Err(HumanControlWireError::Malformed),
    }
    optional_parse::<crate::VaultSessionId>(body, "vaultSessionId")?;
    Ok(())
}

fn validate_pending(value: &Value) -> Result<(), HumanControlWireError> {
    let body = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    exact_keys(
        body,
        &[
            "pendingRequestId",
            "kind",
            "consumerId",
            "identityEvidence",
            "pairingComparisonCode",
            "pairingKeyFingerprint",
            "pairingRemainingMs",
            "vaultId",
            "fieldScope",
            "capability",
            "createdAtMs",
            "expiresAtMs",
        ],
    )?;
    match string(body, "kind")? {
        "pairing" => {
            parse::<crate::PairingRequestId>(body, "pendingRequestId")?;
        }
        "unlock" | "access" | "credential-access" => {
            parse::<crate::ApprovalRequestId>(body, "pendingRequestId")?;
        }
        _ => return Err(HumanControlWireError::Malformed),
    }
    optional_parse::<crate::ConsumerId>(body, "consumerId")?;
    nullable_object(body, "identityEvidence")?
        .map(validate_identity_evidence)
        .transpose()?;
    optional_string(body, "pairingComparisonCode")?;
    optional_string(body, "pairingKeyFingerprint")?;
    optional_unsigned(body, "pairingRemainingMs")?;
    optional_parse::<crate::VaultId>(body, "vaultId")?;
    nullable_object(body, "fieldScope")?
        .map(validate_field_scope)
        .transpose()?;
    nullable_object(body, "capability")?
        .map(validate_capability)
        .transpose()?;
    optional_timestamp(body, "createdAtMs")?;
    optional_timestamp(body, "expiresAtMs")?;
    Ok(())
}

fn validate_credential_review(body: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    parse::<crate::ConsumerId>(body, "consumerId")?;
    parse::<crate::VaultId>(body, "vaultId")?;
    validate_capability(object(body, "capability")?)?;
    boolean(body, "truncated")?;
    bounded_array(body, "candidates")?
        .iter()
        .try_for_each(|value| {
            let candidate = value.as_object().ok_or(HumanControlWireError::Malformed)?;
            exact_keys(
                candidate,
                &[
                    "vaultId",
                    "credentialId",
                    "title",
                    "templateId",
                    "tags",
                    "favorite",
                    "secretFields",
                ],
            )?;
            parse::<crate::VaultId>(candidate, "vaultId")?;
            parse::<crate::CredentialId>(candidate, "credentialId")?;
            string(candidate, "title")?;
            optional_string(candidate, "templateId")?;
            boolean(candidate, "favorite")?;
            bounded_array(candidate, "tags")?
                .iter()
                .try_for_each(|value| {
                    if value.is_string() {
                        Ok(())
                    } else {
                        Err(HumanControlWireError::Malformed)
                    }
                })?;
            bounded_array(candidate, "secretFields")?
                .iter()
                .try_for_each(|value| {
                    let field = value.as_object().ok_or(HumanControlWireError::Malformed)?;
                    exact_keys(field, &["secretFieldId", "role", "label", "kind"])?;
                    parse::<crate::SecretFieldId>(field, "secretFieldId")?;
                    string(field, "role")?;
                    optional_string(field, "label")?;
                    crate::SecretFieldKind::from_str(string(field, "kind")?)
                        .map_err(|_| HumanControlWireError::Malformed)?;
                    Ok(())
                })?;
            Ok(())
        })
}

fn validate_authorization(body: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    boolean(body, "paused")?;
    boolean(body, "authorizedCredentialsTruncated")?;
    boolean(body, "consumersTruncated")?;
    bounded_array(body, "authorizedCredentialIds")?
        .iter()
        .try_for_each(|value| parse_value::<crate::CredentialId>(value).map(|_| ()))?;
    bounded_array(body, "consumers")?
        .iter()
        .try_for_each(validate_consumer_summary)
}

fn validate_consumer_detail(body: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    validate_consumer_summary(
        body.get("consumer")
            .ok_or(HumanControlWireError::Malformed)?,
    )?;
    boolean(body, "fieldGrantsTruncated")?;
    boolean(body, "usageProfilesTruncated")?;
    bounded_array(body, "fieldGrants")?
        .iter()
        .try_for_each(validate_field_grant)?;
    bounded_array(body, "usageProfiles")?
        .iter()
        .try_for_each(validate_usage_profile_summary)?;
    bounded_array(body, "recentAuditEvents")?
        .iter()
        .try_for_each(validate_consumer_audit)
}

fn validate_usage_catalog(body: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    parse::<crate::ConsumerId>(body, "consumerId")?;
    bounded_array(body, "templates")?
        .iter()
        .try_for_each(|value| {
            let item = value.as_object().ok_or(HumanControlWireError::Malformed)?;
            exact_keys(item, &["templateId", "capability", "technicalField"])?;
            crate::BundledUsageProfileTemplateId::from_str(string(item, "templateId")?)
                .map_err(|_| HumanControlWireError::Malformed)?;
            validate_capability(object(item, "capability")?)?;
            validate_technical_field(object(item, "technicalField")?)
        })?;
    if let Some(item) = nullable_object(body, "recommendation")? {
        exact_keys(item, &["recommendationId", "templateId", "technicalName"])?;
        string(item, "recommendationId")?;
        crate::BundledUsageProfileTemplateId::from_str(string(item, "templateId")?)
            .map_err(|_| HumanControlWireError::Malformed)?;
        string(item, "technicalName")?;
    }
    Ok(())
}

fn validate_usage_profile(body: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    parse::<crate::UsageProfileId>(body, "usageProfileId")?;
    parse::<crate::ConsumerId>(body, "consumerId")?;
    string(body, "label")?;
    timestamp(body, "createdAtMs")?;
    let encoded = serde_json::to_string(
        body.get("definition")
            .ok_or(HumanControlWireError::Malformed)?,
    )
    .map_err(|_| HumanControlWireError::Malformed)?;
    UsageProfileDefinition::from_json(&encoded).map_err(|_| HumanControlWireError::Malformed)?;
    Ok(())
}

fn validate_consumer_summary(value: &Value) -> Result<(), HumanControlWireError> {
    let body = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    exact_keys(
        body,
        &[
            "consumerId",
            "label",
            "identityEvidence",
            "accessRuleCount",
            "usageProfileCount",
            "createdAtMs",
        ],
    )?;
    parse::<crate::ConsumerId>(body, "consumerId")?;
    string(body, "label")?;
    validate_identity_evidence(object(body, "identityEvidence")?)?;
    unsigned(body, "accessRuleCount")?;
    unsigned(body, "usageProfileCount")?;
    timestamp(body, "createdAtMs")?;
    Ok(())
}
fn validate_identity_evidence(body: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    exact_keys(
        body,
        &[
            "executableName",
            "bundleIdentifier",
            "teamIdentifier",
            "codeSigningEvidence",
            "codeSignatureFingerprint",
        ],
    )?;
    optional_string(body, "executableName")?;
    optional_string(body, "bundleIdentifier")?;
    optional_string(body, "teamIdentifier")?;
    match string(body, "codeSigningEvidence")? {
        "no-verified-signature"
        | "verified-without-team-identifier"
        | "verified-with-team-identifier" => {}
        _ => return Err(HumanControlWireError::Malformed),
    }
    optional_string(body, "codeSignatureFingerprint")?;
    Ok(())
}
fn validate_field_grant(value: &Value) -> Result<(), HumanControlWireError> {
    let b = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    exact_keys(
        b,
        &[
            "accessRuleId",
            "fieldScope",
            "capability",
            "confirmationPolicy",
            "lifetime",
            "createdAtMs",
            "active",
        ],
    )?;
    parse::<crate::AccessRuleId>(b, "accessRuleId")?;
    validate_field_scope(object(b, "fieldScope")?)?;
    validate_capability(object(b, "capability")?)?;
    crate::ConfirmationPolicy::from_str(string(b, "confirmationPolicy")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    validate_lifetime(object(b, "lifetime")?)?;
    timestamp(b, "createdAtMs")?;
    boolean(b, "active")?;
    Ok(())
}
fn validate_usage_profile_summary(value: &Value) -> Result<(), HumanControlWireError> {
    let b = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    exact_keys(
        b,
        &[
            "usageProfileId",
            "label",
            "capability",
            "placement",
            "createdAtMs",
        ],
    )?;
    parse::<crate::UsageProfileId>(b, "usageProfileId")?;
    string(b, "label")?;
    validate_capability(object(b, "capability")?)?;
    serde_json::from_value::<UsagePlacement>(
        b.get("placement")
            .cloned()
            .ok_or(HumanControlWireError::Malformed)?,
    )
    .map_err(|_| HumanControlWireError::Malformed)?;
    timestamp(b, "createdAtMs")?;
    Ok(())
}
fn validate_consumer_audit(value: &Value) -> Result<(), HumanControlWireError> {
    let b = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    exact_keys(
        b,
        &[
            "auditEventId",
            "occurredAtMs",
            "kind",
            "fieldScope",
            "capability",
            "decision",
            "confirmationMethod",
        ],
    )?;
    parse::<crate::AuditEventId>(b, "auditEventId")?;
    timestamp(b, "occurredAtMs")?;
    crate::AuditEventKind::from_str(string(b, "kind")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    nullable_object(b, "fieldScope")?
        .map(validate_field_scope)
        .transpose()?;
    nullable_object(b, "capability")?
        .map(validate_capability)
        .transpose()?;
    crate::AuditDecision::from_str(string(b, "decision")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    crate::ConfirmationMethod::from_str(string(b, "confirmationMethod")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    Ok(())
}
fn validate_audit_event(value: &Value) -> Result<(), HumanControlWireError> {
    let b = value.as_object().ok_or(HumanControlWireError::Malformed)?;
    exact_keys(
        b,
        &[
            "auditEventId",
            "occurredAtMs",
            "kind",
            "consumerId",
            "fieldScope",
            "capability",
            "useGrantId",
            "decision",
            "confirmationMethod",
        ],
    )?;
    parse::<crate::AuditEventId>(b, "auditEventId")?;
    timestamp(b, "occurredAtMs")?;
    crate::AuditEventKind::from_str(string(b, "kind")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    optional_parse::<crate::ConsumerId>(b, "consumerId")?;
    nullable_object(b, "fieldScope")?
        .map(validate_field_scope)
        .transpose()?;
    nullable_object(b, "capability")?
        .map(validate_capability)
        .transpose()?;
    optional_parse::<crate::UseGrantId>(b, "useGrantId")?;
    crate::AuditDecision::from_str(string(b, "decision")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    crate::ConfirmationMethod::from_str(string(b, "confirmationMethod")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    Ok(())
}
fn validate_field_scope(b: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    exact_keys(b, &["vaultId", "credentialId", "secretFieldId"])?;
    parse::<crate::VaultId>(b, "vaultId")?;
    parse::<crate::CredentialId>(b, "credentialId")?;
    parse::<crate::SecretFieldId>(b, "secretFieldId")?;
    Ok(())
}
fn validate_capability(b: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    exact_keys(b, &["name", "version"])?;
    crate::CapabilityName::from_str(string(b, "name")?)
        .map_err(|_| HumanControlWireError::Malformed)?;
    positive(unsigned(b, "version")?)?;
    Ok(())
}
fn validate_cursor(b: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    exact_keys(b, &["occurredAtMs", "auditEventId"])?;
    timestamp(b, "occurredAtMs")?;
    parse::<crate::AuditEventId>(b, "auditEventId")?;
    Ok(())
}
fn validate_lifetime(b: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    match string(b, "kind")? {
        "persistent" => exact_keys(b, &["kind"]),
        "until" => {
            exact_keys(b, &["kind", "expiresAtMs"])?;
            timestamp(b, "expiresAtMs")?;
            Ok(())
        }
        _ => Err(HumanControlWireError::Malformed),
    }
}
fn validate_technical_field(b: &Map<String, Value>) -> Result<(), HumanControlWireError> {
    match string(b, "kind")? {
        "none" | "environment-variable-name" => exact_keys(b, &["kind"]),
        "http-header-name" => {
            exact_keys(b, &["kind", "suggestedValue"])?;
            string(b, "suggestedValue")?;
            Ok(())
        }
        _ => Err(HumanControlWireError::Malformed),
    }
}

fn exact_keys(body: &Map<String, Value>, expected: &[&str]) -> Result<(), HumanControlWireError> {
    if body.len() != expected.len() || expected.iter().any(|key| !body.contains_key(*key)) {
        return Err(HumanControlWireError::Malformed);
    }
    Ok(())
}
fn string<'a>(body: &'a Map<String, Value>, key: &str) -> Result<&'a str, HumanControlWireError> {
    body.get(key)
        .and_then(Value::as_str)
        .ok_or(HumanControlWireError::Malformed)
}
fn optional_string<'a>(
    body: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, HumanControlWireError> {
    match body.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v)),
        _ => Err(HumanControlWireError::Malformed),
    }
}
fn object<'a>(
    body: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, HumanControlWireError> {
    body.get(key)
        .and_then(Value::as_object)
        .ok_or(HumanControlWireError::Malformed)
}
fn nullable_object<'a>(
    body: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, HumanControlWireError> {
    match body.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::Object(v)) => Ok(Some(v)),
        _ => Err(HumanControlWireError::Malformed),
    }
}
fn array<'a>(
    body: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], HumanControlWireError> {
    body.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(HumanControlWireError::Malformed)
}
fn bounded_array<'a>(
    body: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], HumanControlWireError> {
    let values = array(body, key)?;
    if values.len() > MAX_HUMAN_CONTROL_COLLECTION_ITEMS {
        return Err(HumanControlWireError::Malformed);
    }
    Ok(values)
}
fn boolean(body: &Map<String, Value>, key: &str) -> Result<bool, HumanControlWireError> {
    body.get(key)
        .and_then(Value::as_bool)
        .ok_or(HumanControlWireError::Malformed)
}
fn unsigned(body: &Map<String, Value>, key: &str) -> Result<u64, HumanControlWireError> {
    body.get(key)
        .and_then(Value::as_u64)
        .ok_or(HumanControlWireError::Malformed)
}
fn optional_unsigned(
    body: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, HumanControlWireError> {
    match body.get(key) {
        Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or(HumanControlWireError::Malformed),
        None => Err(HumanControlWireError::Malformed),
    }
}
fn positive(value: u64) -> Result<u64, HumanControlWireError> {
    if value == 0 {
        Err(HumanControlWireError::Malformed)
    } else {
        Ok(value)
    }
}
fn timestamp(
    body: &Map<String, Value>,
    key: &str,
) -> Result<StateTimestamp, HumanControlWireError> {
    let value = body
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(HumanControlWireError::Malformed)?;
    StateTimestamp::from_unix_millis(value).map_err(|_| HumanControlWireError::Malformed)
}
fn optional_timestamp(
    body: &Map<String, Value>,
    key: &str,
) -> Result<Option<StateTimestamp>, HumanControlWireError> {
    match body.get(key) {
        Some(Value::Null) => Ok(None),
        Some(_) => timestamp(body, key).map(Some),
        None => Err(HumanControlWireError::Malformed),
    }
}
fn parse<T: FromStr>(body: &Map<String, Value>, key: &str) -> Result<T, HumanControlWireError> {
    string(body, key)?
        .parse()
        .map_err(|_| HumanControlWireError::Malformed)
}
fn parse_value<T: FromStr>(value: &Value) -> Result<T, HumanControlWireError> {
    value
        .as_str()
        .ok_or(HumanControlWireError::Malformed)?
        .parse()
        .map_err(|_| HumanControlWireError::Malformed)
}
fn optional_parse<T: FromStr>(
    body: &Map<String, Value>,
    key: &str,
) -> Result<Option<T>, HumanControlWireError> {
    match body.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => parse_value(value).map(Some),
        None => Err(HumanControlWireError::Malformed),
    }
}
fn fixed_base64<const N: usize>(value: &str) -> Result<[u8; N], HumanControlWireError> {
    let mut bytes = BASE64_STANDARD
        .decode(value)
        .map_err(|_| HumanControlWireError::Malformed)?;
    if bytes.len() != N || BASE64_STANDARD.encode(&bytes) != value {
        bytes.zeroize();
        return Err(HumanControlWireError::Malformed);
    }
    let mut result = [0; N];
    result.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(result)
}
fn protocol_version(
    body: &Map<String, Value>,
) -> Result<HumanControlProtocolVersion, HumanControlWireError> {
    exact_keys(body, &["major", "minor"])?;
    let major =
        u16::try_from(unsigned(body, "major")?).map_err(|_| HumanControlWireError::Malformed)?;
    let minor =
        u16::try_from(unsigned(body, "minor")?).map_err(|_| HumanControlWireError::Malformed)?;
    HumanControlProtocolVersion::new(major, minor).map_err(|_| HumanControlWireError::Malformed)
}
fn remove_string(
    body: &mut Map<String, Value>,
    key: &str,
) -> Result<String, HumanControlWireError> {
    match body.remove(key) {
        Some(Value::String(v)) => Ok(v),
        _ => Err(HumanControlWireError::Malformed),
    }
}
fn remove_version(
    body: &mut Map<String, Value>,
) -> Result<HumanControlProtocolVersion, HumanControlWireError> {
    match body.remove("version") {
        Some(Value::Object(v)) => protocol_version(&v),
        _ => Err(HumanControlWireError::Malformed),
    }
}
fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(v) => v.zeroize(),
        Value::Array(v) => v.iter_mut().for_each(zeroize_json_strings),
        Value::Object(v) => v.values_mut().for_each(zeroize_json_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

impl Display for HumanControlClientResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Success(_) => "human-control request succeeded",
            Self::Failure(_) => "human-control request failed",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_human_control_hello_wire_envelope, decode_human_control_wire_envelope,
        BrokerInstanceId, HumanControlLimits, HumanControlProtocolVersionRange,
        HumanControlVersionOffer, CONTROLLER_ROLE, HUMAN_CONTROL_OPERATION_CONTRACTS,
    };

    fn version() -> HumanControlProtocolVersion {
        HumanControlProtocolVersion::current()
    }

    fn request_id() -> HumanControlRequestId {
        HumanControlRequestId::from_bytes([0x41; 16])
    }

    fn hello_request() -> HumanControlRequest {
        HumanControlRequest::Hello(
            HumanControlVersionOffer::new(
                CONTROLLER_ROLE,
                [HumanControlProtocolVersionRange::new(1, 0, 0).expect("range")],
                [HUMAN_CONTROL_SCHEMA_ID.to_owned()],
            )
            .expect("offer"),
        )
    }

    fn hello_response() -> HumanControlResponse {
        HumanControlResponse::Hello {
            protocol: version(),
            schema: HUMAN_CONTROL_SCHEMA_ID,
            broker_instance_id: BrokerInstanceId::generate(),
            limits: HumanControlLimits::current(),
            operations: HUMAN_CONTROL_OPERATION_CONTRACTS
                .iter()
                .map(|contract| contract.operation())
                .collect(),
        }
    }

    #[test]
    fn typed_hello_request_round_trips_through_the_strict_decoder() {
        let payload = encode_human_control_request(request_id(), version(), &hello_request())
            .expect("encode");
        let envelope = decode_human_control_hello_wire_envelope(payload).expect("decode");

        assert_eq!(envelope.request_id(), request_id());
        assert_eq!(envelope.version(), version());
        assert_eq!(envelope.operation(), HumanControlOperation::Hello);
        assert!(matches!(
            envelope
                .to_typed_request(StateTimestamp::from_unix_millis(1).expect("timestamp"))
                .expect("typed"),
            HumanControlRequest::Hello(_)
        ));
    }

    #[test]
    fn optional_request_fields_are_omitted_instead_of_encoded_as_null() {
        let consumer_id = crate::ConsumerId::generate();
        let catalog = encode_human_control_request(
            request_id(),
            version(),
            &HumanControlRequest::UsageProfileCatalog {
                consumer_id,
                executable_name_hint: None,
            },
        )
        .expect("catalog");
        let audit = encode_human_control_request(
            HumanControlRequestId::from_bytes([0x43; 16]),
            version(),
            &HumanControlRequest::AuditList {
                filter: BrokerAuditFilter::all(),
                cursor: None,
                limit: 10,
            },
        )
        .expect("audit");

        for (payload, forbidden) in [
            (catalog.as_bytes(), "executableName"),
            (audit.as_bytes(), "cursor"),
        ] {
            let text = std::str::from_utf8(payload).expect("UTF-8");
            assert!(!text.contains(forbidden));
            assert!(!text.contains(":null"));
            decode_human_control_wire_envelope(payload.to_vec(), version()).expect("decode");
        }
    }

    #[test]
    fn request_envelope_zeroizes_unlock_material_and_its_encoded_form() {
        let marker = b"seeded-unlock-private-marker";
        let encoded_marker = BASE64_STANDARD.encode(marker);
        let request = HumanControlRequest::VaultUnlock {
            vault_id: psw_core::VaultId::generate(),
            credential: HumanControlVaultUnlockCredential::MasterPassword(
                psw_core::SecretBytes::new(marker.to_vec()),
            ),
        };
        let mut envelope = request_envelope(request_id(), version(), &request).expect("envelope");
        let before = serde_json::to_string(&envelope.0).expect("serialize");
        assert!(before.contains(&encoded_marker));

        envelope.zeroize();

        let after = serde_json::to_string(&envelope.0).expect("serialize zeroized");
        assert!(!after.contains("seeded-unlock-private-marker"));
        assert!(!after.contains(&encoded_marker));
    }

    #[test]
    fn success_and_failure_responses_bind_request_version_and_closed_schema() {
        let success = encode_human_control_response(
            request_id(),
            version(),
            HumanControlOperation::Hello,
            &hello_response(),
        )
        .expect("success");
        let decoded = decode_human_control_response(
            &success,
            request_id(),
            version(),
            HumanControlOperation::Hello,
        )
        .expect("decode success");
        let HumanControlClientResponse::Success(decoded) = decoded else {
            panic!("expected success");
        };
        assert!(decoded.has_complete_operation_catalog());
        assert_eq!(decoded.hello_selection().expect("selection").0, version());

        assert!(matches!(
            decode_human_control_response(
                &success,
                HumanControlRequestId::from_bytes([0x44; 16]),
                version(),
                HumanControlOperation::Hello,
            ),
            Err(HumanControlWireError::Incompatible)
        ));

        let failure = HumanControlProtocolFailure::new(
            HumanControlFailureCode::AuthenticationRequired,
            false,
            Some(HumanControlRequiredAction::AuthenticateController),
        );
        let encoded =
            encode_human_control_failure(request_id(), version(), failure).expect("failure");
        assert!(!std::str::from_utf8(&encoded)
            .expect("UTF-8")
            .contains("message"));
        assert!(matches!(
            decode_human_control_response(
                &encoded,
                request_id(),
                version(),
                HumanControlOperation::ReadinessGet,
            )
            .expect("decode failure"),
            HumanControlClientResponse::Failure(value) if value == failure
        ));
    }

    #[test]
    fn response_decoder_rejects_duplicate_unknown_and_drifted_catalog_fields() {
        let success = encode_human_control_response(
            request_id(),
            version(),
            HumanControlOperation::Hello,
            &hello_response(),
        )
        .expect("success");
        let success = std::str::from_utf8(&success).expect("UTF-8");
        let duplicate = success.replacen(
            "\"protocol\":\"keptnear.human-control\"",
            "\"protocol\":\"keptnear.human-control\",\"protocol\":\"keptnear.human-control\"",
            1,
        );
        let unknown = success.replacen(
            "\"result\":{",
            "\"result\":{\"seeded-private-marker\":true,",
            1,
        );
        let drifted = success.replacen("\"readiness.get\"", "\"future.operation\"", 1);

        for payload in [duplicate, unknown, drifted] {
            assert!(matches!(
                decode_human_control_response(
                    payload.as_bytes(),
                    request_id(),
                    version(),
                    HumanControlOperation::Hello,
                ),
                Err(HumanControlWireError::Malformed)
            ));
        }
    }

    #[test]
    fn validated_response_debug_never_projects_result_strings() {
        let success = encode_human_control_response(
            request_id(),
            version(),
            HumanControlOperation::Hello,
            &hello_response(),
        )
        .expect("success");
        let decoded = decode_human_control_response(
            &success,
            request_id(),
            version(),
            HumanControlOperation::Hello,
        )
        .expect("decode");
        let debug = format!("{decoded:?}");
        assert!(!debug.contains(HUMAN_CONTROL_SCHEMA_ID));
        assert!(!debug.contains("readiness.get"));
    }
}
