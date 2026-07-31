use std::str::FromStr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use psw_broker::{
    BrokerAccessRequest, BrokerAccessResponse, BrokerCredentialOperationTarget,
    BrokerCredentialSearchRequest, BrokerGrantRevokeRequest, BrokerGrantStatusRequest,
    BrokerHttpCapabilityHeader, BrokerHttpCapabilityRequest, BrokerHttpMethod,
    BrokerProcessCapabilityEnvironment, BrokerProcessCapabilityRequest, BrokerRequest,
    BrokerResponse, Capability, CapabilityName, CredentialFieldScope, SecretFieldKind,
};
use serde_json::{json, Map, Value};

use keptnear_client::BrokerAdapterError;

const DEFAULT_PROCESS_TIMEOUT_MILLIS: u64 = 30_000;
const MAX_APPROVAL_WAIT_MILLIS: u64 = 300_000;
const MAX_PROCESS_TIMEOUT_MILLIS: u64 = 300_000;

pub(crate) trait BrokerToolClient {
    fn execute(&mut self, request: BrokerRequest) -> Result<BrokerResponse, BrokerAdapterError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolInvocationError {
    InvalidInput,
    Broker(BrokerAdapterError),
    UnexpectedResponse,
}

pub(crate) fn is_known_tool(name: &str) -> bool {
    matches!(
        name,
        "credential.search"
            | "access.request"
            | "grant.status"
            | "grant.revoke"
            | "http.request"
            | "process.run"
    )
}

pub(crate) fn catalog() -> Vec<Value> {
    vec![
        credential_search_tool(),
        access_request_tool(),
        grant_status_tool(),
        grant_revoke_tool(),
        http_request_tool(),
        process_run_tool(),
    ]
}

pub(crate) fn invoke(
    client: &mut impl BrokerToolClient,
    name: &str,
    arguments: &Map<String, Value>,
) -> Result<Value, ToolInvocationError> {
    match name {
        "credential.search" => credential_search(client, arguments),
        "access.request" => access_request(client, arguments),
        "grant.status" => grant_status(client, arguments),
        "grant.revoke" => grant_revoke(client, arguments),
        "http.request" => http_request(client, arguments),
        "process.run" => process_run(client, arguments),
        _ => Err(ToolInvocationError::InvalidInput),
    }
}

fn credential_search(
    client: &mut impl BrokerToolClient,
    arguments: &Map<String, Value>,
) -> Result<Value, ToolInvocationError> {
    require_keys(
        arguments,
        &[
            "useGrantId",
            "vaultId",
            "credentialId",
            "secretFieldId",
            "secretKind",
            "vaultSessionId",
        ],
        &["query"],
    )?;
    let target = parse_operation_target(arguments)?;
    let query = optional_string(arguments, "query")?
        .unwrap_or_default()
        .to_owned();
    let response = client
        .execute(BrokerRequest::CredentialSearch(
            BrokerCredentialSearchRequest::new(target, query)
                .map_err(|_| ToolInvocationError::InvalidInput)?,
        ))
        .map_err(ToolInvocationError::Broker)?;
    let BrokerResponse::CredentialSearch(search) = response else {
        return Err(ToolInvocationError::UnexpectedResponse);
    };
    Ok(match search.credential() {
        Some(credential) => json!({
            "credential": {
                "vaultId": credential.vault_id().to_string(),
                "credentialId": credential.credential_id().to_string(),
                "title": credential.title(),
                "authorizedField": {
                    "secretFieldId": credential.secret_field_id().to_string(),
                    "role": credential.role(),
                    "label": credential.label(),
                    "kind": credential.kind().as_str()
                }
            }
        }),
        None => json!({"credential": null}),
    })
}

fn access_request(
    client: &mut impl BrokerToolClient,
    arguments: &Map<String, Value>,
) -> Result<Value, ToolInvocationError> {
    let request_kind = required_string(arguments, "requestKind")?;
    let request = match request_kind {
        "exact" => {
            require_keys(
                arguments,
                &[
                    "requestKind",
                    "capability",
                    "vaultId",
                    "credentialId",
                    "secretFieldId",
                ],
                &[],
            )?;
            BrokerAccessRequest::exact(
                parse_field_scope(arguments)?,
                parse_requested_capability(required_string(arguments, "capability")?)?,
            )
        }
        "credential" => {
            require_keys(
                arguments,
                &["requestKind", "capability", "vaultId", "description"],
                &[],
            )?;
            BrokerAccessRequest::credential(
                parse_id(arguments, "vaultId")?,
                parse_requested_capability(required_string(arguments, "capability")?)?,
                required_string(arguments, "description")?.to_owned(),
            )
        }
        "status" => {
            require_keys(arguments, &["requestKind", "approvalRequestId"], &[])?;
            Ok(BrokerAccessRequest::status(parse_id(
                arguments,
                "approvalRequestId",
            )?))
        }
        "resume" => {
            require_keys(arguments, &["requestKind", "approvalRequestId"], &[])?;
            Ok(BrokerAccessRequest::resume(parse_id(
                arguments,
                "approvalRequestId",
            )?))
        }
        "wait" => {
            require_keys(
                arguments,
                &["requestKind", "approvalRequestId", "timeoutMillis"],
                &[],
            )?;
            BrokerAccessRequest::wait(
                parse_id(arguments, "approvalRequestId")?,
                Duration::from_millis(required_u64(arguments, "timeoutMillis")?),
            )
        }
        _ => return Err(ToolInvocationError::InvalidInput),
    }
    .map_err(|_| ToolInvocationError::InvalidInput)?;

    let response = client
        .execute(BrokerRequest::AccessRequest(request))
        .map_err(ToolInvocationError::Broker)?;
    let BrokerResponse::AccessRequest(access) = response else {
        return Err(ToolInvocationError::UnexpectedResponse);
    };
    match (request_kind, access) {
        ("exact" | "credential", BrokerAccessResponse::Submission(submission)) => Ok(json!({
            "operation": "submission",
            "approvalRequestId": submission.approval_request_id().to_string(),
            "status": submission.status().as_str(),
            "expiresAtMillis": submission.expires_at().unix_millis(),
            "resolvedAtMillis": submission.resolved_at().map(|value| value.unix_millis()),
            "coalesced": submission.coalesced(),
            "timedOut": null
        })),
        ("status", BrokerAccessResponse::Status(receipt)) => Ok(json!({
            "operation": "status",
            "approvalRequestId": receipt.approval_request_id().to_string(),
            "status": receipt.status().as_str(),
            "expiresAtMillis": receipt.expires_at().unix_millis(),
            "resolvedAtMillis": receipt.resolved_at().map(|value| value.unix_millis()),
            "coalesced": null,
            "timedOut": null
        })),
        ("resume", BrokerAccessResponse::Resume(receipt)) => Ok(json!({
            "operation": "resume",
            "approvalRequestId": receipt.approval_request_id().to_string(),
            "status": receipt.status().as_str(),
            "expiresAtMillis": receipt.expires_at().unix_millis(),
            "resolvedAtMillis": receipt.resolved_at().map(|value| value.unix_millis()),
            "coalesced": null,
            "timedOut": null
        })),
        ("wait", BrokerAccessResponse::Wait(wait)) => {
            let receipt = wait.receipt();
            Ok(json!({
                "operation": "wait",
                "approvalRequestId": receipt.approval_request_id().to_string(),
                "status": receipt.status().as_str(),
                "expiresAtMillis": receipt.expires_at().unix_millis(),
                "resolvedAtMillis": receipt.resolved_at().map(|value| value.unix_millis()),
                "coalesced": null,
                "timedOut": wait.timed_out()
            }))
        }
        _ => Err(ToolInvocationError::UnexpectedResponse),
    }
}

fn grant_status(
    client: &mut impl BrokerToolClient,
    arguments: &Map<String, Value>,
) -> Result<Value, ToolInvocationError> {
    require_keys(arguments, &["useGrantId"], &[])?;
    let response = client
        .execute(BrokerRequest::GrantStatus(BrokerGrantStatusRequest::new(
            parse_id(arguments, "useGrantId")?,
        )))
        .map_err(ToolInvocationError::Broker)?;
    let BrokerResponse::GrantStatus(status) = response else {
        return Err(ToolInvocationError::UnexpectedResponse);
    };
    let active_grant = status.active_grant().map(|grant| {
        let field = grant.field_scope();
        json!({
            "useGrantId": grant.use_grant_id().to_string(),
            "vaultId": field.vault_id().to_string(),
            "credentialId": field.credential_id().to_string(),
            "secretFieldId": field.secret_field_id().to_string(),
            "capability": grant.capability().name().as_str(),
            "capabilityVersion": grant.capability().version(),
            "vaultSessionId": grant.vault_session_id().to_string(),
            "scope": grant.scope().as_str(),
            "createdAtMillis": grant.created_at().unix_millis(),
            "expiresAtMillis": grant.expires_at().unix_millis()
        })
    });
    Ok(json!({
        "status": status.status().as_str(),
        "activeGrant": active_grant
    }))
}

fn grant_revoke(
    client: &mut impl BrokerToolClient,
    arguments: &Map<String, Value>,
) -> Result<Value, ToolInvocationError> {
    require_keys(arguments, &["useGrantId"], &[])?;
    let response = client
        .execute(BrokerRequest::GrantRevoke(BrokerGrantRevokeRequest::new(
            parse_id(arguments, "useGrantId")?,
        )))
        .map_err(ToolInvocationError::Broker)?;
    let BrokerResponse::GrantRevoke(revoke) = response else {
        return Err(ToolInvocationError::UnexpectedResponse);
    };
    Ok(json!({"revoked": revoke.revoked()}))
}

fn http_request(
    client: &mut impl BrokerToolClient,
    arguments: &Map<String, Value>,
) -> Result<Value, ToolInvocationError> {
    require_keys(
        arguments,
        &[
            "useGrantId",
            "vaultId",
            "credentialId",
            "secretFieldId",
            "secretKind",
            "vaultSessionId",
            "usageProfileId",
            "method",
            "url",
        ],
        &["headers", "bodyBase64"],
    )?;
    let method = match required_string(arguments, "method")? {
        "GET" => BrokerHttpMethod::Get,
        "HEAD" => BrokerHttpMethod::Head,
        "POST" => BrokerHttpMethod::Post,
        "PUT" => BrokerHttpMethod::Put,
        "PATCH" => BrokerHttpMethod::Patch,
        "DELETE" => BrokerHttpMethod::Delete,
        _ => return Err(ToolInvocationError::InvalidInput),
    };
    let headers = optional_array(arguments, "headers")?
        .unwrap_or(&[])
        .iter()
        .map(parse_http_header)
        .collect::<Result<Vec<_>, _>>()?;
    let body = optional_string(arguments, "bodyBase64")?
        .map(|body| BASE64_STANDARD.decode(body))
        .transpose()
        .map_err(|_| ToolInvocationError::InvalidInput)?
        .unwrap_or_default();
    let request = BrokerHttpCapabilityRequest::new(
        parse_operation_target(arguments)?,
        parse_id(arguments, "usageProfileId")?,
        method,
        required_string(arguments, "url")?.to_owned(),
        headers,
        body,
    )
    .map_err(|_| ToolInvocationError::InvalidInput)?;
    let response = client
        .execute(BrokerRequest::HttpRequest(request))
        .map_err(ToolInvocationError::Broker)?;
    let BrokerResponse::HttpRequest(http) = response else {
        return Err(ToolInvocationError::UnexpectedResponse);
    };
    let body_text = std::str::from_utf8(http.body()).ok();
    Ok(json!({
        "statusCode": http.status_code(),
        "bodyBase64": BASE64_STANDARD.encode(http.body()),
        "bodyText": body_text,
        "truncated": http.truncated()
    }))
}

fn process_run(
    client: &mut impl BrokerToolClient,
    arguments: &Map<String, Value>,
) -> Result<Value, ToolInvocationError> {
    require_keys(
        arguments,
        &[
            "useGrantId",
            "vaultId",
            "credentialId",
            "secretFieldId",
            "secretKind",
            "vaultSessionId",
            "usageProfileId",
            "executable",
        ],
        &[
            "arguments",
            "workingDirectory",
            "environment",
            "timeoutMillis",
        ],
    )?;
    let process_arguments = optional_array(arguments, "arguments")?
        .unwrap_or(&[])
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ToolInvocationError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment = optional_array(arguments, "environment")?
        .unwrap_or(&[])
        .iter()
        .map(parse_process_environment)
        .collect::<Result<Vec<_>, _>>()?;
    let working_directory = optional_nullable_string(arguments, "workingDirectory")?;
    let timeout_millis =
        optional_u64(arguments, "timeoutMillis")?.unwrap_or(DEFAULT_PROCESS_TIMEOUT_MILLIS);
    let request = BrokerProcessCapabilityRequest::new(
        parse_operation_target(arguments)?,
        parse_id(arguments, "usageProfileId")?,
        required_string(arguments, "executable")?.to_owned(),
        process_arguments,
        working_directory,
        environment,
        timeout_millis,
    )
    .map_err(|_| ToolInvocationError::InvalidInput)?;
    let response = client
        .execute(BrokerRequest::ProcessRun(request))
        .map_err(ToolInvocationError::Broker)?;
    let BrokerResponse::ProcessRun(process) = response else {
        return Err(ToolInvocationError::UnexpectedResponse);
    };
    Ok(json!({
        "exitCode": process.exit_code(),
        "terminatedBySignal": process.terminated_by_signal(),
        "stdoutBase64": BASE64_STANDARD.encode(process.stdout()),
        "stderrBase64": BASE64_STANDARD.encode(process.stderr()),
        "stdoutText": std::str::from_utf8(process.stdout()).ok(),
        "stderrText": std::str::from_utf8(process.stderr()).ok(),
        "stdoutTruncated": process.stdout_truncated(),
        "stderrTruncated": process.stderr_truncated()
    }))
}

fn parse_operation_target(
    arguments: &Map<String, Value>,
) -> Result<BrokerCredentialOperationTarget, ToolInvocationError> {
    Ok(BrokerCredentialOperationTarget::new(
        parse_id(arguments, "useGrantId")?,
        parse_field_scope(arguments)?,
        SecretFieldKind::from_str(required_string(arguments, "secretKind")?)
            .map_err(|_| ToolInvocationError::InvalidInput)?,
        parse_id(arguments, "vaultSessionId")?,
    ))
}

fn parse_field_scope(
    arguments: &Map<String, Value>,
) -> Result<CredentialFieldScope, ToolInvocationError> {
    Ok(CredentialFieldScope::new(
        parse_id(arguments, "vaultId")?,
        parse_id(arguments, "credentialId")?,
        parse_id(arguments, "secretFieldId")?,
    ))
}

fn parse_requested_capability(value: &str) -> Result<Capability, ToolInvocationError> {
    let name = CapabilityName::from_str(value).map_err(|_| ToolInvocationError::InvalidInput)?;
    if !matches!(
        name,
        CapabilityName::CredentialSearch | CapabilityName::HttpRequest | CapabilityName::ProcessRun
    ) {
        return Err(ToolInvocationError::InvalidInput);
    }
    Ok(Capability::v1(name))
}

fn parse_http_header(value: &Value) -> Result<BrokerHttpCapabilityHeader, ToolInvocationError> {
    let object = value.as_object().ok_or(ToolInvocationError::InvalidInput)?;
    require_keys(object, &["name", "value"], &[])?;
    BrokerHttpCapabilityHeader::new(
        required_string(object, "name")?.to_owned(),
        required_string(object, "value")?.to_owned(),
    )
    .map_err(|_| ToolInvocationError::InvalidInput)
}

fn parse_process_environment(
    value: &Value,
) -> Result<BrokerProcessCapabilityEnvironment, ToolInvocationError> {
    let object = value.as_object().ok_or(ToolInvocationError::InvalidInput)?;
    require_keys(object, &["name", "value"], &[])?;
    BrokerProcessCapabilityEnvironment::new(
        required_string(object, "name")?.to_owned(),
        required_string(object, "value")?.to_owned(),
    )
    .map_err(|_| ToolInvocationError::InvalidInput)
}

fn parse_id<T>(arguments: &Map<String, Value>, key: &str) -> Result<T, ToolInvocationError>
where
    T: FromStr,
{
    required_string(arguments, key)?
        .parse()
        .map_err(|_| ToolInvocationError::InvalidInput)
}

fn required_string<'a>(
    arguments: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, ToolInvocationError> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ToolInvocationError::InvalidInput)
}

fn optional_string<'a>(
    arguments: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, ToolInvocationError> {
    arguments
        .get(key)
        .map(|value| value.as_str().ok_or(ToolInvocationError::InvalidInput))
        .transpose()
}

fn optional_nullable_string(
    arguments: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, ToolInvocationError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ToolInvocationError::InvalidInput),
    }
}

fn optional_array<'a>(
    arguments: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a [Value]>, ToolInvocationError> {
    arguments
        .get(key)
        .map(|value| {
            value
                .as_array()
                .map(Vec::as_slice)
                .ok_or(ToolInvocationError::InvalidInput)
        })
        .transpose()
}

fn optional_u64(
    arguments: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, ToolInvocationError> {
    arguments
        .get(key)
        .map(|value| value.as_u64().ok_or(ToolInvocationError::InvalidInput))
        .transpose()
}

fn required_u64(arguments: &Map<String, Value>, key: &str) -> Result<u64, ToolInvocationError> {
    optional_u64(arguments, key)?.ok_or(ToolInvocationError::InvalidInput)
}

fn require_keys(
    arguments: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ToolInvocationError> {
    if required.iter().any(|key| !arguments.contains_key(*key))
        || arguments
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(ToolInvocationError::InvalidInput);
    }
    Ok(())
}

fn credential_search_tool() -> Value {
    json!({
        "name": "credential.search",
        "title": "Search authorized credential",
        "description": "Return minimum metadata for one exact credential field already covered by a credential.search Use Grant. Never returns a secret value.",
        "inputSchema": operation_schema(json!({
            "query": {"type": "string", "maxLength": 256}
        }), &[]),
        "outputSchema": {
            "type": "object",
            "properties": {
                "credential": {
                    "oneOf": [
                        {"type": "null"},
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "vaultId": {"type": "string"},
                                "credentialId": {"type": "string"},
                                "title": {"type": "string"},
                                "authorizedField": {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "properties": {
                                        "secretFieldId": {"type": "string"},
                                        "role": {"type": "string"},
                                        "label": {"type": ["string", "null"]},
                                        "kind": secret_kind_schema()
                                    },
                                    "required": ["secretFieldId", "role", "label", "kind"]
                                }
                            },
                            "required": ["vaultId", "credentialId", "title", "authorizedField"]
                        }
                    ]
                }
            },
            "required": ["credential"],
            "additionalProperties": false
        },
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

fn access_request_tool() -> Value {
    json!({
        "name": "access.request",
        "title": "Manage credential access approval",
        "description": "Create, poll, wait for, or resume a local credential-access approval. Consumer status contains only a stable approval identity, state, and time boundaries; candidate metadata and secret values remain in KeptNear.",
        "inputSchema": {
            "type": "object",
            "oneOf": [
                {
                    "additionalProperties": false,
                    "properties": {
                        "requestKind": {"const": "exact"},
                        "capability": requested_capability_schema(),
                        "vaultId": {"type": "string"},
                        "credentialId": {"type": "string"},
                        "secretFieldId": {"type": "string"}
                    },
                    "required": ["requestKind", "capability", "vaultId", "credentialId", "secretFieldId"]
                },
                {
                    "additionalProperties": false,
                    "properties": {
                        "requestKind": {"const": "credential"},
                        "capability": requested_capability_schema(),
                        "vaultId": {"type": "string"},
                        "description": {"type": "string", "minLength": 1, "maxLength": 256}
                    },
                    "required": ["requestKind", "capability", "vaultId", "description"]
                },
                {
                    "additionalProperties": false,
                    "properties": {
                        "requestKind": {"const": "status"},
                        "approvalRequestId": {"type": "string"}
                    },
                    "required": ["requestKind", "approvalRequestId"]
                },
                {
                    "additionalProperties": false,
                    "properties": {
                        "requestKind": {"const": "resume"},
                        "approvalRequestId": {"type": "string"}
                    },
                    "required": ["requestKind", "approvalRequestId"]
                },
                {
                    "additionalProperties": false,
                    "properties": {
                        "requestKind": {"const": "wait"},
                        "approvalRequestId": {"type": "string"},
                        "timeoutMillis": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_APPROVAL_WAIT_MILLIS
                        }
                    },
                    "required": ["requestKind", "approvalRequestId", "timeoutMillis"]
                }
            ]
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "operation": {"enum": ["submission", "status", "resume", "wait"]},
                "approvalRequestId": {"type": "string"},
                "status": {"enum": ["pending", "approved", "denied", "expired", "cancelled"]},
                "expiresAtMillis": {"type": "integer", "minimum": 0},
                "resolvedAtMillis": {"type": ["integer", "null"], "minimum": 0},
                "coalesced": {"type": ["boolean", "null"]},
                "timedOut": {"type": ["boolean", "null"]}
            },
            "required": [
                "operation",
                "approvalRequestId",
                "status",
                "expiresAtMillis",
                "resolvedAtMillis",
                "coalesced",
                "timedOut"
            ]
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

fn grant_status_tool() -> Value {
    json!({
        "name": "grant.status",
        "title": "Check Use Grant",
        "description": "Return active, expired, or unavailable for one Use Grant owned by this paired Consumer. Foreign grant identities are indistinguishable from unavailable.",
        "inputSchema": single_grant_input_schema(),
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "status": {"enum": ["active", "expired", "unavailable"]},
                "activeGrant": {
                    "oneOf": [
                        {"type": "null"},
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "useGrantId": {"type": "string"},
                                "vaultId": {"type": "string"},
                                "credentialId": {"type": "string"},
                                "secretFieldId": {"type": "string"},
                                "capability": requested_capability_schema(),
                                "capabilityVersion": {"type": "integer", "minimum": 1},
                                "vaultSessionId": {"type": "string"},
                                "scope": {"enum": ["one-operation", "unlock-session"]},
                                "createdAtMillis": {"type": "integer", "minimum": 0},
                                "expiresAtMillis": {"type": "integer", "minimum": 0}
                            },
                            "required": [
                                "useGrantId",
                                "vaultId",
                                "credentialId",
                                "secretFieldId",
                                "capability",
                                "capabilityVersion",
                                "vaultSessionId",
                                "scope",
                                "createdAtMillis",
                                "expiresAtMillis"
                            ]
                        }
                    ]
                }
            },
            "required": ["status", "activeGrant"]
        },
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

fn grant_revoke_tool() -> Value {
    json!({
        "name": "grant.revoke",
        "title": "Revoke Use Grant",
        "description": "Revoke one Use Grant only when it belongs to this paired Consumer. Does not revoke the persistent Access Rule.",
        "inputSchema": single_grant_input_schema(),
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {"revoked": {"type": "boolean"}},
            "required": ["revoked"]
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

fn http_request_tool() -> Value {
    json!({
        "name": "http.request",
        "title": "Run authorized HTTPS request",
        "description": "Execute one bounded HTTPS request inside KeptNear using an exact Use Grant and declarative Usage Profile. The credential is never returned; exact echoes are redacted from the response.",
        "inputSchema": operation_schema(json!({
            "usageProfileId": {"type": "string"},
            "method": {"enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]},
            "url": {"type": "string", "maxLength": 4096},
            "headers": {
                "type": "array",
                "maxItems": 32,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"}
                    },
                    "required": ["name", "value"]
                }
            },
            "bodyBase64": {"type": "string"}
        }), &["usageProfileId", "method", "url"]),
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "statusCode": {"type": "integer", "minimum": 100, "maximum": 599},
                "bodyBase64": {"type": "string"},
                "bodyText": {"type": ["string", "null"]},
                "truncated": {"type": "boolean"}
            },
            "required": ["statusCode", "bodyBase64", "bodyText", "truncated"]
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false,
            "openWorldHint": true
        }
    })
}

fn process_run_tool() -> Value {
    json!({
        "name": "process.run",
        "title": "Run authorized process",
        "description": "Launch one explicit absolute executable directly and deliver an approved credential only through its Usage Profile. No shell is inserted and exact secret echoes are redacted from bounded output.",
        "inputSchema": operation_schema(json!({
            "usageProfileId": {"type": "string"},
            "executable": {"type": "string", "maxLength": 4096},
            "arguments": {
                "type": "array",
                "maxItems": 128,
                "items": {"type": "string"}
            },
            "workingDirectory": {"type": ["string", "null"], "maxLength": 4096},
            "environment": {
                "type": "array",
                "maxItems": 64,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"}
                    },
                    "required": ["name", "value"]
                }
            },
            "timeoutMillis": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_PROCESS_TIMEOUT_MILLIS
            }
        }), &["usageProfileId", "executable"]),
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "exitCode": {"type": ["integer", "null"]},
                "terminatedBySignal": {"type": "boolean"},
                "stdoutBase64": {"type": "string"},
                "stderrBase64": {"type": "string"},
                "stdoutText": {"type": ["string", "null"]},
                "stderrText": {"type": ["string", "null"]},
                "stdoutTruncated": {"type": "boolean"},
                "stderrTruncated": {"type": "boolean"}
            },
            "required": [
                "exitCode",
                "terminatedBySignal",
                "stdoutBase64",
                "stderrBase64",
                "stdoutText",
                "stderrText",
                "stdoutTruncated",
                "stderrTruncated"
            ]
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false,
            "openWorldHint": false
        }
    })
}

fn operation_schema(mut extra_properties: Value, extra_required: &[&str]) -> Value {
    let mut properties = common_operation_properties();
    properties.append(
        extra_properties
            .as_object_mut()
            .expect("operation schema properties are an object"),
    );
    let mut required = vec![
        "useGrantId",
        "vaultId",
        "credentialId",
        "secretFieldId",
        "secretKind",
        "vaultSessionId",
    ];
    required.extend_from_slice(extra_required);
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required
    })
}

fn common_operation_properties() -> Map<String, Value> {
    let mut properties = Map::new();
    properties.insert("useGrantId".to_owned(), json!({"type": "string"}));
    properties.insert("vaultId".to_owned(), json!({"type": "string"}));
    properties.insert("credentialId".to_owned(), json!({"type": "string"}));
    properties.insert("secretFieldId".to_owned(), json!({"type": "string"}));
    properties.insert("secretKind".to_owned(), secret_kind_schema());
    properties.insert("vaultSessionId".to_owned(), json!({"type": "string"}));
    properties
}

fn secret_kind_schema() -> Value {
    json!({
        "enum": [
            "password",
            "api-token",
            "api-key",
            "totp-seed",
            "private-key",
            "certificate",
            "generic-secret"
        ]
    })
}

fn requested_capability_schema() -> Value {
    json!({"enum": ["credential.search", "http.request", "process.run"]})
}

fn single_grant_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"useGrantId": {"type": "string"}},
        "required": ["useGrantId"]
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn decoded_response(message_type: &str, result: Value) -> BrokerResponse {
        let request_id = psw_broker::BrokerRequestId::generate();
        let payload = serde_json::to_vec(&json!({
            "protocol_name": psw_broker::BROKER_PROTOCOL_NAME,
            "protocol_major": psw_broker::BROKER_PROTOCOL_MAJOR,
            "protocol_minor": psw_broker::BROKER_PROTOCOL_MINOR,
            "message_type": message_type,
            "request_id": request_id.to_string(),
            "result": result
        }))
        .expect("response JSON");
        psw_broker::decode_broker_response(&payload)
            .expect("decode response")
            .response()
            .clone()
    }

    fn decoded_access_response(result: Value) -> BrokerResponse {
        decoded_response("access.request.result", result)
    }

    fn operation_arguments() -> Map<String, Value> {
        json!({
            "useGrantId": psw_broker::UseGrantId::generate().to_string(),
            "vaultId": psw_broker::VaultId::generate().to_string(),
            "credentialId": psw_broker::CredentialId::generate().to_string(),
            "secretFieldId": psw_broker::SecretFieldId::generate().to_string(),
            "secretKind": "api-token",
            "vaultSessionId": psw_broker::VaultSessionId::generate().to_string()
        })
        .as_object()
        .expect("operation arguments")
        .clone()
    }

    fn required_fields(schema: &Value) -> BTreeSet<String> {
        schema["required"]
            .as_array()
            .expect("required fields")
            .iter()
            .map(|value| value.as_str().expect("required field").to_owned())
            .collect()
    }

    fn schema_for<'a>(catalog: &'a [Value], name: &str) -> &'a Value {
        catalog
            .iter()
            .find(|tool| tool["name"] == name)
            .expect("tool schema")
    }

    struct FakeClient {
        response: Option<Result<BrokerResponse, BrokerAdapterError>>,
        request: Option<BrokerRequest>,
    }

    impl BrokerToolClient for FakeClient {
        fn execute(
            &mut self,
            request: BrokerRequest,
        ) -> Result<BrokerResponse, BrokerAdapterError> {
            self.request = Some(request);
            self.response
                .take()
                .unwrap_or(Err(BrokerAdapterError::Protocol))
        }
    }

    #[test]
    fn catalog_is_stable_complete_and_declares_closed_input_schemas() {
        let catalog = catalog();
        assert_eq!(catalog.len(), 6);
        for unavailable in [
            "secret.get",
            "vault.export",
            "credential.export",
            "plaintext.export",
        ] {
            assert!(!is_known_tool(unavailable));
        }
        assert_eq!(
            catalog
                .iter()
                .map(|tool| tool["name"].as_str().expect("name"))
                .collect::<Vec<_>>(),
            [
                "credential.search",
                "access.request",
                "grant.status",
                "grant.revoke",
                "http.request",
                "process.run"
            ]
        );
        for tool in catalog {
            assert!(
                tool["description"]
                    .as_str()
                    .expect("description")
                    .contains("credential")
                    || tool["description"]
                        .as_str()
                        .expect("description")
                        .contains("Use Grant")
            );
            assert!(tool.get("inputSchema").is_some());
            assert_eq!(tool["outputSchema"]["additionalProperties"], false);
        }
    }

    #[test]
    fn catalog_required_fields_and_closed_shapes_match_runtime_inputs() {
        let catalog = catalog();
        let common = BTreeSet::from([
            "credentialId".to_owned(),
            "secretFieldId".to_owned(),
            "secretKind".to_owned(),
            "useGrantId".to_owned(),
            "vaultId".to_owned(),
            "vaultSessionId".to_owned(),
        ]);

        let credential = schema_for(&catalog, "credential.search");
        assert_eq!(required_fields(&credential["inputSchema"]), common.clone());
        assert_eq!(
            credential["inputSchema"]["additionalProperties"],
            Value::Bool(false)
        );
        assert!(credential["inputSchema"]["properties"]
            .get("query")
            .is_some());

        for name in ["grant.status", "grant.revoke"] {
            let schema = &schema_for(&catalog, name)["inputSchema"];
            assert_eq!(
                required_fields(schema),
                BTreeSet::from(["useGrantId".to_owned()])
            );
            assert_eq!(schema["additionalProperties"], false);
        }

        let mut http_required = common.clone();
        http_required.extend([
            "method".to_owned(),
            "url".to_owned(),
            "usageProfileId".to_owned(),
        ]);
        let http = &schema_for(&catalog, "http.request")["inputSchema"];
        assert_eq!(required_fields(http), http_required);
        assert_eq!(http["additionalProperties"], false);
        assert_eq!(
            http["properties"]["headers"]["items"]["additionalProperties"],
            false
        );

        let mut process_required = common;
        process_required.extend(["executable".to_owned(), "usageProfileId".to_owned()]);
        let process = &schema_for(&catalog, "process.run")["inputSchema"];
        assert_eq!(required_fields(process), process_required);
        assert_eq!(process["additionalProperties"], false);
        assert_eq!(
            process["properties"]["environment"]["items"]["additionalProperties"],
            false
        );

        let access = schema_for(&catalog, "access.request");
        for variant in access["inputSchema"]["oneOf"]
            .as_array()
            .expect("access variants")
        {
            assert_eq!(variant["additionalProperties"], false);
        }
    }

    #[test]
    fn malformed_and_unknown_fields_are_rejected_without_reflection() {
        let mut client = FakeClient {
            response: None,
            request: None,
        };
        let arguments = json!({
            "useGrantId": "not-an-id",
            "secret": "KN_TOOL_SECRET_MARKER"
        });
        assert_eq!(
            invoke(
                &mut client,
                "grant.status",
                arguments.as_object().expect("object")
            ),
            Err(ToolInvocationError::InvalidInput)
        );
        assert!(client.request.is_none());
    }

    #[test]
    fn access_request_schema_covers_submit_status_wait_and_resume() {
        let tool = access_request_tool();
        let variants = tool["inputSchema"]["oneOf"]
            .as_array()
            .expect("access variants");
        assert_eq!(variants.len(), 5);
        assert_eq!(
            variants
                .iter()
                .map(|variant| {
                    variant["properties"]["requestKind"]["const"]
                        .as_str()
                        .expect("request kind")
                })
                .collect::<Vec<_>>(),
            ["exact", "credential", "status", "resume", "wait"]
        );
        assert_eq!(
            variants[4]["properties"]["timeoutMillis"]["maximum"],
            MAX_APPROVAL_WAIT_MILLIS
        );
        assert_eq!(tool["outputSchema"]["additionalProperties"], false);
        assert_eq!(
            tool["outputSchema"]["properties"]["operation"]["enum"],
            json!(["submission", "status", "resume", "wait"])
        );
    }

    #[test]
    fn access_lifecycle_returns_only_resumable_consumer_safe_receipts() {
        let approval_request_id = psw_broker::ApprovalRequestId::generate();
        let expires_at_millis = 9_000_i64;

        let mut status_client = FakeClient {
            response: Some(Ok(decoded_access_response(json!({
                "result_kind": "status",
                "approval_request_id": approval_request_id.to_string(),
                "status": "pending",
                "expires_at_millis": expires_at_millis,
                "resolved_at_millis": null
            })))),
            request: None,
        };
        let status_arguments = json!({
            "requestKind": "status",
            "approvalRequestId": approval_request_id.to_string()
        });
        let status = invoke(
            &mut status_client,
            "access.request",
            status_arguments.as_object().expect("status arguments"),
        )
        .expect("status");
        assert_eq!(
            status,
            json!({
                "operation": "status",
                "approvalRequestId": approval_request_id.to_string(),
                "status": "pending",
                "expiresAtMillis": expires_at_millis,
                "resolvedAtMillis": null,
                "coalesced": null,
                "timedOut": null
            })
        );
        assert!(matches!(
            status_client.request,
            Some(BrokerRequest::AccessRequest(BrokerAccessRequest::Status {
                approval_request_id: requested
            })) if requested == approval_request_id
        ));

        let resolved_at_millis = 8_000_i64;
        let mut resume_client = FakeClient {
            response: Some(Ok(decoded_access_response(json!({
                "result_kind": "resume",
                "approval_request_id": approval_request_id.to_string(),
                "status": "approved",
                "expires_at_millis": expires_at_millis,
                "resolved_at_millis": resolved_at_millis
            })))),
            request: None,
        };
        let resume_arguments = json!({
            "requestKind": "resume",
            "approvalRequestId": approval_request_id.to_string()
        });
        let resumed = invoke(
            &mut resume_client,
            "access.request",
            resume_arguments.as_object().expect("resume arguments"),
        )
        .expect("resume");
        assert_eq!(resumed["operation"], "resume");
        assert_eq!(resumed["status"], "approved");
        assert_eq!(resumed["resolvedAtMillis"], resolved_at_millis);

        let mut wait_client = FakeClient {
            response: Some(Ok(decoded_access_response(json!({
                "result_kind": "wait",
                "approval_request_id": approval_request_id.to_string(),
                "status": "pending",
                "expires_at_millis": expires_at_millis,
                "resolved_at_millis": null,
                "timed_out": true
            })))),
            request: None,
        };
        let wait_arguments = json!({
            "requestKind": "wait",
            "approvalRequestId": approval_request_id.to_string(),
            "timeoutMillis": 25
        });
        let waited = invoke(
            &mut wait_client,
            "access.request",
            wait_arguments.as_object().expect("wait arguments"),
        )
        .expect("wait");
        assert_eq!(waited["operation"], "wait");
        assert_eq!(waited["timedOut"], true);
        assert_eq!(waited["coalesced"], Value::Null);
        assert!(!waited.to_string().contains("secret"));
    }

    #[test]
    fn access_wait_rejects_unbounded_or_unknown_input_before_broker_dispatch() {
        for timeout_millis in [0, MAX_APPROVAL_WAIT_MILLIS + 1] {
            let mut client = FakeClient {
                response: None,
                request: None,
            };
            let arguments = json!({
                "requestKind": "wait",
                "approvalRequestId": psw_broker::ApprovalRequestId::generate().to_string(),
                "timeoutMillis": timeout_millis
            });
            assert_eq!(
                invoke(
                    &mut client,
                    "access.request",
                    arguments.as_object().expect("arguments")
                ),
                Err(ToolInvocationError::InvalidInput)
            );
            assert!(client.request.is_none());
        }
    }

    #[test]
    fn wait_and_process_timeouts_accept_exact_bounds_and_process_default() {
        let approval_request_id = psw_broker::ApprovalRequestId::generate();
        for timeout_millis in [1, MAX_APPROVAL_WAIT_MILLIS] {
            let mut client = FakeClient {
                response: Some(Ok(decoded_response(
                    "grant.revoke.result",
                    json!({"revoked": false}),
                ))),
                request: None,
            };
            let arguments = json!({
                "requestKind": "wait",
                "approvalRequestId": approval_request_id.to_string(),
                "timeoutMillis": timeout_millis
            });
            assert_eq!(
                invoke(
                    &mut client,
                    "access.request",
                    arguments.as_object().expect("wait arguments")
                ),
                Err(ToolInvocationError::UnexpectedResponse)
            );
            assert!(matches!(
                client.request,
                Some(BrokerRequest::AccessRequest(BrokerAccessRequest::Wait {
                    timeout,
                    ..
                })) if timeout == Duration::from_millis(timeout_millis)
            ));
        }

        for (timeout_millis, expected) in [
            (None, DEFAULT_PROCESS_TIMEOUT_MILLIS),
            (Some(1), 1),
            (Some(MAX_PROCESS_TIMEOUT_MILLIS), MAX_PROCESS_TIMEOUT_MILLIS),
        ] {
            let mut arguments = operation_arguments();
            arguments.insert(
                "usageProfileId".to_owned(),
                Value::String(psw_broker::UsageProfileId::generate().to_string()),
            );
            arguments.insert(
                "executable".to_owned(),
                Value::String("/usr/bin/true".to_owned()),
            );
            if let Some(timeout_millis) = timeout_millis {
                arguments.insert("timeoutMillis".to_owned(), json!(timeout_millis));
            }
            let mut client = FakeClient {
                response: Some(Ok(decoded_response(
                    "grant.revoke.result",
                    json!({"revoked": false}),
                ))),
                request: None,
            };
            assert_eq!(
                invoke(&mut client, "process.run", &arguments),
                Err(ToolInvocationError::UnexpectedResponse)
            );
            assert!(matches!(
                client.request,
                Some(BrokerRequest::ProcessRun(ref request))
                    if request.timeout_millis() == expected
            ));
        }

        for timeout_millis in [0, MAX_PROCESS_TIMEOUT_MILLIS + 1] {
            let mut arguments = operation_arguments();
            arguments.insert(
                "usageProfileId".to_owned(),
                Value::String(psw_broker::UsageProfileId::generate().to_string()),
            );
            arguments.insert(
                "executable".to_owned(),
                Value::String("/usr/bin/true".to_owned()),
            );
            arguments.insert("timeoutMillis".to_owned(), json!(timeout_millis));
            let mut client = FakeClient {
                response: None,
                request: None,
            };
            assert_eq!(
                invoke(&mut client, "process.run", &arguments),
                Err(ToolInvocationError::InvalidInput)
            );
            assert!(client.request.is_none());
        }
    }

    #[test]
    fn every_tool_result_matches_its_declared_closed_output_shape() {
        let marker = "KN_SUCCESS_PRIVATE_INPUT_MARKER";
        let use_grant_id = psw_broker::UseGrantId::generate();
        let approval_request_id = psw_broker::ApprovalRequestId::generate();
        let usage_profile_id = psw_broker::UsageProfileId::generate();
        let mut operation = operation_arguments();
        operation.insert(
            "useGrantId".to_owned(),
            Value::String(use_grant_id.to_string()),
        );

        let mut credential_arguments = operation.clone();
        credential_arguments.insert("query".to_owned(), Value::String(marker.to_owned()));
        let access_arguments = json!({
            "requestKind": "credential",
            "capability": "http.request",
            "vaultId": psw_broker::VaultId::generate().to_string(),
            "description": marker
        })
        .as_object()
        .expect("access arguments")
        .clone();
        let grant_arguments = json!({"useGrantId": use_grant_id.to_string()})
            .as_object()
            .expect("grant arguments")
            .clone();
        let mut http_arguments = operation.clone();
        http_arguments.extend([
            (
                "usageProfileId".to_owned(),
                Value::String(usage_profile_id.to_string()),
            ),
            ("method".to_owned(), Value::String("GET".to_owned())),
            (
                "url".to_owned(),
                Value::String(format!("https://example.invalid/{marker}")),
            ),
            (
                "headers".to_owned(),
                json!([{"name": "X-Private-Input", "value": marker}]),
            ),
            (
                "bodyBase64".to_owned(),
                Value::String(BASE64_STANDARD.encode(marker.as_bytes())),
            ),
        ]);
        let mut process_arguments = operation;
        process_arguments.extend([
            (
                "usageProfileId".to_owned(),
                Value::String(usage_profile_id.to_string()),
            ),
            (
                "executable".to_owned(),
                Value::String("/usr/bin/true".to_owned()),
            ),
            ("arguments".to_owned(), json!([marker])),
            (
                "environment".to_owned(),
                json!([{"name": "KN_TEST_VALUE", "value": marker}]),
            ),
        ]);

        let cases = [
            (
                "credential.search",
                credential_arguments,
                decoded_response("credential.search.result", json!({"credential": null})),
            ),
            (
                "access.request",
                access_arguments,
                decoded_access_response(json!({
                    "result_kind": "submission",
                    "approval_request_id": approval_request_id.to_string(),
                    "status": "pending",
                    "expires_at_millis": 9_000,
                    "resolved_at_millis": null,
                    "coalesced": false
                })),
            ),
            (
                "grant.status",
                grant_arguments.clone(),
                decoded_response(
                    "grant.status.result",
                    json!({"status": "unavailable", "active_grant": null}),
                ),
            ),
            (
                "grant.revoke",
                grant_arguments,
                decoded_response("grant.revoke.result", json!({"revoked": false})),
            ),
            (
                "http.request",
                http_arguments,
                decoded_response(
                    "http.request.result",
                    json!({
                        "status_code": 200,
                        "body_base64": BASE64_STANDARD.encode(b"ok"),
                        "truncated": false
                    }),
                ),
            ),
            (
                "process.run",
                process_arguments,
                decoded_response(
                    "process.run.result",
                    json!({
                        "exit_code": 0,
                        "terminated_by_signal": false,
                        "stdout_base64": BASE64_STANDARD.encode(b"ok"),
                        "stderr_base64": "",
                        "stdout_truncated": false,
                        "stderr_truncated": false
                    }),
                ),
            ),
        ];
        let catalog = catalog();

        for (name, arguments, response) in cases {
            let mut client = FakeClient {
                response: Some(Ok(response)),
                request: None,
            };
            let output = invoke(&mut client, name, &arguments).expect("tool output");
            let output_keys = output
                .as_object()
                .expect("closed output")
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            let schema = &schema_for(&catalog, name)["outputSchema"];

            assert_eq!(schema["additionalProperties"], false, "{name}");
            assert_eq!(output_keys, required_fields(schema), "{name}");
            assert!(!output.to_string().contains(marker), "{name}");
            assert!(client.request.is_some(), "{name}");
        }
    }
}
