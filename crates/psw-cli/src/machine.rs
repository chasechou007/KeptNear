use std::fmt::{Debug, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
#[cfg(target_os = "macos")]
use keptnear_client::MacOsBrokerClient;
use keptnear_client::{
    BrokerAdapterError, BrokerAuthenticationStatus, ClientIdentityKind, PairingProfileId,
};
use psw_broker::{
    ApprovalRequestId, BrokerAccessReceiptResponse, BrokerAccessRequest, BrokerAccessResponse,
    BrokerHttpCapabilityRequest, BrokerRequest, BrokerResponse, BrokerStatusResponse,
    MAX_APPROVAL_WAIT, MAX_HTTP_REQUEST_BODY_BYTES,
};
use serde::Serialize;
use zeroize::Zeroize;

use crate::{
    CliAccessRequest, CliApprovalWaitMode, CliHttpRequest, KeptNearCommand, KeptNearInvocation,
};

const CLI_OUTPUT_SCHEMA_VERSION: u8 = 1;
const MAX_PROPAGATED_PROCESS_EXIT_CODE: i32 = 255;

/// Terminal state of one successfully handled machine command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeptNearExecutionOutcome {
    /// The Broker operation completed and one result was written.
    Completed,
    /// The local Consumer needs approval before the command can be retried.
    PairingPending,
    /// A direct child completed and its structured result was written.
    ProcessCompleted {
        /// Numeric child status when the operating system supplied one.
        exit_code: Option<i32>,
        /// Whether the operating system reported signal-based termination.
        terminated_by_signal: bool,
    },
}

impl KeptNearExecutionOutcome {
    /// Returns the stable process exit status for this completed CLI action.
    #[must_use]
    pub const fn exit_status(self) -> i32 {
        match self {
            Self::Completed => 0,
            Self::PairingPending => 1,
            Self::ProcessCompleted {
                exit_code: Some(exit_code @ 0..=MAX_PROPAGATED_PROCESS_EXIT_CODE),
                terminated_by_signal: false,
            } => exit_code,
            Self::ProcessCompleted { .. } => 1,
        }
    }
}

/// Sanitized public CLI execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeptNearExecutionError {
    /// Shared local client or Broker failure.
    Client(BrokerAdapterError),
    /// A submitted request could not complete its bounded approval wait.
    ApprovalWait {
        /// Sanitized shared-client failure from the wait request.
        source: BrokerAdapterError,
        /// Stable request identity needed to retry the asynchronous workflow.
        approval_request_id: ApprovalRequestId,
    },
    /// An explicit HTTP body file could not be read safely within the bound.
    BodyFile,
    /// A parser-owned request could not be reconstructed for dispatch.
    InvalidRequest,
    /// The Broker returned a response for another operation.
    UnexpectedResponse,
    /// Structured output could not be written.
    Output,
    /// The public machine client is not implemented for this operating system.
    UnsupportedPlatform,
}

impl KeptNearExecutionError {
    /// Writes one fixed-schema non-reflective error to the supplied stream.
    pub fn write_json(&self, writer: &mut impl Write) -> io::Result<()> {
        let mut approval_request_id = None;
        let detail = match self {
            Self::Client(BrokerAdapterError::Identity) => ErrorDetail {
                code: "identity-unavailable",
                retryable: false,
                required_action: None,
                approval_request_id: None,
            },
            Self::Client(BrokerAdapterError::Transport) => ErrorDetail {
                code: "broker-unavailable",
                retryable: true,
                required_action: Some("retry-later"),
                approval_request_id: None,
            },
            Self::Client(BrokerAdapterError::Protocol) | Self::UnexpectedResponse => ErrorDetail {
                code: "adapter-protocol-failure",
                retryable: false,
                required_action: None,
                approval_request_id: None,
            },
            Self::Client(BrokerAdapterError::Broker {
                error_code,
                retryable,
                required_action,
                approval_request_id: broker_approval_request_id,
            }) => {
                approval_request_id = broker_approval_request_id.map(|value| value.to_string());
                ErrorDetail {
                    code: error_code.as_str(),
                    retryable: *retryable,
                    required_action: required_action.map(|value| value.as_str()),
                    approval_request_id: approval_request_id.as_deref(),
                }
            }
            Self::ApprovalWait {
                source: BrokerAdapterError::Identity,
                approval_request_id: wait_request_id,
            } => {
                approval_request_id = Some(wait_request_id.to_string());
                ErrorDetail {
                    code: "identity-unavailable",
                    retryable: false,
                    required_action: None,
                    approval_request_id: approval_request_id.as_deref(),
                }
            }
            Self::ApprovalWait {
                source: BrokerAdapterError::Transport,
                approval_request_id: wait_request_id,
            } => {
                approval_request_id = Some(wait_request_id.to_string());
                ErrorDetail {
                    code: "broker-unavailable",
                    retryable: true,
                    required_action: Some("retry-later"),
                    approval_request_id: approval_request_id.as_deref(),
                }
            }
            Self::ApprovalWait {
                source: BrokerAdapterError::Protocol,
                approval_request_id: wait_request_id,
            } => {
                approval_request_id = Some(wait_request_id.to_string());
                ErrorDetail {
                    code: "adapter-protocol-failure",
                    retryable: false,
                    required_action: None,
                    approval_request_id: approval_request_id.as_deref(),
                }
            }
            Self::ApprovalWait {
                source:
                    BrokerAdapterError::Broker {
                        error_code,
                        retryable,
                        required_action,
                        approval_request_id: broker_approval_request_id,
                    },
                approval_request_id: wait_request_id,
            } => {
                approval_request_id = Some(
                    broker_approval_request_id
                        .unwrap_or(*wait_request_id)
                        .to_string(),
                );
                ErrorDetail {
                    code: error_code.as_str(),
                    retryable: *retryable,
                    required_action: required_action.map(|value| value.as_str()),
                    approval_request_id: approval_request_id.as_deref(),
                }
            }
            Self::BodyFile => ErrorDetail {
                code: "body-file-unavailable",
                retryable: false,
                required_action: None,
                approval_request_id: None,
            },
            Self::InvalidRequest => ErrorDetail {
                code: "invalid-request",
                retryable: false,
                required_action: None,
                approval_request_id: None,
            },
            Self::Output => ErrorDetail {
                code: "output-failed",
                retryable: false,
                required_action: None,
                approval_request_id: None,
            },
            Self::UnsupportedPlatform => ErrorDetail {
                code: "unsupported-platform",
                retryable: false,
                required_action: None,
                approval_request_id: None,
            },
        };
        let result = write_json(
            writer,
            &ErrorEnvelope {
                schema_version: CLI_OUTPUT_SCHEMA_VERSION,
                ok: false,
                error: detail,
            },
        );
        approval_request_id.zeroize();
        result
    }
}

impl Display for KeptNearExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeptNear command failed")
    }
}

impl std::error::Error for KeptNearExecutionError {}

trait CliBroker {
    fn status(&mut self) -> Result<BrokerStatusResponse, BrokerAdapterError>;

    fn authenticate(&mut self) -> Result<BrokerAuthenticationStatus, BrokerAdapterError>;

    fn execute(&mut self, request: BrokerRequest) -> Result<BrokerResponse, BrokerAdapterError>;
}

#[cfg(target_os = "macos")]
impl CliBroker for MacOsBrokerClient {
    fn status(&mut self) -> Result<BrokerStatusResponse, BrokerAdapterError> {
        MacOsBrokerClient::status(self)
    }

    fn authenticate(&mut self) -> Result<BrokerAuthenticationStatus, BrokerAdapterError> {
        MacOsBrokerClient::authenticate(self)
    }

    fn execute(&mut self, request: BrokerRequest) -> Result<BrokerResponse, BrokerAdapterError> {
        MacOsBrokerClient::execute(self, request)
    }
}

/// Executes one parsed public machine command through the authenticated Broker.
///
/// This function never opens or parses a vault. On macOS it selects one
/// device-only CLI Consumer identity and uses the owner-only Broker socket.
#[cfg(target_os = "macos")]
pub fn execute_keptnear_invocation(
    invocation: KeptNearInvocation,
    writer: &mut impl Write,
) -> Result<KeptNearExecutionOutcome, KeptNearExecutionError> {
    let (profile, command) = invocation.into_parts();
    let profile = PairingProfileId::new(profile.as_str())
        .map_err(|_| KeptNearExecutionError::InvalidRequest)?;
    let mut client = MacOsBrokerClient::new(ClientIdentityKind::Cli, profile);
    execute_with_client(command, &mut client, writer)
}

/// Reports unsupported platform state without accessing local files.
#[cfg(not(target_os = "macos"))]
pub fn execute_keptnear_invocation(
    _invocation: KeptNearInvocation,
    _writer: &mut impl Write,
) -> Result<KeptNearExecutionOutcome, KeptNearExecutionError> {
    Err(KeptNearExecutionError::UnsupportedPlatform)
}

fn execute_with_client(
    command: KeptNearCommand,
    client: &mut impl CliBroker,
    writer: &mut impl Write,
) -> Result<KeptNearExecutionOutcome, KeptNearExecutionError> {
    if matches!(command, KeptNearCommand::Status) {
        let status = client.status().map_err(KeptNearExecutionError::Client)?;
        write_success(
            writer,
            StatusOutput {
                operation: "status",
                broker_instance_id: status.broker_instance_id().to_string(),
            },
        )?;
        return Ok(KeptNearExecutionOutcome::Completed);
    }

    match client
        .authenticate()
        .map_err(KeptNearExecutionError::Client)?
    {
        BrokerAuthenticationStatus::Authenticated => {}
        BrokerAuthenticationStatus::PairingPending {
            pairing_request_id,
            comparison_code,
        } => {
            write_success(
                writer,
                PairingOutput {
                    operation: "pairing",
                    status: "pending",
                    pairing_request_id: pairing_request_id.to_string(),
                    comparison_code: comparison_code.as_str(),
                },
            )?;
            return Ok(KeptNearExecutionOutcome::PairingPending);
        }
    }

    let (response, expected_response) = match command {
        KeptNearCommand::Status => unreachable!("status returned before authentication"),
        KeptNearCommand::Search(request) => (
            client.execute(BrokerRequest::CredentialSearch(request)),
            ExpectedBrokerResponse::CredentialSearch,
        ),
        KeptNearCommand::AccessRequest(request) => {
            execute_access_request(request, client, writer)?;
            return Ok(KeptNearExecutionOutcome::Completed);
        }
        KeptNearCommand::GrantStatus(request) => (
            client.execute(BrokerRequest::GrantStatus(request)),
            ExpectedBrokerResponse::GrantStatus,
        ),
        KeptNearCommand::Revoke(request) => (
            client.execute(BrokerRequest::GrantRevoke(request)),
            ExpectedBrokerResponse::GrantRevoke,
        ),
        KeptNearCommand::HttpRequest(request) => (
            client.execute(BrokerRequest::HttpRequest(build_http_request(&request)?)),
            ExpectedBrokerResponse::HttpRequest,
        ),
        KeptNearCommand::Run(request) => (
            client.execute(BrokerRequest::ProcessRun(request)),
            ExpectedBrokerResponse::ProcessRun,
        ),
    };
    let response = response.map_err(KeptNearExecutionError::Client)?;
    if !expected_response.matches(&response) {
        return Err(KeptNearExecutionError::UnexpectedResponse);
    }
    let outcome = match &response {
        BrokerResponse::ProcessRun(process) => KeptNearExecutionOutcome::ProcessCompleted {
            exit_code: process.exit_code(),
            terminated_by_signal: process.terminated_by_signal(),
        },
        _ => KeptNearExecutionOutcome::Completed,
    };
    write_broker_response(response, writer)?;
    Ok(outcome)
}

#[derive(Clone, Copy)]
enum ExpectedBrokerResponse {
    CredentialSearch,
    GrantStatus,
    GrantRevoke,
    HttpRequest,
    ProcessRun,
}

impl ExpectedBrokerResponse {
    fn matches(self, response: &BrokerResponse) -> bool {
        matches!(
            (self, response),
            (Self::CredentialSearch, BrokerResponse::CredentialSearch(_))
                | (Self::GrantStatus, BrokerResponse::GrantStatus(_))
                | (Self::GrantRevoke, BrokerResponse::GrantRevoke(_))
                | (Self::HttpRequest, BrokerResponse::HttpRequest(_))
                | (Self::ProcessRun, BrokerResponse::ProcessRun(_))
        )
    }
}

fn execute_access_request(
    request: CliAccessRequest,
    client: &mut impl CliBroker,
    writer: &mut impl Write,
) -> Result<(), KeptNearExecutionError> {
    let (request, wait_mode) = request.into_parts();
    let response = client
        .execute(BrokerRequest::AccessRequest(request))
        .map_err(KeptNearExecutionError::Client)?;
    let BrokerResponse::AccessRequest(BrokerAccessResponse::Submission(submission)) = response
    else {
        return Err(KeptNearExecutionError::UnexpectedResponse);
    };
    let receipt = submission.receipt();
    if wait_mode == CliApprovalWaitMode::NoWait {
        return write_access_result(writer, receipt, submission.coalesced(), false, None);
    }

    let approval_request_id = receipt.approval_request_id();
    let wait_request = BrokerAccessRequest::wait(approval_request_id, MAX_APPROVAL_WAIT)
        .map_err(|_| KeptNearExecutionError::InvalidRequest)?;
    let response = client
        .execute(BrokerRequest::AccessRequest(wait_request))
        .map_err(|source| KeptNearExecutionError::ApprovalWait {
            source,
            approval_request_id,
        })?;
    let BrokerResponse::AccessRequest(BrokerAccessResponse::Wait(wait)) = response else {
        return Err(KeptNearExecutionError::ApprovalWait {
            source: BrokerAdapterError::Protocol,
            approval_request_id,
        });
    };
    write_access_result(
        writer,
        wait.receipt(),
        submission.coalesced(),
        true,
        Some(wait.timed_out()),
    )
}

fn build_http_request(
    request: &CliHttpRequest,
) -> Result<BrokerHttpCapabilityRequest, KeptNearExecutionError> {
    BrokerHttpCapabilityRequest::new(
        request.target(),
        request.usage_profile_id(),
        request.method(),
        request.url().to_owned(),
        request.headers().to_vec(),
        read_body_file(request.body_file())?,
    )
    .map_err(|_| KeptNearExecutionError::InvalidRequest)
}

fn read_body_file(path: Option<&std::path::Path>) -> Result<Vec<u8>, KeptNearExecutionError> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| KeptNearExecutionError::BodyFile)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.len() > MAX_HTTP_REQUEST_BODY_BYTES as u64
    {
        return Err(KeptNearExecutionError::BodyFile);
    }
    let file = open_body_file(path)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| KeptNearExecutionError::BodyFile)?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_HTTP_REQUEST_BODY_BYTES as u64 {
        return Err(KeptNearExecutionError::BodyFile);
    }
    let mut body = Vec::with_capacity(opened_metadata.len() as usize);
    file.take((MAX_HTTP_REQUEST_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| KeptNearExecutionError::BodyFile)?;
    if body.len() > MAX_HTTP_REQUEST_BODY_BYTES {
        body.zeroize();
        return Err(KeptNearExecutionError::BodyFile);
    }
    Ok(body)
}

#[cfg(unix)]
fn open_body_file(path: &std::path::Path) -> Result<File, KeptNearExecutionError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| KeptNearExecutionError::BodyFile)
}

#[cfg(not(unix))]
fn open_body_file(path: &std::path::Path) -> Result<File, KeptNearExecutionError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| KeptNearExecutionError::BodyFile)
}

fn write_broker_response(
    response: BrokerResponse,
    writer: &mut impl Write,
) -> Result<(), KeptNearExecutionError> {
    match response {
        BrokerResponse::CredentialSearch(search) => {
            let credential = search
                .credential()
                .map(|credential| SearchCredentialOutput {
                    vault_id: credential.vault_id().to_string(),
                    credential_id: credential.credential_id().to_string(),
                    title: credential.title(),
                    authorized_field: SearchFieldOutput {
                        secret_field_id: credential.secret_field_id().to_string(),
                        role: credential.role(),
                        label: credential.label(),
                        kind: credential.kind().as_str(),
                    },
                });
            write_success(
                writer,
                SearchOutput {
                    operation: "search",
                    credential,
                },
            )
        }
        BrokerResponse::AccessRequest(BrokerAccessResponse::Submission(submission)) => {
            write_access_result(
                writer,
                submission.receipt(),
                submission.coalesced(),
                false,
                None,
            )
        }
        BrokerResponse::GrantStatus(status) => {
            let active_grant = status.active_grant().map(|grant| {
                let field = grant.field_scope();
                ActiveGrantOutput {
                    use_grant_id: grant.use_grant_id().to_string(),
                    vault_id: field.vault_id().to_string(),
                    credential_id: field.credential_id().to_string(),
                    secret_field_id: field.secret_field_id().to_string(),
                    capability: grant.capability().name().as_str(),
                    capability_version: grant.capability().version(),
                    vault_session_id: grant.vault_session_id().to_string(),
                    scope: grant.scope().as_str(),
                    created_at_millis: grant.created_at().unix_millis(),
                    expires_at_millis: grant.expires_at().unix_millis(),
                }
            });
            write_success(
                writer,
                GrantStatusOutput {
                    operation: "grant.status",
                    status: status.status().as_str(),
                    active_grant,
                },
            )
        }
        BrokerResponse::GrantRevoke(revoke) => write_success(
            writer,
            RevokeOutput {
                operation: "revoke",
                revoked: revoke.revoked(),
            },
        ),
        BrokerResponse::HttpRequest(http) => {
            let mut body_base64 = BASE64_STANDARD.encode(http.body());
            let result = write_success(
                writer,
                HttpOutput {
                    operation: "http.request",
                    status_code: http.status_code(),
                    body_base64: &body_base64,
                    truncated: http.truncated(),
                },
            );
            body_base64.zeroize();
            result
        }
        BrokerResponse::ProcessRun(process) => {
            let mut stdout_base64 = BASE64_STANDARD.encode(process.stdout());
            let mut stderr_base64 = BASE64_STANDARD.encode(process.stderr());
            let result = write_success(
                writer,
                ProcessOutput {
                    operation: "run",
                    exit_code: process.exit_code(),
                    terminated_by_signal: process.terminated_by_signal(),
                    stdout_base64: &stdout_base64,
                    stderr_base64: &stderr_base64,
                    stdout_truncated: process.stdout_truncated(),
                    stderr_truncated: process.stderr_truncated(),
                    compatibility_delivery: ProcessCompatibilityOutput {
                        child_and_descendants_may_retain_or_transmit: true,
                        revocation_stops_future_delivery_only: true,
                        upstream_rotation_required_for_invalidation: true,
                    },
                },
            );
            stdout_base64.zeroize();
            stderr_base64.zeroize();
            result
        }
        _ => Err(KeptNearExecutionError::UnexpectedResponse),
    }
}

fn write_access_result(
    writer: &mut impl Write,
    receipt: BrokerAccessReceiptResponse,
    coalesced: bool,
    waited: bool,
    timed_out: Option<bool>,
) -> Result<(), KeptNearExecutionError> {
    write_success(
        writer,
        AccessSubmissionOutput {
            operation: "access.request",
            approval_request_id: receipt.approval_request_id().to_string(),
            status: receipt.status().as_str(),
            expires_at_millis: receipt.expires_at().unix_millis(),
            resolved_at_millis: receipt.resolved_at().map(|value| value.unix_millis()),
            coalesced,
            waited,
            timed_out,
        },
    )
}

fn write_success(
    writer: &mut impl Write,
    result: impl Serialize,
) -> Result<(), KeptNearExecutionError> {
    write_json(
        writer,
        &SuccessEnvelope {
            schema_version: CLI_OUTPUT_SCHEMA_VERSION,
            ok: true,
            result,
        },
    )
    .map_err(|_| KeptNearExecutionError::Output)
}

fn write_json(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuccessEnvelope<T> {
    schema_version: u8,
    ok: bool,
    result: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope<'a> {
    schema_version: u8,
    ok: bool,
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorDetail<'a> {
    code: &'a str,
    retryable: bool,
    required_action: Option<&'a str>,
    approval_request_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusOutput {
    operation: &'static str,
    broker_instance_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingOutput<'a> {
    operation: &'static str,
    status: &'static str,
    pairing_request_id: String,
    comparison_code: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchOutput<'a> {
    operation: &'static str,
    credential: Option<SearchCredentialOutput<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchCredentialOutput<'a> {
    vault_id: String,
    credential_id: String,
    title: &'a str,
    authorized_field: SearchFieldOutput<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchFieldOutput<'a> {
    secret_field_id: String,
    role: &'a str,
    label: Option<&'a str>,
    kind: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessSubmissionOutput {
    operation: &'static str,
    approval_request_id: String,
    status: &'static str,
    expires_at_millis: i64,
    resolved_at_millis: Option<i64>,
    coalesced: bool,
    waited: bool,
    timed_out: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantStatusOutput {
    operation: &'static str,
    status: &'static str,
    active_grant: Option<ActiveGrantOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActiveGrantOutput {
    use_grant_id: String,
    vault_id: String,
    credential_id: String,
    secret_field_id: String,
    capability: &'static str,
    capability_version: u16,
    vault_session_id: String,
    scope: &'static str,
    created_at_millis: i64,
    expires_at_millis: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeOutput {
    operation: &'static str,
    revoked: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpOutput<'a> {
    operation: &'static str,
    status_code: u16,
    body_base64: &'a str,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessOutput<'a> {
    operation: &'static str,
    exit_code: Option<i32>,
    terminated_by_signal: bool,
    stdout_base64: &'a str,
    stderr_base64: &'a str,
    stdout_truncated: bool,
    stderr_truncated: bool,
    compatibility_delivery: ProcessCompatibilityOutput,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessCompatibilityOutput {
    child_and_descendants_may_retain_or_transmit: bool,
    revocation_stops_future_delivery_only: bool,
    upstream_rotation_required_for_invalidation: bool,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsString;

    use psw_broker::{
        decode_broker_response, BrokerInstanceId, BrokerRequestId, PairingComparisonCode,
        PairingRequestId,
    };
    use serde_json::{json, Value};

    use super::*;
    use crate::{parse_keptnear_arguments, KeptNearCliAction};

    struct FakeBroker {
        status: Result<BrokerStatusResponse, BrokerAdapterError>,
        authentication: Result<BrokerAuthenticationStatus, BrokerAdapterError>,
        responses: VecDeque<Result<BrokerResponse, BrokerAdapterError>>,
        status_calls: usize,
        authentication_calls: usize,
        executed_capabilities: Vec<Option<psw_broker::Capability>>,
        executed_requests: Vec<BrokerRequest>,
    }

    impl FakeBroker {
        fn authenticated(response: BrokerResponse) -> Self {
            Self::authenticated_responses([Ok(response)])
        }

        fn authenticated_responses(
            responses: impl IntoIterator<Item = Result<BrokerResponse, BrokerAdapterError>>,
        ) -> Self {
            Self {
                status: Ok(BrokerStatusResponse::new(BrokerInstanceId::generate())),
                authentication: Ok(BrokerAuthenticationStatus::Authenticated),
                responses: responses.into_iter().collect(),
                status_calls: 0,
                authentication_calls: 0,
                executed_capabilities: Vec::new(),
                executed_requests: Vec::new(),
            }
        }
    }

    impl CliBroker for FakeBroker {
        fn status(&mut self) -> Result<BrokerStatusResponse, BrokerAdapterError> {
            self.status_calls += 1;
            self.status
        }

        fn authenticate(&mut self) -> Result<BrokerAuthenticationStatus, BrokerAdapterError> {
            self.authentication_calls += 1;
            self.authentication
        }

        fn execute(
            &mut self,
            request: BrokerRequest,
        ) -> Result<BrokerResponse, BrokerAdapterError> {
            self.executed_capabilities
                .push(request.required_capability());
            self.executed_requests.push(request);
            self.responses
                .pop_front()
                .expect("scripted Broker response")
        }
    }

    fn command(arguments: &[&str]) -> KeptNearCommand {
        let action =
            parse_keptnear_arguments(arguments.iter().map(OsString::from)).expect("parse command");
        let KeptNearCliAction::Invoke(invocation) = action else {
            panic!("expected invocation");
        };
        invocation.into_command()
    }

    fn decoded_response(message_type: &str, result: Value) -> BrokerResponse {
        let payload = serde_json::to_vec(&json!({
            "protocol_name": "keptnear.broker",
            "protocol_major": 1,
            "protocol_minor": 0,
            "message_type": message_type,
            "request_id": BrokerRequestId::generate().to_string(),
            "result": result
        }))
        .expect("response JSON");
        decode_broker_response(&payload)
            .expect("typed response")
            .response()
            .clone()
    }

    fn assert_success_excludes_marker(
        command: KeptNearCommand,
        response: BrokerResponse,
        marker: &str,
    ) {
        let mut broker = FakeBroker::authenticated(response);
        let mut output = Vec::new();
        execute_with_client(command, &mut broker, &mut output).expect("successful command");
        assert!(!String::from_utf8_lossy(&output).contains(marker));
        let value: Value = serde_json::from_slice(&output).expect("versioned output");
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["ok"], true);
    }

    #[test]
    fn completed_outcomes_map_to_stable_cli_exit_statuses() {
        assert_eq!(KeptNearExecutionOutcome::Completed.exit_status(), 0);
        assert_eq!(KeptNearExecutionOutcome::PairingPending.exit_status(), 1);
        for exit_code in [0, 1, 2, 125, 126, 127, 128, 255] {
            assert_eq!(
                KeptNearExecutionOutcome::ProcessCompleted {
                    exit_code: Some(exit_code),
                    terminated_by_signal: false,
                }
                .exit_status(),
                exit_code
            );
        }
        for exit_code in [None, Some(-1), Some(256)] {
            assert_eq!(
                KeptNearExecutionOutcome::ProcessCompleted {
                    exit_code,
                    terminated_by_signal: false,
                }
                .exit_status(),
                1
            );
        }
        assert_eq!(
            KeptNearExecutionOutcome::ProcessCompleted {
                exit_code: Some(0),
                terminated_by_signal: true,
            }
            .exit_status(),
            1
        );
    }

    #[test]
    fn status_uses_only_non_secret_broker_status_without_consumer_authentication() {
        let instance_id = BrokerInstanceId::generate();
        let mut broker = FakeBroker {
            status: Ok(BrokerStatusResponse::new(instance_id)),
            authentication: Err(BrokerAdapterError::Identity),
            responses: VecDeque::new(),
            status_calls: 0,
            authentication_calls: 0,
            executed_capabilities: Vec::new(),
            executed_requests: Vec::new(),
        };
        let mut output = Vec::new();

        assert_eq!(
            execute_with_client(command(&["status"]), &mut broker, &mut output),
            Ok(KeptNearExecutionOutcome::Completed)
        );
        assert_eq!(broker.status_calls, 1);
        assert_eq!(broker.authentication_calls, 0);
        assert!(broker.executed_capabilities.is_empty());
        let value: Value = serde_json::from_slice(&output).expect("output JSON");
        assert_eq!(value["result"]["operation"], "status");
        assert_eq!(value["result"]["brokerInstanceId"], instance_id.to_string());
    }

    #[test]
    fn pending_pairing_writes_only_local_comparison_state_and_skips_dispatch() {
        let request_id = PairingRequestId::generate();
        let comparison_code =
            PairingComparisonCode::from_ascii("0123456789").expect("comparison code");
        let mut broker = FakeBroker {
            status: Ok(BrokerStatusResponse::new(BrokerInstanceId::generate())),
            authentication: Ok(BrokerAuthenticationStatus::PairingPending {
                pairing_request_id: request_id,
                comparison_code,
            }),
            responses: VecDeque::new(),
            status_calls: 0,
            authentication_calls: 0,
            executed_capabilities: Vec::new(),
            executed_requests: Vec::new(),
        };
        let grant = format!("use_grant_{}", "1".repeat(32));
        let mut output = Vec::new();

        assert_eq!(
            execute_with_client(command(&["revoke", &grant]), &mut broker, &mut output),
            Ok(KeptNearExecutionOutcome::PairingPending)
        );
        assert_eq!(broker.authentication_calls, 1);
        assert!(broker.executed_capabilities.is_empty());
        let text = String::from_utf8(output).expect("UTF-8");
        assert!(text.contains(&request_id.to_string()));
        assert!(text.contains(comparison_code.as_str()));
        assert!(!text.contains(&grant));
    }

    #[test]
    fn authenticated_revoke_dispatches_shared_typed_request_and_writes_json() {
        let response = decoded_response("grant.revoke.result", json!({"revoked": true}));
        let mut broker = FakeBroker::authenticated(response);
        let grant = format!("use_grant_{}", "2".repeat(32));
        let mut output = Vec::new();

        assert_eq!(
            execute_with_client(command(&["revoke", &grant]), &mut broker, &mut output),
            Ok(KeptNearExecutionOutcome::Completed)
        );
        assert_eq!(broker.authentication_calls, 1);
        assert_eq!(
            broker.executed_capabilities,
            vec![Some(psw_broker::Capability::v1(
                psw_broker::CapabilityName::GrantRevoke
            ))]
        );
        let value: Value = serde_json::from_slice(&output).expect("output JSON");
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["ok"], true);
        assert_eq!(value["result"]["operation"], "revoke");
        assert_eq!(value["result"]["revoked"], true);
        assert!(!String::from_utf8(output).expect("UTF-8").contains(&grant));
    }

    #[test]
    fn access_request_waits_once_by_default_and_returns_the_terminal_receipt() {
        let approval_request_id = ApprovalRequestId::generate();
        let submission = decoded_response(
            "access.request.result",
            json!({
                "result_kind": "submission",
                "approval_request_id": approval_request_id.to_string(),
                "status": "pending",
                "expires_at_millis": 9_000,
                "resolved_at_millis": null,
                "coalesced": true
            }),
        );
        let wait = decoded_response(
            "access.request.result",
            json!({
                "result_kind": "wait",
                "approval_request_id": approval_request_id.to_string(),
                "status": "approved",
                "expires_at_millis": 9_000,
                "resolved_at_millis": 8_000,
                "timed_out": false
            }),
        );
        let mut broker = FakeBroker::authenticated_responses([Ok(submission), Ok(wait)]);
        let vault = format!("vault_{}", "1".repeat(32));
        let credential = format!("credential_{}", "2".repeat(32));
        let field = format!("secret_field_{}", "3".repeat(32));
        let mut output = Vec::new();

        assert_eq!(
            execute_with_client(
                command(&[
                    "access",
                    "request",
                    "--capability",
                    "http.request",
                    "--vault",
                    &vault,
                    "--credential",
                    &credential,
                    "--field",
                    &field,
                ]),
                &mut broker,
                &mut output,
            ),
            Ok(KeptNearExecutionOutcome::Completed)
        );
        assert_eq!(broker.executed_requests.len(), 2);
        assert!(matches!(
            &broker.executed_requests[0],
            BrokerRequest::AccessRequest(BrokerAccessRequest::Exact { .. })
        ));
        assert!(matches!(
            &broker.executed_requests[1],
            BrokerRequest::AccessRequest(BrokerAccessRequest::Wait {
                approval_request_id: request_id,
                timeout,
            }) if *request_id == approval_request_id && *timeout == MAX_APPROVAL_WAIT
        ));
        let value: Value = serde_json::from_slice(&output).expect("output JSON");
        assert_eq!(
            value["result"]["approvalRequestId"],
            approval_request_id.to_string()
        );
        assert_eq!(value["result"]["status"], "approved");
        assert_eq!(value["result"]["coalesced"], true);
        assert_eq!(value["result"]["waited"], true);
        assert_eq!(value["result"]["timedOut"], false);
    }

    #[test]
    fn access_request_no_wait_returns_the_submission_without_a_second_dispatch() {
        let approval_request_id = ApprovalRequestId::generate();
        let submission = decoded_response(
            "access.request.result",
            json!({
                "result_kind": "submission",
                "approval_request_id": approval_request_id.to_string(),
                "status": "pending",
                "expires_at_millis": 9_000,
                "resolved_at_millis": null,
                "coalesced": false
            }),
        );
        let mut broker = FakeBroker::authenticated(submission);
        let vault = format!("vault_{}", "4".repeat(32));
        let mut output = Vec::new();

        assert_eq!(
            execute_with_client(
                command(&[
                    "access",
                    "request",
                    "--capability",
                    "process.run",
                    "--vault",
                    &vault,
                    "--description",
                    "release credential",
                    "--no-wait",
                ]),
                &mut broker,
                &mut output,
            ),
            Ok(KeptNearExecutionOutcome::Completed)
        );
        assert_eq!(broker.executed_requests.len(), 1);
        let value: Value = serde_json::from_slice(&output).expect("output JSON");
        assert_eq!(value["result"]["status"], "pending");
        assert_eq!(value["result"]["waited"], false);
        assert_eq!(value["result"]["timedOut"], Value::Null);
    }

    #[test]
    fn access_wait_timeout_and_transport_failure_preserve_the_approval_identity() {
        let timed_out_id = ApprovalRequestId::generate();
        let timed_out_submission = decoded_response(
            "access.request.result",
            json!({
                "result_kind": "submission",
                "approval_request_id": timed_out_id.to_string(),
                "status": "pending",
                "expires_at_millis": 9_000,
                "resolved_at_millis": null,
                "coalesced": false
            }),
        );
        let timed_out_wait = decoded_response(
            "access.request.result",
            json!({
                "result_kind": "wait",
                "approval_request_id": timed_out_id.to_string(),
                "status": "pending",
                "expires_at_millis": 9_000,
                "resolved_at_millis": null,
                "timed_out": true
            }),
        );
        let vault = format!("vault_{}", "5".repeat(32));
        let credential = format!("credential_{}", "6".repeat(32));
        let field = format!("secret_field_{}", "7".repeat(32));
        let access_command = || {
            command(&[
                "access",
                "request",
                "--capability",
                "credential.search",
                "--vault",
                &vault,
                "--credential",
                &credential,
                "--field",
                &field,
            ])
        };
        let mut broker =
            FakeBroker::authenticated_responses([Ok(timed_out_submission), Ok(timed_out_wait)]);
        let mut output = Vec::new();
        assert_eq!(
            execute_with_client(access_command(), &mut broker, &mut output),
            Ok(KeptNearExecutionOutcome::Completed)
        );
        let value: Value = serde_json::from_slice(&output).expect("output JSON");
        assert_eq!(value["result"]["status"], "pending");
        assert_eq!(value["result"]["waited"], true);
        assert_eq!(value["result"]["timedOut"], true);

        let failed_id = ApprovalRequestId::generate();
        let failed_submission = decoded_response(
            "access.request.result",
            json!({
                "result_kind": "submission",
                "approval_request_id": failed_id.to_string(),
                "status": "pending",
                "expires_at_millis": 9_000,
                "resolved_at_millis": null,
                "coalesced": false
            }),
        );
        let mut broker = FakeBroker::authenticated_responses([
            Ok(failed_submission),
            Err(BrokerAdapterError::Transport),
        ]);
        let error = execute_with_client(access_command(), &mut broker, &mut Vec::new())
            .expect_err("wait transport must fail");
        assert_eq!(
            error,
            KeptNearExecutionError::ApprovalWait {
                source: BrokerAdapterError::Transport,
                approval_request_id: failed_id,
            }
        );
        let mut error_output = Vec::new();
        error.write_json(&mut error_output).expect("error JSON");
        let value: Value = serde_json::from_slice(&error_output).expect("error output");
        assert_eq!(value["error"]["code"], "broker-unavailable");
        assert_eq!(value["error"]["approvalRequestId"], failed_id.to_string());
    }

    #[test]
    fn every_capability_response_uses_the_closed_versioned_json_envelope() {
        let approval_request_id = psw_broker::ApprovalRequestId::generate();
        let cases = [
            (
                decoded_response("credential.search.result", json!({"credential": null})),
                "search",
            ),
            (
                decoded_response(
                    "access.request.result",
                    json!({
                        "result_kind": "submission",
                        "approval_request_id": approval_request_id.to_string(),
                        "status": "pending",
                        "expires_at_millis": 9_000,
                        "resolved_at_millis": null,
                        "coalesced": false
                    }),
                ),
                "access.request",
            ),
            (
                decoded_response(
                    "grant.status.result",
                    json!({"status": "unavailable", "active_grant": null}),
                ),
                "grant.status",
            ),
            (
                decoded_response("grant.revoke.result", json!({"revoked": false})),
                "revoke",
            ),
            (
                decoded_response(
                    "http.request.result",
                    json!({
                        "status_code": 200,
                        "body_base64": BASE64_STANDARD.encode(b"bounded body"),
                        "truncated": false
                    }),
                ),
                "http.request",
            ),
            (
                decoded_response(
                    "process.run.result",
                    json!({
                        "exit_code": 0,
                        "terminated_by_signal": false,
                        "stdout_base64": BASE64_STANDARD.encode(b"bounded stdout"),
                        "stderr_base64": BASE64_STANDARD.encode(b"bounded stderr"),
                        "stdout_truncated": false,
                        "stderr_truncated": false
                    }),
                ),
                "run",
            ),
        ];

        for (response, operation) in cases {
            let mut output = Vec::new();
            write_broker_response(response, &mut output).expect("CLI response");
            let value: Value = serde_json::from_slice(&output).expect("output JSON");
            assert_eq!(value["schemaVersion"], 1);
            assert_eq!(value["ok"], true);
            assert_eq!(value["result"]["operation"], operation);
            assert_eq!(
                value.as_object().expect("envelope").keys().count(),
                3,
                "top-level output stays closed"
            );
        }
    }

    #[test]
    fn process_run_dispatches_once_and_never_writes_raw_child_stream_bytes() {
        let stdout_marker = "KN_CHILD_STDOUT_PRIVATE_10_4";
        let stderr_marker = "KN_CHILD_STDERR_PRIVATE_10_4";
        let response = decoded_response(
            "process.run.result",
            json!({
                "exit_code": 7,
                "terminated_by_signal": false,
                "stdout_base64": BASE64_STANDARD.encode(stdout_marker),
                "stderr_base64": BASE64_STANDARD.encode(stderr_marker),
                "stdout_truncated": true,
                "stderr_truncated": false
            }),
        );
        let mut broker = FakeBroker::authenticated(response);
        let grant = format!("use_grant_{}", "1".repeat(32));
        let vault = format!("vault_{}", "2".repeat(32));
        let credential = format!("credential_{}", "3".repeat(32));
        let field = format!("secret_field_{}", "4".repeat(32));
        let session = format!("vault_session_{}", "5".repeat(32));
        let profile = format!("usage_profile_{}", "6".repeat(32));
        let mut output = Vec::new();

        assert_eq!(
            execute_with_client(
                command(&[
                    "run",
                    "--grant",
                    &grant,
                    "--vault",
                    &vault,
                    "--credential",
                    &credential,
                    "--field",
                    &field,
                    "--kind",
                    "api-token",
                    "--session",
                    &session,
                    "--usage-profile",
                    &profile,
                    "--",
                    "/usr/bin/example-tool",
                    "--publish",
                ]),
                &mut broker,
                &mut output,
            ),
            Ok(KeptNearExecutionOutcome::ProcessCompleted {
                exit_code: Some(7),
                terminated_by_signal: false,
            })
        );
        assert_eq!(
            broker.executed_capabilities,
            vec![Some(psw_broker::Capability::v1(
                psw_broker::CapabilityName::ProcessRun
            ))]
        );
        assert_eq!(broker.executed_requests.len(), 1);
        let BrokerRequest::ProcessRun(request) = &broker.executed_requests[0] else {
            panic!("expected process.run");
        };
        assert_eq!(request.executable(), "/usr/bin/example-tool");
        assert_eq!(request.arguments(), &["--publish".to_owned()]);

        let text = String::from_utf8(output).expect("UTF-8 JSON");
        assert!(!text.contains(stdout_marker));
        assert!(!text.contains(stderr_marker));
        let value: Value = serde_json::from_str(&text).expect("output JSON");
        assert_eq!(value["result"]["operation"], "run");
        assert_eq!(value["result"]["exitCode"], 7);
        assert_eq!(
            value["result"]["stdoutBase64"],
            BASE64_STANDARD.encode(stdout_marker)
        );
        assert_eq!(
            value["result"]["stderrBase64"],
            BASE64_STANDARD.encode(stderr_marker)
        );
        assert_eq!(value["result"]["stdoutTruncated"], true);
        assert_eq!(value["result"]["stderrTruncated"], false);
        assert_eq!(
            value["result"]["compatibilityDelivery"],
            json!({
                "childAndDescendantsMayRetainOrTransmit": true,
                "revocationStopsFutureDeliveryOnly": true,
                "upstreamRotationRequiredForInvalidation": true
            })
        );
        assert_eq!(
            value["result"]
                .as_object()
                .expect("closed process result")
                .keys()
                .count(),
            8
        );
    }

    #[test]
    fn protocol_failures_and_mismatched_results_are_fixed_and_non_reflective() {
        let marker = "KN_CLI_PROTOCOL_PRIVATE_MARKER_10_7";
        let grant = format!("use_grant_{}", "1".repeat(32));
        let vault = format!("vault_{}", "2".repeat(32));
        let credential = format!("credential_{}", "3".repeat(32));
        let field = format!("secret_field_{}", "4".repeat(32));
        let session = format!("vault_session_{}", "5".repeat(32));
        let search = || {
            command(&[
                "search",
                "--grant",
                &grant,
                "--vault",
                &vault,
                "--credential",
                &credential,
                "--field",
                &field,
                "--kind",
                "api-token",
                "--session",
                &session,
                "--query",
                marker,
            ])
        };

        let cases = [
            (
                FakeBroker::authenticated_responses([Err(BrokerAdapterError::Protocol)]),
                KeptNearExecutionError::Client(BrokerAdapterError::Protocol),
            ),
            (
                FakeBroker::authenticated(decoded_response(
                    "grant.revoke.result",
                    json!({"revoked": false}),
                )),
                KeptNearExecutionError::UnexpectedResponse,
            ),
        ];
        for (mut broker, expected_error) in cases {
            let mut success_output = Vec::new();
            let error = execute_with_client(search(), &mut broker, &mut success_output)
                .expect_err("protocol failure");
            assert_eq!(error, expected_error);
            assert!(success_output.is_empty());

            let mut error_output = Vec::new();
            error.write_json(&mut error_output).expect("fixed error");
            let text = String::from_utf8(error_output).expect("UTF-8");
            assert!(!text.contains(marker));
            let value: Value = serde_json::from_str(&text).expect("error JSON");
            assert_eq!(value["error"]["code"], "adapter-protocol-failure");
        }
    }

    #[test]
    fn private_request_markers_do_not_cross_success_or_error_outputs() {
        let marker = "KN_CLI_PRIVATE_REQUEST_MARKER_10_7";
        let grant = format!("use_grant_{}", "1".repeat(32));
        let vault = format!("vault_{}", "2".repeat(32));
        let credential = format!("credential_{}", "3".repeat(32));
        let field = format!("secret_field_{}", "4".repeat(32));
        let session = format!("vault_session_{}", "5".repeat(32));
        let profile = format!("usage_profile_{}", "6".repeat(32));

        assert_success_excludes_marker(
            command(&[
                "search",
                "--grant",
                &grant,
                "--vault",
                &vault,
                "--credential",
                &credential,
                "--field",
                &field,
                "--kind",
                "api-token",
                "--session",
                &session,
                "--query",
                marker,
            ]),
            decoded_response("credential.search.result", json!({"credential": null})),
            marker,
        );

        let approval_request_id = ApprovalRequestId::generate();
        assert_success_excludes_marker(
            command(&[
                "access",
                "request",
                "--capability",
                "http.request",
                "--vault",
                &vault,
                "--description",
                marker,
                "--no-wait",
            ]),
            decoded_response(
                "access.request.result",
                json!({
                    "result_kind": "submission",
                    "approval_request_id": approval_request_id.to_string(),
                    "status": "pending",
                    "expires_at_millis": 9_000,
                    "resolved_at_millis": null,
                    "coalesced": false
                }),
            ),
            marker,
        );

        let body_root = std::env::temp_dir().join(format!(
            "keptnear-cli-marker-{}",
            BrokerRequestId::generate()
        ));
        std::fs::create_dir(&body_root).expect("body root");
        let body_path = body_root.join(marker);
        std::fs::write(&body_path, marker.as_bytes()).expect("body marker");
        let body_path = body_path.to_str().expect("UTF-8 body path");
        let header = format!("X-Request-Marker:{marker}");
        let url = format!("https://example.invalid/{marker}");
        assert_success_excludes_marker(
            command(&[
                "http",
                "request",
                "--grant",
                &grant,
                "--vault",
                &vault,
                "--credential",
                &credential,
                "--field",
                &field,
                "--kind",
                "api-token",
                "--session",
                &session,
                "--usage-profile",
                &profile,
                "--method",
                "POST",
                "--url",
                &url,
                "--header",
                &header,
                "--body-file",
                body_path,
            ]),
            decoded_response(
                "http.request.result",
                json!({
                    "status_code": 204,
                    "body_base64": "",
                    "truncated": false
                }),
            ),
            marker,
        );
        std::fs::remove_dir_all(&body_root).expect("remove body root");

        let working_directory = format!("/private/{marker}");
        let environment = format!("KN_TEST_VALUE={marker}");
        assert_success_excludes_marker(
            command(&[
                "run",
                "--grant",
                &grant,
                "--vault",
                &vault,
                "--credential",
                &credential,
                "--field",
                &field,
                "--kind",
                "api-token",
                "--session",
                &session,
                "--usage-profile",
                &profile,
                "--working-directory",
                &working_directory,
                "--env",
                &environment,
                "--",
                "/usr/bin/printf",
                marker,
            ]),
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
            marker,
        );

        let mut broker = FakeBroker::authenticated_responses([Err(BrokerAdapterError::Broker {
            error_code: psw_broker::BrokerErrorCode::AccessDenied,
            retryable: false,
            required_action: None,
            approval_request_id: None,
        })]);
        let error = execute_with_client(
            command(&[
                "search",
                "--grant",
                &grant,
                "--vault",
                &vault,
                "--credential",
                &credential,
                "--field",
                &field,
                "--kind",
                "api-token",
                "--session",
                &session,
                "--query",
                marker,
            ]),
            &mut broker,
            &mut Vec::new(),
        )
        .expect_err("Broker rejection");
        let mut error_output = Vec::new();
        error.write_json(&mut error_output).expect("fixed error");
        assert!(!String::from_utf8_lossy(&error_output).contains(marker));
    }

    #[test]
    fn body_file_reader_rejects_missing_directories_symlinks_and_oversized_files() {
        let root = std::env::temp_dir().join(format!(
            "keptnear-cli-body-test-{}",
            BrokerRequestId::generate()
        ));
        std::fs::create_dir(&root).expect("temporary root");
        let missing = root.join("missing");
        assert_eq!(
            read_body_file(Some(&missing)),
            Err(KeptNearExecutionError::BodyFile)
        );
        assert_eq!(
            read_body_file(Some(&root)),
            Err(KeptNearExecutionError::BodyFile)
        );

        let oversized = root.join("oversized");
        let file = File::create(&oversized).expect("oversized file");
        file.set_len((MAX_HTTP_REQUEST_BODY_BYTES + 1) as u64)
            .expect("oversized length");
        assert_eq!(
            read_body_file(Some(&oversized)),
            Err(KeptNearExecutionError::BodyFile)
        );

        let body_path = root.join("body");
        std::fs::write(&body_path, b"non-secret body").expect("body");
        assert_eq!(
            read_body_file(Some(&body_path)).expect("body read"),
            b"non-secret body"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = root.join("body-link");
            symlink(&body_path, &link).expect("body symlink");
            assert_eq!(
                read_body_file(Some(&link)),
                Err(KeptNearExecutionError::BodyFile)
            );
        }

        std::fs::remove_dir_all(&root).expect("remove temporary root");
    }

    #[test]
    fn public_errors_are_fixed_and_do_not_reflect_private_input() {
        let marker = "private-error-marker";
        let errors = [
            KeptNearExecutionError::Client(BrokerAdapterError::Identity),
            KeptNearExecutionError::Client(BrokerAdapterError::Transport),
            KeptNearExecutionError::Client(BrokerAdapterError::Protocol),
            KeptNearExecutionError::ApprovalWait {
                source: BrokerAdapterError::Transport,
                approval_request_id: ApprovalRequestId::generate(),
            },
            KeptNearExecutionError::BodyFile,
            KeptNearExecutionError::InvalidRequest,
            KeptNearExecutionError::UnexpectedResponse,
            KeptNearExecutionError::UnsupportedPlatform,
        ];
        for error in errors {
            let mut output = Vec::new();
            error.write_json(&mut output).expect("error JSON");
            let text = String::from_utf8(output).expect("UTF-8");
            assert!(!text.contains(marker));
            let value: Value = serde_json::from_str(&text).expect("error output");
            assert_eq!(value["schemaVersion"], 1);
            assert_eq!(value["ok"], false);
            assert!(value["error"]["code"].is_string());
        }
    }
}
