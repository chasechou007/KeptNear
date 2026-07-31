use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::{Debug, Display, Formatter};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use psw_broker::{
    BrokerAccessRequest, BrokerCredentialOperationTarget, BrokerCredentialSearchRequest,
    BrokerGrantRevokeRequest, BrokerGrantStatusRequest, BrokerHttpCapabilityHeader,
    BrokerHttpCapabilityRequest, BrokerHttpMethod, BrokerProcessCapabilityEnvironment,
    BrokerProcessCapabilityRequest, Capability, CapabilityName, CredentialFieldScope,
    UsageProfileId,
};
use zeroize::Zeroize;

const DEFAULT_PROCESS_TIMEOUT_MILLIS: u64 = 30_000;
const MAX_CLI_PROFILE_ID_BYTES: usize = 64;

/// Stable help text for the public KeptNear machine-use command tree.
pub const KEPTNEAR_HELP: &str = "\
KeptNear local credential CLI

Usage:
  keptnear vault doctor [--json] <vault-path>
  keptnear [--profile <id>] status
  keptnear [--profile <id>] search <target-options> [--query <text>]
  keptnear [--profile <id>] access request --capability <name> --vault <id> (--credential <id> --field <id> | --description <text>) [--no-wait]
  keptnear [--profile <id>] grant status <use-grant-id>
  keptnear [--profile <id>] revoke <use-grant-id>
  keptnear [--profile <id>] http request <target-options> --usage-profile <id> --method <method> --url <https-url> [--header <non-secret-name:value>] [--body-file <path>]
  keptnear [--profile <id>] run <target-options> --usage-profile <id> [--working-directory <path>] [--env <non-secret-name=value>] [--timeout-ms <ms>] -- <absolute-executable> [arg...]
  keptnear help
  keptnear --version

Target options:
  --grant <use-grant-id>
  --vault <vault-id>
  --credential <credential-id>
  --field <secret-field-id>
  --kind <secret-kind>
  --session <vault-session-id>

Access capabilities:
  credential.search | http.request | process.run

Secret kinds:
  password | api-token | api-key | totp-seed | private-key | certificate | generic-secret

Local vault diagnostics:
  vault doctor inspects local vault structure without unlocking or decrypting records.
  It reports only format readiness, aggregate encrypted-record counts, and local unlock-envelope presence.
  It does not use a pairing profile, access the Consumer Keychain, contact the Broker, or contact a sync provider.

Credential output boundary:
  KeptNear never returns a selected credential field as a CLI result.
  There is no raw-value get, reveal, copy, print, dump, or vault-wide plaintext output command.
  Credential placeholders and command substitutions are never expanded, and no command interpreter is inserted.
  Use http request or run so the Broker places one approved field without returning that field.
  Complete plaintext export is available only from the interactive KeptNear app.

Compatibility delivery:
  keptnear run never expands the approved credential into the executable, arguments, or KeptNear standard output.
  The Usage Profile places it through child environment, secret-only standard input, or descriptor 3.
  The child and its descendants may read, retain, transform, or transmit the delivered credential.
  Revoking access or unpairing stops only future KeptNear delivery.
  Rotate the credential with its provider to invalidate a delivered copy.
  Child output is bounded, exact-echo-redacted by the Broker, and base64-encoded; base64 is not encryption.

Exit status and cancellation:
  Completed non-run commands exit 0; KeptNear failures and pending pairing exit 1; invalid arguments exit 2.
  run writes its JSON result, then propagates a numeric child exit code from 0 through 255.
  Signal termination, a missing numeric child status, or an out-of-range status maps to 1 and remains described in JSON.
  Ctrl-C uses native terminal interruption (normally observed by a POSIX shell as 130) and closes the Broker connection.
  The Broker treats that disconnect as cancellation, closes secret input, and kills and reaps the direct child.
  Independently surviving descendants remain outside that cleanup guarantee.
";

/// Canonical local profile selecting one KeptNear CLI Consumer identity.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CliPairingProfileId(String);

impl CliPairingProfileId {
    /// Creates a canonical profile from one bounded path-free identifier.
    pub fn new(value: &str) -> Result<Self, CliPairingProfileIdError> {
        if value.is_empty() || value.len() > MAX_CLI_PROFILE_ID_BYTES || !value.is_ascii() {
            return Err(CliPairingProfileIdError);
        }
        let normalized = value.to_ascii_lowercase();
        let bytes = normalized.as_bytes();
        if !bytes[0].is_ascii_alphanumeric()
            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(CliPairingProfileIdError);
        }
        Ok(Self(normalized))
    }

    /// Returns the canonical non-secret local profile identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CliPairingProfileId {
    fn default() -> Self {
        Self("default".to_owned())
    }
}

impl FromStr for CliPairingProfileId {
    type Err = CliPairingProfileIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Debug for CliPairingProfileId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("CliPairingProfileId")
            .field(&"<profile>")
            .finish()
    }
}

/// Sanitized error for an invalid CLI pairing-profile identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliPairingProfileIdError;

impl Display for CliPairingProfileIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeptNear CLI profile identifier is invalid")
    }
}

impl std::error::Error for CliPairingProfileIdError {}

/// One parsed public KeptNear CLI action.
#[derive(Clone, Eq, PartialEq)]
pub enum KeptNearCliAction {
    /// Print stable command help without contacting the Broker.
    Help,
    /// Print the CLI package version without contacting the Broker.
    Version,
    /// Print package compatibility metadata without contacting local state.
    ComponentMetadata,
    /// Inspect one local Vault without unlocking it or contacting the Broker.
    VaultDoctor(CliVaultDoctorInvocation),
    /// Execute one parsed machine-use command through the local Broker.
    Invoke(Box<KeptNearInvocation>),
}

impl Debug for KeptNearCliAction {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Help => formatter.write_str("KeptNearCliAction::Help"),
            Self::Version => formatter.write_str("KeptNearCliAction::Version"),
            Self::ComponentMetadata => formatter.write_str("KeptNearCliAction::ComponentMetadata"),
            Self::VaultDoctor(invocation) => formatter
                .debug_tuple("KeptNearCliAction::VaultDoctor")
                .field(invocation)
                .finish(),
            Self::Invoke(invocation) => formatter
                .debug_tuple("KeptNearCliAction::Invoke")
                .field(invocation)
                .finish(),
        }
    }
}

/// Output format for one local Vault doctor invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliVaultDoctorOutput {
    /// Human-readable local readiness report.
    Text,
    /// Structured local readiness report.
    Json,
}

/// Strict local-only Vault doctor invocation.
#[derive(Clone, Eq, PartialEq)]
pub struct CliVaultDoctorInvocation {
    path: PathBuf,
    output: CliVaultDoctorOutput,
}

impl CliVaultDoctorInvocation {
    /// Returns the local Vault path selected by the user.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the requested report format.
    #[must_use]
    pub const fn output(&self) -> CliVaultDoctorOutput {
        self.output
    }
}

impl Debug for CliVaultDoctorInvocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CliVaultDoctorInvocation")
            .field("path", &"<path>")
            .field("output", &self.output)
            .finish()
    }
}

/// One parsed invocation with its device-local Consumer profile.
#[derive(Clone, Eq, PartialEq)]
pub struct KeptNearInvocation {
    profile: CliPairingProfileId,
    command: KeptNearCommand,
}

impl KeptNearInvocation {
    /// Returns the selected device-local CLI pairing profile.
    #[must_use]
    pub const fn profile(&self) -> &CliPairingProfileId {
        &self.profile
    }

    /// Returns the parsed stable command.
    #[must_use]
    pub const fn command(&self) -> &KeptNearCommand {
        &self.command
    }

    /// Consumes the invocation and returns its command.
    #[must_use]
    pub fn into_command(self) -> KeptNearCommand {
        self.command
    }

    /// Consumes the invocation into its local profile and typed command.
    #[must_use]
    pub fn into_parts(self) -> (CliPairingProfileId, KeptNearCommand) {
        (self.profile, self.command)
    }
}

impl Debug for KeptNearInvocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeptNearInvocation")
            .field("profile", &self.profile)
            .field("command", &self.command)
            .finish()
    }
}

/// Stable public KeptNear machine-use commands.
#[derive(Clone, Eq, PartialEq)]
pub enum KeptNearCommand {
    /// Read non-secret local Broker status.
    Status,
    /// Search minimum metadata for one already authorized Credential field.
    Search(BrokerCredentialSearchRequest),
    /// Submit one exact-field or human-matched access request.
    AccessRequest(CliAccessRequest),
    /// Read Consumer-scoped status for one Use Grant.
    GrantStatus(BrokerGrantStatusRequest),
    /// Revoke one Consumer-owned Use Grant.
    Revoke(BrokerGrantRevokeRequest),
    /// Perform one Brokered HTTPS request.
    HttpRequest(CliHttpRequest),
    /// Launch one explicit child process through Broker compatibility delivery.
    Run(BrokerProcessCapabilityRequest),
}

/// Parsed access request together with its bounded CLI wait behavior.
#[derive(Clone, Eq, PartialEq)]
pub struct CliAccessRequest {
    request: BrokerAccessRequest,
    wait_mode: CliApprovalWaitMode,
}

impl CliAccessRequest {
    /// Returns the typed Broker access request.
    #[must_use]
    pub const fn request(&self) -> &BrokerAccessRequest {
        &self.request
    }

    /// Returns whether the CLI should wait for the asynchronous decision.
    #[must_use]
    pub const fn wait_mode(&self) -> CliApprovalWaitMode {
        self.wait_mode
    }

    /// Consumes the wrapper into the typed request and wait mode.
    #[must_use]
    pub fn into_parts(self) -> (BrokerAccessRequest, CliApprovalWaitMode) {
        (self.request, self.wait_mode)
    }
}

impl Debug for CliAccessRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CliAccessRequest")
            .field("request", &self.request)
            .field("wait_mode", &self.wait_mode)
            .finish()
    }
}

/// Bounded behavior after submitting one asynchronous access request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliApprovalWaitMode {
    /// Wait once through the Broker's maximum bounded approval interval.
    Interactive,
    /// Return the submission receipt immediately.
    NoWait,
}

impl Debug for KeptNearCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Status => "KeptNearCommand::Status",
            Self::Search(_) => "KeptNearCommand::Search(<redacted>)",
            Self::AccessRequest(_) => "KeptNearCommand::AccessRequest(<redacted>)",
            Self::GrantStatus(_) => "KeptNearCommand::GrantStatus(<redacted>)",
            Self::Revoke(_) => "KeptNearCommand::Revoke(<redacted>)",
            Self::HttpRequest(_) => "KeptNearCommand::HttpRequest(<redacted>)",
            Self::Run(_) => "KeptNearCommand::Run(<redacted>)",
        })
    }
}

/// Parsed HTTP request arguments whose body, if any, remains in a local file.
#[derive(Clone, Eq, PartialEq)]
pub struct CliHttpRequest {
    target: BrokerCredentialOperationTarget,
    usage_profile_id: UsageProfileId,
    method: BrokerHttpMethod,
    url: String,
    headers: Vec<BrokerHttpCapabilityHeader>,
    body_file: Option<PathBuf>,
}

impl CliHttpRequest {
    /// Returns the exact authorized field and Use Grant target.
    #[must_use]
    pub const fn target(&self) -> BrokerCredentialOperationTarget {
        self.target
    }

    /// Returns the selected Consumer-owned Usage Profile.
    #[must_use]
    pub const fn usage_profile_id(&self) -> UsageProfileId {
        self.usage_profile_id
    }

    /// Returns the canonical HTTP method.
    #[must_use]
    pub const fn method(&self) -> BrokerHttpMethod {
        self.method
    }

    /// Returns the private HTTPS destination for later Broker validation.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns validated caller-supplied non-secret headers.
    #[must_use]
    pub fn headers(&self) -> &[BrokerHttpCapabilityHeader] {
        &self.headers
    }

    /// Returns the optional local request-body file.
    #[must_use]
    pub fn body_file(&self) -> Option<&Path> {
        self.body_file.as_deref()
    }
}

impl Debug for CliHttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CliHttpRequest")
            .field("target", &self.target)
            .field("usage_profile_id", &self.usage_profile_id)
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("header_count", &self.headers.len())
            .field("body_file", &self.body_file.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for CliHttpRequest {
    fn drop(&mut self) {
        self.url.zeroize();
    }
}

/// Sanitized command-line syntax failure that never reflects submitted values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeptNearCliParseError;

impl Display for KeptNearCliParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid KeptNear command arguments")
    }
}

impl std::error::Error for KeptNearCliParseError {}

/// Parses the stable KeptNear command tree without accessing a Vault or Broker.
pub fn parse_keptnear_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<KeptNearCliAction, KeptNearCliParseError> {
    let mut utf8_arguments = Vec::new();
    for argument in arguments {
        match argument.into_string() {
            Ok(argument) => utf8_arguments.push(argument),
            Err(_) => {
                utf8_arguments.zeroize();
                return Err(KeptNearCliParseError);
            }
        }
    }
    let result = parse_utf8_arguments(&utf8_arguments);
    utf8_arguments.zeroize();
    result
}

fn parse_utf8_arguments(arguments: &[String]) -> Result<KeptNearCliAction, KeptNearCliParseError> {
    if arguments.is_empty() {
        return Ok(KeptNearCliAction::Help);
    }
    if matches!(arguments, [value] if matches!(value.as_str(), "help" | "-h" | "--help")) {
        return Ok(KeptNearCliAction::Help);
    }
    if matches!(arguments, [value] if matches!(value.as_str(), "-V" | "--version")) {
        return Ok(KeptNearCliAction::Version);
    }
    if matches!(arguments, [value] if value == "--component-metadata") {
        return Ok(KeptNearCliAction::ComponentMetadata);
    }
    if arguments.first().map(String::as_str) == Some("vault") {
        return parse_vault_command(&arguments[1..]);
    }

    let (profile, command_arguments) = parse_global_profile(arguments)?;
    let Some((command, arguments)) = command_arguments.split_first() else {
        return Err(KeptNearCliParseError);
    };
    let command = match command.as_str() {
        "status" if arguments.is_empty() => KeptNearCommand::Status,
        "search" => parse_search(arguments)?,
        "access" => parse_access(arguments)?,
        "grant" => parse_grant(arguments)?,
        "revoke" => parse_revoke(arguments)?,
        "http" => parse_http(arguments)?,
        "run" => parse_run(arguments)?,
        _ => return Err(KeptNearCliParseError),
    };
    Ok(KeptNearCliAction::Invoke(Box::new(KeptNearInvocation {
        profile,
        command,
    })))
}

fn parse_vault_command(arguments: &[String]) -> Result<KeptNearCliAction, KeptNearCliParseError> {
    let Some((subcommand, arguments)) = arguments.split_first() else {
        return Err(KeptNearCliParseError);
    };
    if subcommand != "doctor" {
        return Err(KeptNearCliParseError);
    }

    let mut output = CliVaultDoctorOutput::Text;
    let mut path = None;
    for argument in arguments {
        if argument == "--json" {
            if output == CliVaultDoctorOutput::Json {
                return Err(KeptNearCliParseError);
            }
            output = CliVaultDoctorOutput::Json;
        } else if argument.is_empty() || argument.starts_with('-') || path.is_some() {
            return Err(KeptNearCliParseError);
        } else {
            path = Some(PathBuf::from(argument));
        }
    }

    Ok(KeptNearCliAction::VaultDoctor(CliVaultDoctorInvocation {
        path: path.ok_or(KeptNearCliParseError)?,
        output,
    }))
}

fn parse_global_profile(
    arguments: &[String],
) -> Result<(CliPairingProfileId, &[String]), KeptNearCliParseError> {
    let Some(first) = arguments.first() else {
        return Err(KeptNearCliParseError);
    };
    if first == "--profile" {
        let profile = arguments
            .get(1)
            .ok_or(KeptNearCliParseError)?
            .parse()
            .map_err(|_| KeptNearCliParseError)?;
        return Ok((profile, &arguments[2..]));
    }
    if let Some(value) = first.strip_prefix("--profile=") {
        let profile = value.parse().map_err(|_| KeptNearCliParseError)?;
        return Ok((profile, &arguments[1..]));
    }
    Ok((CliPairingProfileId::default(), arguments))
}

fn parse_search(arguments: &[String]) -> Result<KeptNearCommand, KeptNearCliParseError> {
    let options = ParsedOptions::parse(
        arguments,
        &[
            "grant",
            "vault",
            "credential",
            "field",
            "kind",
            "session",
            "query",
        ],
        &[],
        &[],
    )?;
    let target = parse_operation_target(&options)?;
    let query = options.optional("query").unwrap_or_default().to_owned();
    let request =
        BrokerCredentialSearchRequest::new(target, query).map_err(|_| KeptNearCliParseError)?;
    Ok(KeptNearCommand::Search(request))
}

fn parse_access(arguments: &[String]) -> Result<KeptNearCommand, KeptNearCliParseError> {
    let Some(("request", arguments)) = arguments
        .split_first()
        .map(|(head, tail)| (head.as_str(), tail))
    else {
        return Err(KeptNearCliParseError);
    };
    let options = ParsedOptions::parse(
        arguments,
        &["capability", "vault", "credential", "field", "description"],
        &[],
        &["no-wait"],
    )?;
    let capability = parse_access_capability(options.required("capability")?)?;
    let vault_id = parse_id(options.required("vault")?)?;
    let request = match (
        options.optional("credential"),
        options.optional("field"),
        options.optional("description"),
    ) {
        (Some(credential), Some(field), None) => BrokerAccessRequest::exact(
            CredentialFieldScope::new(vault_id, parse_id(credential)?, parse_id(field)?),
            capability,
        ),
        (None, None, Some(description)) => {
            BrokerAccessRequest::credential(vault_id, capability, description.to_owned())
        }
        _ => return Err(KeptNearCliParseError),
    }
    .map_err(|_| KeptNearCliParseError)?;
    let wait_mode = if options.flag("no-wait") {
        CliApprovalWaitMode::NoWait
    } else {
        CliApprovalWaitMode::Interactive
    };
    Ok(KeptNearCommand::AccessRequest(CliAccessRequest {
        request,
        wait_mode,
    }))
}

fn parse_grant(arguments: &[String]) -> Result<KeptNearCommand, KeptNearCliParseError> {
    let [subcommand, use_grant_id] = arguments else {
        return Err(KeptNearCliParseError);
    };
    if subcommand != "status" {
        return Err(KeptNearCliParseError);
    }
    Ok(KeptNearCommand::GrantStatus(BrokerGrantStatusRequest::new(
        parse_id(use_grant_id)?,
    )))
}

fn parse_revoke(arguments: &[String]) -> Result<KeptNearCommand, KeptNearCliParseError> {
    let [use_grant_id] = arguments else {
        return Err(KeptNearCliParseError);
    };
    Ok(KeptNearCommand::Revoke(BrokerGrantRevokeRequest::new(
        parse_id(use_grant_id)?,
    )))
}

fn parse_http(arguments: &[String]) -> Result<KeptNearCommand, KeptNearCliParseError> {
    let Some(("request", arguments)) = arguments
        .split_first()
        .map(|(head, tail)| (head.as_str(), tail))
    else {
        return Err(KeptNearCliParseError);
    };
    let options = ParsedOptions::parse(
        arguments,
        &[
            "grant",
            "vault",
            "credential",
            "field",
            "kind",
            "session",
            "usage-profile",
            "method",
            "url",
            "header",
            "body-file",
        ],
        &["header"],
        &[],
    )?;
    let method = parse_http_method(options.required("method")?)?;
    let headers = options
        .all("header")
        .iter()
        .map(|header| parse_http_header(header))
        .collect::<Result<Vec<_>, _>>()?;
    let body_file = options
        .optional("body-file")
        .map(|path| {
            if path.is_empty() {
                Err(KeptNearCliParseError)
            } else {
                Ok(PathBuf::from(path))
            }
        })
        .transpose()?;
    let target = parse_operation_target(&options)?;
    let usage_profile_id = parse_id(options.required("usage-profile")?)?;
    let url = options.required("url")?.to_owned();
    BrokerHttpCapabilityRequest::new(
        target,
        usage_profile_id,
        method,
        url.clone(),
        headers.clone(),
        Vec::new(),
    )
    .map_err(|_| KeptNearCliParseError)?;
    Ok(KeptNearCommand::HttpRequest(CliHttpRequest {
        target,
        usage_profile_id,
        method,
        url,
        headers,
        body_file,
    }))
}

fn parse_run(arguments: &[String]) -> Result<KeptNearCommand, KeptNearCliParseError> {
    let separator = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or(KeptNearCliParseError)?;
    let option_arguments = &arguments[..separator];
    let child_arguments = &arguments[separator + 1..];
    let Some((executable, child_arguments)) = child_arguments.split_first() else {
        return Err(KeptNearCliParseError);
    };
    let options = ParsedOptions::parse(
        option_arguments,
        &[
            "grant",
            "vault",
            "credential",
            "field",
            "kind",
            "session",
            "usage-profile",
            "working-directory",
            "env",
            "timeout-ms",
        ],
        &["env"],
        &[],
    )?;
    let environment = options
        .all("env")
        .iter()
        .map(|entry| parse_process_environment(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let timeout_millis = options
        .optional("timeout-ms")
        .map(|value| value.parse().map_err(|_| KeptNearCliParseError))
        .transpose()?
        .unwrap_or(DEFAULT_PROCESS_TIMEOUT_MILLIS);
    let request = BrokerProcessCapabilityRequest::new(
        parse_operation_target(&options)?,
        parse_id(options.required("usage-profile")?)?,
        executable.to_owned(),
        child_arguments.to_vec(),
        options.optional("working-directory").map(str::to_owned),
        environment,
        timeout_millis,
    )
    .map_err(|_| KeptNearCliParseError)?;
    Ok(KeptNearCommand::Run(request))
}

fn parse_operation_target(
    options: &ParsedOptions,
) -> Result<BrokerCredentialOperationTarget, KeptNearCliParseError> {
    Ok(BrokerCredentialOperationTarget::new(
        parse_id(options.required("grant")?)?,
        CredentialFieldScope::new(
            parse_id(options.required("vault")?)?,
            parse_id(options.required("credential")?)?,
            parse_id(options.required("field")?)?,
        ),
        parse_id(options.required("kind")?)?,
        parse_id(options.required("session")?)?,
    ))
}

fn parse_access_capability(value: &str) -> Result<Capability, KeptNearCliParseError> {
    let name = CapabilityName::from_str(value).map_err(|_| KeptNearCliParseError)?;
    if !matches!(
        name,
        CapabilityName::CredentialSearch | CapabilityName::HttpRequest | CapabilityName::ProcessRun
    ) {
        return Err(KeptNearCliParseError);
    }
    Ok(Capability::v1(name))
}

fn parse_http_method(value: &str) -> Result<BrokerHttpMethod, KeptNearCliParseError> {
    match value.to_ascii_uppercase().as_str() {
        "GET" => Ok(BrokerHttpMethod::Get),
        "HEAD" => Ok(BrokerHttpMethod::Head),
        "POST" => Ok(BrokerHttpMethod::Post),
        "PUT" => Ok(BrokerHttpMethod::Put),
        "PATCH" => Ok(BrokerHttpMethod::Patch),
        "DELETE" => Ok(BrokerHttpMethod::Delete),
        _ => Err(KeptNearCliParseError),
    }
}

fn parse_http_header(value: &str) -> Result<BrokerHttpCapabilityHeader, KeptNearCliParseError> {
    let (name, value) = value.split_once(':').ok_or(KeptNearCliParseError)?;
    BrokerHttpCapabilityHeader::new(name.trim().to_owned(), value.trim_start().to_owned())
        .map_err(|_| KeptNearCliParseError)
}

fn parse_process_environment(
    value: &str,
) -> Result<BrokerProcessCapabilityEnvironment, KeptNearCliParseError> {
    let (name, value) = value.split_once('=').ok_or(KeptNearCliParseError)?;
    BrokerProcessCapabilityEnvironment::new(name.to_owned(), value.to_owned())
        .map_err(|_| KeptNearCliParseError)
}

fn parse_id<T>(value: &str) -> Result<T, KeptNearCliParseError>
where
    T: FromStr,
{
    value.parse().map_err(|_| KeptNearCliParseError)
}

struct ParsedOptions {
    values: BTreeMap<String, Vec<String>>,
    flags: BTreeSet<String>,
}

impl ParsedOptions {
    fn parse(
        arguments: &[String],
        allowed: &[&str],
        repeatable: &[&str],
        allowed_flags: &[&str],
    ) -> Result<Self, KeptNearCliParseError> {
        let mut values = BTreeMap::<String, Vec<String>>::new();
        let mut flags = BTreeSet::<String>::new();
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            let option = argument
                .strip_prefix("--")
                .filter(|option| !option.is_empty())
                .ok_or(KeptNearCliParseError)?;
            let (name, inline_value) = option
                .split_once('=')
                .map_or((option, None), |(name, value)| (name, Some(value)));
            if allowed_flags.contains(&name) {
                if inline_value.is_some() || !flags.insert(name.to_owned()) {
                    return Err(KeptNearCliParseError);
                }
                index += 1;
                continue;
            }
            if !allowed.contains(&name) {
                return Err(KeptNearCliParseError);
            }
            let value = if let Some(value) = inline_value {
                value.to_owned()
            } else {
                index += 1;
                let value = arguments.get(index).ok_or(KeptNearCliParseError)?;
                if value == "--" || value.starts_with("--") {
                    return Err(KeptNearCliParseError);
                }
                value.to_owned()
            };
            let entries = values.entry(name.to_owned()).or_default();
            if !entries.is_empty() && !repeatable.contains(&name) {
                return Err(KeptNearCliParseError);
            }
            entries.push(value);
            index += 1;
        }
        Ok(Self { values, flags })
    }

    fn required(&self, name: &str) -> Result<&str, KeptNearCliParseError> {
        self.optional(name).ok_or(KeptNearCliParseError)
    }

    fn optional(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn all(&self, name: &str) -> &[String] {
        self.values.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}

impl Drop for ParsedOptions {
    fn drop(&mut self) {
        for values in self.values.values_mut() {
            values.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<KeptNearCliAction, KeptNearCliParseError> {
        parse_keptnear_arguments(arguments.iter().map(OsString::from))
    }

    fn invocation(action: KeptNearCliAction) -> KeptNearInvocation {
        let KeptNearCliAction::Invoke(invocation) = action else {
            panic!("expected invocation");
        };
        *invocation
    }

    fn stable_id(prefix: &str, digit: char) -> String {
        format!("{prefix}{}", digit.to_string().repeat(32))
    }

    fn target_arguments() -> Vec<String> {
        vec![
            "--grant".to_owned(),
            stable_id("use_grant_", '1'),
            "--vault".to_owned(),
            stable_id("vault_", '2'),
            "--credential".to_owned(),
            stable_id("credential_", '3'),
            "--field".to_owned(),
            stable_id("secret_field_", '4'),
            "--kind".to_owned(),
            "api-token".to_owned(),
            "--session".to_owned(),
            stable_id("vault_session_", '5'),
        ]
    }

    fn run_arguments(executable: &str, child_arguments: &[&str]) -> Vec<String> {
        let mut arguments = vec!["run".to_owned()];
        arguments.extend(target_arguments());
        arguments.extend([
            "--usage-profile".to_owned(),
            stable_id("usage_profile_", '6'),
            "--".to_owned(),
            executable.to_owned(),
        ]);
        arguments.extend(
            child_arguments
                .iter()
                .map(|argument| (*argument).to_owned()),
        );
        arguments
    }

    #[test]
    fn help_and_version_are_local_actions_with_a_closed_command_catalog() {
        assert_eq!(parse(&[]), Ok(KeptNearCliAction::Help));
        assert_eq!(parse(&["help"]), Ok(KeptNearCliAction::Help));
        assert_eq!(parse(&["--version"]), Ok(KeptNearCliAction::Version));
        assert_eq!(
            parse(&["--component-metadata"]),
            Ok(KeptNearCliAction::ComponentMetadata)
        );
        assert!(KEPTNEAR_HELP.contains("vault doctor"));
        for command in [
            "status",
            "search",
            "access request",
            "grant status",
            "revoke",
            "http request",
            "run",
        ] {
            assert!(KEPTNEAR_HELP.contains(command));
        }
        assert!(!KEPTNEAR_HELP.contains("secret.get"));
        assert!(!KEPTNEAR_HELP.contains("\n  keptnear get"));
        assert!(!KEPTNEAR_HELP.contains("\n  keptnear export"));
        assert!(!KEPTNEAR_HELP.contains("\n  keptnear shell"));
        assert!(KEPTNEAR_HELP.contains("--no-wait"));
        for boundary in [
            "Local vault diagnostics:",
            "without unlocking or decrypting records",
            "does not use a pairing profile, access the Consumer Keychain, contact the Broker, or contact a sync provider",
            "Credential output boundary:",
            "never returns a selected credential field as a CLI result",
            "no raw-value get, reveal, copy, print, dump, or vault-wide plaintext output command",
            "placeholders and command substitutions are never expanded",
            "Complete plaintext export is available only from the interactive KeptNear app",
        ] {
            assert!(KEPTNEAR_HELP.contains(boundary), "{boundary}");
        }
        for disclosure in [
            "Compatibility delivery:",
            "never expands the approved credential into the executable, arguments, or KeptNear standard output",
            "child and its descendants may read, retain, transform, or transmit",
            "Revoking access or unpairing stops only future KeptNear delivery",
            "Rotate the credential with its provider to invalidate a delivered copy",
            "base64 is not encryption",
        ] {
            assert!(KEPTNEAR_HELP.contains(disclosure), "{disclosure}");
        }
    }

    #[test]
    fn vault_doctor_is_a_strict_local_action_outside_pairing_profiles() {
        let marker = "/private/KN_DOCTOR_PATH_10_6.pswvault";
        let action = parse(&["vault", "doctor", "--json", marker]).expect("vault doctor");
        let KeptNearCliAction::VaultDoctor(invocation) = action else {
            panic!("expected Vault doctor");
        };
        assert_eq!(invocation.path(), Path::new(marker));
        assert_eq!(invocation.output(), CliVaultDoctorOutput::Json);
        assert!(!format!("{invocation:?}").contains(marker));

        for arguments in [
            vec!["vault", "doctor"],
            vec!["vault", "doctor", "--json", "--json", marker],
            vec!["vault", "doctor", "--unknown", marker],
            vec!["vault", "doctor", marker, "second-path"],
            vec!["vault", "export", marker],
            vec!["doctor", marker],
            vec!["--profile", "automation", "vault", "doctor", marker],
        ] {
            let error = parse(&arguments).expect_err("invalid local diagnostic command");
            let rendered = format!("{error:?} {error}");
            assert_eq!(error.to_string(), "invalid KeptNear command arguments");
            assert!(!rendered.contains(marker));
        }
    }

    #[test]
    fn status_uses_default_or_canonical_explicit_profile() {
        let default = invocation(parse(&["status"]).expect("default status"));
        assert_eq!(default.profile().as_str(), "default");
        assert!(matches!(default.command(), KeptNearCommand::Status));

        let explicit =
            invocation(parse(&["--profile=Release.Automation", "status"]).expect("profile status"));
        assert_eq!(explicit.profile().as_str(), "release.automation");
        assert!(!format!("{explicit:?}").contains("release.automation"));
    }

    #[test]
    fn profile_ids_are_bounded_canonical_and_debug_redacted() {
        assert_eq!(
            CliPairingProfileId::new("Release_Profile.1")
                .expect("profile")
                .as_str(),
            "release_profile.1"
        );
        for invalid in ["", "-release", "release-", "../release", "release/profile"] {
            assert_eq!(
                CliPairingProfileId::new(invalid),
                Err(CliPairingProfileIdError)
            );
        }
        assert_eq!(
            CliPairingProfileId::new(&"a".repeat(MAX_CLI_PROFILE_ID_BYTES + 1)),
            Err(CliPairingProfileIdError)
        );
        assert!(!format!("{:?}", CliPairingProfileId::default()).contains("default"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_arguments_fail_without_reflection() {
        use std::os::unix::ffi::OsStringExt;

        let error = parse_keptnear_arguments([
            OsString::from("status"),
            OsString::from_vec(vec![b'p', b'r', 0xff, b'v']),
        ])
        .expect_err("non-UTF-8 must fail");
        assert_eq!(error.to_string(), "invalid KeptNear command arguments");
    }

    #[test]
    fn search_parses_one_exact_operation_target_and_optional_query() {
        let mut arguments = vec!["search".to_owned()];
        arguments.extend(target_arguments());
        arguments.extend(["--query".to_owned(), "release account".to_owned()]);
        let action =
            parse_keptnear_arguments(arguments.into_iter().map(OsString::from)).expect("search");
        let KeptNearCommand::Search(request) = invocation(action).into_command() else {
            panic!("expected search");
        };
        assert_eq!(
            request.target().use_grant_id().to_string(),
            stable_id("use_grant_", '1')
        );
        let expected =
            BrokerCredentialSearchRequest::new(request.target(), "release account".to_owned())
                .expect("expected");
        assert_eq!(request, expected);
    }

    #[test]
    fn access_request_supports_exact_and_human_matched_forms() {
        let exact = invocation(
            parse(&[
                "access",
                "request",
                "--capability",
                "http.request",
                "--vault",
                &stable_id("vault_", '1'),
                "--credential",
                &stable_id("credential_", '2'),
                "--field",
                &stable_id("secret_field_", '3'),
            ])
            .expect("exact access"),
        );
        let KeptNearCommand::AccessRequest(exact) = exact.into_command() else {
            panic!("expected exact request");
        };
        assert_eq!(exact.wait_mode(), CliApprovalWaitMode::Interactive);
        let BrokerAccessRequest::Exact {
            field_scope,
            capability,
        } = exact.request()
        else {
            panic!("expected exact request");
        };
        assert_eq!(field_scope.vault_id().to_string(), stable_id("vault_", '1'));
        assert_eq!(capability.name(), CapabilityName::HttpRequest);

        let matched = invocation(
            parse(&[
                "access",
                "request",
                "--capability",
                "process.run",
                "--vault",
                &stable_id("vault_", '4'),
                "--description",
                "release credential",
                "--no-wait",
            ])
            .expect("matched access"),
        );
        let KeptNearCommand::AccessRequest(matched) = matched.into_command() else {
            panic!("expected matched request");
        };
        assert_eq!(matched.wait_mode(), CliApprovalWaitMode::NoWait);
        assert!(matches!(
            matched.request(),
            BrokerAccessRequest::Credential { .. }
        ));
    }

    #[test]
    fn access_no_wait_is_a_unique_valueless_flag() {
        let base = [
            "access",
            "request",
            "--capability",
            "http.request",
            "--vault",
            "vault_11111111111111111111111111111111",
            "--credential",
            "credential_22222222222222222222222222222222",
            "--field",
            "secret_field_33333333333333333333333333333333",
        ];
        let mut duplicate = base.to_vec();
        duplicate.extend(["--no-wait", "--no-wait"]);
        assert_eq!(parse(&duplicate), Err(KeptNearCliParseError));

        let mut assigned = base.to_vec();
        assigned.push("--no-wait=true");
        assert_eq!(parse(&assigned), Err(KeptNearCliParseError));
    }

    #[test]
    fn grant_status_and_revoke_accept_only_canonical_grant_ids() {
        let grant_id = stable_id("use_grant_", '6');
        let status = invocation(parse(&["grant", "status", &grant_id]).expect("grant status"));
        let KeptNearCommand::GrantStatus(request) = status.into_command() else {
            panic!("expected status");
        };
        assert_eq!(request.use_grant_id().to_string(), grant_id);

        let revoke = invocation(parse(&["revoke", &grant_id]).expect("revoke"));
        let KeptNearCommand::Revoke(request) = revoke.into_command() else {
            panic!("expected revoke");
        };
        assert_eq!(request.use_grant_id().to_string(), grant_id);
    }

    #[test]
    fn http_request_parses_validated_headers_and_keeps_body_path_private() {
        let mut arguments = vec!["http".to_owned(), "request".to_owned()];
        arguments.extend(target_arguments());
        arguments.extend([
            "--usage-profile".to_owned(),
            stable_id("usage_profile_", '6'),
            "--method".to_owned(),
            "post".to_owned(),
            "--url".to_owned(),
            "https://api.example.test/releases".to_owned(),
            "--header".to_owned(),
            "Accept: application/json".to_owned(),
            "--body-file".to_owned(),
            "/private/request.json".to_owned(),
        ]);
        let action = parse_keptnear_arguments(arguments.into_iter().map(OsString::from))
            .expect("http request");
        let KeptNearCommand::HttpRequest(request) = invocation(action).into_command() else {
            panic!("expected HTTP request");
        };
        assert_eq!(request.method(), BrokerHttpMethod::Post);
        assert_eq!(request.headers().len(), 1);
        assert_eq!(
            request.body_file(),
            Some(Path::new("/private/request.json"))
        );
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("api.example.test"));
        assert!(!rendered.contains("/private/request.json"));
    }

    #[test]
    fn run_requires_an_explicit_separator_and_validates_direct_child_input() {
        let mut arguments = vec!["run".to_owned()];
        arguments.extend(target_arguments());
        arguments.extend([
            "--usage-profile".to_owned(),
            stable_id("usage_profile_", '6'),
            "--working-directory".to_owned(),
            "/private/work".to_owned(),
            "--env".to_owned(),
            "MODE=release".to_owned(),
            "--timeout-ms".to_owned(),
            "45000".to_owned(),
            "--".to_owned(),
            "/usr/bin/example-tool".to_owned(),
            "--publish".to_owned(),
        ]);
        let action =
            parse_keptnear_arguments(arguments.into_iter().map(OsString::from)).expect("run");
        let KeptNearCommand::Run(request) = invocation(action).into_command() else {
            panic!("expected run");
        };
        assert_eq!(request.executable(), "/usr/bin/example-tool");
        assert_eq!(request.arguments(), &["--publish".to_owned()]);
        assert_eq!(request.timeout_millis(), 45_000);
        assert_eq!(request.environment().len(), 1);
        assert_eq!(request.environment()[0].name(), "MODE");
        assert_eq!(request.environment()[0].value(), "release");
    }

    #[test]
    fn invalid_unknown_and_malformed_commands_fail_closed() {
        let marker = "private-command-marker";
        for arguments in [
            vec!["status", marker],
            vec!["--profile", "../unsafe", "status"],
            vec!["grant", "status", "not-an-id"],
            vec!["revoke"],
            vec!["run", "--", "/bin/sh"],
        ] {
            let error = parse(&arguments).expect_err("must reject");
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(marker));
            assert_eq!(error.to_string(), "invalid KeptNear command arguments");
        }
    }

    #[test]
    fn raw_secret_and_whole_vault_output_commands_fail_before_dispatch() {
        let marker = "KN_RAW_OUTPUT_REQUEST_10_5";
        for arguments in [
            vec!["get", marker],
            vec!["secret.get", marker],
            vec!["secret", "get", marker],
            vec!["credential", "get", marker],
            vec!["credential", "reveal", marker],
            vec!["reveal", marker],
            vec!["show", marker],
            vec!["copy", marker],
            vec!["print", marker],
            vec!["dump", marker],
            vec!["export", marker],
            vec!["vault", "export", marker],
            vec!["credential", "export", marker],
            vec!["secret", "export", marker],
            vec!["plaintext", "export", marker],
            vec!["vault", "dump", marker],
            vec!["backup", "--plaintext", marker],
        ] {
            let error = parse(&arguments).expect_err("raw output path must reject");
            let rendered = format!("{error:?} {error}");
            assert_eq!(error.to_string(), "invalid KeptNear command arguments");
            assert!(!rendered.contains(marker));
        }

        let mut search = vec!["search".to_owned()];
        search.extend(target_arguments());
        search.extend(["--include-secret".to_owned(), marker.to_owned()]);
        let mut run = run_arguments("/usr/bin/example-tool", &[]);
        run.splice(
            run.len() - 2..run.len() - 2,
            ["--secret".to_owned(), marker.to_owned()],
        );
        let grant = stable_id("use_grant_", '7');
        let equivalent_options = [
            search,
            run,
            vec![
                "grant".to_owned(),
                "status".to_owned(),
                grant,
                "--show-secret".to_owned(),
                marker.to_owned(),
            ],
        ];
        for arguments in equivalent_options {
            let error = parse_keptnear_arguments(arguments.into_iter().map(OsString::from))
                .expect_err("equivalent raw output option must reject");
            let rendered = format!("{error:?} {error}");
            assert_eq!(error.to_string(), "invalid KeptNear command arguments");
            assert!(!rendered.contains(marker));
        }
    }

    #[test]
    fn run_rejects_interpreters_and_never_expands_argument_text() {
        for executable in [
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "/bin/dash",
            "/bin/ksh",
            "/bin/csh",
            "/bin/tcsh",
            "/usr/local/bin/fish",
            "/usr/bin/env",
        ] {
            let error = parse_keptnear_arguments(
                run_arguments(executable, &["-c", "printenv"])
                    .into_iter()
                    .map(OsString::from),
            )
            .expect_err("interpreter launcher must reject");
            assert_eq!(error.to_string(), "invalid KeptNear command arguments");
        }

        let literal_arguments = [
            "${KEPTNEAR_SECRET}",
            "$(keptnear get credential)",
            "`keptnear get credential`",
            "$KEPTNEAR_SECRET",
            "value; keptnear get credential",
        ];
        let action = parse_keptnear_arguments(
            run_arguments("/usr/bin/example-tool", &literal_arguments)
                .into_iter()
                .map(OsString::from),
        )
        .expect("metacharacters remain literal non-secret child input");
        let KeptNearCommand::Run(request) = invocation(action).into_command() else {
            panic!("expected run");
        };
        assert_eq!(
            request.arguments(),
            &literal_arguments.map(str::to_owned).to_vec()
        );
    }

    #[test]
    fn duplicate_options_and_mixed_access_forms_are_rejected() {
        assert_eq!(
            parse(&["--profile", "one", "--profile", "two", "status"]),
            Err(KeptNearCliParseError)
        );
        assert_eq!(
            parse(&[
                "access",
                "request",
                "--capability",
                "http.request",
                "--vault",
                &stable_id("vault_", '1'),
                "--credential",
                &stable_id("credential_", '2'),
                "--field",
                &stable_id("secret_field_", '3'),
                "--description",
                "ambiguous",
            ]),
            Err(KeptNearCliParseError)
        );
    }

    #[test]
    fn action_debug_excludes_every_private_cli_input_class() {
        let mut arguments = vec![
            "--profile".to_owned(),
            "private-profile".to_owned(),
            "run".to_owned(),
        ];
        arguments.extend(target_arguments());
        arguments.extend([
            "--usage-profile".to_owned(),
            stable_id("usage_profile_", '6'),
            "--working-directory".to_owned(),
            "/private/path-marker".to_owned(),
            "--env".to_owned(),
            "PRIVATE_NAME=private-value-marker".to_owned(),
            "--".to_owned(),
            "/usr/bin/private-executable-marker".to_owned(),
            "private-argument-marker".to_owned(),
        ]);
        let action = parse_keptnear_arguments(arguments.into_iter().map(OsString::from))
            .expect("private run");
        let rendered = format!("{action:?}");
        for marker in [
            "private-profile",
            "private/path-marker",
            "PRIVATE_NAME",
            "private-value-marker",
            "private-executable-marker",
            "private-argument-marker",
        ] {
            assert!(!rendered.contains(marker));
        }
    }
}
