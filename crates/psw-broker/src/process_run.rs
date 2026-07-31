use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::path::{Component, Path};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use nix::fcntl::{fcntl, FcntlArg, OFlag};
#[cfg(unix)]
use nix::unistd::{close, dup2};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use psw_core::SecretBytes;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::BrokerErrorCode;
use crate::state_model::UsagePlacement;

/// Maximum UTF-8 byte length accepted for an absolute executable path.
pub const MAX_PROCESS_EXECUTABLE_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 byte length accepted for an absolute working directory.
pub const MAX_PROCESS_WORKING_DIRECTORY_BYTES: usize = 4 * 1024;
/// Maximum number of non-secret child arguments.
pub const MAX_PROCESS_ARGUMENTS: usize = 128;
/// Maximum aggregate UTF-8 bytes accepted across child arguments.
pub const MAX_PROCESS_ARGUMENT_BYTES: usize = 256 * 1024;
/// Maximum number of explicit non-secret child environment entries.
pub const MAX_PROCESS_ENVIRONMENT_ENTRIES: usize = 64;
/// Maximum UTF-8 byte length accepted for one child environment name.
pub const MAX_PROCESS_ENVIRONMENT_NAME_BYTES: usize = 128;
/// Maximum UTF-8 byte length accepted for one child environment value.
pub const MAX_PROCESS_ENVIRONMENT_VALUE_BYTES: usize = 32 * 1024;
/// Maximum aggregate bytes accepted across child environment names and values.
pub const MAX_PROCESS_ENVIRONMENT_BYTES: usize = 128 * 1024;
/// Maximum secret size delivered to one child process.
pub const MAX_PROCESS_SECRET_BYTES: usize = 1024 * 1024;
/// Maximum bytes returned for each redacted child output stream.
pub const MAX_PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum wall-clock lifetime accepted for one child-process operation.
pub const MAX_PROCESS_RUN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Dedicated descriptor used by `ProcessFileDescriptor` placement.
pub const PROCESS_RUN_FILE_DESCRIPTOR: i32 = 3;

const MAX_PROCESS_ARGUMENT_VALUE_BYTES: usize = 32 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const PROCESS_EXIT_DRAIN_GRACE: Duration = Duration::from_millis(50);
const OUTPUT_READ_BUFFER_BYTES: usize = 16 * 1024;
const OUTPUT_READS_PER_POLL: usize = 8;
const OUTPUT_REDACTION: &[u8] = b"[REDACTED]";

/// One explicit non-secret child environment entry.
pub struct BrokerProcessEnvironment {
    name: String,
    value: String,
}

impl BrokerProcessEnvironment {
    /// Validates one child-only environment entry.
    pub fn new(mut name: String, mut value: String) -> Result<Self, BrokerProcessRunError> {
        if !is_valid_environment_name(&name)
            || value.len() > MAX_PROCESS_ENVIRONMENT_VALUE_BYTES
            || value.as_bytes().contains(&0)
        {
            name.zeroize();
            value.zeroize();
            return Err(BrokerProcessRunError::InvalidRequest);
        }
        Ok(Self { name, value })
    }

    /// Returns the validated environment variable name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the validated non-secret environment value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Debug for BrokerProcessEnvironment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerProcessEnvironment")
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for BrokerProcessEnvironment {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

/// Bounded direct child-process request with no credential value.
pub struct BrokerProcessRunRequest {
    executable: String,
    arguments: Vec<String>,
    working_directory: Option<String>,
    environment: Vec<BrokerProcessEnvironment>,
    timeout: Duration,
}

impl BrokerProcessRunRequest {
    /// Validates direct process inputs before any Use Grant is consumed.
    ///
    /// The executable and working directory must be unambiguous absolute
    /// paths. Version 1 rejects common shell launchers and `/usr/bin/env`;
    /// KeptNear never inserts an interpreter of its own.
    pub fn new(
        mut executable: String,
        mut arguments: Vec<String>,
        mut working_directory: Option<String>,
        environment: Vec<BrokerProcessEnvironment>,
        timeout: Duration,
    ) -> Result<Self, BrokerProcessRunError> {
        let argument_bytes = arguments
            .iter()
            .try_fold(0_usize, |total, argument| total.checked_add(argument.len()));
        let environment_bytes = environment.iter().try_fold(0_usize, |total, entry| {
            total
                .checked_add(entry.name.len())
                .and_then(|total| total.checked_add(entry.value.len()))
        });
        let mut names = HashSet::with_capacity(environment.len());
        let environment_is_unique = environment
            .iter()
            .all(|entry| names.insert(entry.name.as_str()));
        let valid = is_valid_absolute_path(&executable, MAX_PROCESS_EXECUTABLE_BYTES, false)
            && !is_prohibited_launcher(&executable)
            && arguments.len() <= MAX_PROCESS_ARGUMENTS
            && arguments.iter().all(|argument| {
                argument.len() <= MAX_PROCESS_ARGUMENT_VALUE_BYTES
                    && !argument.as_bytes().contains(&0)
            })
            && argument_bytes.is_some_and(|bytes| bytes <= MAX_PROCESS_ARGUMENT_BYTES)
            && working_directory.as_ref().is_none_or(|directory| {
                is_valid_absolute_path(directory, MAX_PROCESS_WORKING_DIRECTORY_BYTES, true)
            })
            && environment.len() <= MAX_PROCESS_ENVIRONMENT_ENTRIES
            && environment_bytes.is_some_and(|bytes| bytes <= MAX_PROCESS_ENVIRONMENT_BYTES)
            && environment_is_unique
            && !timeout.is_zero()
            && timeout <= MAX_PROCESS_RUN_TIMEOUT;
        if !valid {
            executable.zeroize();
            for argument in &mut arguments {
                argument.zeroize();
            }
            if let Some(directory) = working_directory.as_mut() {
                directory.zeroize();
            }
            return Err(BrokerProcessRunError::InvalidRequest);
        }

        Ok(Self {
            executable,
            arguments,
            working_directory,
            environment,
            timeout,
        })
    }

    /// Returns the validated absolute executable path.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Returns the bounded non-secret argument list.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Returns the explicit absolute working directory, if supplied.
    #[must_use]
    pub fn working_directory(&self) -> Option<&str> {
        self.working_directory.as_deref()
    }

    /// Returns the explicit non-secret child environment.
    #[must_use]
    pub fn environment(&self) -> &[BrokerProcessEnvironment] {
        &self.environment
    }

    /// Returns the bounded operation timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    fn contains_exact_secret(&self, secret: &[u8]) -> bool {
        contains_exact(self.executable.as_bytes(), secret)
            || self
                .arguments
                .iter()
                .any(|argument| contains_exact(argument.as_bytes(), secret))
            || self
                .working_directory
                .as_ref()
                .is_some_and(|directory| contains_exact(directory.as_bytes(), secret))
            || self.environment.iter().any(|entry| {
                contains_exact(entry.name.as_bytes(), secret)
                    || contains_exact(entry.value.as_bytes(), secret)
            })
    }
}

impl Debug for BrokerProcessRunRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerProcessRunRequest")
            .field("executable", &"<redacted>")
            .field("argument_count", &self.arguments.len())
            .field(
                "working_directory",
                &self.working_directory.as_ref().map(|_| "<redacted>"),
            )
            .field("environment_count", &self.environment.len())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Drop for BrokerProcessRunRequest {
    fn drop(&mut self) {
        self.executable.zeroize();
        for argument in &mut self.arguments {
            argument.zeroize();
        }
        if let Some(directory) = self.working_directory.as_mut() {
            directory.zeroize();
        }
    }
}

type BrokerProcessRunCancellationProbe = dyn Fn() -> bool + Send + Sync;

/// Cooperative cancellation handle for one child-process operation.
#[derive(Clone)]
pub struct BrokerProcessRunCancellation {
    cancelled: Arc<AtomicBool>,
    external_probe: Option<Arc<BrokerProcessRunCancellationProbe>>,
}

impl BrokerProcessRunCancellation {
    pub(crate) fn with_external_probe(probe: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            external_probe: Some(Arc::new(probe)),
        }
    }

    /// Requests cancellation. The Broker closes secret writers and terminates
    /// the directly launched child when it next observes this state.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self.external_probe.as_ref().is_some_and(|probe| probe())
    }
}

impl Default for BrokerProcessRunCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            external_probe: None,
        }
    }
}

impl Debug for BrokerProcessRunCancellation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerProcessRunCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Bounded child-process result after exact-secret output redaction.
pub struct BrokerProcessRunResponse {
    exit_code: Option<i32>,
    terminated_by_signal: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

impl BrokerProcessRunResponse {
    /// Returns the child exit code, or `None` when no numeric code exists.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Returns whether the platform reported signal-based termination.
    #[must_use]
    pub const fn terminated_by_signal(&self) -> bool {
        self.terminated_by_signal
    }

    /// Returns bounded standard output after exact-secret redaction.
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns bounded standard error after exact-secret redaction.
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Returns whether standard output bytes were omitted.
    #[must_use]
    pub const fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    /// Returns whether standard error bytes were omitted.
    #[must_use]
    pub const fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }
}

impl Debug for BrokerProcessRunResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerProcessRunResponse")
            .field("exit_code", &self.exit_code)
            .field("terminated_by_signal", &self.terminated_by_signal)
            .field("stdout", &"<redacted>")
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr", &"<redacted>")
            .field("stderr_bytes", &self.stderr.len())
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr_truncated", &self.stderr_truncated)
            .finish()
    }
}

impl Drop for BrokerProcessRunResponse {
    fn drop(&mut self) {
        self.stdout.zeroize();
        self.stderr.zeroize();
    }
}

/// Sanitized validation, placement, spawn, or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerProcessRunError {
    /// An executable, argument, directory, environment, size, or timeout is invalid.
    InvalidRequest,
    /// The Usage Profile is not a process placement supported by version 1.
    UnsupportedPlacement,
    /// The exact authorized field is no longer available with the expected kind.
    SecretUnavailable,
    /// The selected secret cannot be represented safely by the placement.
    SecretPlacementInvalid,
    /// This platform does not provide the version 1 process boundary.
    UnsupportedPlatform,
    /// The direct child could not be started.
    SpawnFailed,
    /// The full secret could not be delivered through the selected channel.
    InputDeliveryFailed,
    /// A child output stream could not be captured safely.
    OutputCaptureFailed,
    /// The direct child state could not be observed or reaped.
    WaitFailed,
    /// The bounded child operation exceeded its declared timeout.
    TimedOut,
    /// The caller cancelled the child operation.
    Cancelled,
}

impl BrokerProcessRunError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(self) -> BrokerErrorCode {
        match self {
            Self::InvalidRequest | Self::SecretPlacementInvalid => BrokerErrorCode::InvalidRequest,
            Self::UnsupportedPlacement | Self::UnsupportedPlatform => {
                BrokerErrorCode::UnsupportedCapability
            }
            Self::SecretUnavailable => BrokerErrorCode::AccessDenied,
            Self::SpawnFailed
            | Self::InputDeliveryFailed
            | Self::OutputCaptureFailed
            | Self::WaitFailed
            | Self::TimedOut
            | Self::Cancelled => BrokerErrorCode::OperationFailed,
        }
    }
}

impl Display for BrokerProcessRunError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "child process request is invalid",
            Self::UnsupportedPlacement => "child process secret placement is unsupported",
            Self::SecretUnavailable => "child process credential scope is unavailable",
            Self::SecretPlacementInvalid => "child process credential cannot be placed safely",
            Self::UnsupportedPlatform => "child process execution is unsupported",
            Self::SpawnFailed => "child process could not be started",
            Self::InputDeliveryFailed => "child process input delivery failed",
            Self::OutputCaptureFailed => "child process output capture failed",
            Self::WaitFailed => "child process lifecycle failed",
            Self::TimedOut => "child process operation timed out",
            Self::Cancelled => "child process operation was cancelled",
        })
    }
}

impl std::error::Error for BrokerProcessRunError {}

pub(crate) struct BrokerProcessRunManager;

impl BrokerProcessRunManager {
    pub(crate) fn execute(
        request: &BrokerProcessRunRequest,
        placement: &UsagePlacement,
        secret: &SecretBytes,
        cancellation: &BrokerProcessRunCancellation,
    ) -> Result<BrokerProcessRunResponse, BrokerProcessRunError> {
        let secret = secret.expose();
        if secret.is_empty()
            || secret.len() > MAX_PROCESS_SECRET_BYTES
            || request.contains_exact_secret(secret)
        {
            return Err(BrokerProcessRunError::SecretPlacementInvalid);
        }
        validate_placement(placement)?;
        if cancellation.is_cancelled() {
            return Err(BrokerProcessRunError::Cancelled);
        }

        #[cfg(unix)]
        {
            execute_unix(request, placement, secret, cancellation)
        }
        #[cfg(not(unix))]
        {
            let _ = (request, placement, secret, cancellation);
            Err(BrokerProcessRunError::UnsupportedPlatform)
        }
    }
}

#[cfg(unix)]
fn execute_unix(
    request: &BrokerProcessRunRequest,
    placement: &UsagePlacement,
    secret: &[u8],
    cancellation: &BrokerProcessRunCancellation,
) -> Result<BrokerProcessRunResponse, BrokerProcessRunError> {
    let started_at = Instant::now();
    let mut command = Command::new(&request.executable);
    command
        .args(&request.arguments)
        .current_dir(request.working_directory.as_deref().unwrap_or("/"))
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for entry in &request.environment {
        command.env(&entry.name, &entry.value);
    }

    let mut placement_secret = None;
    let mut input = None;
    match placement {
        UsagePlacement::ProcessEnvironment { variable_name } => {
            if request
                .environment
                .iter()
                .any(|entry| entry.name == *variable_name)
            {
                return Err(BrokerProcessRunError::InvalidRequest);
            }
            let text = std::str::from_utf8(secret)
                .map_err(|_| BrokerProcessRunError::SecretPlacementInvalid)?;
            if text.as_bytes().contains(&0) {
                return Err(BrokerProcessRunError::SecretPlacementInvalid);
            }
            let secret_text = Zeroizing::new(text.to_owned());
            command
                .stdin(Stdio::null())
                .env(variable_name, &*secret_text);
            placement_secret = Some(secret_text);
        }
        UsagePlacement::ProcessStdin { append_newline } => {
            command.stdin(Stdio::piped());
            let mut bytes = Zeroizing::new(secret.to_vec());
            if *append_newline {
                bytes.push(b'\n');
            }
            input = Some(bytes);
        }
        UsagePlacement::ProcessFileDescriptor {
            reference_variable_name,
            render_dev_fd_path,
        } => {
            if reference_variable_name
                .as_ref()
                .is_some_and(|name| request.environment.iter().any(|entry| entry.name == *name))
            {
                return Err(BrokerProcessRunError::InvalidRequest);
            }
            command.stdin(Stdio::piped());
            if let Some(name) = reference_variable_name {
                let reference = if *render_dev_fd_path {
                    format!("/dev/fd/{PROCESS_RUN_FILE_DESCRIPTOR}")
                } else {
                    PROCESS_RUN_FILE_DESCRIPTOR.to_string()
                };
                command.env(name, reference);
            }
            // Command prepares the anonymous stdin pipe before this hook. The
            // child maps only that read end to descriptor 3; the parent keeps
            // the corresponding ChildStdin writer.
            unsafe {
                command.pre_exec(|| {
                    dup2(0, PROCESS_RUN_FILE_DESCRIPTOR).map_err(errno_to_io)?;
                    close(0).map_err(errno_to_io)?;
                    Ok(())
                });
            }
            input = Some(Zeroizing::new(secret.to_vec()));
        }
        UsagePlacement::HttpBearerAuthorization {} | UsagePlacement::HttpHeader { .. } => {
            return Err(BrokerProcessRunError::UnsupportedPlacement);
        }
    }

    let mut child = command
        .spawn()
        .map_err(|_| BrokerProcessRunError::SpawnFailed)?;
    drop(command);
    drop(placement_secret);

    let Some(mut stdout) = child.stdout.take() else {
        return Err(error_after_termination(
            &mut child,
            BrokerProcessRunError::OutputCaptureFailed,
        ));
    };
    let Some(mut stderr) = child.stderr.take() else {
        return Err(error_after_termination(
            &mut child,
            BrokerProcessRunError::OutputCaptureFailed,
        ));
    };
    let mut writer = match input {
        Some(bytes) => {
            let Some(stdin) = child.stdin.take() else {
                return Err(error_after_termination(
                    &mut child,
                    BrokerProcessRunError::InputDeliveryFailed,
                ));
            };
            Some(PendingSecretInput::new(stdin, bytes))
        }
        None => None,
    };

    if set_nonblocking(stdout.as_raw_fd()).is_err()
        || set_nonblocking(stderr.as_raw_fd()).is_err()
        || writer
            .as_ref()
            .is_some_and(|pending| set_nonblocking(pending.raw_fd()).is_err())
    {
        return Err(error_after_termination(
            &mut child,
            BrokerProcessRunError::OutputCaptureFailed,
        ));
    }

    let mut stdout_redactor = StreamingSecretRedactor::new(MAX_PROCESS_OUTPUT_BYTES);
    let mut stderr_redactor = StreamingSecretRedactor::new(MAX_PROCESS_OUTPUT_BYTES);
    let mut child_status = None;
    let mut child_exited_at = None;
    let deadline = started_at
        .checked_add(request.timeout)
        .unwrap_or_else(Instant::now);

    loop {
        if child_status.is_none() && cancellation.is_cancelled() {
            writer.take();
            return Err(error_after_termination(
                &mut child,
                BrokerProcessRunError::Cancelled,
            ));
        }
        if child_status.is_none() && Instant::now() >= deadline {
            writer.take();
            return Err(error_after_termination(
                &mut child,
                BrokerProcessRunError::TimedOut,
            ));
        }

        let mut made_progress = false;
        if let Some(pending) = writer.as_mut() {
            match pending.write_available() {
                Ok(WriteProgress::Pending(progress)) => made_progress |= progress,
                Ok(WriteProgress::Complete) => {
                    writer.take();
                    made_progress = true;
                }
                Err(()) => {
                    writer.take();
                    return Err(error_after_termination(
                        &mut child,
                        BrokerProcessRunError::InputDeliveryFailed,
                    ));
                }
            }
        }

        match drain_output(&mut stdout, &mut stdout_redactor, secret) {
            Ok(progress) => made_progress |= progress,
            Err(error) => {
                writer.take();
                return Err(error_after_termination(&mut child, error));
            }
        }
        match drain_output(&mut stderr, &mut stderr_redactor, secret) {
            Ok(progress) => made_progress |= progress,
            Err(error) => {
                writer.take();
                return Err(error_after_termination(&mut child, error));
            }
        }

        if child_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    child_status = Some(status);
                    child_exited_at = Some(Instant::now());
                    made_progress = true;
                }
                Ok(None) => {}
                Err(_) => {
                    writer.take();
                    return Err(error_after_termination(
                        &mut child,
                        BrokerProcessRunError::WaitFailed,
                    ));
                }
            }
        }

        if child_status.is_some() && writer.is_some() {
            return Err(BrokerProcessRunError::InputDeliveryFailed);
        }
        if child_status.is_some() && stdout_redactor.is_closed() && stderr_redactor.is_closed() {
            break;
        }
        if child_exited_at.is_some_and(|exited_at| exited_at.elapsed() >= PROCESS_EXIT_DRAIN_GRACE)
        {
            if !stdout_redactor.is_closed() {
                stdout_redactor.mark_truncated();
            }
            if !stderr_redactor.is_closed() {
                stderr_redactor.mark_truncated();
            }
            break;
        }
        if !made_progress {
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }

    stdout_redactor.finish(secret);
    stderr_redactor.finish(secret);
    let status = child_status.ok_or(BrokerProcessRunError::WaitFailed)?;
    Ok(build_response(status, stdout_redactor, stderr_redactor))
}

#[cfg(unix)]
fn set_nonblocking(raw_fd: i32) -> Result<(), ()> {
    let current = fcntl(raw_fd, FcntlArg::F_GETFL).map_err(|_| ())?;
    let flags = OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK;
    fcntl(raw_fd, FcntlArg::F_SETFL(flags)).map_err(|_| ())?;
    Ok(())
}

#[cfg(unix)]
fn errno_to_io(errno: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

#[cfg(unix)]
fn terminate_and_reap(child: &mut Child) -> Result<(), ()> {
    match child.try_wait() {
        Ok(Some(_)) => Ok(()),
        Ok(None) | Err(_) => {
            let _ = child.kill();
            child.wait().map(|_| ()).map_err(|_| ())
        }
    }
}

#[cfg(unix)]
fn error_after_termination(
    child: &mut Child,
    original: BrokerProcessRunError,
) -> BrokerProcessRunError {
    if terminate_and_reap(child).is_ok() {
        original
    } else {
        BrokerProcessRunError::WaitFailed
    }
}

#[cfg(unix)]
fn drain_output<R>(
    stream: &mut R,
    redactor: &mut StreamingSecretRedactor,
    secret: &[u8],
) -> Result<bool, BrokerProcessRunError>
where
    R: Read,
{
    if redactor.is_closed() {
        return Ok(false);
    }
    let mut buffer = Zeroizing::new(vec![0_u8; OUTPUT_READ_BUFFER_BYTES]);
    let mut made_progress = false;
    for _ in 0..OUTPUT_READS_PER_POLL {
        match stream.read(&mut buffer) {
            Ok(0) => {
                redactor.close(secret);
                return Ok(true);
            }
            Ok(bytes_read) => {
                redactor.feed(&buffer[..bytes_read], secret);
                buffer[..bytes_read].zeroize();
                made_progress = true;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(made_progress),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BrokerProcessRunError::OutputCaptureFailed),
        }
    }
    Ok(made_progress)
}

#[cfg(unix)]
fn build_response(
    status: ExitStatus,
    mut stdout: StreamingSecretRedactor,
    mut stderr: StreamingSecretRedactor,
) -> BrokerProcessRunResponse {
    let stdout_truncated = stdout.truncated;
    let stderr_truncated = stderr.truncated;
    BrokerProcessRunResponse {
        exit_code: status.code(),
        terminated_by_signal: status.code().is_none(),
        stdout: std::mem::take(&mut *stdout.output),
        stderr: std::mem::take(&mut *stderr.output),
        stdout_truncated,
        stderr_truncated,
    }
}

#[cfg(unix)]
struct PendingSecretInput {
    writer: ChildStdin,
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}

#[cfg(unix)]
impl PendingSecretInput {
    fn new(writer: ChildStdin, bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            writer,
            bytes,
            offset: 0,
        }
    }

    fn raw_fd(&self) -> i32 {
        self.writer.as_raw_fd()
    }

    fn write_available(&mut self) -> Result<WriteProgress, ()> {
        let starting_offset = self.offset;
        while self.offset < self.bytes.len() {
            match self.writer.write(&self.bytes[self.offset..]) {
                Ok(0) => return Err(()),
                Ok(written) => self.offset = self.offset.saturating_add(written),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(WriteProgress::Pending(self.offset != starting_offset));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(()),
            }
        }
        Ok(WriteProgress::Complete)
    }
}

#[cfg(unix)]
enum WriteProgress {
    Pending(bool),
    Complete,
}

struct StreamingSecretRedactor {
    pending: Zeroizing<Vec<u8>>,
    output: Zeroizing<Vec<u8>>,
    limit: usize,
    truncated: bool,
    closed: bool,
}

impl StreamingSecretRedactor {
    fn new(limit: usize) -> Self {
        Self {
            pending: Zeroizing::new(Vec::new()),
            output: Zeroizing::new(Vec::with_capacity(limit.min(16 * 1024))),
            limit,
            truncated: false,
            closed: false,
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn mark_truncated(&mut self) {
        self.truncated = true;
        self.closed = true;
    }

    fn feed(&mut self, bytes: &[u8], secret: &[u8]) {
        debug_assert!(!secret.is_empty());
        self.pending.extend_from_slice(bytes);
        loop {
            if let Some(position) = find_exact(&self.pending, secret) {
                let prefix = Zeroizing::new(self.pending[..position].to_vec());
                self.append(&prefix);
                self.append_redaction();
                self.consume_pending(position.saturating_add(secret.len()));
                continue;
            }
            let retained = secret.len().saturating_sub(1);
            let safe = self.pending.len().saturating_sub(retained);
            if safe > 0 {
                let prefix = Zeroizing::new(self.pending[..safe].to_vec());
                self.append(&prefix);
                self.consume_pending(safe);
            }
            break;
        }
    }

    fn close(&mut self, secret: &[u8]) {
        self.finish(secret);
        self.closed = true;
    }

    fn finish(&mut self, secret: &[u8]) {
        if self.pending.is_empty() {
            return;
        }
        self.feed(&[], secret);
        if !self.pending.is_empty() {
            let remainder = Zeroizing::new(self.pending.to_vec());
            self.append(&remainder);
            self.pending.zeroize();
            self.pending.clear();
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        let available = self.limit.saturating_sub(self.output.len());
        let copied = bytes.len().min(available);
        self.output.extend_from_slice(&bytes[..copied]);
        if copied != bytes.len() {
            self.truncated = true;
        }
    }

    fn append_redaction(&mut self) {
        if self.output.len().saturating_add(OUTPUT_REDACTION.len()) <= self.limit {
            self.output.extend_from_slice(OUTPUT_REDACTION);
            return;
        }
        self.truncated = true;
        if self.limit >= OUTPUT_REDACTION.len() {
            self.output
                .truncate(self.limit.saturating_sub(OUTPUT_REDACTION.len()));
            self.output.extend_from_slice(OUTPUT_REDACTION);
        } else {
            self.output.truncate(self.limit);
        }
    }

    fn consume_pending(&mut self, consumed: usize) {
        let remaining = self.pending.len().saturating_sub(consumed);
        self.pending.copy_within(consumed.., 0);
        self.pending[remaining..].zeroize();
        self.pending.truncate(remaining);
    }
}

fn is_valid_environment_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PROCESS_ENVIRONMENT_NAME_BYTES {
        return false;
    }
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_placement(placement: &UsagePlacement) -> Result<(), BrokerProcessRunError> {
    match placement {
        UsagePlacement::ProcessEnvironment { variable_name } => {
            if is_valid_environment_name(variable_name) {
                Ok(())
            } else {
                Err(BrokerProcessRunError::InvalidRequest)
            }
        }
        UsagePlacement::ProcessStdin { .. } => Ok(()),
        UsagePlacement::ProcessFileDescriptor {
            reference_variable_name,
            ..
        } => {
            if reference_variable_name
                .as_ref()
                .is_none_or(|name| is_valid_environment_name(name))
            {
                Ok(())
            } else {
                Err(BrokerProcessRunError::InvalidRequest)
            }
        }
        UsagePlacement::HttpBearerAuthorization {} | UsagePlacement::HttpHeader { .. } => {
            Err(BrokerProcessRunError::UnsupportedPlacement)
        }
    }
}

fn is_valid_absolute_path(value: &str, limit: usize, allow_root: bool) -> bool {
    if value.is_empty() || value.len() > limit || value.as_bytes().contains(&0) {
        return false;
    }
    let path = Path::new(value);
    if !path.is_absolute() || (!allow_root && path.parent().is_none()) {
        return false;
    }
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn is_prohibited_launcher(executable: &str) -> bool {
    Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "sh" | "bash" | "zsh" | "dash" | "ksh" | "csh" | "tcsh" | "fish" | "env"
            )
        })
}

fn contains_exact(value: &[u8], secret: &[u8]) -> bool {
    value
        .windows(secret.len())
        .any(|candidate| candidate == secret)
}

fn find_exact(value: &[u8], secret: &[u8]) -> Option<usize> {
    value
        .windows(secret.len())
        .position(|candidate| candidate == secret)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn request(
        executable: &str,
        arguments: Vec<String>,
        environment: Vec<BrokerProcessEnvironment>,
        timeout: Duration,
    ) -> BrokerProcessRunRequest {
        BrokerProcessRunRequest::new(executable.to_owned(), arguments, None, environment, timeout)
            .expect("request")
    }

    fn execute(
        request: &BrokerProcessRunRequest,
        placement: &UsagePlacement,
        secret: &[u8],
    ) -> Result<BrokerProcessRunResponse, BrokerProcessRunError> {
        BrokerProcessRunManager::execute(
            request,
            placement,
            &SecretBytes::new(secret.to_vec()),
            &BrokerProcessRunCancellation::default(),
        )
    }

    fn test_child_request(mode: &str, timeout: Duration) -> BrokerProcessRunRequest {
        let executable = std::env::current_exe().expect("test executable");
        let executable = executable.to_str().expect("UTF-8 test executable");
        request(
            executable,
            vec![
                "--exact".to_owned(),
                "process_run::tests::child_output_helper".to_owned(),
                "--nocapture".to_owned(),
            ],
            vec![BrokerProcessEnvironment::new(
                "KEPTNEAR_PROCESS_TEST_CHILD".to_owned(),
                mode.to_owned(),
            )
            .expect("environment")],
            timeout,
        )
    }

    #[test]
    fn request_validation_rejects_relative_paths_shells_duplicates_and_unbounded_inputs() {
        for executable in ["cat", "/bin/sh", "/usr/bin/env", "/bin/../bin/cat"] {
            assert_eq!(
                BrokerProcessRunRequest::new(
                    executable.to_owned(),
                    Vec::new(),
                    None,
                    Vec::new(),
                    Duration::from_secs(1),
                )
                .expect_err("invalid executable"),
                BrokerProcessRunError::InvalidRequest
            );
        }
        let duplicate = vec![
            BrokerProcessEnvironment::new("LANG".to_owned(), "C".to_owned()).expect("env"),
            BrokerProcessEnvironment::new("LANG".to_owned(), "C".to_owned()).expect("env"),
        ];
        assert_eq!(
            BrokerProcessRunRequest::new(
                "/bin/cat".to_owned(),
                Vec::new(),
                None,
                duplicate,
                Duration::from_secs(1),
            )
            .expect_err("duplicate environment"),
            BrokerProcessRunError::InvalidRequest
        );
        assert_eq!(
            BrokerProcessRunRequest::new(
                "/bin/cat".to_owned(),
                Vec::new(),
                None,
                Vec::new(),
                Duration::ZERO,
            )
            .expect_err("zero timeout"),
            BrokerProcessRunError::InvalidRequest
        );
        assert_eq!(
            BrokerProcessEnvironment::new("INVALID-NAME".to_owned(), "value".to_owned())
                .expect_err("invalid variable"),
            BrokerProcessRunError::InvalidRequest
        );
    }

    #[test]
    fn request_and_response_debug_hide_operation_material() {
        let redacted_request = request(
            "/bin/cat",
            vec!["KN_PROCESS_ARGUMENT_MARKER".to_owned()],
            vec![BrokerProcessEnvironment::new(
                "KN_PROCESS_NAME_MARKER".to_owned(),
                "KN_PROCESS_VALUE_MARKER".to_owned(),
            )
            .expect("env")],
            Duration::from_secs(1),
        );
        let debug = format!("{redacted_request:?}");
        for marker in [
            "/bin/cat",
            "KN_PROCESS_ARGUMENT_MARKER",
            "KN_PROCESS_NAME_MARKER",
            "KN_PROCESS_VALUE_MARKER",
        ] {
            assert!(!debug.contains(marker));
        }

        let output_marker = "KN_PROCESS_RESPONSE_OUTPUT_MARKER_88";
        let secret = b"KN_PROCESS_RESPONSE_SECRET_88";
        let response_request = request(
            "/bin/echo",
            vec![output_marker.to_owned()],
            Vec::new(),
            Duration::from_secs(1),
        );
        let response = execute(
            &response_request,
            &UsagePlacement::ProcessEnvironment {
                variable_name: "KEPTNEAR_TOKEN".to_owned(),
            },
            secret,
        )
        .expect("response");
        assert!(response
            .stdout()
            .windows(output_marker.len())
            .any(|value| value == output_marker.as_bytes()));
        let response_debug = format!("{response:?}");
        for marker in [output_marker.as_bytes(), secret] {
            assert!(!response_debug
                .as_bytes()
                .windows(marker.len())
                .any(|value| value == marker));
        }
    }

    #[test]
    fn streaming_redactor_catches_cross_chunk_secret_and_preserves_complete_marker_at_limit() {
        let secret = b"cross-chunk-secret";
        let mut redactor = StreamingSecretRedactor::new(17);
        redactor.feed(b"prefix cross-", secret);
        redactor.feed(b"chunk-secret suffix", secret);
        redactor.close(secret);

        assert_eq!(&*redactor.output, b"prefix [REDACTED]");
        assert!(redactor.truncated);
        assert!(!redactor
            .output
            .windows(secret.len())
            .any(|value| value == secret));
    }

    #[test]
    fn streaming_redactor_removes_exact_echo_at_every_chunk_split() {
        let secret = b"KN_PROCESS_EVERY_SPLIT_SECRET_88";
        for split in 0..=secret.len() {
            let mut redactor = StreamingSecretRedactor::new(1024);
            let mut first = Zeroizing::new(b"prefix ".to_vec());
            first.extend_from_slice(&secret[..split]);
            let mut second = Zeroizing::new(secret[split..].to_vec());
            second.extend_from_slice(b" suffix");

            redactor.feed(&first, secret);
            redactor.feed(&second, secret);
            redactor.close(secret);

            assert_eq!(&*redactor.output, b"prefix [REDACTED] suffix");
            assert!(!redactor.truncated);
            assert!(!redactor
                .output
                .windows(secret.len())
                .any(|value| value == secret));
        }
    }

    #[test]
    fn stdin_and_descriptor_placements_deliver_without_returning_secret() {
        let secret = b"KN_PROCESS_STDIN_SECRET_86";
        let cat = request("/bin/cat", Vec::new(), Vec::new(), Duration::from_secs(2));
        let stdin_response = execute(
            &cat,
            &UsagePlacement::ProcessStdin {
                append_newline: true,
            },
            secret,
        )
        .expect("stdin");
        assert_eq!(stdin_response.exit_code(), Some(0));
        assert_eq!(stdin_response.stdout(), b"[REDACTED]\n");

        for render_dev_fd_path in [false, true] {
            let descriptor_child = test_child_request("descriptor", Duration::from_secs(2));
            let descriptor_response = execute(
                &descriptor_child,
                &UsagePlacement::ProcessFileDescriptor {
                    reference_variable_name: Some("KEPTNEAR_SECRET_FD".to_owned()),
                    render_dev_fd_path,
                },
                secret,
            )
            .expect("descriptor");
            assert_eq!(descriptor_response.exit_code(), Some(0));
            assert!(descriptor_response
                .stdout()
                .windows(OUTPUT_REDACTION.len())
                .any(|value| value == OUTPUT_REDACTION));
            assert!(!descriptor_response
                .stdout()
                .windows(secret.len())
                .any(|value| value == secret));
        }
    }

    #[test]
    fn environment_is_minimal_and_secret_echo_is_redacted() {
        let secret = b"KN_PROCESS_ENV_SECRET_86";
        let print_secret = request(
            "/usr/bin/printenv",
            vec!["KEPTNEAR_TOKEN".to_owned()],
            Vec::new(),
            Duration::from_secs(2),
        );
        let response = execute(
            &print_secret,
            &UsagePlacement::ProcessEnvironment {
                variable_name: "KEPTNEAR_TOKEN".to_owned(),
            },
            secret,
        )
        .expect("environment");
        assert_eq!(response.exit_code(), Some(0));
        assert_eq!(response.stdout(), b"[REDACTED]\n");

        let print_path = request(
            "/usr/bin/printenv",
            vec!["PATH".to_owned()],
            Vec::new(),
            Duration::from_secs(2),
        );
        let response = execute(
            &print_path,
            &UsagePlacement::ProcessEnvironment {
                variable_name: "KEPTNEAR_TOKEN".to_owned(),
            },
            secret,
        )
        .expect("minimal environment");
        assert_ne!(response.exit_code(), Some(0));
        assert!(response.stdout().is_empty());
    }

    #[test]
    fn stdout_and_stderr_are_both_redacted() {
        let secret = b"KN_PROCESS_BOTH_STREAMS_SECRET_86";
        let child = test_child_request("echo", Duration::from_secs(2));
        let response = execute(
            &child,
            &UsagePlacement::ProcessStdin {
                append_newline: false,
            },
            secret,
        )
        .expect("test child");
        assert!(response
            .stdout()
            .windows(OUTPUT_REDACTION.len())
            .any(|value| value == OUTPUT_REDACTION));
        assert!(response
            .stderr()
            .windows(OUTPUT_REDACTION.len())
            .any(|value| value == OUTPUT_REDACTION));
        assert!(!response
            .stdout()
            .windows(secret.len())
            .any(|value| value == secret));
        assert!(!response
            .stderr()
            .windows(secret.len())
            .any(|value| value == secret));
    }

    #[test]
    fn dual_stream_output_is_bounded_and_contains_no_exact_secret() {
        let secret = b"KN_PROCESS_BOUNDED_OUTPUT_SECRET_88";
        let child = test_child_request("bounded-output", Duration::from_secs(5));
        let response = execute(
            &child,
            &UsagePlacement::ProcessStdin {
                append_newline: false,
            },
            secret,
        )
        .expect("bounded output");

        assert_eq!(response.exit_code(), Some(0));
        assert_eq!(response.stdout().len(), MAX_PROCESS_OUTPUT_BYTES);
        assert_eq!(response.stderr().len(), MAX_PROCESS_OUTPUT_BYTES);
        assert!(response.stdout_truncated());
        assert!(response.stderr_truncated());
        for output in [response.stdout(), response.stderr()] {
            assert!(output
                .windows(OUTPUT_REDACTION.len())
                .any(|value| value == OUTPUT_REDACTION));
            assert!(!output.windows(secret.len()).any(|value| value == secret));
        }
    }

    #[test]
    fn child_output_helper() {
        match std::env::var("KEPTNEAR_PROCESS_TEST_CHILD").as_deref() {
            Ok("echo") => {
                let mut input = Zeroizing::new(Vec::new());
                std::io::stdin()
                    .read_to_end(&mut input)
                    .expect("read child input");
                std::io::stdout()
                    .write_all(&input)
                    .expect("write child stdout");
                std::io::stderr()
                    .write_all(&input)
                    .expect("write child stderr");
            }
            Ok("descriptor") => {
                let reference = std::env::var("KEPTNEAR_SECRET_FD").expect("descriptor reference");
                assert!(matches!(reference.as_str(), "3" | "/dev/fd/3"));
                let descriptor_path = if reference == "3" {
                    "/dev/fd/3".to_owned()
                } else {
                    reference
                };
                let mut descriptor = std::fs::File::open(descriptor_path).expect("open descriptor");
                let mut input = Zeroizing::new(Vec::new());
                descriptor.read_to_end(&mut input).expect("read descriptor");
                std::io::stdout()
                    .write_all(&input)
                    .expect("write descriptor stdout");
            }
            Ok("bounded-output") => {
                let mut input = Zeroizing::new(Vec::new());
                std::io::stdin()
                    .read_to_end(&mut input)
                    .expect("read bounded input");
                let filler = [b'x'; OUTPUT_READ_BUFFER_BYTES];
                let repetitions = MAX_PROCESS_OUTPUT_BYTES / OUTPUT_READ_BUFFER_BYTES + 2;
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&input).expect("write bounded stdout");
                for _ in 0..repetitions {
                    stdout.write_all(&filler).expect("fill stdout");
                }
                drop(stdout);
                let mut stderr = std::io::stderr().lock();
                stderr.write_all(&input).expect("write bounded stderr");
                for _ in 0..repetitions {
                    stderr.write_all(&filler).expect("fill stderr");
                }
            }
            Ok("retention") => {
                let retained = std::env::var("KEPTNEAR_RETENTION_SECRET")
                    .expect("retained environment secret");
                assert!(!retained.is_empty());
                let descendant = Command::new("/bin/sleep")
                    .arg("2")
                    .spawn()
                    .expect("spawn retaining descendant");
                drop(descendant);
            }
            Ok("continuous-output") => {
                let chunk = [b'x'; OUTPUT_READ_BUFFER_BYTES];
                let mut stdout = std::io::stdout().lock();
                let mut stderr = std::io::stderr().lock();
                loop {
                    stdout.write_all(&chunk).expect("continuous stdout");
                    stderr.write_all(&chunk).expect("continuous stderr");
                }
            }
            _ => {}
        }
    }

    #[test]
    fn timeout_and_precancel_return_fixed_failures() {
        let sleep = request(
            "/bin/sleep",
            vec!["2".to_owned()],
            Vec::new(),
            Duration::from_millis(20),
        );
        assert_eq!(
            execute(
                &sleep,
                &UsagePlacement::ProcessStdin {
                    append_newline: false,
                },
                b"KN_PROCESS_TIMEOUT_SECRET_86",
            )
            .expect_err("timeout"),
            BrokerProcessRunError::TimedOut
        );

        let cancellation = BrokerProcessRunCancellation::default();
        cancellation.cancel();
        assert_eq!(
            BrokerProcessRunManager::execute(
                &sleep,
                &UsagePlacement::ProcessStdin {
                    append_newline: false,
                },
                &SecretBytes::new(b"KN_PROCESS_CANCEL_SECRET_86".to_vec()),
                &cancellation,
            )
            .expect_err("cancelled"),
            BrokerProcessRunError::Cancelled
        );
    }

    #[test]
    fn live_cancellation_terminates_and_reaps_the_direct_child() {
        let cancellation = BrokerProcessRunCancellation::default();
        let child_cancellation = cancellation.clone();
        let operation = std::thread::spawn(move || {
            let sleep = request(
                "/bin/sleep",
                vec!["2".to_owned()],
                Vec::new(),
                Duration::from_secs(2),
            );
            BrokerProcessRunManager::execute(
                &sleep,
                &UsagePlacement::ProcessStdin {
                    append_newline: false,
                },
                &SecretBytes::new(b"KN_PROCESS_LIVE_CANCEL_SECRET_86".to_vec()),
                &child_cancellation,
            )
        });
        std::thread::sleep(Duration::from_millis(20));
        cancellation.cancel();

        assert_eq!(
            operation
                .join()
                .expect("operation thread")
                .expect_err("cancel"),
            BrokerProcessRunError::Cancelled
        );
    }

    #[test]
    fn continuous_output_cannot_starve_timeout_cleanup() {
        let secret = b"KN_PROCESS_CONTINUOUS_OUTPUT_SECRET_88";
        let child = test_child_request("continuous-output", Duration::from_millis(40));
        let started_at = Instant::now();
        let error = execute(
            &child,
            &UsagePlacement::ProcessEnvironment {
                variable_name: "KEPTNEAR_TOKEN".to_owned(),
            },
            secret,
        )
        .expect_err("timeout");

        assert_eq!(error, BrokerProcessRunError::TimedOut);
        assert!(started_at.elapsed() < Duration::from_secs(1));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered
            .as_bytes()
            .windows(secret.len())
            .any(|value| value == secret));
    }

    #[test]
    fn descendant_retention_does_not_hold_the_completed_operation_open() {
        let secret = b"KN_PROCESS_DESCENDANT_RETENTION_SECRET_88";
        let child = test_child_request("retention", Duration::from_secs(3));
        let started_at = Instant::now();
        let response = execute(
            &child,
            &UsagePlacement::ProcessEnvironment {
                variable_name: "KEPTNEAR_RETENTION_SECRET".to_owned(),
            },
            secret,
        )
        .expect("retaining descendant");

        assert_eq!(response.exit_code(), Some(0));
        assert!(started_at.elapsed() < Duration::from_secs(1));
        assert!(response.stdout_truncated());
        assert!(response.stderr_truncated());
        for output in [response.stdout(), response.stderr()] {
            assert!(!output.windows(secret.len()).any(|value| value == secret));
        }
    }

    #[test]
    fn placement_validation_rejects_collisions_and_unrepresentable_secrets() {
        let environment_collision = request(
            "/bin/cat",
            Vec::new(),
            vec![BrokerProcessEnvironment::new(
                "KEPTNEAR_TOKEN".to_owned(),
                "non-secret-context".to_owned(),
            )
            .expect("environment")],
            Duration::from_secs(1),
        );
        assert_eq!(
            execute(
                &environment_collision,
                &UsagePlacement::ProcessEnvironment {
                    variable_name: "KEPTNEAR_TOKEN".to_owned(),
                },
                b"KN_PROCESS_ENV_COLLISION_SECRET_88",
            )
            .expect_err("environment collision"),
            BrokerProcessRunError::InvalidRequest
        );

        let descriptor_collision = request(
            "/bin/cat",
            Vec::new(),
            vec![BrokerProcessEnvironment::new(
                "KEPTNEAR_SECRET_FD".to_owned(),
                "non-secret-context".to_owned(),
            )
            .expect("environment")],
            Duration::from_secs(1),
        );
        assert_eq!(
            execute(
                &descriptor_collision,
                &UsagePlacement::ProcessFileDescriptor {
                    reference_variable_name: Some("KEPTNEAR_SECRET_FD".to_owned()),
                    render_dev_fd_path: false,
                },
                b"KN_PROCESS_FD_COLLISION_SECRET_88",
            )
            .expect_err("descriptor collision"),
            BrokerProcessRunError::InvalidRequest
        );

        let cat = request("/bin/cat", Vec::new(), Vec::new(), Duration::from_secs(1));
        for invalid_secret in [
            Vec::new(),
            vec![0xff],
            b"contains\0nul".to_vec(),
            vec![b'x'; MAX_PROCESS_SECRET_BYTES + 1],
        ] {
            let error = execute(
                &cat,
                &UsagePlacement::ProcessEnvironment {
                    variable_name: "KEPTNEAR_TOKEN".to_owned(),
                },
                &invalid_secret,
            )
            .expect_err("invalid environment secret");
            assert_eq!(error, BrokerProcessRunError::SecretPlacementInvalid);
        }
        assert_eq!(
            execute(
                &cat,
                &UsagePlacement::HttpBearerAuthorization {},
                b"KN_PROCESS_UNSUPPORTED_PLACEMENT_SECRET_88",
            )
            .expect_err("unsupported placement"),
            BrokerProcessRunError::UnsupportedPlacement
        );
    }

    #[test]
    fn request_cannot_repeat_exact_secret_in_any_nonsecret_input() {
        let secret = b"KN_PROCESS_INPUT_SECRET_88";
        let requests = [
            BrokerProcessRunRequest::new(
                "/tmp/KN_PROCESS_INPUT_SECRET_88/tool".to_owned(),
                Vec::new(),
                None,
                Vec::new(),
                Duration::from_secs(1),
            )
            .expect("executable request"),
            BrokerProcessRunRequest::new(
                "/bin/cat".to_owned(),
                vec!["prefix-KN_PROCESS_INPUT_SECRET_88-suffix".to_owned()],
                None,
                Vec::new(),
                Duration::from_secs(1),
            )
            .expect("argument request"),
            BrokerProcessRunRequest::new(
                "/bin/cat".to_owned(),
                Vec::new(),
                Some("/tmp/KN_PROCESS_INPUT_SECRET_88".to_owned()),
                Vec::new(),
                Duration::from_secs(1),
            )
            .expect("working-directory request"),
            BrokerProcessRunRequest::new(
                "/bin/cat".to_owned(),
                Vec::new(),
                None,
                vec![BrokerProcessEnvironment::new(
                    "KN_PROCESS_INPUT_SECRET_88".to_owned(),
                    "context".to_owned(),
                )
                .expect("environment name")],
                Duration::from_secs(1),
            )
            .expect("environment-name request"),
            BrokerProcessRunRequest::new(
                "/bin/cat".to_owned(),
                Vec::new(),
                None,
                vec![BrokerProcessEnvironment::new(
                    "KEPTNEAR_CONTEXT".to_owned(),
                    "prefix-KN_PROCESS_INPUT_SECRET_88-suffix".to_owned(),
                )
                .expect("environment value")],
                Duration::from_secs(1),
            )
            .expect("environment-value request"),
        ];

        for request in requests {
            assert_eq!(
                execute(
                    &request,
                    &UsagePlacement::ProcessStdin {
                        append_newline: false,
                    },
                    secret,
                )
                .expect_err("secret-bearing process input"),
                BrokerProcessRunError::SecretPlacementInvalid
            );
        }
    }
}
