use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::socket::{
    connect as connect_socket, getsockopt, socket, sockopt::SocketError, AddressFamily, SockFlag,
    SockType, UnixAddr,
};
use nix::unistd::{geteuid, getpeereid};

use crate::macos_peer_evidence::observe_peer;
use crate::{
    serve_routed_broker_connection, BrokerConnectionClass, BrokerConnectionExit,
    BrokerConnectionRouteError, BrokerProcess, BrokerProcessError, BrokerProcessRunCancellation,
    BrokerRuntime, ControllerKeyStore, DevicePaths, HumanControlDispatcher,
    ObservedConsumerIdentity,
};

/// Stable filename of the local Broker socket.
pub const BROKER_SOCKET_FILENAME: &str = "broker-v1.sock";

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;

/// Logical Unix transport entry involved in a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixBrokerTransportEntry {
    /// The private `~/.keptnear/runtime` directory.
    RuntimeDirectory,
    /// The stable Broker socket entry.
    Socket,
    /// One accepted or connected peer stream.
    Peer,
}

impl UnixBrokerTransportEntry {
    fn label(self) -> &'static str {
        match self {
            Self::RuntimeDirectory => "Broker runtime directory",
            Self::Socket => "Broker socket",
            Self::Peer => "Broker peer",
        }
    }
}

/// Sanitized Unix transport operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixBrokerTransportOperation {
    /// Inspect an entry without following symbolic links.
    Inspect,
    /// Probe whether an existing socket has a live listener.
    ProbeExisting,
    /// Remove a verified stale socket.
    RemoveStale,
    /// Bind the stable local socket.
    Bind,
    /// Apply owner-only socket permissions.
    SetPermissions,
    /// Accept one local peer.
    Accept,
    /// Connect to the local Broker.
    Connect,
    /// Read operating-system peer credentials.
    PeerCredentials,
    /// Clone a connected stream for independent framed reads and writes.
    CloneStream,
    /// Configure bounded stream reads and writes.
    SetTimeout,
    /// Select and serve one supported local protocol.
    RouteProtocol,
    /// Shut down a connected peer.
    Shutdown,
    /// Remove the listener's socket during clean shutdown.
    Cleanup,
}

impl UnixBrokerTransportOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::ProbeExisting => "probe",
            Self::RemoveStale => "remove stale",
            Self::Bind => "bind",
            Self::SetPermissions => "set permissions on",
            Self::Accept => "accept",
            Self::Connect => "connect to",
            Self::PeerCredentials => "read credentials for",
            Self::CloneStream => "clone",
            Self::SetTimeout => "set timeout on",
            Self::RouteProtocol => "route protocol for",
            Self::Shutdown => "shut down",
            Self::Cleanup => "clean up",
        }
    }
}

/// Fail-closed local Unix transport error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnixBrokerTransportError {
    /// A filesystem or socket operation failed.
    Io {
        /// Logical entry involved in the failure.
        entry: UnixBrokerTransportEntry,
        /// Sanitized operation that failed.
        operation: UnixBrokerTransportOperation,
        /// Operating-system error category without source text or path.
        kind: io::ErrorKind,
    },
    /// The runtime directory is a symbolic link.
    RuntimeDirectorySymbolicLink,
    /// The runtime entry is not a directory.
    RuntimeEntryNotDirectory,
    /// The socket entry is a symbolic link.
    SocketSymbolicLink,
    /// An existing socket-path entry is not a Unix socket.
    SocketEntryNotSocket,
    /// A runtime or socket entry belongs to another user.
    UnexpectedOwner {
        /// Rejected logical entry.
        entry: UnixBrokerTransportEntry,
    },
    /// A runtime or socket entry exposes broader permissions.
    InsecurePermissions {
        /// Rejected logical entry.
        entry: UnixBrokerTransportEntry,
        /// Observed permission bits.
        mode: u32,
    },
    /// Another listener is already reachable at the stable socket.
    AlreadyRunning,
    /// An accepted or connected peer does not match the current user.
    UnexpectedPeer,
    /// The socket path was replaced while stale cleanup was in progress.
    SocketChanged,
    /// The framed Broker process loop failed for this peer.
    Process {
        /// Sanitized process-loop error.
        source: BrokerProcessError,
    },
}

impl Display for UnixBrokerTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io {
                entry,
                operation,
                kind,
            } => write!(
                formatter,
                "{} {} failed: {kind}",
                operation.label(),
                entry.label()
            ),
            Self::RuntimeDirectorySymbolicLink => {
                formatter.write_str("Broker runtime directory must not be a symbolic link")
            }
            Self::RuntimeEntryNotDirectory => {
                formatter.write_str("Broker runtime entry must be a directory")
            }
            Self::SocketSymbolicLink => {
                formatter.write_str("Broker socket must not be a symbolic link")
            }
            Self::SocketEntryNotSocket => {
                formatter.write_str("Broker socket entry must be a Unix socket")
            }
            Self::UnexpectedOwner { entry } => {
                write!(formatter, "{} has an unexpected owner", entry.label())
            }
            Self::InsecurePermissions { entry, mode } => write!(
                formatter,
                "{} has insecure permissions (mode {mode:04o})",
                entry.label()
            ),
            Self::AlreadyRunning => formatter.write_str("Broker is already running"),
            Self::UnexpectedPeer => {
                formatter.write_str("Broker peer does not match the current user")
            }
            Self::SocketChanged => {
                formatter.write_str("Broker socket changed during stale cleanup")
            }
            Self::Process { source } => Display::fmt(source, formatter),
        }
    }
}

impl std::error::Error for UnixBrokerTransportError {}

impl From<BrokerProcessError> for UnixBrokerTransportError {
    fn from(source: BrokerProcessError) -> Self {
        Self::Process { source }
    }
}

impl From<BrokerConnectionRouteError> for UnixBrokerTransportError {
    fn from(source: BrokerConnectionRouteError) -> Self {
        match source {
            BrokerConnectionRouteError::Consumer(source) => Self::Process { source },
            BrokerConnectionRouteError::InitialFrame
            | BrokerConnectionRouteError::UnknownProtocol
            | BrokerConnectionRouteError::HumanControl(_)
            | BrokerConnectionRouteError::ClockUnavailable => Self::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::RouteProtocol,
                kind: io::ErrorKind::InvalidData,
            },
        }
    }
}

/// Operating-system identity observed for one local socket peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixBrokerPeerIdentity {
    effective_user_id: u32,
    effective_group_id: u32,
    process_id: Option<u32>,
}

impl UnixBrokerPeerIdentity {
    /// Returns the peer's effective user ID.
    #[must_use]
    pub const fn effective_user_id(self) -> u32 {
        self.effective_user_id
    }

    /// Returns the peer's effective group ID.
    #[must_use]
    pub const fn effective_group_id(self) -> u32 {
        self.effective_group_id
    }

    /// Returns the peer process ID from the socket audit token when available.
    #[must_use]
    pub const fn process_id(self) -> Option<u32> {
        self.process_id
    }
}

/// One current-user Unix stream with operating-system-observed peer identity.
pub struct UnixBrokerConnection {
    stream: UnixStream,
    peer_identity: UnixBrokerPeerIdentity,
    observed_identity: ObservedConsumerIdentity,
}

impl UnixBrokerConnection {
    /// Connects to the stable Broker socket after validating local entries.
    pub fn connect(paths: &DevicePaths) -> Result<Self, UnixBrokerTransportError> {
        let expected_user = geteuid().as_raw();
        Self::connect_at(paths.runtime(), expected_user)
    }

    /// Connects to the stable Broker socket within one nonzero local deadline.
    pub fn connect_with_timeout(
        paths: &DevicePaths,
        timeout: Duration,
    ) -> Result<Self, UnixBrokerTransportError> {
        let expected_user = geteuid().as_raw();
        Self::connect_at_with_timeout(paths.runtime(), expected_user, timeout)
    }

    /// Returns the operating-system identity observed for the peer.
    #[must_use]
    pub const fn peer_identity(&self) -> UnixBrokerPeerIdentity {
        self.peer_identity
    }

    /// Returns path-free executable and optional signing evidence for the peer.
    #[must_use]
    pub const fn observed_identity(&self) -> &ObservedConsumerIdentity {
        &self.observed_identity
    }

    /// Applies bounded read and write waits without exposing the raw socket.
    pub fn set_operation_timeout(
        &self,
        timeout: Option<Duration>,
    ) -> Result<(), UnixBrokerTransportError> {
        self.stream
            .set_read_timeout(timeout)
            .and_then(|()| self.stream.set_write_timeout(timeout))
            .map_err(|error| UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::SetTimeout,
                kind: error.kind(),
            })
    }

    /// Serves this accepted peer through the transport-independent process.
    pub fn serve(
        self,
        process: &BrokerProcess,
    ) -> Result<BrokerConnectionExit, UnixBrokerTransportError> {
        let mut reader = self
            .stream
            .try_clone()
            .map_err(|error| UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::CloneStream,
                kind: error.kind(),
            })?;
        let mut writer = self.stream;
        let result = process
            .serve_connection(&mut reader, &mut writer)
            .map_err(UnixBrokerTransportError::from);
        let shutdown = writer.shutdown(Shutdown::Both);
        match (result, shutdown) {
            (Ok(exit), Ok(())) => Ok(exit),
            (Ok(exit), Err(error)) if error.kind() == io::ErrorKind::NotConnected => Ok(exit),
            (Ok(_), Err(error)) => Err(UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::Shutdown,
                kind: error.kind(),
            }),
            (Err(error), _) => Err(error),
        }
    }

    /// Serves this accepted peer through the runtime-aware authenticated dispatcher.
    pub fn serve_runtime(
        self,
        runtime: &BrokerRuntime,
    ) -> Result<BrokerConnectionExit, UnixBrokerTransportError> {
        let observed_identity = self.observed_identity.clone();
        let process_cancellation = process_run_cancellation_for_stream(&self.stream)?;
        let mut reader = self
            .stream
            .try_clone()
            .map_err(|error| UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::CloneStream,
                kind: error.kind(),
            })?;
        let mut writer = self.stream;
        let result = runtime
            .process()
            .serve_runtime_connection_with_process_cancellation(
                runtime,
                &observed_identity,
                &mut reader,
                &mut writer,
                &process_cancellation,
            )
            .map_err(UnixBrokerTransportError::from);
        let shutdown = writer.shutdown(Shutdown::Both);
        match (result, shutdown) {
            (Ok(exit), Ok(())) => Ok(exit),
            (Ok(exit), Err(error)) if error.kind() == io::ErrorKind::NotConnected => Ok(exit),
            (Ok(_), Err(error)) => Err(UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::Shutdown,
                kind: error.kind(),
            }),
            (Err(error), _) => Err(error),
        }
    }

    /// Serves this peer through the explicit source-level protocol router.
    ///
    /// The product entry point does not call this method before activation and
    /// shared controller Keychain acceptance are complete.
    pub fn serve_routed<S>(
        self,
        runtime: &mut BrokerRuntime,
        dispatcher: &HumanControlDispatcher<S>,
    ) -> Result<(BrokerConnectionClass, BrokerConnectionExit), UnixBrokerTransportError>
    where
        S: ControllerKeyStore,
    {
        let observed_identity = self.observed_identity.clone();
        let process_cancellation = process_run_cancellation_for_stream(&self.stream)?;
        let mut reader = self
            .stream
            .try_clone()
            .map_err(|error| UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::CloneStream,
                kind: error.kind(),
            })?;
        let mut writer = self.stream;
        let result = serve_routed_broker_connection(
            runtime,
            dispatcher,
            &observed_identity,
            &mut reader,
            &mut writer,
            &process_cancellation,
        )
        .map_err(UnixBrokerTransportError::from);
        let shutdown = writer.shutdown(Shutdown::Both);
        match (result, shutdown) {
            (Ok(exit), Ok(())) => Ok(exit),
            (Ok(exit), Err(error)) if error.kind() == io::ErrorKind::NotConnected => Ok(exit),
            (Ok(_), Err(error)) => Err(UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::Shutdown,
                kind: error.kind(),
            }),
            (Err(error), _) => Err(error),
        }
    }

    /// Closes both directions of this connection.
    pub fn shutdown(&self) -> Result<(), UnixBrokerTransportError> {
        self.stream
            .shutdown(Shutdown::Both)
            .map_err(|error| UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::Shutdown,
                kind: error.kind(),
            })
    }

    fn connect_at(
        runtime_directory: &Path,
        expected_user: u32,
    ) -> Result<Self, UnixBrokerTransportError> {
        validate_runtime_directory(runtime_directory, expected_user)?;
        let socket_path = runtime_directory.join(BROKER_SOCKET_FILENAME);
        validate_socket_entry(&socket_path, expected_user)?;
        let stream =
            UnixStream::connect(&socket_path).map_err(|error| UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Socket,
                operation: UnixBrokerTransportOperation::Connect,
                kind: error.kind(),
            })?;
        let (peer_identity, observed_identity) = read_peer_identity(&stream)?;
        validate_peer_identity(peer_identity, expected_user)?;
        Ok(Self {
            stream,
            peer_identity,
            observed_identity,
        })
    }

    fn connect_at_with_timeout(
        runtime_directory: &Path,
        expected_user: u32,
        timeout: Duration,
    ) -> Result<Self, UnixBrokerTransportError> {
        validate_runtime_directory(runtime_directory, expected_user)?;
        let socket_path = runtime_directory.join(BROKER_SOCKET_FILENAME);
        validate_socket_entry(&socket_path, expected_user)?;
        let stream = connect_unix_socket_with_timeout(&socket_path, timeout)?;
        let (peer_identity, observed_identity) = read_peer_identity(&stream)?;
        validate_peer_identity(peer_identity, expected_user)?;
        Ok(Self {
            stream,
            peer_identity,
            observed_identity,
        })
    }
}

fn connect_unix_socket_with_timeout(
    socket_path: &Path,
    timeout: Duration,
) -> Result<UnixStream, UnixBrokerTransportError> {
    if timeout.is_zero() {
        return Err(connect_io_error(io::ErrorKind::TimedOut));
    }
    let address = UnixAddr::new(socket_path).map_err(connect_errno_error)?;
    let descriptor = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(connect_errno_error)?;
    fcntl(
        descriptor.as_raw_fd(),
        FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
    )
    .map_err(connect_errno_error)?;
    fcntl(descriptor.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
        .map_err(connect_errno_error)?;
    match connect_socket(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(Errno::EINPROGRESS | Errno::EALREADY | Errno::EWOULDBLOCK) => {
            wait_for_connect(&descriptor, timeout)?;
        }
        Err(error) => return Err(connect_errno_error(error)),
    }
    let stream: UnixStream = descriptor.into();
    stream
        .set_nonblocking(false)
        .map_err(|error| connect_io_error(error.kind()))?;
    Ok(stream)
}

fn wait_for_connect(
    descriptor: &OwnedFd,
    timeout: Duration,
) -> Result<(), UnixBrokerTransportError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| connect_io_error(io::ErrorKind::InvalidInput))?;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(connect_io_error(io::ErrorKind::TimedOut));
        }
        let timeout_millis = poll_timeout_millis(deadline.saturating_duration_since(now));
        let mut descriptors = [PollFd::new(descriptor, PollFlags::POLLOUT)];
        match poll(&mut descriptors, timeout_millis) {
            Ok(0) => return Err(connect_io_error(io::ErrorKind::TimedOut)),
            Ok(_) => {
                let socket_error =
                    getsockopt(descriptor, SocketError).map_err(connect_errno_error)?;
                return if socket_error == 0 {
                    Ok(())
                } else {
                    Err(connect_io_error(
                        io::Error::from_raw_os_error(socket_error).kind(),
                    ))
                };
            }
            Err(Errno::EINTR) => {}
            Err(error) => return Err(connect_errno_error(error)),
        }
    }
}

fn poll_timeout_millis(timeout: Duration) -> i32 {
    let millis = timeout.as_millis().max(1);
    i32::try_from(millis).unwrap_or(i32::MAX)
}

fn connect_errno_error(error: Errno) -> UnixBrokerTransportError {
    connect_io_error(io::Error::from_raw_os_error(error as i32).kind())
}

const fn connect_io_error(kind: io::ErrorKind) -> UnixBrokerTransportError {
    UnixBrokerTransportError::Io {
        entry: UnixBrokerTransportEntry::Socket,
        operation: UnixBrokerTransportOperation::Connect,
        kind,
    }
}

fn process_run_cancellation_for_stream(
    stream: &UnixStream,
) -> Result<BrokerProcessRunCancellation, UnixBrokerTransportError> {
    let monitor = stream
        .try_clone()
        .map_err(|error| UnixBrokerTransportError::Io {
            entry: UnixBrokerTransportEntry::Peer,
            operation: UnixBrokerTransportOperation::CloneStream,
            kind: error.kind(),
        })?;
    Ok(BrokerProcessRunCancellation::with_external_probe(
        move || peer_request_side_closed(&monitor),
    ))
}

fn peer_request_side_closed(stream: &UnixStream) -> bool {
    let mut descriptors = [PollFd::new(stream, PollFlags::POLLIN)];
    match poll(&mut descriptors, 0) {
        Ok(_) => descriptors[0].revents().is_none_or(|events| {
            events.intersects(PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL)
        }),
        Err(Errno::EINTR) => false,
        Err(_) => true,
    }
}

impl Read for UnixBrokerConnection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for UnixBrokerConnection {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Owner-only Unix listener for the local Broker.
pub struct UnixBrokerListener {
    listener: Option<UnixListener>,
    socket_path: PathBuf,
    socket_identity: FileIdentity,
    expected_user: u32,
    cleanup_armed: bool,
}

impl UnixBrokerListener {
    /// Binds the stable Broker socket in the validated runtime directory.
    pub fn bind(paths: &DevicePaths) -> Result<Self, UnixBrokerTransportError> {
        let expected_user = geteuid().as_raw();
        Self::bind_at(paths.runtime(), expected_user)
    }

    /// Returns the full socket path for local client configuration.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accepts one current-user peer and records its operating-system identity.
    pub fn accept(&self) -> Result<UnixBrokerConnection, UnixBrokerTransportError> {
        let listener = self.listener.as_ref().expect("active Unix Broker listener");
        let (stream, _) = listener
            .accept()
            .map_err(|error| UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Peer,
                operation: UnixBrokerTransportOperation::Accept,
                kind: error.kind(),
            })?;
        let (peer_identity, observed_identity) = read_peer_identity(&stream)?;
        validate_peer_identity(peer_identity, self.expected_user)?;
        Ok(UnixBrokerConnection {
            stream,
            peer_identity,
            observed_identity,
        })
    }

    /// Accepts and serves one peer through the Broker process core.
    pub fn serve_one(
        &self,
        process: &BrokerProcess,
    ) -> Result<BrokerConnectionExit, UnixBrokerTransportError> {
        self.accept()?.serve(process)
    }

    /// Accepts and serves one peer through pairing-aware runtime dispatch.
    pub fn serve_one_runtime(
        &self,
        runtime: &BrokerRuntime,
    ) -> Result<BrokerConnectionExit, UnixBrokerTransportError> {
        self.accept()?.serve_runtime(runtime)
    }

    /// Accepts one peer through the explicit source-level protocol router.
    pub fn serve_one_routed<S>(
        &self,
        runtime: &mut BrokerRuntime,
        dispatcher: &HumanControlDispatcher<S>,
    ) -> Result<(BrokerConnectionClass, BrokerConnectionExit), UnixBrokerTransportError>
    where
        S: ControllerKeyStore,
    {
        self.accept()?.serve_routed(runtime, dispatcher)
    }

    /// Closes the listener and removes only its unchanged socket entry.
    pub fn shutdown(mut self) -> Result<(), UnixBrokerTransportError> {
        self.listener.take();
        let result = remove_owned_socket(
            &self.socket_path,
            self.socket_identity,
            self.expected_user,
            UnixBrokerTransportOperation::Cleanup,
        );
        if result.is_ok() {
            self.cleanup_armed = false;
        }
        result
    }

    fn bind_at(
        runtime_directory: &Path,
        expected_user: u32,
    ) -> Result<Self, UnixBrokerTransportError> {
        validate_runtime_directory(runtime_directory, expected_user)?;
        let socket_path = runtime_directory.join(BROKER_SOCKET_FILENAME);
        prepare_socket_path(&socket_path, expected_user)?;

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                return Err(UnixBrokerTransportError::AlreadyRunning);
            }
            Err(error) => {
                return Err(UnixBrokerTransportError::Io {
                    entry: UnixBrokerTransportEntry::Socket,
                    operation: UnixBrokerTransportOperation::Bind,
                    kind: error.kind(),
                });
            }
        };
        let mut incomplete = IncompleteSocket::new(socket_path.clone(), expected_user);

        fs::set_permissions(
            &socket_path,
            fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
        )
        .map_err(|error| UnixBrokerTransportError::Io {
            entry: UnixBrokerTransportEntry::Socket,
            operation: UnixBrokerTransportOperation::SetPermissions,
            kind: error.kind(),
        })?;
        let metadata = validate_socket_entry(&socket_path, expected_user)?;
        let socket_identity = FileIdentity::from_metadata(&metadata);
        incomplete.disarm();

        Ok(Self {
            listener: Some(listener),
            socket_path,
            socket_identity,
            expected_user,
            cleanup_armed: true,
        })
    }
}

impl Drop for UnixBrokerListener {
    fn drop(&mut self) {
        self.listener.take();
        if self.cleanup_armed {
            let _ = remove_owned_socket(
                &self.socket_path,
                self.socket_identity,
                self.expected_user,
                UnixBrokerTransportOperation::Cleanup,
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct IncompleteSocket {
    socket_path: PathBuf,
    expected_user: u32,
    armed: bool,
}

impl IncompleteSocket {
    fn new(socket_path: PathBuf, expected_user: u32) -> Self {
        Self {
            socket_path,
            expected_user,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for IncompleteSocket {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path) {
            if metadata.file_type().is_socket() && metadata.uid() == self.expected_user {
                let _ = fs::remove_file(&self.socket_path);
            }
        }
    }
}

fn validate_runtime_directory(
    runtime_directory: &Path,
    expected_user: u32,
) -> Result<(), UnixBrokerTransportError> {
    let metadata =
        fs::symlink_metadata(runtime_directory).map_err(|error| UnixBrokerTransportError::Io {
            entry: UnixBrokerTransportEntry::RuntimeDirectory,
            operation: UnixBrokerTransportOperation::Inspect,
            kind: error.kind(),
        })?;
    if metadata.file_type().is_symlink() {
        return Err(UnixBrokerTransportError::RuntimeDirectorySymbolicLink);
    }
    if !metadata.is_dir() {
        return Err(UnixBrokerTransportError::RuntimeEntryNotDirectory);
    }
    if metadata.uid() != expected_user {
        return Err(UnixBrokerTransportError::UnexpectedOwner {
            entry: UnixBrokerTransportEntry::RuntimeDirectory,
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode != PRIVATE_DIRECTORY_MODE {
        return Err(UnixBrokerTransportError::InsecurePermissions {
            entry: UnixBrokerTransportEntry::RuntimeDirectory,
            mode,
        });
    }
    Ok(())
}

fn validate_socket_entry(
    socket_path: &Path,
    expected_user: u32,
) -> Result<fs::Metadata, UnixBrokerTransportError> {
    let metadata =
        fs::symlink_metadata(socket_path).map_err(|error| UnixBrokerTransportError::Io {
            entry: UnixBrokerTransportEntry::Socket,
            operation: UnixBrokerTransportOperation::Inspect,
            kind: error.kind(),
        })?;
    if metadata.file_type().is_symlink() {
        return Err(UnixBrokerTransportError::SocketSymbolicLink);
    }
    if !metadata.file_type().is_socket() {
        return Err(UnixBrokerTransportError::SocketEntryNotSocket);
    }
    if metadata.uid() != expected_user {
        return Err(UnixBrokerTransportError::UnexpectedOwner {
            entry: UnixBrokerTransportEntry::Socket,
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode != PRIVATE_SOCKET_MODE {
        return Err(UnixBrokerTransportError::InsecurePermissions {
            entry: UnixBrokerTransportEntry::Socket,
            mode,
        });
    }
    Ok(metadata)
}

fn prepare_socket_path(
    socket_path: &Path,
    expected_user: u32,
) -> Result<(), UnixBrokerTransportError> {
    let metadata = match fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Socket,
                operation: UnixBrokerTransportOperation::Inspect,
                kind: error.kind(),
            });
        }
    };
    validate_socket_metadata(&metadata, expected_user)?;
    let identity = FileIdentity::from_metadata(&metadata);

    match UnixStream::connect(socket_path) {
        Ok(_) => return Err(UnixBrokerTransportError::AlreadyRunning),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(error) => {
            return Err(UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Socket,
                operation: UnixBrokerTransportOperation::ProbeExisting,
                kind: error.kind(),
            });
        }
    }

    remove_owned_socket(
        socket_path,
        identity,
        expected_user,
        UnixBrokerTransportOperation::RemoveStale,
    )
}

fn validate_socket_metadata(
    metadata: &fs::Metadata,
    expected_user: u32,
) -> Result<(), UnixBrokerTransportError> {
    if metadata.file_type().is_symlink() {
        return Err(UnixBrokerTransportError::SocketSymbolicLink);
    }
    if !metadata.file_type().is_socket() {
        return Err(UnixBrokerTransportError::SocketEntryNotSocket);
    }
    if metadata.uid() != expected_user {
        return Err(UnixBrokerTransportError::UnexpectedOwner {
            entry: UnixBrokerTransportEntry::Socket,
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode != PRIVATE_SOCKET_MODE {
        return Err(UnixBrokerTransportError::InsecurePermissions {
            entry: UnixBrokerTransportEntry::Socket,
            mode,
        });
    }
    Ok(())
}

fn remove_owned_socket(
    socket_path: &Path,
    expected_identity: FileIdentity,
    expected_user: u32,
    operation: UnixBrokerTransportOperation,
) -> Result<(), UnixBrokerTransportError> {
    let metadata = match fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(UnixBrokerTransportError::Io {
                entry: UnixBrokerTransportEntry::Socket,
                operation,
                kind: error.kind(),
            });
        }
    };
    validate_socket_metadata(&metadata, expected_user)?;
    if FileIdentity::from_metadata(&metadata) != expected_identity {
        return Err(UnixBrokerTransportError::SocketChanged);
    }
    fs::remove_file(socket_path).map_err(|error| UnixBrokerTransportError::Io {
        entry: UnixBrokerTransportEntry::Socket,
        operation,
        kind: error.kind(),
    })
}

fn read_peer_identity(
    stream: &UnixStream,
) -> Result<(UnixBrokerPeerIdentity, ObservedConsumerIdentity), UnixBrokerTransportError> {
    let (effective_user, effective_group) =
        getpeereid(stream.as_raw_fd()).map_err(|_| UnixBrokerTransportError::Io {
            entry: UnixBrokerTransportEntry::Peer,
            operation: UnixBrokerTransportOperation::PeerCredentials,
            kind: io::ErrorKind::Other,
        })?;
    let effective_user_id = effective_user.as_raw();
    let observation = observe_peer(stream.as_raw_fd(), effective_user_id);
    Ok((
        UnixBrokerPeerIdentity {
            effective_user_id,
            effective_group_id: effective_group.as_raw(),
            process_id: observation.process_id,
        },
        observation.identity,
    ))
}

fn validate_peer_identity(
    peer_identity: UnixBrokerPeerIdentity,
    expected_user: u32,
) -> Result<(), UnixBrokerTransportError> {
    if peer_identity.effective_user_id != expected_user {
        return Err(UnixBrokerTransportError::UnexpectedPeer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use psw_core::SecretBytes;

    use crate::process_run::BrokerProcessRunManager;
    use crate::{
        decode_broker_response, encode_broker_request, read_broker_frame, write_broker_frame,
        BrokerHelloRequest, BrokerProcessRunError, BrokerProcessRunRequest, BrokerProtocolVersion,
        BrokerProtocolVersionRange, BrokerRequest, BrokerRequestEnvelope, BrokerRequestId,
        BrokerResponse, UsagePlacement,
    };

    use super::*;

    struct TestRuntime {
        root: PathBuf,
        runtime: PathBuf,
        owner: u32,
    }

    impl TestRuntime {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let root = PathBuf::from("target/kn-ut")
                .join(format!("kn-ut-{label}-{}-{unique}", std::process::id()));
            let runtime = root.join("runtime");
            fs::create_dir_all(&runtime).expect("runtime");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("runtime mode");
            let owner = fs::symlink_metadata(&runtime).expect("metadata").uid();
            Self {
                root,
                runtime,
                owner,
            }
        }

        fn socket_path(&self) -> PathBuf {
            self.runtime.join(BROKER_SOCKET_FILENAME)
        }
    }

    impl Drop for TestRuntime {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn hello_request() -> BrokerRequestEnvelope {
        BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Hello(
                BrokerHelloRequest::new(
                    vec![BrokerProtocolVersionRange::new(1, 0, 0).expect("range")],
                    vec![],
                )
                .expect("hello"),
            ),
        )
    }

    fn framed_request(request: &BrokerRequestEnvelope) -> Vec<u8> {
        let payload = encode_broker_request(request).expect("encode");
        let mut frame = Vec::new();
        write_broker_frame(&mut frame, &payload).expect("frame");
        frame
    }

    fn expect_transport_error<T>(
        result: Result<T, UnixBrokerTransportError>,
        context: &str,
    ) -> UnixBrokerTransportError {
        match result {
            Ok(_) => panic!("{context}: expected transport error"),
            Err(error) => error,
        }
    }

    #[test]
    fn listener_creates_owner_only_socket_and_cleans_it_on_shutdown() {
        let test = TestRuntime::new("mode");
        let listener = UnixBrokerListener::bind_at(&test.runtime, test.owner).expect("bind");
        let metadata = fs::symlink_metadata(listener.socket_path()).expect("socket");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), test.owner);
        assert_eq!(metadata.mode() & 0o777, PRIVATE_SOCKET_MODE);

        listener.shutdown().expect("shutdown");
        assert!(!test.socket_path().exists());
    }

    #[test]
    fn listener_refuses_active_instance_and_recovers_verified_stale_socket() {
        let active_test = TestRuntime::new("active");
        let active =
            UnixBrokerListener::bind_at(&active_test.runtime, active_test.owner).expect("bind");
        assert!(matches!(
            UnixBrokerListener::bind_at(&active_test.runtime, active_test.owner),
            Err(UnixBrokerTransportError::AlreadyRunning)
        ));
        drop(active);

        let stale_test = TestRuntime::new("stale");
        let stale = UnixListener::bind(stale_test.socket_path()).expect("stale listener");
        fs::set_permissions(
            stale_test.socket_path(),
            fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
        )
        .expect("socket mode");
        drop(stale);
        let replacement =
            UnixBrokerListener::bind_at(&stale_test.runtime, stale_test.owner).expect("replace");
        assert!(replacement.socket_path().exists());
    }

    #[test]
    fn listener_rejects_unsafe_runtime_and_socket_entries_without_paths_in_errors() {
        let mode_test = TestRuntime::new("runtime-mode");
        fs::set_permissions(&mode_test.runtime, fs::Permissions::from_mode(0o750))
            .expect("loosen runtime");
        let error = expect_transport_error(
            UnixBrokerListener::bind_at(&mode_test.runtime, mode_test.owner),
            "runtime mode",
        );
        assert_eq!(
            error,
            UnixBrokerTransportError::InsecurePermissions {
                entry: UnixBrokerTransportEntry::RuntimeDirectory,
                mode: 0o750,
            }
        );
        assert!(!error
            .to_string()
            .contains(mode_test.runtime.to_string_lossy().as_ref()));

        let owner_test = TestRuntime::new("runtime-owner");
        assert_eq!(
            expect_transport_error(
                UnixBrokerListener::bind_at(&owner_test.runtime, owner_test.owner.wrapping_add(1),),
                "runtime owner",
            ),
            UnixBrokerTransportError::UnexpectedOwner {
                entry: UnixBrokerTransportEntry::RuntimeDirectory,
            }
        );

        let runtime_file_test = TestRuntime::new("runtime-file");
        let runtime_file = runtime_file_test.root.join("runtime-file");
        fs::write(&runtime_file, b"not a directory").expect("runtime file");
        assert_eq!(
            expect_transport_error(
                UnixBrokerListener::bind_at(&runtime_file, runtime_file_test.owner),
                "runtime file",
            ),
            UnixBrokerTransportError::RuntimeEntryNotDirectory
        );

        let runtime_link_test = TestRuntime::new("runtime-link");
        let runtime_link = runtime_link_test.root.join("runtime-link");
        symlink(&runtime_link_test.runtime, &runtime_link).expect("runtime symlink");
        assert_eq!(
            expect_transport_error(
                UnixBrokerListener::bind_at(&runtime_link, runtime_link_test.owner),
                "runtime symlink",
            ),
            UnixBrokerTransportError::RuntimeDirectorySymbolicLink
        );

        let file_test = TestRuntime::new("file");
        fs::write(file_test.socket_path(), b"not a socket").expect("file");
        assert!(matches!(
            UnixBrokerListener::bind_at(&file_test.runtime, file_test.owner),
            Err(UnixBrokerTransportError::SocketEntryNotSocket)
        ));

        let link_test = TestRuntime::new("symlink");
        let target = link_test.root.join("target");
        fs::write(&target, b"target").expect("target");
        symlink(&target, link_test.socket_path()).expect("symlink");
        assert!(matches!(
            UnixBrokerListener::bind_at(&link_test.runtime, link_test.owner),
            Err(UnixBrokerTransportError::SocketSymbolicLink)
        ));
    }

    #[test]
    fn listener_rejects_broad_stale_socket_permissions() {
        let test = TestRuntime::new("socket-mode");
        let stale = UnixListener::bind(test.socket_path()).expect("listener");
        fs::set_permissions(test.socket_path(), fs::Permissions::from_mode(0o660)).expect("loosen");
        drop(stale);
        assert_eq!(
            expect_transport_error(
                UnixBrokerListener::bind_at(&test.runtime, test.owner),
                "socket mode",
            ),
            UnixBrokerTransportError::InsecurePermissions {
                entry: UnixBrokerTransportEntry::Socket,
                mode: 0o660,
            }
        );
    }

    #[test]
    fn cleanup_does_not_remove_a_replacement_entry() {
        let test = TestRuntime::new("replacement");
        let listener = UnixBrokerListener::bind_at(&test.runtime, test.owner).expect("bind");
        fs::remove_file(test.socket_path()).expect("unlink socket");
        fs::write(test.socket_path(), b"replacement").expect("replacement");
        drop(listener);
        assert_eq!(
            fs::read(test.socket_path()).expect("preserved"),
            b"replacement"
        );
    }

    #[test]
    fn accepted_peer_identity_matches_current_user_and_wrong_user_is_rejected() {
        let current_user = geteuid().as_raw();
        assert_eq!(
            validate_peer_identity(
                UnixBrokerPeerIdentity {
                    effective_user_id: current_user,
                    effective_group_id: 1,
                    process_id: None,
                },
                current_user,
            ),
            Ok(())
        );
        assert_eq!(
            validate_peer_identity(
                UnixBrokerPeerIdentity {
                    effective_user_id: current_user.wrapping_add(1),
                    effective_group_id: 1,
                    process_id: None,
                },
                current_user,
            ),
            Err(UnixBrokerTransportError::UnexpectedPeer)
        );
    }

    #[test]
    fn listener_and_connection_exchange_framed_protocol_requests() {
        let test = TestRuntime::new("exchange");
        let listener = UnixBrokerListener::bind_at(&test.runtime, test.owner).expect("bind");
        let runtime = test.runtime.clone();
        let owner = test.owner;
        let hello = hello_request();
        let status = BrokerRequestEnvelope::new(
            BrokerProtocolVersion::current(),
            BrokerRequestId::generate(),
            BrokerRequest::Status,
        );
        let expected_hello_id = hello.request_id();
        let expected_status_id = status.request_id();
        let (sender, receiver) = mpsc::channel();

        let client = thread::spawn(move || {
            let mut connection =
                UnixBrokerConnection::connect_at(&runtime, owner).expect("connect");
            connection
                .write_all(&framed_request(&hello))
                .expect("write hello");
            connection
                .write_all(&framed_request(&status))
                .expect("write status");
            connection
                .stream
                .shutdown(Shutdown::Write)
                .expect("finish requests");

            let first = read_broker_frame(&mut connection)
                .expect("first frame")
                .expect("first response");
            let second = read_broker_frame(&mut connection)
                .expect("second frame")
                .expect("second response");
            sender
                .send((first, second, connection.peer_identity()))
                .expect("send");
        });

        let accepted = listener.accept().expect("accept");
        assert_eq!(accepted.peer_identity().effective_user_id(), test.owner);
        assert_eq!(
            accepted.peer_identity().process_id(),
            Some(std::process::id())
        );
        assert!(accepted.observed_identity().executable_name().is_some());
        assert_eq!(
            accepted
                .serve(&BrokerProcess::new().expect("process"))
                .expect("serve"),
            BrokerConnectionExit::PeerClosed
        );
        client.join().expect("client");

        let (hello_payload, status_payload, server_identity) = receiver.recv().expect("responses");
        assert_eq!(server_identity.effective_user_id(), test.owner);
        let hello_response = decode_broker_response(&hello_payload).expect("hello response");
        assert_eq!(hello_response.request_id(), expected_hello_id);
        assert!(matches!(
            hello_response.response(),
            BrokerResponse::Hello(_)
        ));
        let status_response = decode_broker_response(&status_payload).expect("status response");
        assert_eq!(status_response.request_id(), expected_status_id);
        assert!(matches!(
            status_response.response(),
            BrokerResponse::Status(_)
        ));
    }

    #[test]
    fn peer_disconnect_probe_preserves_frames_and_cleans_up_the_direct_child() {
        let (mut broker_stream, mut client_stream) = UnixStream::pair().expect("socket pair");
        let cancellation =
            process_run_cancellation_for_stream(&broker_stream).expect("disconnect cancellation");

        assert!(!cancellation.is_cancelled());
        client_stream.write_all(b"x").expect("queued frame byte");
        assert!(!cancellation.is_cancelled());
        drop(client_stream);
        assert!(cancellation.is_cancelled());
        let mut byte = [0_u8; 1];
        broker_stream
            .read_exact(&mut byte)
            .expect("probe did not consume byte");
        assert_eq!(byte, *b"x");

        let (broker_stream, client_stream) = UnixStream::pair().expect("process socket pair");
        let child_cancellation =
            process_run_cancellation_for_stream(&broker_stream).expect("process cancellation");
        let operation = thread::spawn(move || {
            let request = BrokerProcessRunRequest::new(
                "/bin/sleep".to_owned(),
                vec!["2".to_owned()],
                None,
                Vec::new(),
                Duration::from_secs(2),
            )
            .expect("child request");
            BrokerProcessRunManager::execute(
                &request,
                &UsagePlacement::ProcessEnvironment {
                    variable_name: "KEPTNEAR_TOKEN".to_owned(),
                },
                &SecretBytes::new(b"KN_DISCONNECT_CLEANUP_SECRET_10_7".to_vec()),
                &child_cancellation,
            )
        });
        thread::sleep(Duration::from_millis(40));
        assert!(!operation.is_finished());

        let cancelled_at = Instant::now();
        drop(client_stream);
        assert_eq!(
            operation
                .join()
                .expect("operation thread")
                .expect_err("disconnect cancellation"),
            BrokerProcessRunError::Cancelled
        );
        assert!(cancelled_at.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn connection_error_debug_and_display_do_not_retain_socket_path() {
        let test = TestRuntime::new("error-redaction");
        let error = expect_transport_error(
            UnixBrokerConnection::connect_at(&test.runtime, test.owner),
            "missing socket",
        );
        let display = error.to_string();
        let debug = format!("{error:?}");
        let path = test.socket_path().to_string_lossy().into_owned();
        assert!(!display.contains(&path));
        assert!(!debug.contains(&path));
    }

    #[test]
    fn framed_exchange_fixture_contains_no_unbounded_transport_state() {
        let hello = hello_request();
        let frame = framed_request(&hello);
        let payload = read_broker_frame(&mut Cursor::new(frame))
            .expect("frame")
            .expect("payload");
        assert!(payload.len() < crate::MAX_BROKER_HELLO_LENGTH);
    }
}
