use std::fmt::{Debug, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

use fs2::FileExt;

use crate::{BrokerRuntime, BrokerRuntimeError, DeviceKeyStore, DevicePathError, DevicePaths};

const BROKER_PROCESS_LOCK_FILENAME: &str = "keptnear-broker.lock";
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Logical process-lock operation with no retained path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerProcessLockOperation {
    /// Open the operating-system account home used as the stable lock anchor.
    OpenAnchor,
    /// Inspect the stable lock entry.
    Inspect,
    /// Open or create the stable lock entry without following links.
    Open,
    /// Acquire the exclusive process lifetime lock.
    Lock,
    /// Record a diagnostic owner PID after acquiring the lock.
    RecordOwner,
}

/// Fail-closed single-Broker ownership error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerProcessLockError {
    /// Another live process owns the authoritative lock.
    AlreadyOwned,
    /// The operating-system account home is not a private directory owned by this user.
    UnsafeAnchor,
    /// The stable lock entry is a symbolic link.
    SymbolicLink,
    /// The stable lock entry is not a regular file.
    UnexpectedFileType,
    /// The lock file belongs to another operating-system user.
    UnexpectedOwner,
    /// The lock inode has another hard-link name and must not be truncated.
    HardLinked,
    /// Existing permissions expose the lock outside the owning user.
    InsecurePermissions {
        /// Observed permission bits.
        mode: u32,
    },
    /// A filesystem or kernel lock operation failed.
    Io {
        /// Fixed attempted operation.
        operation: BrokerProcessLockOperation,
        /// Sanitized I/O category.
        kind: io::ErrorKind,
    },
}

impl Display for BrokerProcessLockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyOwned => formatter.write_str("another Broker process owns the runtime"),
            Self::UnsafeAnchor => {
                formatter.write_str("Broker process lock anchor is not a private user directory")
            }
            Self::SymbolicLink => {
                formatter.write_str("Broker process lock must not be a symbolic link")
            }
            Self::UnexpectedFileType => {
                formatter.write_str("Broker process lock has an unexpected file type")
            }
            Self::UnexpectedOwner => {
                formatter.write_str("Broker process lock has an unexpected owner")
            }
            Self::HardLinked => formatter.write_str("Broker process lock must not be hard linked"),
            Self::InsecurePermissions { mode } => write!(
                formatter,
                "Broker process lock must use owner-only permissions (found {mode:04o})"
            ),
            Self::Io { operation, kind } => {
                write!(
                    formatter,
                    "Broker process lock {operation:?} failed: {kind}"
                )
            }
        }
    }
}

impl std::error::Error for BrokerProcessLockError {}

/// Exclusive process-lifetime ownership of one user's Broker runtime.
pub struct BrokerProcessLock {
    anchor: File,
    _diagnostic: File,
}

impl BrokerProcessLock {
    /// Acquires a kernel lock on the OS-account home before protected state or sockets open.
    ///
    /// The runtime PID file is diagnostic only. Removing or replacing that
    /// owner-writable path cannot replace the home-directory inode holding the
    /// authoritative process-lifetime lock.
    pub fn acquire(paths: &DevicePaths) -> Result<Self, BrokerProcessLockError> {
        Self::acquire_with_anchor_policy(paths, true)
    }

    fn acquire_with_anchor_policy(
        paths: &DevicePaths,
        require_system_parent: bool,
    ) -> Result<Self, BrokerProcessLockError> {
        let home = paths
            .root()
            .parent()
            .expect("prepared device root has a user-home parent");
        if require_system_parent {
            validate_stable_home_parent(home)?;
        }
        let mut anchor_options = OpenOptions::new();
        anchor_options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            anchor_options.custom_flags(
                (nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOFOLLOW).bits(),
            );
        }
        let anchor = anchor_options
            .open(home)
            .map_err(|error| BrokerProcessLockError::Io {
                operation: BrokerProcessLockOperation::OpenAnchor,
                kind: error.kind(),
            })?;
        validate_open_anchor(&anchor)?;
        anchor.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                BrokerProcessLockError::AlreadyOwned
            } else {
                BrokerProcessLockError::Io {
                    operation: BrokerProcessLockOperation::Lock,
                    kind: error.kind(),
                }
            }
        })?;

        let path = paths.runtime().join(BROKER_PROCESS_LOCK_FILENAME);
        validate_optional_lock_path(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
        }
        let mut file = options
            .open(&path)
            .map_err(|error| BrokerProcessLockError::Io {
                operation: BrokerProcessLockOperation::Open,
                kind: error.kind(),
            })?;
        validate_open_lock_file(&file)?;
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| writeln!(file, "{}", std::process::id()))
            .and_then(|()| file.sync_data())
            .map_err(|error| BrokerProcessLockError::Io {
                operation: BrokerProcessLockOperation::RecordOwner,
                kind: error.kind(),
            })?;
        Ok(Self {
            anchor,
            _diagnostic: file,
        })
    }

    #[cfg(test)]
    fn acquire_for_tests(paths: &DevicePaths) -> Result<Self, BrokerProcessLockError> {
        Self::acquire_with_anchor_policy(paths, false)
    }
}

impl Debug for BrokerProcessLock {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerProcessLock(<owner-held>)")
    }
}

impl Drop for BrokerProcessLock {
    fn drop(&mut self) {
        let _ = self.anchor.unlock();
    }
}

#[cfg(unix)]
fn validate_open_anchor(anchor: &File) -> Result<(), BrokerProcessLockError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = anchor
        .metadata()
        .map_err(|error| BrokerProcessLockError::Io {
            operation: BrokerProcessLockOperation::Inspect,
            kind: error.kind(),
        })?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(BrokerProcessLockError::UnsafeAnchor);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_stable_home_parent(home: &Path) -> Result<(), BrokerProcessLockError> {
    use std::os::unix::fs::MetadataExt;

    let parent = home.parent().ok_or(BrokerProcessLockError::UnsafeAnchor)?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| BrokerProcessLockError::Io {
        operation: BrokerProcessLockOperation::Inspect,
        kind: error.kind(),
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() == nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(BrokerProcessLockError::UnsafeAnchor);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_open_anchor(_anchor: &File) -> Result<(), BrokerProcessLockError> {
    Err(BrokerProcessLockError::Io {
        operation: BrokerProcessLockOperation::Inspect,
        kind: io::ErrorKind::Unsupported,
    })
}

#[cfg(not(unix))]
fn validate_stable_home_parent(_home: &Path) -> Result<(), BrokerProcessLockError> {
    Err(BrokerProcessLockError::Io {
        operation: BrokerProcessLockOperation::Inspect,
        kind: io::ErrorKind::Unsupported,
    })
}

/// Ordered service startup failure without local path disclosure.
#[derive(Debug)]
pub enum BrokerServiceStartupError {
    /// Canonical device path preparation failed.
    Paths(DevicePathError),
    /// Another Broker owns the runtime or the lock boundary is unsafe.
    ProcessLock(BrokerProcessLockError),
    /// Protected Broker state could not be opened after ownership was acquired.
    Runtime(BrokerRuntimeError),
}

impl Display for BrokerServiceStartupError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paths(source) => write!(formatter, "Broker service paths failed: {source}"),
            Self::ProcessLock(source) => {
                write!(formatter, "Broker service ownership failed: {source}")
            }
            Self::Runtime(source) => write!(formatter, "Broker service runtime failed: {source}"),
        }
    }
}

impl std::error::Error for BrokerServiceStartupError {}

/// Running Broker runtime that retains authoritative process ownership.
pub struct BrokerServiceRuntime {
    _process_lock: BrokerProcessLock,
    runtime: BrokerRuntime,
}

impl BrokerServiceRuntime {
    /// Prepares paths, acquires ownership, then opens protected state in that order.
    pub fn start_for_current_user<S>(store: S) -> Result<Self, BrokerServiceStartupError>
    where
        S: DeviceKeyStore,
    {
        let paths =
            DevicePaths::prepare_for_current_user().map_err(BrokerServiceStartupError::Paths)?;
        Self::start_with_prepared_paths(paths, store)
    }

    fn start_with_prepared_paths<S>(
        paths: DevicePaths,
        store: S,
    ) -> Result<Self, BrokerServiceStartupError>
    where
        S: DeviceKeyStore,
    {
        let process_lock =
            BrokerProcessLock::acquire(&paths).map_err(BrokerServiceStartupError::ProcessLock)?;
        let runtime = BrokerRuntime::open_or_initialize_with_prepared_paths(paths, store)
            .map_err(BrokerServiceStartupError::Runtime)?;
        Ok(Self {
            _process_lock: process_lock,
            runtime,
        })
    }

    /// Returns the protected Broker runtime while ownership remains held.
    #[must_use]
    pub const fn runtime(&self) -> &BrokerRuntime {
        &self.runtime
    }

    /// Returns mutable runtime access while ownership remains held.
    #[must_use]
    pub const fn runtime_mut(&mut self) -> &mut BrokerRuntime {
        &mut self.runtime
    }
}

#[cfg(unix)]
fn validate_optional_lock_path(path: &Path) -> Result<(), BrokerProcessLockError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_lock_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BrokerProcessLockError::Io {
            operation: BrokerProcessLockOperation::Inspect,
            kind: error.kind(),
        }),
    }
}

#[cfg(not(unix))]
fn validate_optional_lock_path(_path: &Path) -> Result<(), BrokerProcessLockError> {
    Err(BrokerProcessLockError::Io {
        operation: BrokerProcessLockOperation::Inspect,
        kind: io::ErrorKind::Unsupported,
    })
}

#[cfg(unix)]
fn validate_open_lock_file(file: &File) -> Result<(), BrokerProcessLockError> {
    let metadata = file
        .metadata()
        .map_err(|error| BrokerProcessLockError::Io {
            operation: BrokerProcessLockOperation::Inspect,
            kind: error.kind(),
        })?;
    validate_lock_metadata(&metadata)
}

#[cfg(not(unix))]
fn validate_open_lock_file(_file: &File) -> Result<(), BrokerProcessLockError> {
    Err(BrokerProcessLockError::Io {
        operation: BrokerProcessLockOperation::Inspect,
        kind: io::ErrorKind::Unsupported,
    })
}

#[cfg(unix)]
fn validate_lock_metadata(metadata: &fs::Metadata) -> Result<(), BrokerProcessLockError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.file_type().is_symlink() {
        return Err(BrokerProcessLockError::SymbolicLink);
    }
    if !metadata.is_file() {
        return Err(BrokerProcessLockError::UnexpectedFileType);
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(BrokerProcessLockError::UnexpectedOwner);
    }
    if metadata.nlink() != 1 {
        return Err(BrokerProcessLockError::HardLinked);
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(BrokerProcessLockError::InsecurePermissions { mode });
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn paths(label: &str) -> (std::path::PathBuf, DevicePaths) {
        let unique = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "keptnear-process-lock-{label}-{}-{nanos}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let paths = DevicePaths::prepare_for_test_home(&home).expect("paths");
        (home, paths)
    }

    #[test]
    fn active_owner_is_rejected_and_unlocked_stale_file_is_reused() {
        let (home, paths) = paths("ownership");
        let first = BrokerProcessLock::acquire_for_tests(&paths).expect("first lock");
        assert_eq!(
            BrokerProcessLock::acquire_for_tests(&paths).unwrap_err(),
            BrokerProcessLockError::AlreadyOwned
        );
        fs::remove_file(paths.runtime().join(BROKER_PROCESS_LOCK_FILENAME))
            .expect("remove diagnostic PID file");
        assert_eq!(
            BrokerProcessLock::acquire_for_tests(&paths).unwrap_err(),
            BrokerProcessLockError::AlreadyOwned
        );
        drop(first);
        let second = BrokerProcessLock::acquire_for_tests(&paths).expect("reuse stale file");
        drop(second);
        fs::remove_dir_all(home).expect("cleanup");
    }

    #[test]
    fn symbolic_hard_link_and_broad_stale_file_fail_closed_without_target_mutation() {
        {
            let (home, paths) = paths("unsafe-symbolic");
            let lock_path = paths.runtime().join(BROKER_PROCESS_LOCK_FILENAME);
            let target = paths.runtime().join("target");
            fs::write(&target, b"stale").expect("target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
            symlink(&target, &lock_path).expect("symlink");
            assert_eq!(
                BrokerProcessLock::acquire_for_tests(&paths).unwrap_err(),
                BrokerProcessLockError::SymbolicLink
            );
            fs::remove_dir_all(home).expect("cleanup symbolic fixture");
        }
        {
            let (home, paths) = paths("unsafe-hard-link");
            let lock_path = paths.runtime().join(BROKER_PROCESS_LOCK_FILENAME);
            let target = paths.runtime().join("target");
            fs::write(&target, b"stale").expect("target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
            fs::hard_link(&target, &lock_path).expect("hard link");
            assert_eq!(
                BrokerProcessLock::acquire_for_tests(&paths).unwrap_err(),
                BrokerProcessLockError::HardLinked
            );
            assert_eq!(fs::read(&target).expect("unchanged target"), b"stale");
            fs::remove_dir_all(home).expect("cleanup hard-link fixture");
        }
        {
            let (home, paths) = paths("unsafe-permissions");
            let lock_path = paths.runtime().join(BROKER_PROCESS_LOCK_FILENAME);
            fs::write(&lock_path, b"stale").expect("stale file");
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).expect("broad mode");
            assert_eq!(
                BrokerProcessLock::acquire_for_tests(&paths).unwrap_err(),
                BrokerProcessLockError::InsecurePermissions { mode: 0o644 }
            );
            fs::remove_dir_all(home).expect("cleanup permissions fixture");
        }
    }

    #[test]
    fn debug_and_errors_never_include_the_runtime_path() {
        let (home, paths) = paths("redaction");
        let lock = BrokerProcessLock::acquire_for_tests(&paths).expect("lock");
        assert!(!format!("{lock:?}").contains(&home.to_string_lossy().to_string()));
        assert!(!BrokerProcessLockError::AlreadyOwned
            .to_string()
            .contains(&home.to_string_lossy().to_string()));
        drop(lock);
        fs::remove_dir_all(home).expect("cleanup");
    }

    #[test]
    fn owner_writable_home_parent_is_not_a_production_lock_anchor() {
        let (home, paths) = paths("replaceable-anchor");
        assert_eq!(
            BrokerProcessLock::acquire(&paths).unwrap_err(),
            BrokerProcessLockError::UnsafeAnchor
        );
        fs::remove_dir_all(home).expect("cleanup");
    }
}
