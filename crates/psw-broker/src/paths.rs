use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

const DEVICE_ROOT_NAME: &str = ".keptnear";
const CONFIG_DIRECTORY_NAME: &str = "config";
const STATE_DIRECTORY_NAME: &str = "state";
const RUNTIME_DIRECTORY_NAME: &str = "runtime";
const LOGS_DIRECTORY_NAME: &str = "logs";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const GROUP_OR_WORLD_WRITE_MASK: u32 = 0o022;

/// Identifies one path without carrying its full local filesystem value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePathEntry {
    /// The current operating-system user's home directory.
    UserHome,
    /// The canonical `~/.keptnear` device root.
    Root,
    /// The device-local configuration directory.
    Config,
    /// The encrypted durable-state directory.
    State,
    /// The local IPC and transient runtime directory.
    Runtime,
    /// The sanitized local log directory.
    Logs,
}

impl DevicePathEntry {
    fn label(self) -> &'static str {
        match self {
            Self::UserHome => "user home",
            Self::Root => "device root",
            Self::Config => "config directory",
            Self::State => "state directory",
            Self::Runtime => "runtime directory",
            Self::Logs => "logs directory",
        }
    }
}

/// Identifies a filesystem operation without exposing its target path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePathOperation {
    /// Read current operating-system account information.
    ResolveCurrentUser,
    /// Inspect an existing filesystem entry.
    Inspect,
    /// Create a private directory.
    Create,
    /// Apply private directory permissions.
    SetPermissions,
}

impl DevicePathOperation {
    fn label(self) -> &'static str {
        match self {
            Self::ResolveCurrentUser => "resolve current user",
            Self::Inspect => "inspect",
            Self::Create => "create",
            Self::SetPermissions => "set permissions on",
        }
    }
}

/// A fail-closed device-path initialization or validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DevicePathError {
    /// The current platform does not yet have a supported path implementation.
    UnsupportedPlatform,
    /// The operating system did not return a current user account and home.
    CurrentUserUnavailable,
    /// The operating-system account returned a non-absolute home directory.
    HomePathNotAbsolute,
    /// A filesystem operation failed.
    Io {
        /// The logical entry involved in the failure.
        entry: DevicePathEntry,
        /// The attempted operation.
        operation: DevicePathOperation,
        /// The sanitized operating-system error category.
        kind: io::ErrorKind,
    },
    /// A managed entry is a symbolic link.
    SymbolicLink {
        /// The rejected logical entry.
        entry: DevicePathEntry,
    },
    /// A managed entry exists but is not a directory.
    NotDirectory {
        /// The rejected logical entry.
        entry: DevicePathEntry,
    },
    /// A managed entry is not owned by the current effective user.
    UnexpectedOwner {
        /// The rejected logical entry.
        entry: DevicePathEntry,
    },
    /// The user home is writable by its group or by other users.
    InsecureHomePermissions {
        /// The observed permission bits.
        mode: u32,
    },
    /// A managed KeptNear directory is not private to its owner.
    InsecureDirectoryPermissions {
        /// The rejected logical entry.
        entry: DevicePathEntry,
        /// The observed permission bits.
        mode: u32,
    },
}

impl fmt::Display for DevicePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("device paths are unsupported on this platform")
            }
            Self::CurrentUserUnavailable => {
                formatter.write_str("current operating-system user is unavailable")
            }
            Self::HomePathNotAbsolute => {
                formatter.write_str("current operating-system home is not absolute")
            }
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
            Self::SymbolicLink { entry } => {
                write!(formatter, "{} must not be a symbolic link", entry.label())
            }
            Self::NotDirectory { entry } => {
                write!(formatter, "{} must be a directory", entry.label())
            }
            Self::UnexpectedOwner { entry } => {
                write!(formatter, "{} has an unexpected owner", entry.label())
            }
            Self::InsecureHomePermissions { mode } => write!(
                formatter,
                "user home is group or world writable (mode {mode:04o})"
            ),
            Self::InsecureDirectoryPermissions { entry, mode } => write!(
                formatter,
                "{} must use mode 0700 (found {mode:04o})",
                entry.label()
            ),
        }
    }
}

impl std::error::Error for DevicePathError {}

/// Canonical device-local KeptNear directories for one operating-system user.
///
/// Construction does not accept a caller-provided override in production.
/// This keeps the Broker rooted at the home directory recorded by the
/// operating system rather than an inherited `HOME` environment variable.
#[derive(Clone, Eq, PartialEq)]
pub struct DevicePaths {
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
    runtime: PathBuf,
    logs: PathBuf,
}

impl DevicePaths {
    /// Resolves, creates, and validates the current user's device directories.
    ///
    /// The operation is idempotent. Newly created directories use mode `0700`.
    /// Existing roots or children fail closed when they are symbolic links,
    /// have another owner, or expose any group or world permissions.
    pub fn prepare_for_current_user() -> Result<Self, DevicePathError> {
        prepare_for_current_user()
    }

    /// Returns the canonical `~/.keptnear` root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the private configuration directory.
    pub fn config(&self) -> &Path {
        &self.config
    }

    /// Returns the private encrypted-state directory.
    pub fn state(&self) -> &Path {
        &self.state
    }

    /// Returns the private runtime and local-IPC directory.
    pub fn runtime(&self) -> &Path {
        &self.runtime
    }

    /// Returns the private sanitized-log directory.
    pub fn logs(&self) -> &Path {
        &self.logs
    }

    #[cfg(all(test, unix))]
    pub(crate) fn prepare_for_test_home(home: &Path) -> Result<Self, DevicePathError> {
        let paths = Self::from_home(home)?;
        prepare_for_owner(&paths, nix::unistd::geteuid().as_raw())?;
        Ok(paths)
    }

    fn from_home(home: &Path) -> Result<Self, DevicePathError> {
        if !home.is_absolute() {
            return Err(DevicePathError::HomePathNotAbsolute);
        }
        let root = home.join(DEVICE_ROOT_NAME);
        Ok(Self {
            config: root.join(CONFIG_DIRECTORY_NAME),
            state: root.join(STATE_DIRECTORY_NAME),
            runtime: root.join(RUNTIME_DIRECTORY_NAME),
            logs: root.join(LOGS_DIRECTORY_NAME),
            root,
        })
    }
}

#[cfg(unix)]
fn prepare_for_current_user() -> Result<DevicePaths, DevicePathError> {
    let (home, effective_user) = current_user_home_and_owner()?;
    let paths = DevicePaths::from_home(&home)?;
    prepare_for_owner(&paths, effective_user)?;
    Ok(paths)
}

#[cfg(unix)]
fn current_user_home_and_owner() -> Result<(PathBuf, u32), DevicePathError> {
    use nix::unistd::{geteuid, User};

    let effective_user = geteuid();
    let user = User::from_uid(effective_user).map_err(|_| DevicePathError::Io {
        entry: DevicePathEntry::UserHome,
        operation: DevicePathOperation::ResolveCurrentUser,
        kind: io::ErrorKind::Other,
    })?;
    let user = user.ok_or(DevicePathError::CurrentUserUnavailable)?;
    Ok((user.dir, effective_user.as_raw()))
}

#[cfg(not(unix))]
fn prepare_for_current_user() -> Result<DevicePaths, DevicePathError> {
    Err(DevicePathError::UnsupportedPlatform)
}

#[cfg(unix)]
fn prepare_for_owner(paths: &DevicePaths, expected_owner: u32) -> Result<(), DevicePathError> {
    validate_user_home(
        paths.root.parent().expect("device root has home parent"),
        expected_owner,
    )?;
    ensure_private_directory(&paths.root, DevicePathEntry::Root, expected_owner)?;
    ensure_private_directory(&paths.config, DevicePathEntry::Config, expected_owner)?;
    ensure_private_directory(&paths.state, DevicePathEntry::State, expected_owner)?;
    ensure_private_directory(&paths.runtime, DevicePathEntry::Runtime, expected_owner)?;
    ensure_private_directory(&paths.logs, DevicePathEntry::Logs, expected_owner)
}

#[cfg(unix)]
fn validate_user_home(home: &Path, expected_owner: u32) -> Result<(), DevicePathError> {
    let metadata = inspect_directory(home, DevicePathEntry::UserHome, expected_owner)?;
    let mode = unix_mode(&metadata);
    if mode & GROUP_OR_WORLD_WRITE_MASK != 0 {
        return Err(DevicePathError::InsecureHomePermissions { mode });
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_directory(
    path: &Path,
    entry: DevicePathEntry,
    expected_owner: u32,
) -> Result<(), DevicePathError> {
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            builder.create(path).map_err(|error| DevicePathError::Io {
                entry,
                operation: DevicePathOperation::Create,
                kind: error.kind(),
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).map_err(
                |error| DevicePathError::Io {
                    entry,
                    operation: DevicePathOperation::SetPermissions,
                    kind: error.kind(),
                },
            )?;
        }
        Err(error) => {
            return Err(DevicePathError::Io {
                entry,
                operation: DevicePathOperation::Inspect,
                kind: error.kind(),
            });
        }
    }

    let metadata = inspect_directory(path, entry, expected_owner)?;
    let mode = unix_mode(&metadata);
    if mode != PRIVATE_DIRECTORY_MODE {
        return Err(DevicePathError::InsecureDirectoryPermissions { entry, mode });
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_directory(
    path: &Path,
    entry: DevicePathEntry,
    expected_owner: u32,
) -> Result<std::fs::Metadata, DevicePathError> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path).map_err(|error| DevicePathError::Io {
        entry,
        operation: DevicePathOperation::Inspect,
        kind: error.kind(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(DevicePathError::SymbolicLink { entry });
    }
    if !metadata.is_dir() {
        return Err(DevicePathError::NotDirectory { entry });
    }
    if metadata.uid() != expected_owner {
        return Err(DevicePathError::UnexpectedOwner { entry });
    }
    Ok(metadata)
}

#[cfg(unix)]
fn unix_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;

    metadata.mode() & 0o777
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        current_user_home_and_owner, prepare_for_owner, validate_user_home, DevicePathEntry,
        DevicePathError, DevicePaths, PRIVATE_DIRECTORY_MODE,
    };
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static HOME_ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

    struct EnvironmentVariableGuard {
        key: &'static str,
        original: Option<OsString>,
    }

    impl EnvironmentVariableGuard {
        fn replace(key: &'static str, value: &Path) -> Self {
            let original = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for EnvironmentVariableGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    struct TestHome {
        path: PathBuf,
    }

    impl TestHome {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "keptnear-broker-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test home");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect test home");
            Self { path }
        }

        fn owner(&self) -> u32 {
            fs::symlink_metadata(&self.path)
                .expect("inspect test home")
                .uid()
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn prepared_paths(home: &TestHome) -> DevicePaths {
        let paths = DevicePaths::from_home(&home.path).expect("resolve paths");
        prepare_for_owner(&paths, home.owner()).expect("prepare paths");
        paths
    }

    fn assert_private_directory(path: &Path) {
        let metadata = fs::symlink_metadata(path).expect("inspect private directory");
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            PRIVATE_DIRECTORY_MODE
        );
    }

    #[test]
    fn prepares_canonical_private_directory_layout_idempotently() {
        let home = TestHome::new("layout");
        let paths = prepared_paths(&home);

        assert_eq!(paths.root(), home.path.join(".keptnear"));
        assert_eq!(paths.config(), home.path.join(".keptnear/config"));
        assert_eq!(paths.state(), home.path.join(".keptnear/state"));
        assert_eq!(paths.runtime(), home.path.join(".keptnear/runtime"));
        assert_eq!(paths.logs(), home.path.join(".keptnear/logs"));
        for path in [
            paths.root(),
            paths.config(),
            paths.state(),
            paths.runtime(),
            paths.logs(),
        ] {
            assert_private_directory(path);
        }

        prepare_for_owner(&paths, home.owner()).expect("repeat preparation");
    }

    #[test]
    fn rejects_relative_home_without_creating_state() {
        assert!(matches!(
            DevicePaths::from_home(Path::new("relative-home")),
            Err(DevicePathError::HomePathNotAbsolute)
        ));
    }

    #[test]
    fn current_user_resolution_ignores_inherited_home_override() {
        let _lock = HOME_ENVIRONMENT_LOCK.lock().expect("lock HOME test");
        let fake_home = TestHome::new("ignored-home");
        let _guard = EnvironmentVariableGuard::replace("HOME", &fake_home.path);

        let (resolved_home, resolved_owner) =
            current_user_home_and_owner().expect("resolve operating-system account");

        assert_ne!(resolved_home, fake_home.path);
        assert_eq!(
            fs::symlink_metadata(&resolved_home)
                .expect("inspect resolved home")
                .uid(),
            resolved_owner
        );
    }

    #[test]
    fn rejects_group_or_world_writable_user_home() {
        let home = TestHome::new("writable-home");
        fs::set_permissions(&home.path, fs::Permissions::from_mode(0o770))
            .expect("loosen test home");
        let paths = DevicePaths::from_home(&home.path).expect("resolve paths");

        assert_eq!(
            prepare_for_owner(&paths, home.owner()),
            Err(DevicePathError::InsecureHomePermissions { mode: 0o770 })
        );
        assert!(!paths.root().exists());
    }

    #[test]
    fn rejects_symbolic_link_root_and_children() {
        let root_home = TestHome::new("root-symlink");
        let root_target = root_home.path.join("redirected-root");
        fs::create_dir(&root_target).expect("create root target");
        symlink(&root_target, root_home.path.join(".keptnear")).expect("link root");
        let root_paths = DevicePaths::from_home(&root_home.path).expect("resolve root paths");
        assert_eq!(
            prepare_for_owner(&root_paths, root_home.owner()),
            Err(DevicePathError::SymbolicLink {
                entry: DevicePathEntry::Root
            })
        );

        let child_home = TestHome::new("child-symlink");
        let child_paths = prepared_paths(&child_home);
        fs::remove_dir(child_paths.runtime()).expect("remove runtime directory");
        let child_target = child_home.path.join("redirected-runtime");
        fs::create_dir(&child_target).expect("create runtime target");
        symlink(&child_target, child_paths.runtime()).expect("link runtime");
        assert_eq!(
            prepare_for_owner(&child_paths, child_home.owner()),
            Err(DevicePathError::SymbolicLink {
                entry: DevicePathEntry::Runtime
            })
        );
    }

    #[test]
    fn rejects_non_directory_and_overbroad_managed_entries() {
        let file_home = TestHome::new("root-file");
        fs::write(file_home.path.join(".keptnear"), b"not a directory").expect("write root file");
        let file_paths = DevicePaths::from_home(&file_home.path).expect("resolve file paths");
        assert_eq!(
            prepare_for_owner(&file_paths, file_home.owner()),
            Err(DevicePathError::NotDirectory {
                entry: DevicePathEntry::Root
            })
        );

        let mode_home = TestHome::new("broad-mode");
        let mode_paths = prepared_paths(&mode_home);
        fs::set_permissions(mode_paths.logs(), fs::Permissions::from_mode(0o750))
            .expect("loosen logs");
        assert_eq!(
            prepare_for_owner(&mode_paths, mode_home.owner()),
            Err(DevicePathError::InsecureDirectoryPermissions {
                entry: DevicePathEntry::Logs,
                mode: 0o750
            })
        );
    }

    #[test]
    fn rejects_unexpected_owner_without_exposing_path_in_error() {
        let home = TestHome::new("owner");
        let wrong_owner = home.owner().wrapping_add(1);
        let error = validate_user_home(&home.path, wrong_owner).expect_err("reject owner");

        assert_eq!(
            error,
            DevicePathError::UnexpectedOwner {
                entry: DevicePathEntry::UserHome
            }
        );
        assert!(!error
            .to_string()
            .contains(home.path.to_string_lossy().as_ref()));
    }
}
