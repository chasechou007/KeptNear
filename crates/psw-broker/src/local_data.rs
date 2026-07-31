use std::fmt::{Display, Formatter};

use crate::device_key::{DeviceKeyError, DeviceKeyManager, DeviceKeyStore};
use crate::grant_invalidation::{
    BrokerGrantInvalidationError, BrokerGrantInvalidationSummary, BrokerGrantInvalidator,
};
use crate::paths::DevicePaths;
use crate::state_store::{DeviceStateError, DeviceStateRemoval, DeviceStateStore};
use crate::vault_session::{BrokerVaultSessionError, BrokerVaultSessionManager};

/// Proof that the product obtained explicit human confirmation for local-data removal.
///
/// The UI or adapter owns the confirmation interaction. Requiring this value
/// keeps destructive removal out of ordinary startup and reinstall paths.
#[derive(Debug)]
pub struct BrokerLocalDataClearConfirmation {
    _private: (),
}

impl BrokerLocalDataClearConfirmation {
    /// Creates a confirmation token only after an explicit human decision.
    #[must_use]
    pub const fn after_user_confirmation() -> Self {
        Self { _private: () }
    }
}

/// Non-secret result of a completed local device-state clear.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerLocalDataClearSummary {
    vault_lock_events_processed: usize,
    use_grants_removed: usize,
    managed_state_files_removed: usize,
    device_key_removed: bool,
    authenticated_reset_preparation: bool,
}

impl BrokerLocalDataClearSummary {
    /// Returns the number of queued vault-lock events processed or discarded.
    #[must_use]
    pub const fn vault_lock_events_processed(self) -> usize {
        self.vault_lock_events_processed
    }

    /// Returns the number of Use Grants removed from authenticated state.
    #[must_use]
    pub const fn use_grants_removed(self) -> usize {
        self.use_grants_removed
    }

    /// Returns the number of database, WAL, and shared-memory files removed.
    #[must_use]
    pub const fn managed_state_files_removed(self) -> usize {
        self.managed_state_files_removed
    }

    /// Returns whether an existing device root key was removed.
    #[must_use]
    pub const fn device_key_removed(self) -> bool {
        self.device_key_removed
    }

    /// Returns whether grants were revoked through an authenticated transaction.
    ///
    /// This is false only for explicit recovery of state that could not be
    /// opened, such as a database whose device key is already unavailable.
    #[must_use]
    pub const fn authenticated_reset_preparation(self) -> bool {
        self.authenticated_reset_preparation
    }
}

/// Sanitized reinstall or explicit local-data-clear failure.
#[derive(Debug)]
pub enum BrokerLocalDataError {
    /// The device-bound Keychain root could not be loaded.
    DeviceKey(DeviceKeyError),
    /// Encrypted state could not be opened, closed, validated, or removed.
    DeviceState(DeviceStateError),
    /// Live sessions and grants could not be revoked before removal.
    GrantInvalidation(BrokerGrantInvalidationError),
    /// The session manager could not shut down for unopenable-state recovery.
    VaultSession(BrokerVaultSessionError),
    /// State files are gone, but Keychain root deletion failed.
    ///
    /// The operation is intentionally retryable through the unopenable-state
    /// clear path because recreating a database is never attempted here.
    DeviceKeyDeletionAfterStateRemoval {
        /// Number of managed state files removed before the Keychain failure.
        managed_state_files_removed: usize,
        /// Sanitized Keychain lifecycle failure.
        source: DeviceKeyError,
    },
}

impl BrokerLocalDataError {
    /// Returns whether managed encrypted state was already removed.
    #[must_use]
    pub const fn device_state_was_removed(&self) -> bool {
        matches!(
            self,
            Self::DeviceKeyDeletionAfterStateRemoval {
                managed_state_files_removed: _,
                source: _
            }
        )
    }

    /// Returns the completed state-file count for a partial Keychain failure.
    #[must_use]
    pub const fn managed_state_files_removed(&self) -> Option<usize> {
        match self {
            Self::DeviceKeyDeletionAfterStateRemoval {
                managed_state_files_removed,
                ..
            } => Some(*managed_state_files_removed),
            _ => None,
        }
    }
}

impl Display for BrokerLocalDataError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceKey(source) => {
                write!(formatter, "device-key reinstall recovery failed: {source}")
            }
            Self::DeviceState(source) => {
                write!(
                    formatter,
                    "local encrypted-state operation failed: {source}"
                )
            }
            Self::GrantInvalidation(source) => {
                write!(formatter, "local-data reset preparation failed: {source}")
            }
            Self::VaultSession(source) => {
                write!(
                    formatter,
                    "local-data reset session shutdown failed: {source}"
                )
            }
            Self::DeviceKeyDeletionAfterStateRemoval { source, .. } => write!(
                formatter,
                "encrypted state was removed but device-key deletion failed: {source}"
            ),
        }
    }
}

impl std::error::Error for BrokerLocalDataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DeviceKey(source) => Some(source),
            Self::DeviceState(source) => Some(source),
            Self::GrantInvalidation(source) => Some(source),
            Self::VaultSession(source) => Some(source),
            Self::DeviceKeyDeletionAfterStateRemoval { source, .. } => Some(source),
        }
    }
}

/// Coordinates reinstall recovery and explicitly confirmed local-state clearing.
pub struct BrokerLocalDataManager<S> {
    device_keys: DeviceKeyManager<S>,
}

impl<S> BrokerLocalDataManager<S>
where
    S: DeviceKeyStore,
{
    /// Creates a coordinator around the platform's stable device-key store.
    pub fn new(store: S) -> Self {
        Self {
            device_keys: DeviceKeyManager::new(store),
        }
    }

    /// Reopens preserved state after reinstall without creating replacement data.
    ///
    /// A missing Keychain item or database is returned as an error. This path
    /// never initializes a root key and never overwrites encrypted state.
    pub fn reopen_after_reinstall(
        &self,
        paths: &DevicePaths,
    ) -> Result<DeviceStateStore, BrokerLocalDataError> {
        let root_key = self
            .device_keys
            .load_existing()
            .map_err(BrokerLocalDataError::DeviceKey)?;
        DeviceStateStore::open_existing(paths, &root_key).map_err(BrokerLocalDataError::DeviceState)
    }

    /// Clears authenticated device state after explicit human confirmation.
    ///
    /// Sessions and grants are revoked first, the SQLCipher connection is
    /// closed, managed files are removed and verified, and only then is the
    /// device root key removed and verified.
    pub fn clear_local_data(
        &self,
        _confirmation: BrokerLocalDataClearConfirmation,
        sessions: &BrokerVaultSessionManager,
        mut state: DeviceStateStore,
        paths: &DevicePaths,
    ) -> Result<BrokerLocalDataClearSummary, BrokerLocalDataError> {
        let preparation = BrokerGrantInvalidator::prepare_device_data_reset(sessions, &mut state)
            .map_err(BrokerLocalDataError::GrantInvalidation)?;
        let removal = state
            .remove_for_local_data_clear(paths)
            .map_err(BrokerLocalDataError::DeviceState)?;
        self.finish_clear(removal, preparation, true)
    }

    /// Clears state that cannot be authenticated after explicit confirmation.
    ///
    /// This recovery path is intended for corrupt state or a missing device
    /// key. It still shuts down sessions and validates every managed file, but
    /// cannot transactionally count grants in an unopenable database.
    pub fn clear_unopenable_local_data(
        &self,
        _confirmation: BrokerLocalDataClearConfirmation,
        sessions: &BrokerVaultSessionManager,
        paths: &DevicePaths,
    ) -> Result<BrokerLocalDataClearSummary, BrokerLocalDataError> {
        let vault_lock_events_processed = sessions
            .shutdown()
            .map_err(BrokerLocalDataError::VaultSession)?
            .len();
        let removal = DeviceStateStore::remove_existing_for_local_data_clear(paths)
            .map_err(BrokerLocalDataError::DeviceState)?;
        let preparation = BrokerGrantInvalidationSummary::default();
        let mut summary = self.finish_clear(removal, preparation, false)?;
        summary.vault_lock_events_processed = vault_lock_events_processed;
        Ok(summary)
    }

    fn finish_clear(
        &self,
        removal: DeviceStateRemoval,
        preparation: BrokerGrantInvalidationSummary,
        authenticated_reset_preparation: bool,
    ) -> Result<BrokerLocalDataClearSummary, BrokerLocalDataError> {
        let managed_state_files_removed = removal.managed_files_removed();
        let device_key_removed = self.device_keys.delete_existing().map_err(|source| {
            BrokerLocalDataError::DeviceKeyDeletionAfterStateRemoval {
                managed_state_files_removed,
                source,
            }
        })?;
        Ok(BrokerLocalDataClearSummary {
            vault_lock_events_processed: preparation.lock_events_processed(),
            use_grants_removed: preparation.use_grants_removed(),
            managed_state_files_removed,
            device_key_removed,
            authenticated_reset_preparation,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::device_key::{DeviceKeyStoreError, DeviceRootKey, DEVICE_ROOT_KEY_LENGTH};
    use crate::state_model::StateTimestamp;
    use crate::state_store::DEVICE_STATE_DATABASE_FILENAME;

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct MemoryKeyState {
        bytes: Option<Vec<u8>>,
        delete_error: Option<DeviceKeyStoreError>,
        retain_after_delete: bool,
    }

    #[derive(Clone, Default)]
    struct MemoryKeyStore {
        state: Arc<Mutex<MemoryKeyState>>,
    }

    impl MemoryKeyStore {
        fn contains_key(&self) -> bool {
            self.state.lock().expect("key state").bytes.is_some()
        }

        fn bytes(&self) -> Option<Vec<u8>> {
            self.state.lock().expect("key state").bytes.clone()
        }

        fn fail_next_delete(&self) {
            self.state.lock().expect("key state").delete_error =
                Some(DeviceKeyStoreError::Platform { status: -1 });
        }
    }

    impl DeviceKeyStore for MemoryKeyStore {
        fn load(&self) -> Result<Option<DeviceRootKey>, DeviceKeyStoreError> {
            self.state
                .lock()
                .expect("key state")
                .bytes
                .clone()
                .map(DeviceRootKey::from_stored_bytes)
                .transpose()
        }

        fn create_new(&self, key: &DeviceRootKey) -> Result<(), DeviceKeyStoreError> {
            let mut state = self.state.lock().expect("key state");
            if state.bytes.is_some() {
                return Err(DeviceKeyStoreError::AlreadyExists);
            }
            state.bytes = Some(key.expose().to_vec());
            Ok(())
        }

        fn delete(&self) -> Result<bool, DeviceKeyStoreError> {
            let mut state = self.state.lock().expect("key state");
            if let Some(error) = state.delete_error.take() {
                return Err(error);
            }
            let existed = state.bytes.is_some();
            if !state.retain_after_delete {
                state.bytes.take();
            }
            Ok(existed)
        }
    }

    struct TestHome {
        path: PathBuf,
        paths: DevicePaths,
    }

    impl TestHome {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keptnear-local-data-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test home");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protect test home");
            let paths = DevicePaths::prepare_for_test_home(&path).expect("prepare paths");
            Self { path, paths }
        }

        fn database_path(&self) -> PathBuf {
            self.paths.state().join(DEVICE_STATE_DATABASE_FILENAME)
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn timestamp(value: i64) -> StateTimestamp {
        StateTimestamp::from_unix_millis(value).expect("timestamp")
    }

    fn initialized(
        label: &str,
    ) -> (
        TestHome,
        MemoryKeyStore,
        BrokerLocalDataManager<MemoryKeyStore>,
        DeviceStateStore,
    ) {
        let home = TestHome::new(label);
        let key_store = MemoryKeyStore::default();
        let root_key = DeviceKeyManager::new(key_store.clone())
            .initialize_new()
            .expect("initialize key");
        let state = DeviceStateStore::initialize_new(&home.paths, &root_key, timestamp(100))
            .expect("initialize state");
        let manager = BrokerLocalDataManager::new(key_store.clone());
        (home, key_store, manager, state)
    }

    fn sessions() -> BrokerVaultSessionManager {
        BrokerVaultSessionManager::new(Duration::from_secs(300)).expect("sessions")
    }

    #[test]
    fn reinstall_reopens_the_same_key_and_authenticated_state() {
        let (home, key_store, manager, state) = initialized("reinstall");
        state
            .set_apps_tools_paused(true, timestamp(200))
            .expect("persist pause");
        state
            .set_audit_retention_days(365, timestamp(210))
            .expect("persist retention");
        let original_key = key_store.bytes().expect("stored key");
        drop(state);

        let reopened = manager
            .reopen_after_reinstall(&home.paths)
            .expect("reopen after reinstall");

        assert!(reopened.apps_tools_paused().expect("pause"));
        assert_eq!(reopened.audit_retention_days().expect("retention"), 365);
        assert_eq!(key_store.bytes().expect("preserved key"), original_key);
    }

    #[test]
    fn reinstall_with_a_missing_key_fails_without_creating_a_replacement() {
        let home = TestHome::new("missing-key");
        let root_key =
            DeviceRootKey::from_stored_bytes(vec![9; DEVICE_ROOT_KEY_LENGTH]).expect("root key");
        let state = DeviceStateStore::initialize_new(&home.paths, &root_key, timestamp(100))
            .expect("initialize state");
        drop(state);
        let before = fs::read(home.database_path()).expect("database before");
        let key_store = MemoryKeyStore::default();
        let manager = BrokerLocalDataManager::new(key_store.clone());

        assert!(matches!(
            manager.reopen_after_reinstall(&home.paths),
            Err(BrokerLocalDataError::DeviceKey(DeviceKeyError::Missing))
        ));
        assert!(!key_store.contains_key());
        assert_eq!(
            fs::read(home.database_path()).expect("database after"),
            before
        );
    }

    #[test]
    fn confirmed_clear_removes_state_then_key_but_preserves_directories_and_vaults() {
        let (home, key_store, manager, state) = initialized("clear");
        let portable_vault = home.path.join("personal.pswvault");
        fs::create_dir(&portable_vault).expect("portable vault");
        let sessions = sessions();

        let summary = manager
            .clear_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                state,
                &home.paths,
            )
            .expect("clear local data");

        assert!(summary.authenticated_reset_preparation());
        assert!(summary.managed_state_files_removed() >= 1);
        assert!(summary.device_key_removed());
        assert!(sessions.is_shutdown().expect("shutdown"));
        assert!(!home.database_path().exists());
        assert!(!key_store.contains_key());
        assert!(home.paths.root().is_dir());
        assert!(home.paths.config().is_dir());
        assert!(home.paths.state().is_dir());
        assert!(home.paths.runtime().is_dir());
        assert!(home.paths.logs().is_dir());
        assert!(portable_vault.is_dir());
    }

    #[test]
    fn unsafe_state_refuses_clear_and_retains_the_device_key() {
        let (home, key_store, manager, state) = initialized("unsafe");
        drop(state);
        let target = home.paths.state().join("target.db");
        fs::rename(home.database_path(), &target).expect("move database");
        symlink(&target, home.database_path()).expect("symlink database");
        let sessions = sessions();

        let error = manager
            .clear_unopenable_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                &home.paths,
            )
            .expect_err("reject unsafe state");

        assert!(matches!(
            error,
            BrokerLocalDataError::DeviceState(DeviceStateError::SymbolicLink { .. })
        ));
        assert!(key_store.contains_key());
        assert!(target.exists());
    }

    #[test]
    fn keychain_failure_after_state_removal_is_explicit_and_retryable() {
        let (home, key_store, manager, state) = initialized("key-delete-retry");
        let sessions = sessions();
        key_store.fail_next_delete();

        let error = manager
            .clear_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                state,
                &home.paths,
            )
            .expect_err("key deletion must fail once");

        assert!(error.device_state_was_removed());
        assert!(error.managed_state_files_removed().expect("removed count") >= 1);
        assert!(!home.database_path().exists());
        assert!(key_store.contains_key());

        let retry = manager
            .clear_unopenable_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                &home.paths,
            )
            .expect("retry key deletion");
        assert_eq!(retry.managed_state_files_removed(), 0);
        assert!(retry.device_key_removed());
        assert!(!key_store.contains_key());
    }

    #[test]
    fn corrupt_missing_key_state_can_be_cleared_and_clear_is_idempotent() {
        let home = TestHome::new("corrupt-recovery");
        let database = home.database_path();
        fs::write(&database, [0x5a; 64]).expect("write corrupt state");
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
            .expect("protect corrupt state");
        let key_store = MemoryKeyStore::default();
        let manager = BrokerLocalDataManager::new(key_store.clone());
        let sessions = sessions();

        let first = manager
            .clear_unopenable_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                &home.paths,
            )
            .expect("clear corrupt state");
        assert!(!first.authenticated_reset_preparation());
        assert_eq!(first.managed_state_files_removed(), 1);
        assert!(!first.device_key_removed());
        assert!(!database.exists());

        let second = manager
            .clear_unopenable_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                &home.paths,
            )
            .expect("repeat clear");
        assert_eq!(second.managed_state_files_removed(), 0);
        assert!(!second.device_key_removed());
        assert!(!key_store.contains_key());
    }

    #[test]
    fn state_removal_failure_never_deletes_the_device_key() {
        let (home, key_store, manager, state) = initialized("state-failure");
        drop(state);
        fs::set_permissions(home.paths.state(), fs::Permissions::from_mode(0o500))
            .expect("make state directory invalid");
        let sessions = sessions();

        let error = manager
            .clear_unopenable_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                &home.paths,
            )
            .expect_err("reject invalid directory");

        assert!(matches!(
            error,
            BrokerLocalDataError::DeviceState(DeviceStateError::InsecurePermissions { .. })
        ));
        assert!(key_store.contains_key());
        fs::set_permissions(home.paths.state(), fs::Permissions::from_mode(0o700))
            .expect("restore state directory");
    }

    #[test]
    fn mismatched_open_store_never_removes_state_or_device_key() {
        let (home, key_store, manager, state) = initialized("path-mismatch-source");
        let other_home = TestHome::new("path-mismatch-target");
        let sessions = sessions();

        let error = manager
            .clear_local_data(
                BrokerLocalDataClearConfirmation::after_user_confirmation(),
                &sessions,
                state,
                &other_home.paths,
            )
            .expect_err("reject mismatched state root");

        assert!(matches!(
            error,
            BrokerLocalDataError::DeviceState(DeviceStateError::StorePathMismatch)
        ));
        assert!(home.database_path().exists());
        assert!(!other_home.database_path().exists());
        assert!(key_store.contains_key());
    }

    #[test]
    fn errors_never_render_local_paths_or_key_material() {
        let error = BrokerLocalDataError::DeviceState(DeviceStateError::Io {
            entry: crate::DeviceStateFileEntry::Database,
            operation: crate::DeviceStateFileOperation::Remove,
            kind: io::ErrorKind::PermissionDenied,
        });
        let rendered = error.to_string();

        assert!(!rendered.contains('/'));
        assert!(!rendered.contains("keptnear-local-data"));
        assert!(!rendered.contains("token"));
    }
}
