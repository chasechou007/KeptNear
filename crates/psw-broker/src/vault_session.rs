use std::fmt::{Debug, Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use psw_core::{
    CredentialId, CredentialSummary, LockedVault, OpenVaultRequest, SecretBytes, UnlockRequest,
    UnlockedVault, VaultCore, VaultError, VaultId,
};

use crate::VaultSessionId;

/// Default idle duration before an unlocked Broker vault session locks.
pub const DEFAULT_BROKER_AUTO_LOCK_TIMEOUT: Duration = Duration::from_secs(300);

const MAX_PENDING_LOCK_EVENTS: usize = 1024;

/// Sanitized core or filesystem operation involved in a vault-session failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerVaultSessionOperation {
    /// Resolve a user-selected vault path to one stable local path.
    ResolvePath,
    /// Open and validate encrypted vault metadata.
    Open,
    /// Authenticate unlock material and unwrap the vault key.
    Unlock,
    /// Read metadata for one already-authorized stable credential identity.
    ReadCredentialMetadata,
    /// Read one exact already-authorized Secret Field.
    ReadCredentialSecret,
    /// Start the process-local auto-lock worker.
    StartAutoLockWorker,
}

impl BrokerVaultSessionOperation {
    fn label(self) -> &'static str {
        match self {
            Self::ResolvePath => "resolve vault path",
            Self::Open => "open vault",
            Self::Unlock => "unlock vault",
            Self::ReadCredentialMetadata => "read credential metadata",
            Self::ReadCredentialSecret => "read credential secret",
            Self::StartAutoLockWorker => "start auto-lock worker",
        }
    }
}

/// Path-free failure returned by the Broker vault-session lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerVaultSessionError {
    /// The configured idle timeout is zero.
    InvalidAutoLockTimeout,
    /// The Broker session manager has completed shutdown.
    ShutDown,
    /// The requested vault is not tracked by this Broker process.
    VaultNotOpen,
    /// A machine-facing session cannot use a legacy vault without a stable ID.
    StableVaultIdentityRequired,
    /// The same stable vault identity is already tracked at another local path.
    VaultIdentityAlreadyOpen,
    /// A tracked local path now resolves to a different stable vault identity.
    VaultPathIdentityChanged,
    /// The requested vault is currently locked.
    VaultLocked,
    /// The requested vault already has an unlocked session.
    VaultAlreadyUnlocked,
    /// Another request is already unlocking this vault.
    VaultUnlockInProgress,
    /// The unlock result was superseded by lock, close, or shutdown.
    VaultUnlockCancelled,
    /// The supplied master password or local unlock material was rejected.
    InvalidCredentials,
    /// The vault format is newer than this Broker supports.
    UnsupportedVaultFormat,
    /// The vault structure or authenticated metadata is invalid.
    InvalidVault,
    /// A vault cryptographic operation failed without exposing source details.
    CryptographicFailure,
    /// The core operation is not available in this build.
    UnsupportedCoreOperation,
    /// The core returned a state that is invalid for this lifecycle operation.
    InvalidCoreState,
    /// A filesystem operation failed.
    Io {
        /// Sanitized operation that failed.
        operation: BrokerVaultSessionOperation,
        /// Operating-system error category without source text or path.
        kind: io::ErrorKind,
    },
    /// In-memory lifecycle state is unavailable after a synchronization failure.
    StateUnavailable,
    /// The auto-lock worker stopped unexpectedly.
    AutoLockWorkerUnavailable,
}

impl Display for BrokerVaultSessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAutoLockTimeout => {
                formatter.write_str("Broker auto-lock timeout must be greater than zero")
            }
            Self::ShutDown => formatter.write_str("Broker vault sessions are shut down"),
            Self::VaultNotOpen => formatter.write_str("Vault is not open in the Broker"),
            Self::StableVaultIdentityRequired => {
                formatter.write_str("Vault must be migrated before machine access")
            }
            Self::VaultIdentityAlreadyOpen => {
                formatter.write_str("Vault identity is already open at another local path")
            }
            Self::VaultPathIdentityChanged => {
                formatter.write_str("Open vault path no longer has the expected identity")
            }
            Self::VaultLocked => formatter.write_str("Vault is locked"),
            Self::VaultAlreadyUnlocked => formatter.write_str("Vault is already unlocked"),
            Self::VaultUnlockInProgress => {
                formatter.write_str("Vault unlock is already in progress")
            }
            Self::VaultUnlockCancelled => formatter.write_str("Vault unlock was cancelled"),
            Self::InvalidCredentials => formatter.write_str("Vault credentials were rejected"),
            Self::UnsupportedVaultFormat => {
                formatter.write_str("Vault format is not supported by this Broker")
            }
            Self::InvalidVault => formatter.write_str("Vault is invalid"),
            Self::CryptographicFailure => {
                formatter.write_str("Vault cryptographic operation failed")
            }
            Self::UnsupportedCoreOperation => {
                formatter.write_str("Vault operation is not supported by this build")
            }
            Self::InvalidCoreState => formatter.write_str("Vault core state is invalid"),
            Self::Io { operation, kind } => {
                write!(formatter, "{} failed: {kind}", operation.label())
            }
            Self::StateUnavailable => {
                formatter.write_str("Broker vault-session state is unavailable")
            }
            Self::AutoLockWorkerUnavailable => {
                formatter.write_str("Broker auto-lock worker is unavailable")
            }
        }
    }
}

impl std::error::Error for BrokerVaultSessionError {}

/// Non-secret lock state of one Broker-tracked vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerVaultLockState {
    /// Metadata is tracked but no vault key is held.
    Locked,
    /// A bounded core unlock operation is in progress without a published key.
    Unlocking,
    /// The Broker holds one in-memory unlocked core session.
    Unlocked,
}

/// Non-secret snapshot of one Broker-tracked vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerVaultSessionSnapshot {
    vault_id: VaultId,
    lock_state: BrokerVaultLockState,
    vault_session_id: Option<VaultSessionId>,
}

impl BrokerVaultSessionSnapshot {
    /// Returns the stable vault identity.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Returns whether this tracked vault is locked or unlocked.
    #[must_use]
    pub const fn lock_state(self) -> BrokerVaultLockState {
        self.lock_state
    }

    /// Returns the current unlock-session identity, if unlocked.
    #[must_use]
    pub const fn vault_session_id(self) -> Option<VaultSessionId> {
        self.vault_session_id
    }
}

/// Reason an unlocked Broker vault session ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerVaultLockReason {
    /// A human or trusted control-plane action requested lock.
    Manual,
    /// The configured idle duration elapsed.
    IdleTimeout,
    /// The tracked vault was explicitly closed.
    Closed,
    /// The Broker vault-session manager shut down.
    Shutdown,
}

/// Non-secret event emitted when an unlocked vault session ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerVaultLockEvent {
    vault_id: VaultId,
    vault_session_id: VaultSessionId,
    reason: BrokerVaultLockReason,
}

impl BrokerVaultLockEvent {
    /// Returns the stable identity of the locked vault.
    #[must_use]
    pub const fn vault_id(self) -> VaultId {
        self.vault_id
    }

    /// Returns the ended unlock-session identity.
    #[must_use]
    pub const fn vault_session_id(self) -> VaultSessionId {
        self.vault_session_id
    }

    /// Returns why the unlock session ended.
    #[must_use]
    pub const fn reason(self) -> BrokerVaultLockReason {
        self.reason
    }
}

/// Internal checkpoint for reliably invalidating grants after session lock.
pub(crate) struct BrokerVaultLockEventCheckpoint {
    events: Vec<BrokerVaultLockEvent>,
    overflowed: bool,
    overflow_generation: u64,
}

impl BrokerVaultLockEventCheckpoint {
    pub(crate) fn events(&self) -> &[BrokerVaultLockEvent] {
        &self.events
    }

    pub(crate) const fn overflowed(&self) -> bool {
        self.overflowed
    }
}

/// Process-owned lifecycle manager for machine-facing unlocked vault sessions.
///
/// Snapshots and errors intentionally omit vault paths, display names, and core
/// error text. The manager does not evaluate Consumer authorization.
pub struct BrokerVaultSessionManager {
    core: VaultCore,
    shared: Arc<BrokerVaultSessionShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl BrokerVaultSessionManager {
    /// Creates an empty session manager with a non-zero idle timeout.
    pub fn new(auto_lock_timeout: Duration) -> Result<Self, BrokerVaultSessionError> {
        validate_auto_lock_timeout(auto_lock_timeout)?;
        let shared = Arc::new(BrokerVaultSessionShared {
            state: Mutex::new(BrokerVaultSessionState {
                auto_lock_timeout,
                is_shutdown: false,
                vaults: Vec::new(),
                next_unlock_attempt: 0,
                in_flight_unlocks: 0,
                pending_lock_events: Vec::new(),
                lock_event_overflowed: false,
                lock_event_overflow_generation: 0,
            }),
            wake_worker: Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("keptnear-vault-auto-lock".to_owned())
            .spawn(move || auto_lock_worker(&worker_shared))
            .map_err(|error| BrokerVaultSessionError::Io {
                operation: BrokerVaultSessionOperation::StartAutoLockWorker,
                kind: error.kind(),
            })?;
        Ok(Self {
            core: VaultCore::new(),
            shared,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Returns the current auto-lock timeout.
    pub fn auto_lock_timeout(&self) -> Result<Duration, BrokerVaultSessionError> {
        let state = self.lock_state()?;
        ensure_running(&state)?;
        Ok(state.auto_lock_timeout)
    }

    /// Replaces the idle timeout and immediately locks sessions already over it.
    pub fn set_auto_lock_timeout(
        &self,
        auto_lock_timeout: Duration,
    ) -> Result<Vec<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        self.set_auto_lock_timeout_at(auto_lock_timeout, Instant::now())
    }

    /// Opens and tracks one current-format vault in locked state.
    pub fn open_vault(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        self.open_vault_internal(path.as_ref(), None)
    }

    /// Opens a vault only when its stable identity matches the trusted caller's
    /// already-authenticated identity.
    ///
    /// This is the control-plane entry point for synchronizing a human-unlocked
    /// vault into machine-facing Broker state. Neither the supplied path nor the
    /// expected identity is retained when validation fails.
    pub fn open_vault_with_expected_identity(
        &self,
        path: impl AsRef<Path>,
        expected_vault_id: VaultId,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        self.open_vault_internal(path.as_ref(), Some(expected_vault_id))
    }

    fn open_vault_internal(
        &self,
        path: &Path,
        expected_vault_id: Option<VaultId>,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        {
            let state = self.lock_state()?;
            ensure_running(&state)?;
        }
        let canonical_path =
            fs::canonicalize(path).map_err(|error| BrokerVaultSessionError::Io {
                operation: BrokerVaultSessionOperation::ResolvePath,
                kind: error.kind(),
            })?;
        let locked = self
            .core
            .open_vault(OpenVaultRequest {
                path: canonical_path.clone(),
            })
            .map_err(|error| map_core_error(BrokerVaultSessionOperation::Open, error))?;
        if let Some(expected_vault_id) = expected_vault_id {
            ensure_expected_vault_identity(&locked, expected_vault_id)?;
        }
        let vault_id = locked
            .metadata
            .vault_id
            .ok_or(BrokerVaultSessionError::StableVaultIdentityRequired)?;

        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        if let Some(existing) = state
            .vaults
            .iter()
            .find(|vault| vault.path == canonical_path)
        {
            if existing.vault_id != vault_id {
                return Err(BrokerVaultSessionError::VaultPathIdentityChanged);
            }
            return Ok(existing.snapshot());
        }
        if state.vaults.iter().any(|vault| vault.vault_id == vault_id) {
            return Err(BrokerVaultSessionError::VaultIdentityAlreadyOpen);
        }

        let managed = ManagedVault {
            path: canonical_path,
            vault_id,
            state: ManagedVaultState::Locked,
        };
        let snapshot = managed.snapshot();
        state.vaults.push(managed);
        Ok(snapshot)
    }

    /// Unlocks a tracked vault with a human-supplied master password.
    pub fn unlock_with_master_password(
        &self,
        vault_id: VaultId,
        master_password: SecretBytes,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        self.unlock_at(
            vault_id,
            BrokerVaultUnlockCredential::MasterPassword(master_password),
            Instant::now(),
        )
    }

    /// Unlocks a tracked vault with device-local convenience material.
    pub fn unlock_with_local_material(
        &self,
        vault_id: VaultId,
        local_unlock_material: SecretBytes,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        self.unlock_at(
            vault_id,
            BrokerVaultUnlockCredential::LocalMaterial(local_unlock_material),
            Instant::now(),
        )
    }

    /// Locks one tracked vault, returning an event only if it was unlocked.
    pub fn lock_vault(
        &self,
        vault_id: VaultId,
    ) -> Result<Option<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        let vault = find_vault_mut(&mut state, vault_id)?;
        let event = lock_managed_vault(vault, BrokerVaultLockReason::Manual);
        if let Some(event) = event {
            queue_lock_events(&mut state, &[event]);
        }
        drop(state);
        self.shared.wake_worker.notify_all();
        Ok(event)
    }

    /// Stops tracking one vault and ends its unlock session if needed.
    pub fn close_vault(
        &self,
        vault_id: VaultId,
    ) -> Result<Option<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        let index = state
            .vaults
            .iter()
            .position(|vault| vault.vault_id == vault_id)
            .ok_or(BrokerVaultSessionError::VaultNotOpen)?;
        let mut vault = state.vaults.remove(index);
        let event = lock_managed_vault(&mut vault, BrokerVaultLockReason::Closed);
        if let Some(event) = event {
            queue_lock_events(&mut state, &[event]);
        }
        drop(state);
        self.shared.wake_worker.notify_all();
        Ok(event)
    }

    /// Locks every session whose monotonic idle duration reached the timeout.
    pub fn lock_idle_vaults(&self) -> Result<Vec<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        self.lock_idle_vaults_at(Instant::now())
    }

    /// Returns the monotonic duration until the next unlocked session expires.
    pub fn next_auto_lock_in(&self) -> Result<Option<Duration>, BrokerVaultSessionError> {
        self.next_auto_lock_in_at(Instant::now())
    }

    /// Returns one non-secret tracked-vault snapshot.
    pub fn snapshot(
        &self,
        vault_id: VaultId,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        let state = self.lock_state()?;
        ensure_running(&state)?;
        state
            .vaults
            .iter()
            .find(|vault| vault.vault_id == vault_id)
            .map(ManagedVault::snapshot)
            .ok_or(BrokerVaultSessionError::VaultNotOpen)
    }

    /// Returns non-secret snapshots for every tracked vault.
    pub fn snapshots(&self) -> Result<Vec<BrokerVaultSessionSnapshot>, BrokerVaultSessionError> {
        let state = self.lock_state()?;
        ensure_running(&state)?;
        Ok(state.vaults.iter().map(ManagedVault::snapshot).collect())
    }

    pub(crate) fn lock_event_checkpoint(
        &self,
    ) -> Result<BrokerVaultLockEventCheckpoint, BrokerVaultSessionError> {
        let state = self.lock_state()?;
        Ok(BrokerVaultLockEventCheckpoint {
            events: state.pending_lock_events.clone(),
            overflowed: state.lock_event_overflowed,
            overflow_generation: state.lock_event_overflow_generation,
        })
    }

    pub(crate) fn acknowledge_lock_event_checkpoint(
        &self,
        checkpoint: BrokerVaultLockEventCheckpoint,
    ) -> Result<(), BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        state
            .pending_lock_events
            .retain(|event| !checkpoint.events.contains(event));
        if checkpoint.overflowed
            && state.lock_event_overflow_generation == checkpoint.overflow_generation
        {
            state.lock_event_overflowed = false;
        }
        Ok(())
    }

    /// Returns whether explicit shutdown has completed.
    pub fn is_shutdown(&self) -> Result<bool, BrokerVaultSessionError> {
        Ok(self.lock_state()?.is_shutdown)
    }

    /// Locks all unlocked vaults, drops tracked paths, and rejects future work.
    ///
    /// Repeated shutdown is idempotent and returns no additional events.
    pub fn shutdown(&self) -> Result<Vec<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        let mut events = Vec::new();
        if !state.is_shutdown {
            state.is_shutdown = true;
            for vault in &mut state.vaults {
                if let Some(event) = lock_managed_vault(vault, BrokerVaultLockReason::Shutdown) {
                    events.push(event);
                }
            }
            queue_lock_events(&mut state, &events);
            state.vaults.clear();
        }
        self.shared.wake_worker.notify_all();
        while state.in_flight_unlocks != 0 {
            state = self
                .shared
                .wake_worker
                .wait(state)
                .map_err(|_| BrokerVaultSessionError::StateUnavailable)?;
        }
        drop(state);
        self.join_worker()?;
        Ok(events)
    }

    /// Refreshes idle time after an accepted human or credential operation.
    ///
    /// Callers must not invoke this for rejected, unauthenticated, or polling
    /// requests because those requests must not keep a vault unlocked.
    pub fn record_credential_activity(
        &self,
        vault_id: VaultId,
    ) -> Result<(), BrokerVaultSessionError> {
        self.record_credential_activity_at(vault_id, Instant::now())
    }

    pub(crate) fn credential_summary(
        &self,
        vault_id: VaultId,
        vault_session_id: VaultSessionId,
        credential_id: CredentialId,
    ) -> Result<Option<CredentialSummary>, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        let managed = find_vault_mut(&mut state, vault_id)?;
        let result = match &mut managed.state {
            ManagedVaultState::Locked => return Err(BrokerVaultSessionError::VaultLocked),
            ManagedVaultState::Unlocking { .. } => {
                return Err(BrokerVaultSessionError::VaultUnlockInProgress);
            }
            ManagedVaultState::Unlocked {
                vault,
                vault_session_id: current_session_id,
                last_activity,
            } => {
                if *current_session_id != vault_session_id {
                    return Err(BrokerVaultSessionError::VaultLocked);
                }
                let result = vault.credential_summary(credential_id).map_err(|error| {
                    map_core_error(BrokerVaultSessionOperation::ReadCredentialMetadata, error)
                });
                if result.is_ok() {
                    *last_activity = Instant::now();
                }
                result
            }
        };
        drop(state);
        self.shared.wake_worker.notify_all();
        result
    }

    pub(crate) fn matching_credential_summaries(
        &self,
        vault_id: VaultId,
        vault_session_id: VaultSessionId,
        query: &str,
    ) -> Result<Vec<CredentialSummary>, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        let managed = find_vault_mut(&mut state, vault_id)?;
        let result = match &mut managed.state {
            ManagedVaultState::Locked => return Err(BrokerVaultSessionError::VaultLocked),
            ManagedVaultState::Unlocking { .. } => {
                return Err(BrokerVaultSessionError::VaultUnlockInProgress);
            }
            ManagedVaultState::Unlocked {
                vault,
                vault_session_id: current_session_id,
                last_activity,
            } => {
                if *current_session_id != vault_session_id {
                    return Err(BrokerVaultSessionError::VaultLocked);
                }
                let result = vault
                    .active_credential_summaries_matching(query)
                    .map_err(|error| {
                        map_core_error(BrokerVaultSessionOperation::ReadCredentialMetadata, error)
                    });
                if result.is_ok() {
                    *last_activity = Instant::now();
                }
                result
            }
        };
        drop(state);
        self.shared.wake_worker.notify_all();
        result
    }

    pub(crate) fn credential_secret_field(
        &self,
        vault_id: VaultId,
        vault_session_id: VaultSessionId,
        credential_id: CredentialId,
        secret_field_id: psw_core::SecretFieldId,
        expected_kind: psw_core::SecretFieldKind,
    ) -> Result<Option<SecretBytes>, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        let managed = find_vault_mut(&mut state, vault_id)?;
        let result = match &mut managed.state {
            ManagedVaultState::Locked => return Err(BrokerVaultSessionError::VaultLocked),
            ManagedVaultState::Unlocking { .. } => {
                return Err(BrokerVaultSessionError::VaultUnlockInProgress);
            }
            ManagedVaultState::Unlocked {
                vault,
                vault_session_id: current_session_id,
                last_activity,
            } => {
                if *current_session_id != vault_session_id {
                    return Err(BrokerVaultSessionError::VaultLocked);
                }
                let result = vault
                    .credential_secret_field(credential_id, secret_field_id, expected_kind)
                    .map_err(|error| {
                        map_core_error(BrokerVaultSessionOperation::ReadCredentialSecret, error)
                    });
                if result.is_ok() {
                    *last_activity = Instant::now();
                }
                result
            }
        };
        drop(state);
        self.shared.wake_worker.notify_all();
        result
    }

    fn set_auto_lock_timeout_at(
        &self,
        auto_lock_timeout: Duration,
        now: Instant,
    ) -> Result<Vec<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        validate_auto_lock_timeout(auto_lock_timeout)?;
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        state.auto_lock_timeout = auto_lock_timeout;
        let events = lock_idle_vaults_in_state(&mut state, now);
        queue_lock_events(&mut state, &events);
        drop(state);
        self.shared.wake_worker.notify_all();
        Ok(events)
    }

    fn unlock_at(
        &self,
        vault_id: VaultId,
        credential: BrokerVaultUnlockCredential,
        now: Instant,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        let (path, unlock_attempt) = {
            let mut state = self.lock_state()?;
            ensure_running(&state)?;
            let index = state
                .vaults
                .iter()
                .position(|vault| vault.vault_id == vault_id)
                .ok_or(BrokerVaultSessionError::VaultNotOpen)?;
            match state.vaults[index].state {
                ManagedVaultState::Locked => {}
                ManagedVaultState::Unlocking { .. } => {
                    return Err(BrokerVaultSessionError::VaultUnlockInProgress);
                }
                ManagedVaultState::Unlocked { .. } => {
                    return Err(BrokerVaultSessionError::VaultAlreadyUnlocked);
                }
            }
            let unlock_attempt = state.next_unlock_attempt;
            state.next_unlock_attempt = state
                .next_unlock_attempt
                .checked_add(1)
                .ok_or(BrokerVaultSessionError::StateUnavailable)?;
            state.in_flight_unlocks = state
                .in_flight_unlocks
                .checked_add(1)
                .ok_or(BrokerVaultSessionError::StateUnavailable)?;
            state.vaults[index].state = ManagedVaultState::Unlocking { unlock_attempt };
            (state.vaults[index].path.clone(), unlock_attempt)
        };
        self.shared.wake_worker.notify_all();
        let attempt = InFlightUnlock::new(Arc::clone(&self.shared), vault_id, unlock_attempt);

        let unlock_result = (|| {
            let locked = self
                .core
                .open_vault(OpenVaultRequest { path })
                .map_err(|error| map_core_error(BrokerVaultSessionOperation::Open, error))?;
            ensure_expected_vault_identity(&locked, vault_id)?;
            match credential {
                BrokerVaultUnlockCredential::MasterPassword(master_password) => locked
                    .unlock(UnlockRequest { master_password })
                    .map_err(|error| map_core_error(BrokerVaultSessionOperation::Unlock, error)),
                BrokerVaultUnlockCredential::LocalMaterial(local_unlock_material) => locked
                    .unlock_with_local_material(local_unlock_material)
                    .map_err(|error| map_core_error(BrokerVaultSessionOperation::Unlock, error)),
            }
        })();
        self.finish_unlock(attempt, unlock_result, now)
    }

    fn finish_unlock(
        &self,
        mut attempt: InFlightUnlock,
        unlock_result: Result<UnlockedVault, BrokerVaultSessionError>,
        now: Instant,
    ) -> Result<BrokerVaultSessionSnapshot, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        complete_in_flight_unlock(&mut state, &mut attempt)?;
        self.shared.wake_worker.notify_all();
        if state.is_shutdown {
            discard_unlock_result(unlock_result);
            return Err(BrokerVaultSessionError::ShutDown);
        }
        let Some(index) = state
            .vaults
            .iter()
            .position(|vault| vault.vault_id == attempt.vault_id)
        else {
            discard_unlock_result(unlock_result);
            return Err(BrokerVaultSessionError::VaultUnlockCancelled);
        };
        if !matches!(
            state.vaults[index].state,
            ManagedVaultState::Unlocking {
                unlock_attempt: current
            } if current == attempt.unlock_attempt
        ) {
            discard_unlock_result(unlock_result);
            return Err(BrokerVaultSessionError::VaultUnlockCancelled);
        }

        let unlocked = match unlock_result {
            Ok(unlocked) => unlocked,
            Err(error) => {
                state.vaults[index].state = ManagedVaultState::Locked;
                drop(state);
                self.shared.wake_worker.notify_all();
                return Err(error);
            }
        };
        let vault_session_id = VaultSessionId::generate();
        state.vaults[index].state = ManagedVaultState::Unlocked {
            vault: unlocked,
            vault_session_id,
            last_activity: now,
        };
        let snapshot = state.vaults[index].snapshot();
        drop(state);
        self.shared.wake_worker.notify_all();
        Ok(snapshot)
    }

    fn record_credential_activity_at(
        &self,
        vault_id: VaultId,
        now: Instant,
    ) -> Result<(), BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        let vault = find_vault_mut(&mut state, vault_id)?;
        let last_activity = match &mut vault.state {
            ManagedVaultState::Locked => return Err(BrokerVaultSessionError::VaultLocked),
            ManagedVaultState::Unlocking { .. } => {
                return Err(BrokerVaultSessionError::VaultUnlockInProgress);
            }
            ManagedVaultState::Unlocked { last_activity, .. } => last_activity,
        };
        *last_activity = now;
        drop(state);
        self.shared.wake_worker.notify_all();
        Ok(())
    }

    fn lock_idle_vaults_at(
        &self,
        now: Instant,
    ) -> Result<Vec<BrokerVaultLockEvent>, BrokerVaultSessionError> {
        let mut state = self.lock_state()?;
        ensure_running(&state)?;
        let events = lock_idle_vaults_in_state(&mut state, now);
        queue_lock_events(&mut state, &events);
        drop(state);
        self.shared.wake_worker.notify_all();
        Ok(events)
    }

    fn next_auto_lock_in_at(
        &self,
        now: Instant,
    ) -> Result<Option<Duration>, BrokerVaultSessionError> {
        let state = self.lock_state()?;
        ensure_running(&state)?;
        Ok(next_auto_lock_in_state(&state, now))
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, BrokerVaultSessionState>, BrokerVaultSessionError> {
        self.shared
            .state
            .lock()
            .map_err(|_| BrokerVaultSessionError::StateUnavailable)
    }

    fn join_worker(&self) -> Result<(), BrokerVaultSessionError> {
        let worker = self
            .worker
            .lock()
            .map_err(|_| BrokerVaultSessionError::StateUnavailable)?
            .take();
        if let Some(worker) = worker {
            worker
                .join()
                .map_err(|_| BrokerVaultSessionError::AutoLockWorkerUnavailable)?;
        }
        Ok(())
    }
}

impl Debug for BrokerVaultSessionManager {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerVaultSessionManager")
            .finish_non_exhaustive()
    }
}

impl Drop for BrokerVaultSessionManager {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.is_shutdown = true;
            for vault in &mut state.vaults {
                let _ = lock_managed_vault(vault, BrokerVaultLockReason::Shutdown);
            }
            state.vaults.clear();
        }
        self.shared.wake_worker.notify_all();
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                let _ = worker.join();
            }
        }
    }
}

struct BrokerVaultSessionShared {
    state: Mutex<BrokerVaultSessionState>,
    wake_worker: Condvar,
}

struct InFlightUnlock {
    shared: Arc<BrokerVaultSessionShared>,
    vault_id: VaultId,
    unlock_attempt: u64,
    active: bool,
}

impl InFlightUnlock {
    fn new(shared: Arc<BrokerVaultSessionShared>, vault_id: VaultId, unlock_attempt: u64) -> Self {
        Self {
            shared,
            vault_id,
            unlock_attempt,
            active: true,
        }
    }
}

impl Drop for InFlightUnlock {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut state) = self.shared.state.lock() {
            if let Some(vault) = state.vaults.iter_mut().find(|vault| {
                vault.vault_id == self.vault_id
                    && matches!(
                        vault.state,
                        ManagedVaultState::Unlocking {
                            unlock_attempt
                        } if unlock_attempt == self.unlock_attempt
                    )
            }) {
                vault.state = ManagedVaultState::Locked;
            }
            state.in_flight_unlocks = state.in_flight_unlocks.saturating_sub(1);
        }
        self.shared.wake_worker.notify_all();
    }
}

struct BrokerVaultSessionState {
    auto_lock_timeout: Duration,
    is_shutdown: bool,
    vaults: Vec<ManagedVault>,
    next_unlock_attempt: u64,
    in_flight_unlocks: usize,
    pending_lock_events: Vec<BrokerVaultLockEvent>,
    lock_event_overflowed: bool,
    lock_event_overflow_generation: u64,
}

struct ManagedVault {
    path: PathBuf,
    vault_id: VaultId,
    state: ManagedVaultState,
}

impl ManagedVault {
    fn snapshot(&self) -> BrokerVaultSessionSnapshot {
        match &self.state {
            ManagedVaultState::Locked => BrokerVaultSessionSnapshot {
                vault_id: self.vault_id,
                lock_state: BrokerVaultLockState::Locked,
                vault_session_id: None,
            },
            ManagedVaultState::Unlocking { .. } => BrokerVaultSessionSnapshot {
                vault_id: self.vault_id,
                lock_state: BrokerVaultLockState::Unlocking,
                vault_session_id: None,
            },
            ManagedVaultState::Unlocked {
                vault_session_id, ..
            } => BrokerVaultSessionSnapshot {
                vault_id: self.vault_id,
                lock_state: BrokerVaultLockState::Unlocked,
                vault_session_id: Some(*vault_session_id),
            },
        }
    }
}

enum ManagedVaultState {
    Locked,
    Unlocking {
        unlock_attempt: u64,
    },
    Unlocked {
        vault: UnlockedVault,
        vault_session_id: VaultSessionId,
        last_activity: Instant,
    },
}

enum BrokerVaultUnlockCredential {
    MasterPassword(SecretBytes),
    LocalMaterial(SecretBytes),
}

fn validate_auto_lock_timeout(auto_lock_timeout: Duration) -> Result<(), BrokerVaultSessionError> {
    if auto_lock_timeout.is_zero() {
        return Err(BrokerVaultSessionError::InvalidAutoLockTimeout);
    }
    Ok(())
}

fn ensure_running(state: &BrokerVaultSessionState) -> Result<(), BrokerVaultSessionError> {
    if state.is_shutdown {
        return Err(BrokerVaultSessionError::ShutDown);
    }
    Ok(())
}

fn auto_lock_worker(shared: &BrokerVaultSessionShared) {
    let Ok(mut state) = shared.state.lock() else {
        return;
    };
    loop {
        if state.is_shutdown {
            return;
        }

        let wait_duration = next_auto_lock_in_state(&state, Instant::now());
        state = match wait_duration {
            Some(duration) => {
                let Ok((state, _)) = shared.wake_worker.wait_timeout(state, duration) else {
                    return;
                };
                state
            }
            None => {
                let Ok(state) = shared.wake_worker.wait(state) else {
                    return;
                };
                state
            }
        };

        if state.is_shutdown {
            return;
        }
        let events = lock_idle_vaults_in_state(&mut state, Instant::now());
        queue_lock_events(&mut state, &events);
    }
}

fn next_auto_lock_in_state(state: &BrokerVaultSessionState, now: Instant) -> Option<Duration> {
    state
        .vaults
        .iter()
        .filter_map(|vault| match &vault.state {
            ManagedVaultState::Locked | ManagedVaultState::Unlocking { .. } => None,
            ManagedVaultState::Unlocked { last_activity, .. } => {
                let idle = now
                    .checked_duration_since(*last_activity)
                    .unwrap_or_default();
                Some(state.auto_lock_timeout.saturating_sub(idle))
            }
        })
        .min()
}

fn queue_lock_events(state: &mut BrokerVaultSessionState, events: &[BrokerVaultLockEvent]) {
    for event in events {
        if state.pending_lock_events.len() < MAX_PENDING_LOCK_EVENTS {
            state.pending_lock_events.push(*event);
        } else {
            state.lock_event_overflowed = true;
            state.lock_event_overflow_generation =
                state.lock_event_overflow_generation.saturating_add(1);
        }
    }
}

fn find_vault_mut(
    state: &mut BrokerVaultSessionState,
    vault_id: VaultId,
) -> Result<&mut ManagedVault, BrokerVaultSessionError> {
    state
        .vaults
        .iter_mut()
        .find(|vault| vault.vault_id == vault_id)
        .ok_or(BrokerVaultSessionError::VaultNotOpen)
}

fn ensure_expected_vault_identity(
    locked: &LockedVault,
    expected_vault_id: VaultId,
) -> Result<(), BrokerVaultSessionError> {
    match locked.metadata.vault_id {
        Some(vault_id) if vault_id == expected_vault_id => Ok(()),
        Some(_) => Err(BrokerVaultSessionError::VaultPathIdentityChanged),
        None => Err(BrokerVaultSessionError::StableVaultIdentityRequired),
    }
}

fn lock_idle_vaults_in_state(
    state: &mut BrokerVaultSessionState,
    now: Instant,
) -> Vec<BrokerVaultLockEvent> {
    let timeout = state.auto_lock_timeout;
    let mut events = Vec::new();
    for vault in &mut state.vaults {
        let should_lock = match &vault.state {
            ManagedVaultState::Locked | ManagedVaultState::Unlocking { .. } => false,
            ManagedVaultState::Unlocked { last_activity, .. } => {
                now.checked_duration_since(*last_activity)
                    .unwrap_or_default()
                    >= timeout
            }
        };
        if should_lock {
            if let Some(event) = lock_managed_vault(vault, BrokerVaultLockReason::IdleTimeout) {
                events.push(event);
            }
        }
    }
    events
}

fn lock_managed_vault(
    vault: &mut ManagedVault,
    reason: BrokerVaultLockReason,
) -> Option<BrokerVaultLockEvent> {
    let previous = std::mem::replace(&mut vault.state, ManagedVaultState::Locked);
    let ManagedVaultState::Unlocked {
        vault: unlocked,
        vault_session_id,
        ..
    } = previous
    else {
        return None;
    };
    drop(unlocked.lock());
    Some(BrokerVaultLockEvent {
        vault_id: vault.vault_id,
        vault_session_id,
        reason,
    })
}

fn discard_unlock_result(result: Result<UnlockedVault, BrokerVaultSessionError>) {
    if let Ok(unlocked) = result {
        drop(unlocked.lock());
    }
}

fn complete_in_flight_unlock(
    state: &mut BrokerVaultSessionState,
    attempt: &mut InFlightUnlock,
) -> Result<(), BrokerVaultSessionError> {
    if !attempt.active || state.in_flight_unlocks == 0 {
        return Err(BrokerVaultSessionError::StateUnavailable);
    }
    state.in_flight_unlocks -= 1;
    attempt.active = false;
    Ok(())
}

fn map_core_error(
    operation: BrokerVaultSessionOperation,
    error: VaultError,
) -> BrokerVaultSessionError {
    match error {
        VaultError::Io { source, .. } => BrokerVaultSessionError::Io {
            operation,
            kind: source.kind(),
        },
        VaultError::UnsupportedFormat { .. } => BrokerVaultSessionError::UnsupportedVaultFormat,
        VaultError::InvalidCredentials => BrokerVaultSessionError::InvalidCredentials,
        VaultError::InvalidVault { .. } => BrokerVaultSessionError::InvalidVault,
        VaultError::Crypto { .. } => BrokerVaultSessionError::CryptographicFailure,
        VaultError::NotImplemented { .. } => BrokerVaultSessionError::UnsupportedCoreOperation,
        VaultError::Locked | VaultError::ItemNotFound { .. } => {
            BrokerVaultSessionError::InvalidCoreState
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use psw_core::{CreateVaultRequest, OpenVaultRequest, UnlockRequest, VaultCore, VaultMetadata};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn default_manager() -> BrokerVaultSessionManager {
        BrokerVaultSessionManager::new(DEFAULT_BROKER_AUTO_LOCK_TIMEOUT).expect("manager")
    }

    struct TestVault {
        root: PathBuf,
        path: PathBuf,
        vault_id: VaultId,
        password: SecretBytes,
    }

    impl TestVault {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "keptnear-broker-session-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("test root");
            let path = root.join("Test.pswvault");
            let password = SecretBytes::new(b"correct horse battery staple".to_vec());
            let locked = VaultCore::new()
                .create_vault(CreateVaultRequest {
                    path: path.clone(),
                    display_name: Some("Broker session fixture".to_owned()),
                    master_password: password.clone(),
                })
                .expect("create vault");
            let vault_id = locked.metadata.vault_id.expect("current vault ID");
            Self {
                root,
                path,
                vault_id,
                password,
            }
        }

        fn replace_metadata(&self, metadata: &VaultMetadata) {
            let encoded = serde_json::to_vec_pretty(metadata).expect("encode metadata");
            fs::write(self.path.join("vault.json"), encoded).expect("replace metadata");
        }
    }

    impl Drop for TestVault {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("copy directory");
        for entry in fs::read_dir(source).expect("read source") {
            let entry = entry.expect("source entry");
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if entry.file_type().expect("entry type").is_dir() {
                copy_tree(&source_path, &destination_path);
            } else {
                fs::copy(source_path, destination_path).expect("copy file");
            }
        }
    }

    #[test]
    fn open_requires_current_stable_identity_and_returns_no_path_metadata() {
        let vault = TestVault::new("open");
        let manager = default_manager();
        let snapshot = manager.open_vault(&vault.path).expect("open");
        assert_eq!(snapshot.vault_id(), vault.vault_id);
        assert_eq!(snapshot.lock_state(), BrokerVaultLockState::Locked);
        assert_eq!(snapshot.vault_session_id(), None);
        assert_eq!(manager.open_vault(&vault.path).expect("reopen"), snapshot);

        let legacy = TestVault::new("legacy");
        let mut metadata = serde_json::from_slice::<VaultMetadata>(
            &fs::read(legacy.path.join("vault.json")).unwrap(),
        )
        .expect("metadata");
        metadata.vault_format_version = 1;
        metadata.record_format_version = 1;
        metadata.vault_id = None;
        legacy.replace_metadata(&metadata);
        assert_eq!(
            manager.open_vault(&legacy.path),
            Err(BrokerVaultSessionError::StableVaultIdentityRequired)
        );
    }

    #[test]
    fn wrong_password_leaves_vault_locked_and_new_unlocks_rotate_session_identity() {
        let vault = TestVault::new("unlock");
        let manager = default_manager();
        manager.open_vault(&vault.path).expect("open");
        assert_eq!(
            manager.unlock_with_master_password(
                vault.vault_id,
                SecretBytes::new(b"wrong password".to_vec()),
            ),
            Err(BrokerVaultSessionError::InvalidCredentials)
        );
        assert_eq!(
            manager
                .snapshot(vault.vault_id)
                .expect("snapshot")
                .lock_state(),
            BrokerVaultLockState::Locked
        );

        let first = manager
            .unlock_with_master_password(vault.vault_id, vault.password.clone())
            .expect("unlock");
        let first_session = first.vault_session_id().expect("session");
        assert_eq!(
            manager.unlock_with_master_password(
                vault.vault_id,
                SecretBytes::new(b"ignored while unlocked".to_vec()),
            ),
            Err(BrokerVaultSessionError::VaultAlreadyUnlocked)
        );

        let lock = manager
            .lock_vault(vault.vault_id)
            .expect("lock")
            .expect("lock event");
        assert_eq!(lock.vault_session_id(), first_session);
        assert_eq!(lock.reason(), BrokerVaultLockReason::Manual);
        assert_eq!(manager.lock_vault(vault.vault_id).expect("repeat"), None);

        let second = manager
            .unlock_with_master_password(vault.vault_id, vault.password.clone())
            .expect("unlock again");
        assert_ne!(second.vault_session_id(), Some(first_session));
    }

    #[test]
    fn duplicate_identity_at_another_path_fails_closed_without_exposing_paths() {
        let original = TestVault::new("identity-original");
        let duplicate_path = original.root.join("Duplicate.pswvault");
        let copy_report = VaultCore::new()
            .open_vault(OpenVaultRequest {
                path: original.path.clone(),
            })
            .expect("open original for portable copy")
            .unlock(UnlockRequest {
                master_password: original.password.clone(),
            })
            .expect("unlock original for portable copy")
            .backup_to(duplicate_path.clone())
            .expect("create portable duplicate");
        assert_eq!(copy_report.copied_item_files, 0);
        assert_eq!(
            VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: duplicate_path.clone(),
                })
                .expect("open portable duplicate")
                .metadata
                .vault_id,
            Some(original.vault_id)
        );
        let manager = default_manager();
        let original_snapshot = manager.open_vault(&original.path).expect("open original");
        let error = manager
            .open_vault_with_expected_identity(&duplicate_path, original.vault_id)
            .expect_err("reject duplicate identity");
        assert_eq!(error, BrokerVaultSessionError::VaultIdentityAlreadyOpen);
        for path in [&original.path, &duplicate_path] {
            let marker = path.to_string_lossy();
            assert!(!error.to_string().contains(marker.as_ref()));
            assert!(!format!("{error:?}").contains(marker.as_ref()));
        }
        assert_eq!(manager.snapshots().expect("snapshots"), [original_snapshot]);
        let state = manager.lock_state().expect("state");
        assert_eq!(state.vaults.len(), 1);
        assert_eq!(
            state.vaults[0].path,
            fs::canonicalize(&original.path).expect("canonical original")
        );
    }

    #[test]
    fn expected_identity_mismatch_and_replaced_path_do_not_change_tracking() {
        let original = TestVault::new("identity-original");
        let replacement = TestVault::new("identity-replacement");
        let manager = default_manager();
        assert_eq!(
            manager.open_vault_with_expected_identity(&replacement.path, original.vault_id),
            Err(BrokerVaultSessionError::VaultPathIdentityChanged)
        );
        assert!(manager
            .snapshots()
            .expect("no inserted mismatch")
            .is_empty());

        let original_snapshot = manager
            .open_vault_with_expected_identity(&original.path, original.vault_id)
            .expect("open expected original");
        fs::remove_dir_all(&original.path).expect("remove original");
        copy_tree(&replacement.path, &original.path);
        let error = manager
            .open_vault_with_expected_identity(&original.path, original.vault_id)
            .expect_err("reject replaced path");
        assert_eq!(error, BrokerVaultSessionError::VaultPathIdentityChanged);
        for path in [&original.path, &replacement.path] {
            let marker = path.to_string_lossy();
            assert!(!error.to_string().contains(marker.as_ref()));
            assert!(!format!("{error:?}").contains(marker.as_ref()));
        }
        assert_eq!(manager.snapshots().expect("snapshots"), [original_snapshot]);
    }

    #[test]
    fn concurrent_unlock_creates_exactly_one_session() {
        use std::sync::Barrier;

        let vault = TestVault::new("concurrent-unlock");
        let manager = Arc::new(default_manager());
        manager.open_vault(&vault.path).expect("open");
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            let password = vault.password.clone();
            let vault_id = vault.vault_id;
            workers.push(thread::spawn(move || {
                barrier.wait();
                manager.unlock_with_master_password(vault_id, password)
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("unlock worker"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Err(BrokerVaultSessionError::VaultUnlockInProgress
                            | BrokerVaultSessionError::VaultAlreadyUnlocked)
                    )
                })
                .count(),
            1
        );
    }

    #[test]
    fn manual_lock_cancels_an_unpublished_unlock_result() {
        let vault = TestVault::new("cancel-unlock");
        let unlocked = VaultCore::new()
            .open_vault(OpenVaultRequest {
                path: vault.path.clone(),
            })
            .expect("open")
            .unlock(UnlockRequest {
                master_password: vault.password.clone(),
            })
            .expect("unlock");
        let manager = default_manager();
        manager.open_vault(&vault.path).expect("Broker open");
        let unlock_attempt = 41;
        {
            let mut state = manager.lock_state().expect("state");
            find_vault_mut(&mut state, vault.vault_id)
                .expect("tracked")
                .state = ManagedVaultState::Unlocking { unlock_attempt };
            state.in_flight_unlocks = 1;
        }

        assert_eq!(manager.lock_vault(vault.vault_id).expect("cancel"), None);
        let attempt =
            InFlightUnlock::new(Arc::clone(&manager.shared), vault.vault_id, unlock_attempt);
        assert_eq!(
            manager.finish_unlock(attempt, Ok(unlocked), Instant::now()),
            Err(BrokerVaultSessionError::VaultUnlockCancelled)
        );
        assert_eq!(
            manager
                .snapshot(vault.vault_id)
                .expect("snapshot")
                .lock_state(),
            BrokerVaultLockState::Locked
        );
    }

    #[test]
    fn shutdown_waits_until_in_flight_unlock_result_is_discarded() {
        let vault = TestVault::new("shutdown-in-flight");
        let unlocked = VaultCore::new()
            .open_vault(OpenVaultRequest {
                path: vault.path.clone(),
            })
            .expect("open")
            .unlock(UnlockRequest {
                master_password: vault.password.clone(),
            })
            .expect("unlock");
        let manager = Arc::new(default_manager());
        manager.open_vault(&vault.path).expect("Broker open");
        let unlock_attempt = 73;
        {
            let mut state = manager.lock_state().expect("state");
            find_vault_mut(&mut state, vault.vault_id)
                .expect("tracked")
                .state = ManagedVaultState::Unlocking { unlock_attempt };
            state.in_flight_unlocks = 1;
        }
        let attempt =
            InFlightUnlock::new(Arc::clone(&manager.shared), vault.vault_id, unlock_attempt);
        let shutdown_manager = Arc::clone(&manager);
        let shutdown = thread::spawn(move || shutdown_manager.shutdown());

        let deadline = Instant::now() + Duration::from_secs(2);
        while !manager.is_shutdown().expect("shutdown state") {
            assert!(Instant::now() < deadline, "shutdown did not begin");
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            manager.finish_unlock(attempt, Ok(unlocked), Instant::now()),
            Err(BrokerVaultSessionError::ShutDown)
        );
        assert!(shutdown
            .join()
            .expect("shutdown thread")
            .expect("shutdown")
            .is_empty());
    }

    #[test]
    fn local_unlock_material_uses_the_same_session_boundary() {
        let vault = TestVault::new("local-material");
        let unlocked = VaultCore::new()
            .open_vault(OpenVaultRequest {
                path: vault.path.clone(),
            })
            .expect("open")
            .unlock(UnlockRequest {
                master_password: vault.password.clone(),
            })
            .expect("unlock");
        let local_material = unlocked.local_unlock_material().expect("local material");
        drop(unlocked.lock());

        let manager = default_manager();
        manager.open_vault(&vault.path).expect("open in Broker");
        let outcome = manager
            .unlock_with_local_material(vault.vault_id, local_material)
            .expect("local unlock");
        assert_eq!(outcome.lock_state(), BrokerVaultLockState::Unlocked);
    }

    #[test]
    fn monotonic_activity_and_timeout_changes_drive_auto_lock() {
        let vault = TestVault::new("auto-lock");
        let manager = BrokerVaultSessionManager::new(Duration::from_secs(10)).expect("manager");
        manager.open_vault(&vault.path).expect("open");
        let start = Instant::now();
        let unlocked = manager
            .unlock_at(
                vault.vault_id,
                BrokerVaultUnlockCredential::MasterPassword(vault.password.clone()),
                start,
            )
            .expect("unlock");
        let session_id = unlocked.vault_session_id().expect("session");
        assert_eq!(
            manager
                .next_auto_lock_in_at(start + Duration::from_secs(3))
                .expect("deadline"),
            Some(Duration::from_secs(7))
        );

        manager
            .record_credential_activity_at(vault.vault_id, start + Duration::from_secs(4))
            .expect("activity");
        assert!(manager
            .lock_idle_vaults_at(start + Duration::from_secs(10))
            .expect("sweep")
            .is_empty());
        let events = manager
            .set_auto_lock_timeout_at(Duration::from_secs(5), start + Duration::from_secs(10))
            .expect("shorten timeout");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].vault_session_id(), session_id);
        assert_eq!(events[0].reason(), BrokerVaultLockReason::IdleTimeout);
        assert_eq!(manager.next_auto_lock_in().expect("deadline"), None);
        assert_eq!(
            manager.record_credential_activity(vault.vault_id),
            Err(BrokerVaultSessionError::VaultLocked)
        );
    }

    #[test]
    fn background_worker_locks_without_incoming_requests_and_queues_event() {
        let vault = TestVault::new("background-auto-lock");
        let manager = BrokerVaultSessionManager::new(Duration::from_millis(40)).expect("manager");
        manager.open_vault(&vault.path).expect("open");
        let unlocked = manager
            .unlock_with_master_password(vault.vault_id, vault.password.clone())
            .expect("unlock");
        let session_id = unlocked.vault_session_id().expect("session");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if manager
                .snapshot(vault.vault_id)
                .expect("snapshot")
                .lock_state()
                == BrokerVaultLockState::Locked
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "background auto-lock did not fire"
            );
            thread::sleep(Duration::from_millis(5));
        }

        let checkpoint = manager.lock_event_checkpoint().expect("events");
        assert!(!checkpoint.overflowed());
        assert_eq!(checkpoint.events().len(), 1);
        assert_eq!(checkpoint.events()[0].vault_session_id(), session_id);
        assert_eq!(
            checkpoint.events()[0].reason(),
            BrokerVaultLockReason::IdleTimeout
        );
        manager
            .acknowledge_lock_event_checkpoint(checkpoint)
            .expect("acknowledge");
        assert!(manager
            .lock_event_checkpoint()
            .expect("acknowledged")
            .events()
            .is_empty());
    }

    #[test]
    fn lock_event_checkpoint_is_retryable_and_preserves_newer_events() {
        let vault = TestVault::new("lock-event-checkpoint");
        let manager = default_manager();
        manager.open_vault(&vault.path).expect("open");
        let first_session = manager
            .unlock_with_master_password(vault.vault_id, vault.password.clone())
            .expect("first unlock")
            .vault_session_id()
            .expect("first session");
        manager.lock_vault(vault.vault_id).expect("first lock");

        let first_checkpoint = manager.lock_event_checkpoint().expect("first checkpoint");
        assert_eq!(first_checkpoint.events().len(), 1);
        assert_eq!(
            first_checkpoint.events()[0].vault_session_id(),
            first_session
        );
        assert_eq!(
            manager
                .lock_event_checkpoint()
                .expect("retry checkpoint")
                .events(),
            first_checkpoint.events()
        );

        let second_session = manager
            .unlock_with_master_password(vault.vault_id, vault.password.clone())
            .expect("second unlock")
            .vault_session_id()
            .expect("second session");
        manager.lock_vault(vault.vault_id).expect("second lock");
        manager
            .acknowledge_lock_event_checkpoint(first_checkpoint)
            .expect("acknowledge first");

        let second_checkpoint = manager.lock_event_checkpoint().expect("second checkpoint");
        assert_eq!(second_checkpoint.events().len(), 1);
        assert_eq!(
            second_checkpoint.events()[0].vault_session_id(),
            second_session
        );
    }

    #[test]
    fn lock_event_queue_is_bounded_and_new_overflow_survives_old_acknowledgement() {
        let event = BrokerVaultLockEvent {
            vault_id: VaultId::generate(),
            vault_session_id: VaultSessionId::generate(),
            reason: BrokerVaultLockReason::IdleTimeout,
        };
        let manager = default_manager();
        {
            let mut state = manager.lock_state().expect("state");
            queue_lock_events(&mut state, &vec![event; MAX_PENDING_LOCK_EVENTS + 1]);
            assert_eq!(state.pending_lock_events.len(), MAX_PENDING_LOCK_EVENTS);
            assert!(state.lock_event_overflowed);
        }

        let checkpoint = manager.lock_event_checkpoint().expect("checkpoint");
        assert!(checkpoint.overflowed());
        {
            let mut state = manager.lock_state().expect("state");
            queue_lock_events(&mut state, &[event]);
        }
        manager
            .acknowledge_lock_event_checkpoint(checkpoint)
            .expect("acknowledge");

        let remaining = manager.lock_event_checkpoint().expect("remaining");
        assert!(remaining.events().is_empty());
        assert!(remaining.overflowed());
    }

    #[test]
    fn close_and_shutdown_drop_sessions_and_are_idempotent() {
        let first = TestVault::new("close");
        let second = TestVault::new("shutdown");
        let manager = default_manager();
        manager.open_vault(&first.path).expect("open first");
        manager
            .unlock_with_master_password(first.vault_id, first.password.clone())
            .expect("unlock first");
        let closed = manager
            .close_vault(first.vault_id)
            .expect("close")
            .expect("close event");
        assert_eq!(closed.reason(), BrokerVaultLockReason::Closed);
        assert_eq!(
            manager.snapshot(first.vault_id),
            Err(BrokerVaultSessionError::VaultNotOpen)
        );

        manager.open_vault(&second.path).expect("open second");
        manager
            .unlock_with_master_password(second.vault_id, second.password.clone())
            .expect("unlock second");
        let shutdown = manager.shutdown().expect("shutdown");
        assert_eq!(shutdown.len(), 1);
        assert_eq!(shutdown[0].reason(), BrokerVaultLockReason::Shutdown);
        assert!(manager.is_shutdown().expect("shutdown state"));
        assert!(manager.shutdown().expect("repeat shutdown").is_empty());
        assert_eq!(
            manager.open_vault(&first.path),
            Err(BrokerVaultSessionError::ShutDown)
        );
        assert_eq!(
            manager.snapshot(second.vault_id),
            Err(BrokerVaultSessionError::ShutDown)
        );
    }

    #[test]
    fn lifecycle_errors_and_debug_output_do_not_retain_paths_or_secrets() {
        let marker = "session-path-secret-marker";
        let path = std::env::temp_dir().join(marker).join("missing.pswvault");
        let manager = default_manager();
        let error = manager.open_vault(path).expect_err("missing path");
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
        assert!(!format!("{manager:?}").contains(marker));

        let invalid_vault = map_core_error(
            BrokerVaultSessionOperation::Open,
            VaultError::InvalidVault {
                reason: marker.to_owned(),
            },
        );
        let io_error = map_core_error(
            BrokerVaultSessionOperation::Unlock,
            VaultError::io(
                "sensitive operation",
                io::Error::new(io::ErrorKind::PermissionDenied, marker),
            ),
        );
        for error in [invalid_vault, io_error] {
            assert!(!error.to_string().contains(marker));
            assert!(!format!("{error:?}").contains(marker));
        }
        assert_eq!(
            BrokerVaultSessionManager::new(Duration::ZERO).expect_err("zero timeout"),
            BrokerVaultSessionError::InvalidAutoLockTimeout
        );
    }
}
