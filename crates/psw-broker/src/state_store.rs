use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use hkdf::Hkdf;
use psw_core::{CredentialId, VaultId};
use rusqlite::ffi::ErrorCode;
use rusqlite::types::{Type, ValueRef};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::audit::{BrokerAuditCursor, BrokerAuditFilter};
use crate::controller_authority_contract::{
    derive_controller_id, CONTROLLER_AUTHORITY_CONTRACT_ID, CONTROLLER_SIGNING_ALGORITHM,
};
use crate::controller_key::ControllerAuthorityRecord;
use crate::device_key::DeviceRootKey;
use crate::paths::DevicePaths;
use crate::sqlcipher_ffi;
use crate::state_model::{
    AccessRule, AccessRuleId, ApprovalKind, ApprovalRequest, ApprovalRequestId, ApprovalStatus,
    ApprovalSubject, AuditDecision, AuditEvent, AuditEventKind, AuditScope, AuthorizationTarget,
    Capability, Consumer, ConsumerId, CredentialFieldScope, DeviceStateValidationError, GrantScope,
    LocalIdParseError, ObservedConsumerIdentity, RuleLifetime, StateTimestamp, UsagePlacement,
    UsageProfile, UsageProfileId, UseGrant, UseGrantId, VaultSessionId,
    CURRENT_USAGE_PROFILE_DEFINITION_VERSION,
};
use crate::state_schema::{
    CREATE_SCHEMA_V1, CURRENT_DEVICE_SCHEMA_VERSION, MIGRATE_SCHEMA_V1_TO_V2, REQUIRED_TABLES,
    REQUIRED_TABLES_V1,
};
use crate::ControllerId;

/// Stable filename of the encrypted device-state database.
pub const DEVICE_STATE_DATABASE_FILENAME: &str = "device-v1.db";
/// SQLCipher major version accepted by the device-state format.
pub const DEVICE_STATE_SQLCIPHER_MAJOR: u16 = 4;
/// Initial local audit retention setting.
pub const DEFAULT_AUDIT_RETENTION_DAYS: u16 = 90;
/// Shortest configurable local audit retention period.
pub const MIN_AUDIT_RETENTION_DAYS: u16 = 1;
/// Longest configurable local audit retention period.
pub const MAX_AUDIT_RETENTION_DAYS: u16 = 3_650;
/// Absolute event-count bound applied in addition to time-based retention.
pub const MAX_RETAINED_AUDIT_EVENTS: usize = 10_000;

const DATABASE_KEY_DOMAIN: &[u8] = b"KeptNear device state SQLCipher v1";
const APPROVAL_DIGEST_KEY_DOMAIN: &[u8] = b"KeptNear approval coalescing key v1";
const RAW_KEY_LITERAL_LENGTH: usize = 2 + 64 + 1;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const SQLITE_PLAINTEXT_HEADER: &[u8; 16] = b"SQLite format 3\0";
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AUDIT_QUERY_LIMIT: usize = 1_000;
const AUDIT_RETENTION_DAY_MILLIS: i64 = 86_400_000;

/// Logical encrypted-state file involved in a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStateFileEntry {
    /// The private `state` directory.
    StateDirectory,
    /// The encrypted main database.
    Database,
    /// The encrypted write-ahead log.
    WriteAheadLog,
    /// The SQLite shared-memory coordination file.
    SharedMemory,
}

impl DeviceStateFileEntry {
    fn label(self) -> &'static str {
        match self {
            Self::StateDirectory => "device state directory",
            Self::Database => "device state database",
            Self::WriteAheadLog => "device state write-ahead log",
            Self::SharedMemory => "device state shared-memory file",
        }
    }
}

/// Sanitized filesystem operation attempted for encrypted device state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStateFileOperation {
    /// Inspect an existing entry without following symbolic links.
    Inspect,
    /// Create a new private database file.
    Create,
    /// Read the encrypted database header.
    ReadHeader,
    /// Apply owner-only file permissions.
    SetPermissions,
    /// Remove one managed encrypted-state file.
    Remove,
    /// Flush a managed directory entry update to durable storage.
    Sync,
}

impl DeviceStateFileOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Create => "create",
            Self::ReadHeader => "read header from",
            Self::SetPermissions => "set permissions on",
            Self::Remove => "remove",
            Self::Sync => "sync",
        }
    }
}

/// Logical SQLCipher operation involved in a sanitized database error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStateDatabaseOperation {
    /// Open the prevalidated database file.
    Open,
    /// Apply the derived raw database key.
    Key,
    /// Configure the encrypted connection.
    Configure,
    /// Authenticate encrypted pages and schema.
    Authenticate,
    /// Create the first schema transaction.
    InitializeSchema,
    /// Verify the expected schema.
    VerifySchema,
    /// Read a device-state record.
    Read,
    /// Write a device-state record.
    Write,
    /// Close the authenticated database before destructive removal.
    Close,
}

impl DeviceStateDatabaseOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Key => "key",
            Self::Configure => "configure",
            Self::Authenticate => "authenticate",
            Self::InitializeSchema => "initialize schema for",
            Self::VerifySchema => "verify schema for",
            Self::Read => "read",
            Self::Write => "write",
            Self::Close => "close",
        }
    }
}

/// Value-free category for a SQLCipher or SQLite failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStateDatabaseErrorCategory {
    /// Another local connection currently owns the required lock.
    Busy,
    /// A database constraint rejected the operation.
    Constraint,
    /// The database is corrupt or structurally inconsistent.
    Corrupt,
    /// The database or storage is unavailable.
    Unavailable,
    /// The operation failed without a more specific safe category.
    Other,
}

/// Fail-closed encrypted device-state error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceStateError {
    /// Device state has already been initialized.
    AlreadyInitialized,
    /// No encrypted device-state database exists.
    Missing,
    /// An open store was not created from the requested canonical state root.
    StorePathMismatch,
    /// The platform does not provide required Unix file guarantees.
    UnsupportedPlatform,
    /// A managed state entry is a symbolic link.
    SymbolicLink {
        /// Rejected logical entry.
        entry: DeviceStateFileEntry,
    },
    /// A managed state entry has an unexpected filesystem type.
    UnexpectedFileType {
        /// Rejected logical entry.
        entry: DeviceStateFileEntry,
    },
    /// A managed state entry belongs to another operating-system user.
    UnexpectedOwner {
        /// Rejected logical entry.
        entry: DeviceStateFileEntry,
    },
    /// A managed state entry is broader than its required owner-only mode.
    InsecurePermissions {
        /// Rejected logical entry.
        entry: DeviceStateFileEntry,
        /// Observed permission bits.
        mode: u32,
    },
    /// A removal call returned, but the managed entry remained present.
    RemovalVerificationFailed {
        /// Logical entry that remained present.
        entry: DeviceStateFileEntry,
    },
    /// An I/O operation failed with a sanitized category.
    Io {
        /// Logical entry involved.
        entry: DeviceStateFileEntry,
        /// Attempted operation.
        operation: DeviceStateFileOperation,
        /// Sanitized operating-system error category.
        kind: io::ErrorKind,
    },
    /// An existing database is empty or shorter than an encrypted header.
    TruncatedDatabase,
    /// An existing database exposes a plaintext SQLite header.
    PlaintextDatabase,
    /// Key verification or encrypted page authentication failed.
    AuthenticationFailed,
    /// The linked encryption provider is not the required SQLCipher major.
    UnsupportedSqlCipher {
        /// Observed major version, or zero when unavailable.
        major: u16,
    },
    /// The database schema is newer, older, or otherwise unsupported.
    UnsupportedSchema {
        /// Observed schema version.
        found: i64,
        /// Only schema version accepted by this implementation.
        supported: i64,
    },
    /// Required schema objects are absent or inconsistent.
    CorruptSchema,
    /// Device-root-key derivation failed.
    KeyDerivationFailed,
    /// A SQLCipher operation failed without retaining SQL or driver text.
    Database {
        /// Logical operation involved.
        operation: DeviceStateDatabaseOperation,
        /// Value-free failure category.
        category: DeviceStateDatabaseErrorCategory,
    },
    /// A caller supplied invalid typed state.
    InvalidModel {
        /// Value-free structural reason.
        reason: &'static str,
    },
    /// An authenticated row could not be decoded as canonical typed state.
    CorruptRecord,
    /// An insert conflicts with an existing immutable identity or scope.
    Conflict,
    /// A bounded query limit was outside its accepted range.
    InvalidQueryLimit,
}

impl fmt::Display for DeviceStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => formatter.write_str("device state is already initialized"),
            Self::Missing => formatter.write_str("encrypted device state is missing"),
            Self::StorePathMismatch => {
                formatter.write_str("open device state does not match the requested state root")
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("encrypted device state is unsupported on this platform")
            }
            Self::SymbolicLink { entry } => {
                write!(formatter, "{} must not be a symbolic link", entry.label())
            }
            Self::UnexpectedFileType { entry } => {
                write!(formatter, "{} has an unexpected file type", entry.label())
            }
            Self::UnexpectedOwner { entry } => {
                write!(formatter, "{} has an unexpected owner", entry.label())
            }
            Self::InsecurePermissions { entry, mode } => write!(
                formatter,
                "{} has insecure permissions (mode {mode:04o})",
                entry.label()
            ),
            Self::RemovalVerificationFailed { entry } => {
                write!(formatter, "{} remained after removal", entry.label())
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
            Self::TruncatedDatabase => formatter.write_str("encrypted device state is truncated"),
            Self::PlaintextDatabase => {
                formatter.write_str("device state has a plaintext database header")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("encrypted device state authentication failed")
            }
            Self::UnsupportedSqlCipher { major } => {
                write!(formatter, "unsupported SQLCipher major version {major}")
            }
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "unsupported device-state schema version {found}; expected {supported}"
            ),
            Self::CorruptSchema => {
                formatter.write_str("encrypted device-state schema is incomplete")
            }
            Self::KeyDerivationFailed => formatter.write_str("device-state key derivation failed"),
            Self::Database {
                operation,
                category,
            } => write!(
                formatter,
                "{} encrypted device state failed: {category:?}",
                operation.label()
            ),
            Self::InvalidModel { reason } => {
                write!(formatter, "invalid device-state model: {reason}")
            }
            Self::CorruptRecord => {
                formatter.write_str("encrypted device-state record is not canonical")
            }
            Self::Conflict => formatter.write_str("device-state identity already exists"),
            Self::InvalidQueryLimit => {
                formatter.write_str("device-state query limit is outside the accepted range")
            }
        }
    }
}

impl std::error::Error for DeviceStateError {}

impl From<DeviceStateValidationError> for DeviceStateError {
    fn from(error: DeviceStateValidationError) -> Self {
        Self::InvalidModel {
            reason: error.reason(),
        }
    }
}

/// Parsed non-secret SQLCipher library version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlCipherVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl SqlCipherVersion {
    /// Returns the major format-compatibility version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the minor library version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Returns the patch library version.
    #[must_use]
    pub const fn patch(self) -> u16 {
        self.patch
    }
}

/// Non-secret counts from removing authorization for one deleted field.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FieldAuthorizationRemoval {
    access_rules_removed: usize,
    use_grants_removed: usize,
    approvals_removed: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthorizationRemovalCounts {
    consumers_removed: usize,
    access_rules_removed: usize,
    use_grants_removed: usize,
    usage_profiles_removed: usize,
    approvals_removed: usize,
}

impl AuthorizationRemovalCounts {
    pub(crate) const fn consumers_removed(self) -> usize {
        self.consumers_removed
    }

    pub(crate) const fn access_rules_removed(self) -> usize {
        self.access_rules_removed
    }

    pub(crate) const fn use_grants_removed(self) -> usize {
        self.use_grants_removed
    }

    pub(crate) const fn usage_profiles_removed(self) -> usize {
        self.usage_profiles_removed
    }

    pub(crate) const fn approvals_removed(self) -> usize {
        self.approvals_removed
    }
}

/// Non-secret result of removing managed encrypted device-state files.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceStateRemoval {
    managed_files_removed: usize,
}

impl DeviceStateRemoval {
    /// Returns the number of database, WAL, and shared-memory files removed.
    #[must_use]
    pub const fn managed_files_removed(self) -> usize {
        self.managed_files_removed
    }
}

impl FieldAuthorizationRemoval {
    /// Returns the number of persistent Access Rules removed.
    #[must_use]
    pub const fn access_rules_removed(self) -> usize {
        self.access_rules_removed
    }

    /// Returns the number of active or stale Use Grants removed.
    #[must_use]
    pub const fn use_grants_removed(self) -> usize {
        self.use_grants_removed
    }

    /// Returns the number of pending or resolved approval rows removed.
    #[must_use]
    pub const fn approvals_removed(self) -> usize {
        self.approvals_removed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StoredUseGrantAuthorization {
    Unavailable,
    NotYetActive,
    Expired,
    Authorized(UseGrant),
}

/// SQLCipher-backed repository for device-local trust and authorization state.
pub struct DeviceStateStore {
    connection: Connection,
    database_path: PathBuf,
    sqlcipher_version: SqlCipherVersion,
    approval_digest_key: ApprovalDigestKey,
}

impl fmt::Debug for DeviceStateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceStateStore")
            .field("database_path", &"<redacted>")
            .field("sqlcipher_version", &self.sqlcipher_version)
            .finish_non_exhaustive()
    }
}

impl DeviceStateStore {
    #[cfg(test)]
    pub(crate) fn initialize_for_tests(
        state_directory: &Path,
        root_key: &DeviceRootKey,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateError> {
        Self::initialize_at(state_directory, root_key, created_at)
    }

    #[cfg(test)]
    pub(crate) fn open_for_tests(
        state_directory: &Path,
        root_key: &DeviceRootKey,
    ) -> Result<Self, DeviceStateError> {
        Self::open_at(state_directory, root_key)
    }

    /// Initializes a new encrypted database without replacing existing state.
    pub fn initialize_new(
        paths: &DevicePaths,
        root_key: &DeviceRootKey,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateError> {
        Self::initialize_at(paths.state(), root_key, created_at)
    }

    /// Opens and authenticates an existing encrypted database.
    pub fn open_existing(
        paths: &DevicePaths,
        root_key: &DeviceRootKey,
    ) -> Result<Self, DeviceStateError> {
        Self::open_at(paths.state(), root_key)
    }

    /// Reports whether any managed encrypted-state file already exists.
    ///
    /// Every existing entry is validated without following symbolic links.
    /// A lone WAL or shared-memory file counts as preserved state so startup
    /// never creates a replacement device key over an incomplete database.
    pub fn has_managed_state(paths: &DevicePaths) -> Result<bool, DeviceStateError> {
        validate_state_directory(paths.state())?;
        let database_path = paths.state().join(DEVICE_STATE_DATABASE_FILENAME);
        let mut exists = false;
        for (path, entry) in
            std::iter::once((database_path.clone(), DeviceStateFileEntry::Database))
                .chain(database_sidecars(&database_path))
        {
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    validate_private_file(&path, entry)?;
                    exists = true;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(DeviceStateError::Io {
                        entry,
                        operation: DeviceStateFileOperation::Inspect,
                        kind: error.kind(),
                    });
                }
            }
        }
        Ok(exists)
    }

    /// Closes this authenticated store and removes only its managed state files.
    ///
    /// Callers must first complete explicit user confirmation and revoke live
    /// Broker sessions. The canonical `~/.keptnear` directory tree and
    /// portable vault files are intentionally outside this boundary.
    pub fn remove_for_local_data_clear(
        self,
        paths: &DevicePaths,
    ) -> Result<DeviceStateRemoval, DeviceStateError> {
        let expected_database = paths.state().join(DEVICE_STATE_DATABASE_FILENAME);
        if self.database_path != expected_database {
            return Err(DeviceStateError::StorePathMismatch);
        }
        validate_state_directory(paths.state())?;
        self.verify_managed_files()?;

        let Self { connection, .. } = self;
        connection
            .close()
            .map_err(|(_, error)| map_database_error(DeviceStateDatabaseOperation::Close, error))?;
        remove_existing_state_files(paths.state())
    }

    /// Removes managed state files when the database cannot be authenticated.
    ///
    /// This recovery-only operation validates ownership, type, and permissions
    /// before deleting the database, WAL, and shared-memory files. It is
    /// idempotent and never traverses or removes the containing directories.
    pub fn remove_existing_for_local_data_clear(
        paths: &DevicePaths,
    ) -> Result<DeviceStateRemoval, DeviceStateError> {
        remove_existing_state_files(paths.state())
    }

    /// Returns the linked SQLCipher version verified when the store opened.
    #[must_use]
    pub const fn sqlcipher_version(&self) -> SqlCipherVersion {
        self.sqlcipher_version
    }

    /// Returns the authenticated KeptNear device-state schema version.
    pub fn schema_version(&self) -> Result<i64, DeviceStateError> {
        read_schema_version(&self.connection)
    }

    /// Loads the one approved public controller record, if bootstrap has completed.
    pub fn controller_authority_record(
        &self,
    ) -> Result<Option<ControllerAuthorityRecord>, DeviceStateError> {
        let row = self
            .connection
            .query_row(
                "SELECT contract_id, signing_algorithm, controller_id, public_key, created_at_ms
                 FROM controller_authority
                 WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
        let Some((contract, algorithm, controller_id, public_key, created_at_ms)) = row else {
            return Ok(None);
        };
        if contract != CONTROLLER_AUTHORITY_CONTRACT_ID
            || algorithm != CONTROLLER_SIGNING_ALGORITHM
            || controller_id.len() != 32
            || public_key.len() != 32
        {
            return Err(DeviceStateError::CorruptRecord);
        }
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| DeviceStateError::CorruptRecord)?;
        let controller_id: [u8; 32] = controller_id
            .try_into()
            .map_err(|_| DeviceStateError::CorruptRecord)?;
        if controller_id != derive_controller_id(&public_key) {
            return Err(DeviceStateError::CorruptRecord);
        }
        let created_at = StateTimestamp::from_unix_millis(created_at_ms)
            .map_err(|_| DeviceStateError::CorruptRecord)?;
        let record = ControllerAuthorityRecord::new(public_key, created_at);
        if record.controller_id() != ControllerId::from_bytes(controller_id) {
            return Err(DeviceStateError::CorruptRecord);
        }
        Ok(Some(record))
    }

    /// Inserts the first approved public controller record without replacement.
    pub fn insert_controller_authority_record(
        &self,
        record: ControllerAuthorityRecord,
    ) -> Result<(), DeviceStateError> {
        let inserted = self
            .connection
            .execute(
                "INSERT INTO controller_authority (
                    singleton,
                    contract_id,
                    signing_algorithm,
                    controller_id,
                    public_key,
                    created_at_ms
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![
                    CONTROLLER_AUTHORITY_CONTRACT_ID,
                    CONTROLLER_SIGNING_ALGORITHM,
                    record.controller_id().as_bytes().as_slice(),
                    record.public_key().as_slice(),
                    record.created_at().unix_millis(),
                ],
            )
            .map_err(map_write_error)?;
        if inserted != 1 {
            return Err(DeviceStateError::Conflict);
        }
        self.verify_managed_files()
    }

    /// Removes only the public controller record during ordered local-data clearing.
    pub fn remove_controller_authority_record(&self) -> Result<bool, DeviceStateError> {
        let removed = self
            .connection
            .execute("DELETE FROM controller_authority WHERE singleton = 1", [])
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(removed == 1)
    }

    pub(crate) fn approval_coalescing_digest(
        &self,
        canonical_request: &[u8],
    ) -> Result<[u8; 32], DeviceStateError> {
        self.approval_digest_key.digest(canonical_request)
    }

    /// Inserts an approved Consumer without replacing an existing identity.
    pub(crate) fn insert_consumer(&self, consumer: &Consumer) -> Result<(), DeviceStateError> {
        let evidence = consumer.observed_identity();
        let inserted = self
            .connection
            .execute(
                "INSERT INTO consumers (
                    consumer_id,
                    pairing_public_key,
                    label,
                    executable_name,
                    bundle_identifier,
                    team_identifier,
                    code_signature_digest,
                    created_at_ms
                )
                SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
                WHERE NOT EXISTS (
                    SELECT 1 FROM consumers WHERE pairing_public_key = ?2
                )",
                params![
                    consumer.consumer_id().to_string(),
                    consumer.pairing_public_key().as_slice(),
                    consumer.label(),
                    evidence.executable_name(),
                    evidence.bundle_identifier(),
                    evidence.team_identifier(),
                    evidence.code_signature_digest().map(<[u8; 32]>::as_slice),
                    consumer.created_at().unix_millis(),
                ],
            )
            .map_err(map_write_error)?;
        if inserted != 1 {
            return Err(DeviceStateError::Conflict);
        }
        self.verify_managed_files()
    }

    /// Loads one Consumer by immutable identity.
    pub fn consumer(&self, consumer_id: ConsumerId) -> Result<Option<Consumer>, DeviceStateError> {
        let wire = self
            .connection
            .query_row(
                "SELECT
                    consumer_id,
                    pairing_public_key,
                    label,
                    executable_name,
                    bundle_identifier,
                    team_identifier,
                    code_signature_digest,
                    created_at_ms
                 FROM consumers
                 WHERE consumer_id = ?1",
                [consumer_id.to_string()],
                read_consumer_wire,
            )
            .optional()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
        wire.map(ConsumerWire::into_model).transpose()
    }

    /// Loads the one Consumer bound to an Ed25519 pairing public key.
    pub fn consumer_by_pairing_public_key(
        &self,
        pairing_public_key: &[u8; 32],
    ) -> Result<Option<Consumer>, DeviceStateError> {
        let consumers = query_models(
            &self.connection,
            "SELECT
                consumer_id,
                pairing_public_key,
                label,
                executable_name,
                bundle_identifier,
                team_identifier,
                code_signature_digest,
                created_at_ms
             FROM consumers
             WHERE pairing_public_key = ?1
             ORDER BY created_at_ms, consumer_id
             LIMIT 2",
            params![pairing_public_key.as_slice()],
            read_consumer_wire,
            ConsumerWire::into_model,
        )?;
        match consumers.as_slice() {
            [] => Ok(None),
            [consumer] => Ok(Some(consumer.clone())),
            _ => Err(DeviceStateError::CorruptSchema),
        }
    }

    /// Lists approved Consumers in deterministic creation order.
    pub fn consumers(&self) -> Result<Vec<Consumer>, DeviceStateError> {
        query_models(
            &self.connection,
            "SELECT
                consumer_id,
                pairing_public_key,
                label,
                executable_name,
                bundle_identifier,
                team_identifier,
                code_signature_digest,
                created_at_ms
             FROM consumers
             ORDER BY created_at_ms, consumer_id",
            [],
            read_consumer_wire,
            ConsumerWire::into_model,
        )
    }

    /// Removes one Consumer and transactionally cascades its rules, grants, and profiles.
    ///
    /// Audit events intentionally remain as stable, non-secret historical
    /// decisions. Pending approvals for the Consumer are removed explicitly.
    pub fn remove_consumer(&mut self, consumer_id: ConsumerId) -> Result<bool, DeviceStateError> {
        Ok(self
            .remove_consumer_authorization(consumer_id)?
            .consumers_removed()
            != 0)
    }

    pub(crate) fn remove_consumer_field_authorization(
        &mut self,
        consumer_id: ConsumerId,
        field_scope: CredentialFieldScope,
    ) -> Result<AuthorizationRemovalCounts, DeviceStateError> {
        let consumer_id = consumer_id.to_string();
        let vault_id = field_scope.vault_id().to_string();
        let credential_id = field_scope.credential_id().to_string();
        let secret_field_id = field_scope.secret_field_id().to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        let approvals_removed = transaction
            .execute(
                "DELETE FROM approvals
                 WHERE consumer_id = ?1
                   AND vault_id = ?2
                   AND credential_id = ?3
                   AND secret_field_id = ?4",
                params![&consumer_id, &vault_id, &credential_id, &secret_field_id],
            )
            .map_err(map_write_error)?;
        let use_grants_removed = transaction
            .execute(
                "DELETE FROM use_grants
                 WHERE consumer_id = ?1
                   AND vault_id = ?2
                   AND credential_id = ?3
                   AND secret_field_id = ?4",
                params![&consumer_id, &vault_id, &credential_id, &secret_field_id],
            )
            .map_err(map_write_error)?;
        let access_rules_removed = transaction
            .execute(
                "DELETE FROM access_rules
                 WHERE consumer_id = ?1
                   AND vault_id = ?2
                   AND credential_id = ?3
                   AND secret_field_id = ?4",
                params![&consumer_id, &vault_id, &credential_id, &secret_field_id],
            )
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        self.verify_managed_files()?;
        Ok(AuthorizationRemovalCounts {
            access_rules_removed,
            use_grants_removed,
            approvals_removed,
            ..AuthorizationRemovalCounts::default()
        })
    }

    pub(crate) fn remove_consumer_authorization(
        &mut self,
        consumer_id: ConsumerId,
    ) -> Result<AuthorizationRemovalCounts, DeviceStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        let encoded = consumer_id.to_string();
        let approvals_removed = transaction
            .execute("DELETE FROM approvals WHERE consumer_id = ?1", [&encoded])
            .map_err(map_write_error)?;
        let use_grants_removed = transaction
            .execute("DELETE FROM use_grants WHERE consumer_id = ?1", [&encoded])
            .map_err(map_write_error)?;
        let access_rules_removed = transaction
            .execute(
                "DELETE FROM access_rules WHERE consumer_id = ?1",
                [&encoded],
            )
            .map_err(map_write_error)?;
        let usage_profiles_removed = transaction
            .execute(
                "DELETE FROM usage_profiles WHERE consumer_id = ?1",
                [&encoded],
            )
            .map_err(map_write_error)?;
        let consumers_removed = transaction
            .execute("DELETE FROM consumers WHERE consumer_id = ?1", [&encoded])
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        self.verify_managed_files()?;
        Ok(AuthorizationRemovalCounts {
            consumers_removed,
            access_rules_removed,
            use_grants_removed,
            usage_profiles_removed,
            approvals_removed,
        })
    }

    pub(crate) fn remove_all_consumer_authorization(
        &mut self,
    ) -> Result<AuthorizationRemovalCounts, DeviceStateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        let approvals_removed = transaction
            .execute("DELETE FROM approvals", [])
            .map_err(map_write_error)?;
        let use_grants_removed = transaction
            .execute("DELETE FROM use_grants", [])
            .map_err(map_write_error)?;
        let access_rules_removed = transaction
            .execute("DELETE FROM access_rules", [])
            .map_err(map_write_error)?;
        let usage_profiles_removed = transaction
            .execute("DELETE FROM usage_profiles", [])
            .map_err(map_write_error)?;
        let consumers_removed = transaction
            .execute("DELETE FROM consumers", [])
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        self.verify_managed_files()?;
        Ok(AuthorizationRemovalCounts {
            consumers_removed,
            access_rules_removed,
            use_grants_removed,
            usage_profiles_removed,
            approvals_removed,
        })
    }

    /// Inserts a persistent Access Rule without replacing an existing scope.
    pub(crate) fn insert_access_rule(&self, rule: &AccessRule) -> Result<(), DeviceStateError> {
        insert_access_rule_row(&self.connection, rule)?;
        self.verify_managed_files()
    }

    pub(crate) fn access_rule_for_target(
        &self,
        target: AuthorizationTarget,
    ) -> Result<Option<AccessRule>, DeviceStateError> {
        access_rule_for_target_from_connection(&self.connection, target)
    }

    /// Lists persistent Access Rules owned by one Consumer.
    pub fn access_rules_for_consumer(
        &self,
        consumer_id: ConsumerId,
    ) -> Result<Vec<AccessRule>, DeviceStateError> {
        query_models(
            &self.connection,
            "SELECT
                access_rule_id,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                confirmation_policy,
                expires_at_ms,
                created_at_ms
             FROM access_rules
             WHERE consumer_id = ?1
             ORDER BY created_at_ms, access_rule_id",
            [consumer_id.to_string()],
            read_access_rule_wire,
            AccessRuleWire::into_model,
        )
    }

    /// Lists credentials with at least one active field authorization in one vault.
    ///
    /// This is a trusted human-control projection. It returns stable identities
    /// only and does not expose credential labels, field labels, or Consumer
    /// metadata.
    pub fn active_authorized_credential_ids_for_vault(
        &self,
        vault_id: VaultId,
        evaluated_at: StateTimestamp,
    ) -> Result<BTreeSet<CredentialId>, DeviceStateError> {
        let rules = query_models(
            &self.connection,
            "SELECT
                access_rule_id,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                confirmation_policy,
                expires_at_ms,
                created_at_ms
             FROM access_rules
             WHERE vault_id = ?1
             ORDER BY created_at_ms, access_rule_id",
            [vault_id.to_string()],
            read_access_rule_wire,
            AccessRuleWire::into_model,
        )?;
        Ok(rules
            .into_iter()
            .filter(|rule| rule.is_active_at(evaluated_at))
            .map(|rule| rule.target().field_scope().credential_id())
            .collect())
    }

    /// Removes one Access Rule and grants derived from that rule.
    pub fn remove_access_rule(
        &self,
        access_rule_id: AccessRuleId,
    ) -> Result<bool, DeviceStateError> {
        let removed = self
            .connection
            .execute(
                "DELETE FROM access_rules WHERE access_rule_id = ?1",
                [access_rule_id.to_string()],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(removed == 1)
    }

    pub(crate) fn insert_use_grant(&self, grant: &UseGrant) -> Result<(), DeviceStateError> {
        insert_use_grant_row(&self.connection, grant)?;
        self.verify_managed_files()
    }

    /// Lists Use Grants owned by one Consumer.
    pub fn use_grants_for_consumer(
        &self,
        consumer_id: ConsumerId,
    ) -> Result<Vec<UseGrant>, DeviceStateError> {
        query_models(
            &self.connection,
            "SELECT
                use_grant_id,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                source_rule_id,
                vault_session_id,
                grant_scope,
                created_at_ms,
                expires_at_ms
             FROM use_grants
             WHERE consumer_id = ?1
             ORDER BY created_at_ms, use_grant_id",
            [consumer_id.to_string()],
            read_use_grant_wire,
            UseGrantWire::into_model,
        )
    }

    pub(crate) fn use_grants_for_rule_session(
        &self,
        target: AuthorizationTarget,
        source_rule_id: AccessRuleId,
        vault_session_id: VaultSessionId,
    ) -> Result<Vec<UseGrant>, DeviceStateError> {
        let field = target.field_scope();
        query_models(
            &self.connection,
            "SELECT
                use_grant_id,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                source_rule_id,
                vault_session_id,
                grant_scope,
                created_at_ms,
                expires_at_ms
             FROM use_grants
             WHERE consumer_id = ?1
               AND vault_id = ?2
               AND credential_id = ?3
               AND secret_field_id = ?4
               AND capability_name = ?5
               AND capability_version = ?6
               AND source_rule_id = ?7
               AND vault_session_id = ?8
               AND grant_scope = 'unlock-session'
             ORDER BY created_at_ms, use_grant_id
             LIMIT 2",
            params![
                target.consumer_id().to_string(),
                field.vault_id().to_string(),
                field.credential_id().to_string(),
                field.secret_field_id().to_string(),
                target.capability().name().as_str(),
                i64::from(target.capability().version()),
                source_rule_id.to_string(),
                vault_session_id.to_string(),
            ],
            read_use_grant_wire,
            UseGrantWire::into_model,
        )
    }

    pub(crate) fn authorize_stored_use_grant(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        vault_session_id: VaultSessionId,
        evaluated_at: StateTimestamp,
    ) -> Result<StoredUseGrantAuthorization, DeviceStateError> {
        let Some(grant) = self.use_grant(use_grant_id)? else {
            return Ok(StoredUseGrantAuthorization::Unavailable);
        };
        if grant.target() != target || grant.vault_session_id() != vault_session_id {
            return Ok(StoredUseGrantAuthorization::Unavailable);
        }
        if evaluated_at < grant.created_at() {
            return Ok(StoredUseGrantAuthorization::NotYetActive);
        }
        if evaluated_at >= grant.expires_at() {
            return if self.remove_use_grant(use_grant_id)? {
                Ok(StoredUseGrantAuthorization::Expired)
            } else {
                Ok(StoredUseGrantAuthorization::Unavailable)
            };
        }
        if grant.scope() == GrantScope::OneOperation && !self.remove_use_grant(use_grant_id)? {
            return Ok(StoredUseGrantAuthorization::Unavailable);
        }
        Ok(StoredUseGrantAuthorization::Authorized(grant))
    }

    pub(crate) fn use_grant_matches_target_session(
        &self,
        use_grant_id: UseGrantId,
        target: AuthorizationTarget,
        vault_session_id: VaultSessionId,
    ) -> Result<bool, DeviceStateError> {
        let Some(grant) = self.use_grant(use_grant_id)? else {
            return Ok(false);
        };
        Ok(grant.target() == target && grant.vault_session_id() == vault_session_id)
    }

    pub(crate) fn remove_use_grant(
        &self,
        use_grant_id: UseGrantId,
    ) -> Result<bool, DeviceStateError> {
        let removed = self
            .connection
            .execute(
                "DELETE FROM use_grants WHERE use_grant_id = ?1",
                [use_grant_id.to_string()],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(removed == 1)
    }

    pub(crate) fn use_grant_for_consumer(
        &self,
        consumer_id: ConsumerId,
        use_grant_id: UseGrantId,
    ) -> Result<Option<UseGrant>, DeviceStateError> {
        Ok(self
            .use_grant(use_grant_id)?
            .filter(|grant| grant.target().consumer_id() == consumer_id))
    }

    pub(crate) fn remove_use_grant_for_consumer(
        &self,
        consumer_id: ConsumerId,
        use_grant_id: UseGrantId,
    ) -> Result<bool, DeviceStateError> {
        let removed = self
            .connection
            .execute(
                "DELETE FROM use_grants
                 WHERE use_grant_id = ?1
                   AND consumer_id = ?2",
                params![use_grant_id.to_string(), consumer_id.to_string()],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(removed == 1)
    }

    fn use_grant(&self, use_grant_id: UseGrantId) -> Result<Option<UseGrant>, DeviceStateError> {
        let mut grants = query_models(
            &self.connection,
            "SELECT
                use_grant_id,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                source_rule_id,
                vault_session_id,
                grant_scope,
                created_at_ms,
                expires_at_ms
             FROM use_grants
             WHERE use_grant_id = ?1
             LIMIT 1",
            [use_grant_id.to_string()],
            read_use_grant_wire,
            UseGrantWire::into_model,
        )?;
        Ok(grants.pop())
    }

    pub(crate) fn invalidate_use_grants_for_sessions(
        &mut self,
        sessions: &[(VaultId, VaultSessionId)],
    ) -> Result<usize, DeviceStateError> {
        if sessions.is_empty() {
            return Ok(0);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        let mut removed = 0_usize;
        for (vault_id, vault_session_id) in sessions {
            removed = removed.saturating_add(
                transaction
                    .execute(
                        "DELETE FROM use_grants
                         WHERE vault_id = ?1 AND vault_session_id = ?2",
                        params![vault_id.to_string(), vault_session_id.to_string()],
                    )
                    .map_err(map_write_error)?,
            );
        }
        transaction
            .commit()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        self.verify_managed_files()?;
        Ok(removed)
    }

    pub(crate) fn invalidate_all_use_grants(&mut self) -> Result<usize, DeviceStateError> {
        let removed = self
            .connection
            .execute("DELETE FROM use_grants", [])
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(removed)
    }

    /// Removes every authorization record scoped to a deleted credential field.
    ///
    /// Audit events remain as stable, non-secret historical decisions.
    pub fn remove_field_authorization(
        &mut self,
        field_scope: CredentialFieldScope,
    ) -> Result<FieldAuthorizationRemoval, DeviceStateError> {
        let vault_id = field_scope.vault_id().to_string();
        let credential_id = field_scope.credential_id().to_string();
        let secret_field_id = field_scope.secret_field_id().to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        let approvals_removed = transaction
            .execute(
                "DELETE FROM approvals
                 WHERE vault_id = ?1 AND credential_id = ?2 AND secret_field_id = ?3",
                params![&vault_id, &credential_id, &secret_field_id],
            )
            .map_err(map_write_error)?;
        let use_grants_removed = transaction
            .execute(
                "DELETE FROM use_grants
                 WHERE vault_id = ?1 AND credential_id = ?2 AND secret_field_id = ?3",
                params![&vault_id, &credential_id, &secret_field_id],
            )
            .map_err(map_write_error)?;
        let access_rules_removed = transaction
            .execute(
                "DELETE FROM access_rules
                 WHERE vault_id = ?1 AND credential_id = ?2 AND secret_field_id = ?3",
                params![&vault_id, &credential_id, &secret_field_id],
            )
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        self.verify_managed_files()?;
        Ok(FieldAuthorizationRemoval {
            access_rules_removed,
            use_grants_removed,
            approvals_removed,
        })
    }

    /// Inserts one typed declarative Usage Profile.
    pub fn insert_usage_profile(&self, profile: &UsageProfile) -> Result<(), DeviceStateError> {
        let placement_json = serde_json::to_string(profile.placement())
            .map_err(|_| DeviceStateError::CorruptRecord)?;
        self.connection
            .execute(
                "INSERT INTO usage_profiles (
                    usage_profile_id,
                    consumer_id,
                    label,
                    capability_name,
                    capability_version,
                    definition_version,
                    placement_json,
                    created_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    profile.usage_profile_id().to_string(),
                    profile.consumer_id().to_string(),
                    profile.label(),
                    profile.capability().name().as_str(),
                    i64::from(profile.capability().version()),
                    i64::from(profile.definition().version()),
                    placement_json,
                    profile.created_at().unix_millis(),
                ],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()
    }

    /// Lists Usage Profiles owned by one Consumer.
    pub fn usage_profiles_for_consumer(
        &self,
        consumer_id: ConsumerId,
    ) -> Result<Vec<UsageProfile>, DeviceStateError> {
        query_models(
            &self.connection,
            "SELECT
                usage_profile_id,
                consumer_id,
                label,
                capability_name,
                capability_version,
                definition_version,
                placement_json,
                created_at_ms
             FROM usage_profiles
             WHERE consumer_id = ?1
             ORDER BY created_at_ms, usage_profile_id",
            [consumer_id.to_string()],
            read_usage_profile_wire,
            UsageProfileWire::into_model,
        )
    }

    /// Removes one Usage Profile.
    pub fn remove_usage_profile(
        &self,
        usage_profile_id: UsageProfileId,
    ) -> Result<bool, DeviceStateError> {
        let removed = self
            .connection
            .execute(
                "DELETE FROM usage_profiles WHERE usage_profile_id = ?1",
                [usage_profile_id.to_string()],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(removed == 1)
    }

    /// Inserts one asynchronous approval request.
    pub(crate) fn insert_approval(
        &self,
        approval: &ApprovalRequest,
    ) -> Result<(), DeviceStateError> {
        let columns = ApprovalColumns::from_subject(approval.subject());
        self.connection
            .execute(
                "INSERT INTO approvals (
                    approval_request_id,
                    approval_kind,
                    consumer_id,
                    pairing_public_key,
                    executable_name,
                    bundle_identifier,
                    team_identifier,
                    code_signature_digest,
                    vault_id,
                    credential_id,
                    secret_field_id,
                    capability_name,
                    capability_version,
                    coalescing_digest,
                    approval_status,
                    created_at_ms,
                    expires_at_ms,
                    resolved_at_ms
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
                )",
                params![
                    approval.approval_request_id().to_string(),
                    approval.subject().kind().as_str(),
                    columns.consumer_id,
                    columns.pairing_public_key.as_deref(),
                    columns.executable_name,
                    columns.bundle_identifier,
                    columns.team_identifier,
                    columns.code_signature_digest.as_deref(),
                    columns.vault_id,
                    columns.credential_id,
                    columns.secret_field_id,
                    columns.capability_name,
                    columns.capability_version,
                    approval.coalescing_digest().as_slice(),
                    approval.status().as_str(),
                    approval.created_at().unix_millis(),
                    approval.expires_at().unix_millis(),
                    approval.resolved_at().map(StateTimestamp::unix_millis),
                ],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()
    }

    /// Loads one approval by immutable request identity.
    pub fn approval(
        &self,
        approval_request_id: ApprovalRequestId,
    ) -> Result<Option<ApprovalRequest>, DeviceStateError> {
        let wire = self
            .connection
            .query_row(
                APPROVAL_SELECT_BY_ID,
                [approval_request_id.to_string()],
                read_approval_wire,
            )
            .optional()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
        wire.map(ApprovalWire::into_model).transpose()
    }

    /// Lists pending approvals in deterministic expiry order.
    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRequest>, DeviceStateError> {
        query_models(
            &self.connection,
            APPROVAL_SELECT_PENDING,
            [],
            read_approval_wire,
            ApprovalWire::into_model,
        )
    }

    pub(crate) fn pending_approval_by_digest(
        &self,
        coalescing_digest: &[u8; 32],
    ) -> Result<Option<ApprovalRequest>, DeviceStateError> {
        let approvals = query_models(
            &self.connection,
            "
            SELECT
                approval_request_id,
                approval_kind,
                consumer_id,
                pairing_public_key,
                executable_name,
                bundle_identifier,
                team_identifier,
                code_signature_digest,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                coalescing_digest,
                approval_status,
                created_at_ms,
                expires_at_ms,
                resolved_at_ms
            FROM approvals
            WHERE coalescing_digest = ?1 AND approval_status = 'pending'
            ORDER BY approval_request_id
            LIMIT 2",
            [coalescing_digest.as_slice()],
            read_approval_wire,
            ApprovalWire::into_model,
        )?;
        match approvals.as_slice() {
            [] => Ok(None),
            [approval] => Ok(Some(approval.clone())),
            _ => Err(DeviceStateError::CorruptSchema),
        }
    }

    pub(crate) fn expire_pending_approvals(
        &self,
        observed_at: StateTimestamp,
    ) -> Result<usize, DeviceStateError> {
        let updated = self
            .connection
            .execute(
                "UPDATE approvals
                 SET approval_status = 'expired', resolved_at_ms = expires_at_ms
                 WHERE approval_status = 'pending' AND expires_at_ms <= ?1",
                [observed_at.unix_millis()],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(updated)
    }

    pub(crate) fn resolve_pending_approval(
        &self,
        approval_request_id: ApprovalRequestId,
        status: ApprovalStatus,
        resolved_at: StateTimestamp,
    ) -> Result<StoredApprovalResolution, DeviceStateError> {
        if status == ApprovalStatus::Pending || status == ApprovalStatus::Expired {
            return Err(DeviceStateError::InvalidModel {
                reason: "approval decision must be approved, denied, or cancelled",
            });
        }
        let updated = self
            .connection
            .execute(
                "UPDATE approvals
                 SET approval_status = CASE
                         WHEN expires_at_ms <= ?1 THEN 'expired'
                         ELSE ?2
                     END,
                     resolved_at_ms = CASE
                         WHEN expires_at_ms <= ?1 THEN expires_at_ms
                         ELSE ?1
                     END
                 WHERE approval_request_id = ?3
                   AND approval_status = 'pending'
                   AND created_at_ms <= ?1",
                params![
                    resolved_at.unix_millis(),
                    status.as_str(),
                    approval_request_id.to_string(),
                ],
            )
            .map_err(map_write_error)?;
        self.verify_managed_files()?;
        let Some(approval) = self.approval(approval_request_id)? else {
            return Ok(StoredApprovalResolution::Missing);
        };
        if updated == 1 {
            return if approval.status() == ApprovalStatus::Expired {
                Ok(StoredApprovalResolution::Expired(approval))
            } else {
                Ok(StoredApprovalResolution::Resolved(approval))
            };
        }
        if approval.status() == ApprovalStatus::Pending {
            return Ok(StoredApprovalResolution::NotYetCreated);
        }
        Ok(StoredApprovalResolution::AlreadyTerminal(approval))
    }

    pub(crate) fn approve_pending_with_allow_once_grant(
        &mut self,
        approval_request_id: ApprovalRequestId,
        expected_subject: &ApprovalSubject,
        grant: &UseGrant,
        resolved_at: StateTimestamp,
    ) -> Result<StoredAllowOnceResolution, DeviceStateError> {
        if grant.scope() != GrantScope::OneOperation
            || grant.source_rule_id().is_some()
            || grant.created_at() != resolved_at
        {
            return Err(DeviceStateError::InvalidModel {
                reason: "Allow Once approval requires one source-less operation grant",
            });
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        let Some(request) = approval_from_connection(&transaction, approval_request_id)? else {
            return Ok(StoredAllowOnceResolution::Missing);
        };

        if request.subject() != expected_subject
            || !allow_once_grant_matches_subject(grant, expected_subject)
            || grant.expires_at() > request.expires_at()
        {
            return Ok(StoredAllowOnceResolution::SubjectMismatch(request));
        }
        if request.status() != ApprovalStatus::Pending {
            return Ok(StoredAllowOnceResolution::AlreadyTerminal(request));
        }
        if request.created_at() > resolved_at {
            return Ok(StoredAllowOnceResolution::NotYetCreated);
        }
        if request.expires_at() <= resolved_at {
            transaction
                .execute(
                    "UPDATE approvals
                     SET approval_status = 'expired', resolved_at_ms = expires_at_ms
                     WHERE approval_request_id = ?1 AND approval_status = 'pending'",
                    [approval_request_id.to_string()],
                )
                .map_err(map_write_error)?;
            approval_from_connection(&transaction, approval_request_id)?
                .ok_or(DeviceStateError::CorruptSchema)?;
            transaction
                .commit()
                .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
            self.verify_managed_files()?;
            return Ok(StoredAllowOnceResolution::Expired);
        }

        insert_use_grant_row(&transaction, grant)?;
        let updated = transaction
            .execute(
                "UPDATE approvals
                 SET approval_status = 'approved', resolved_at_ms = ?1
                 WHERE approval_request_id = ?2
                   AND approval_status = 'pending'
                   AND created_at_ms <= ?1
                   AND expires_at_ms > ?1",
                params![resolved_at.unix_millis(), approval_request_id.to_string(),],
            )
            .map_err(map_write_error)?;
        if updated != 1 {
            return Err(DeviceStateError::Conflict);
        }
        let approved = approval_from_connection(&transaction, approval_request_id)?
            .ok_or(DeviceStateError::CorruptSchema)?;
        transaction
            .commit()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        self.verify_managed_files()?;
        Ok(StoredAllowOnceResolution::Approved(approved))
    }

    pub(crate) fn approve_pending_with_access_rule(
        &mut self,
        approval_request_id: ApprovalRequestId,
        expected_subject: &ApprovalSubject,
        proposed_rule: &AccessRule,
        resolved_at: StateTimestamp,
    ) -> Result<StoredAccessRuleResolution, DeviceStateError> {
        if proposed_rule.created_at() != resolved_at
            || !authorization_target_matches_subject(proposed_rule.target(), expected_subject)
        {
            return Err(DeviceStateError::InvalidModel {
                reason: "persistent Access Rule does not match its approval subject",
            });
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        let Some(request) = approval_from_connection(&transaction, approval_request_id)? else {
            return Ok(StoredAccessRuleResolution::Missing);
        };

        if request.subject() != expected_subject
            || !authorization_target_matches_subject(proposed_rule.target(), expected_subject)
        {
            return Ok(StoredAccessRuleResolution::SubjectMismatch(request));
        }
        if request.status() != ApprovalStatus::Pending {
            return Ok(StoredAccessRuleResolution::AlreadyTerminal(request));
        }
        if request.created_at() > resolved_at {
            return Ok(StoredAccessRuleResolution::NotYetCreated);
        }
        if request.expires_at() <= resolved_at {
            transaction
                .execute(
                    "UPDATE approvals
                     SET approval_status = 'expired', resolved_at_ms = expires_at_ms
                     WHERE approval_request_id = ?1 AND approval_status = 'pending'",
                    [approval_request_id.to_string()],
                )
                .map_err(map_write_error)?;
            approval_from_connection(&transaction, approval_request_id)?
                .ok_or(DeviceStateError::CorruptSchema)?;
            transaction
                .commit()
                .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
            self.verify_managed_files()?;
            return Ok(StoredAccessRuleResolution::Expired);
        }

        let existing =
            access_rule_for_target_from_connection(&transaction, proposed_rule.target())?;
        let (persisted_rule, newly_created) = match existing {
            Some(existing) if existing.is_active_at(resolved_at) => {
                if existing.confirmation_policy() != proposed_rule.confirmation_policy()
                    || existing.lifetime() != proposed_rule.lifetime()
                {
                    return Ok(StoredAccessRuleResolution::ConflictingRule(request));
                }
                (existing, false)
            }
            Some(existing) => {
                transaction
                    .execute(
                        "DELETE FROM access_rules WHERE access_rule_id = ?1",
                        [existing.access_rule_id().to_string()],
                    )
                    .map_err(map_write_error)?;
                insert_access_rule_row(&transaction, proposed_rule)?;
                (proposed_rule.clone(), true)
            }
            None => {
                insert_access_rule_row(&transaction, proposed_rule)?;
                (proposed_rule.clone(), true)
            }
        };

        let updated = transaction
            .execute(
                "UPDATE approvals
                 SET approval_status = 'approved', resolved_at_ms = ?1
                 WHERE approval_request_id = ?2
                   AND approval_status = 'pending'
                   AND created_at_ms <= ?1
                   AND expires_at_ms > ?1",
                params![resolved_at.unix_millis(), approval_request_id.to_string()],
            )
            .map_err(map_write_error)?;
        if updated != 1 {
            return Err(DeviceStateError::Conflict);
        }
        let approved = approval_from_connection(&transaction, approval_request_id)?
            .ok_or(DeviceStateError::CorruptSchema)?;
        transaction
            .commit()
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Write, error))?;
        self.verify_managed_files()?;
        Ok(StoredAccessRuleResolution::Approved {
            request: approved,
            rule: persisted_rule,
            newly_created,
        })
    }

    /// Appends one immutable, secret-free audit event and enforces retention.
    ///
    /// The insert, retention watermark update, age pruning, and absolute
    /// event-count pruning commit in one immediate SQLCipher transaction.
    pub fn append_audit_event(&self, event: &AuditEvent) -> Result<(), DeviceStateError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(map_write_error)?;
        insert_audit_event(&transaction, event)?;
        advance_audit_retention_watermark(&transaction, event.occurred_at())?;
        prune_audit_events(&transaction, event.occurred_at())?;
        transaction.commit().map_err(map_write_error)?;
        self.verify_managed_files()
    }

    /// Applies configured audit retention using a trusted local observation time.
    ///
    /// This is intended for Broker startup so an idle database cannot retain
    /// expired events indefinitely. A persisted monotonic watermark prevents a
    /// later wall-clock rollback from extending prior retention.
    pub fn enforce_audit_retention(
        &self,
        observed_at: StateTimestamp,
    ) -> Result<usize, DeviceStateError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(map_write_error)?;
        advance_audit_retention_watermark(&transaction, observed_at)?;
        let removed = prune_audit_events(&transaction, observed_at)?;
        transaction.commit().map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok(removed)
    }

    /// Returns the newest encrypted audit events up to a hard bound.
    pub fn recent_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, DeviceStateError> {
        if limit == 0 || limit > MAX_AUDIT_QUERY_LIMIT {
            return Err(DeviceStateError::InvalidQueryLimit);
        }
        query_models(
            &self.connection,
            "SELECT
                audit_event_id,
                occurred_at_ms,
                event_kind,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                decision,
                confirmation_method,
                use_grant_id
             FROM audit_events
             ORDER BY occurred_at_ms DESC, audit_event_id DESC
             LIMIT ?1",
            [i64::try_from(limit).map_err(|_| DeviceStateError::InvalidQueryLimit)?],
            read_audit_wire,
            AuditWire::into_model,
        )
    }

    pub(crate) fn filtered_audit_events(
        &self,
        filter: BrokerAuditFilter,
        cursor: Option<BrokerAuditCursor>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, DeviceStateError> {
        if limit == 0 || limit > MAX_AUDIT_QUERY_LIMIT {
            return Err(DeviceStateError::InvalidQueryLimit);
        }
        let event_kind = filter.event_kind().map(AuditEventKind::as_str);
        let decision = filter.decision().map(AuditDecision::as_str);
        let consumer_id = filter.consumer_id().map(|value| value.to_string());
        let vault_id = filter.vault_id().map(|value| value.to_string());
        let field_scope = filter.field_scope();
        let field_vault_id = field_scope.map(|value| value.vault_id().to_string());
        let credential_id = field_scope.map(|value| value.credential_id().to_string());
        let secret_field_id = field_scope.map(|value| value.secret_field_id().to_string());
        let capability = filter.capability();
        let capability_name = capability.map(|value| value.name().as_str());
        let capability_version = capability.map(|value| i64::from(value.version()));
        let occurred_at_or_after = filter
            .occurred_at_or_after()
            .map(StateTimestamp::unix_millis);
        let occurred_before = filter.occurred_before().map(StateTimestamp::unix_millis);
        let cursor_occurred_at = cursor.map(|value| value.occurred_at().unix_millis());
        let cursor_event_id = cursor.map(|value| value.audit_event_id().to_string());
        query_models(
            &self.connection,
            "SELECT
                audit_event_id,
                occurred_at_ms,
                event_kind,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                decision,
                confirmation_method,
                use_grant_id
             FROM audit_events
             WHERE (?1 IS NULL OR event_kind = ?1)
               AND (?2 IS NULL OR decision = ?2)
               AND (?3 IS NULL OR consumer_id = ?3)
               AND (?4 IS NULL OR vault_id = ?4)
               AND (
                   ?5 IS NULL
                   OR (
                       vault_id = ?5
                       AND credential_id = ?6
                       AND secret_field_id = ?7
                   )
               )
               AND (
                   ?8 IS NULL
                   OR (
                       capability_name = ?8
                       AND capability_version = ?9
                   )
               )
               AND (?10 IS NULL OR occurred_at_ms >= ?10)
               AND (?11 IS NULL OR occurred_at_ms < ?11)
               AND (
                   ?12 IS NULL
                   OR occurred_at_ms < ?12
                   OR (occurred_at_ms = ?12 AND audit_event_id < ?13)
               )
             ORDER BY occurred_at_ms DESC, audit_event_id DESC
             LIMIT ?14",
            params![
                event_kind,
                decision,
                consumer_id,
                vault_id,
                field_vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                occurred_at_or_after,
                occurred_before,
                cursor_occurred_at,
                cursor_event_id,
                i64::try_from(limit).map_err(|_| DeviceStateError::InvalidQueryLimit)?,
            ],
            read_audit_wire,
            AuditWire::into_model,
        )
    }

    pub(crate) fn clear_audit_events_matching(
        &self,
        filter: BrokerAuditFilter,
    ) -> Result<(usize, usize), DeviceStateError> {
        let event_kind = filter.event_kind().map(AuditEventKind::as_str);
        let decision = filter.decision().map(AuditDecision::as_str);
        let consumer_id = filter.consumer_id().map(|value| value.to_string());
        let vault_id = filter.vault_id().map(|value| value.to_string());
        let field_scope = filter.field_scope();
        let field_vault_id = field_scope.map(|value| value.vault_id().to_string());
        let credential_id = field_scope.map(|value| value.credential_id().to_string());
        let secret_field_id = field_scope.map(|value| value.secret_field_id().to_string());
        let capability = filter.capability();
        let capability_name = capability.map(|value| value.name().as_str());
        let capability_version = capability.map(|value| i64::from(value.version()));
        let occurred_at_or_after = filter
            .occurred_at_or_after()
            .map(StateTimestamp::unix_millis);
        let occurred_before = filter.occurred_before().map(StateTimestamp::unix_millis);
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(map_write_error)?;
        let removed = transaction
            .execute(
                "DELETE FROM audit_events
                 WHERE (?1 IS NULL OR event_kind = ?1)
                   AND (?2 IS NULL OR decision = ?2)
                   AND (?3 IS NULL OR consumer_id = ?3)
                   AND (?4 IS NULL OR vault_id = ?4)
                   AND (
                       ?5 IS NULL
                       OR (
                           vault_id = ?5
                           AND credential_id = ?6
                           AND secret_field_id = ?7
                       )
                   )
                   AND (
                       ?8 IS NULL
                       OR (
                           capability_name = ?8
                           AND capability_version = ?9
                       )
                   )
                   AND (?10 IS NULL OR occurred_at_ms >= ?10)
                   AND (?11 IS NULL OR occurred_at_ms < ?11)",
                params![
                    event_kind,
                    decision,
                    consumer_id,
                    vault_id,
                    field_vault_id,
                    credential_id,
                    secret_field_id,
                    capability_name,
                    capability_version,
                    occurred_at_or_after,
                    occurred_before,
                ],
            )
            .map_err(map_write_error)?;
        let remaining: i64 = transaction
            .query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
        transaction.commit().map_err(map_write_error)?;
        self.verify_managed_files()?;
        Ok((
            removed,
            usize::try_from(remaining).map_err(|_| DeviceStateError::CorruptRecord)?,
        ))
    }

    /// Returns the stored device-wide Apps & Tools pause state.
    pub fn apps_tools_paused(&self) -> Result<bool, DeviceStateError> {
        self.connection
            .query_row(
                "SELECT apps_tools_paused FROM device_settings WHERE singleton = 1",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))
    }

    /// Persists the device-wide Apps & Tools pause state.
    pub fn set_apps_tools_paused(
        &self,
        paused: bool,
        updated_at: StateTimestamp,
    ) -> Result<(), DeviceStateError> {
        let updated = self
            .connection
            .execute(
                "UPDATE device_settings
                 SET apps_tools_paused = ?1, updated_at_ms = MAX(updated_at_ms, ?2)
                 WHERE singleton = 1",
                params![paused, updated_at.unix_millis()],
            )
            .map_err(map_write_error)?;
        if updated != 1 {
            return Err(DeviceStateError::CorruptSchema);
        }
        self.verify_managed_files()
    }

    /// Returns the configured local audit retention period.
    pub fn audit_retention_days(&self) -> Result<u16, DeviceStateError> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT audit_retention_days FROM device_settings WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
        u16::try_from(value).map_err(|_| DeviceStateError::CorruptRecord)
    }

    /// Persists a bounded local audit retention period and prunes immediately.
    pub fn set_audit_retention_days(
        &self,
        days: u16,
        updated_at: StateTimestamp,
    ) -> Result<(), DeviceStateError> {
        if !(MIN_AUDIT_RETENTION_DAYS..=MAX_AUDIT_RETENTION_DAYS).contains(&days) {
            return Err(DeviceStateError::InvalidModel {
                reason: "audit retention must be between 1 and 3650 days",
            });
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(map_write_error)?;
        let updated = transaction
            .execute(
                "UPDATE device_settings
                 SET audit_retention_days = ?1,
                     updated_at_ms = MAX(updated_at_ms, ?2)
                 WHERE singleton = 1",
                params![i64::from(days), updated_at.unix_millis()],
            )
            .map_err(map_write_error)?;
        if updated != 1 {
            return Err(DeviceStateError::CorruptSchema);
        }
        prune_audit_events(&transaction, updated_at)?;
        transaction.commit().map_err(map_write_error)?;
        self.verify_managed_files()
    }

    fn initialize_at(
        state_directory: &Path,
        root_key: &DeviceRootKey,
        created_at: StateTimestamp,
    ) -> Result<Self, DeviceStateError> {
        validate_state_directory(state_directory)?;
        let database_path = state_directory.join(DEVICE_STATE_DATABASE_FILENAME);
        ensure_new_database_paths_available(&database_path)?;
        create_private_database_file(&database_path)?;
        let mut cleanup = IncompleteDatabase::new(database_path.clone());

        let mut connection = open_connection(&database_path)?;
        let sqlcipher_version = key_and_configure(&connection, root_key)?;
        authenticate_empty_database(&connection)?;
        initialize_schema(&mut connection, created_at)?;
        configure_authenticated_connection(&connection)?;
        verify_authenticated_database(&connection)?;
        verify_database_header(&database_path)?;

        let store = Self {
            connection,
            database_path,
            sqlcipher_version,
            approval_digest_key: ApprovalDigestKey::derive(root_key)?,
        };
        store.verify_managed_files()?;
        cleanup.disarm();
        Ok(store)
    }

    fn open_at(state_directory: &Path, root_key: &DeviceRootKey) -> Result<Self, DeviceStateError> {
        validate_state_directory(state_directory)?;
        let database_path = state_directory.join(DEVICE_STATE_DATABASE_FILENAME);
        validate_existing_database_paths(&database_path)?;
        verify_database_header(&database_path)?;

        let mut connection = open_connection(&database_path)?;
        let sqlcipher_version = key_and_configure(&connection, root_key)?;
        authenticate_existing_database(&connection)?;
        verify_database_integrity(&connection)?;
        migrate_schema(&mut connection)?;
        verify_schema(&connection)?;
        configure_authenticated_connection(&connection)?;
        verify_authenticated_database(&connection)?;

        let store = Self {
            connection,
            database_path,
            sqlcipher_version,
            approval_digest_key: ApprovalDigestKey::derive(root_key)?,
        };
        store.verify_managed_files()?;
        Ok(store)
    }

    fn verify_managed_files(&self) -> Result<(), DeviceStateError> {
        validate_private_file(&self.database_path, DeviceStateFileEntry::Database)?;
        for (path, entry) in database_sidecars(&self.database_path) {
            validate_optional_private_file(&path, entry)?;
        }
        Ok(())
    }
}

fn insert_audit_event(
    transaction: &Transaction<'_>,
    event: &AuditEvent,
) -> Result<(), DeviceStateError> {
    let scope = event.scope();
    let field_scope = scope.field_scope();
    let capability = scope.capability();
    transaction
        .execute(
            "INSERT INTO audit_events (
                audit_event_id,
                occurred_at_ms,
                event_kind,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                decision,
                confirmation_method,
                use_grant_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                event.audit_event_id().to_string(),
                event.occurred_at().unix_millis(),
                event.kind().as_str(),
                scope.consumer_id().map(|value| value.to_string()),
                field_scope.map(|value| value.vault_id().to_string()),
                field_scope.map(|value| value.credential_id().to_string()),
                field_scope.map(|value| value.secret_field_id().to_string()),
                capability.map(|value| value.name().as_str()),
                capability.map(|value| i64::from(value.version())),
                event.decision().as_str(),
                event.confirmation_method().as_str(),
                scope.use_grant_id().map(|value| value.to_string()),
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn advance_audit_retention_watermark(
    transaction: &Transaction<'_>,
    observed_at: StateTimestamp,
) -> Result<(), DeviceStateError> {
    let updated = transaction
        .execute(
            "UPDATE device_settings
             SET updated_at_ms = MAX(updated_at_ms, ?1)
             WHERE singleton = 1",
            [observed_at.unix_millis()],
        )
        .map_err(map_write_error)?;
    if updated != 1 {
        return Err(DeviceStateError::CorruptSchema);
    }
    Ok(())
}

fn prune_audit_events(
    transaction: &Transaction<'_>,
    observed_at: StateTimestamp,
) -> Result<usize, DeviceStateError> {
    let (retention_days, stored_watermark): (i64, i64) = transaction
        .query_row(
            "SELECT audit_retention_days, updated_at_ms
             FROM device_settings
             WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
    if !(i64::from(MIN_AUDIT_RETENTION_DAYS)..=i64::from(MAX_AUDIT_RETENTION_DAYS))
        .contains(&retention_days)
    {
        return Err(DeviceStateError::CorruptRecord);
    }

    let anchor = stored_watermark.max(observed_at.unix_millis());
    let retention_millis = retention_days.saturating_mul(AUDIT_RETENTION_DAY_MILLIS);
    let cutoff = anchor.saturating_sub(retention_millis).max(0);
    let removed_by_age = transaction
        .execute(
            "DELETE FROM audit_events WHERE occurred_at_ms < ?1",
            [cutoff],
        )
        .map_err(map_write_error)?;
    let removed_by_count = transaction
        .execute(
            "DELETE FROM audit_events
             WHERE audit_event_id IN (
                 SELECT audit_event_id
                 FROM audit_events
                 ORDER BY occurred_at_ms DESC, audit_event_id DESC
                 LIMIT -1 OFFSET ?1
             )",
            [i64::try_from(MAX_RETAINED_AUDIT_EVENTS)
                .map_err(|_| DeviceStateError::CorruptSchema)?],
        )
        .map_err(map_write_error)?;
    Ok(removed_by_age.saturating_add(removed_by_count))
}

pub(crate) enum StoredApprovalResolution {
    Resolved(ApprovalRequest),
    Expired(ApprovalRequest),
    AlreadyTerminal(ApprovalRequest),
    NotYetCreated,
    Missing,
}

pub(crate) enum StoredAllowOnceResolution {
    Approved(ApprovalRequest),
    Expired,
    AlreadyTerminal(ApprovalRequest),
    NotYetCreated,
    SubjectMismatch(ApprovalRequest),
    Missing,
}

pub(crate) enum StoredAccessRuleResolution {
    Approved {
        request: ApprovalRequest,
        rule: AccessRule,
        newly_created: bool,
    },
    Expired,
    AlreadyTerminal(ApprovalRequest),
    NotYetCreated,
    SubjectMismatch(ApprovalRequest),
    ConflictingRule(ApprovalRequest),
    Missing,
}

struct ApprovalDigestKey {
    bytes: [u8; 32],
}

impl ApprovalDigestKey {
    fn derive(root_key: &DeviceRootKey) -> Result<Self, DeviceStateError> {
        let hkdf = Hkdf::<Sha256>::new(None, root_key.expose());
        let mut bytes = [0_u8; 32];
        hkdf.expand(APPROVAL_DIGEST_KEY_DOMAIN, &mut bytes)
            .map_err(|_| DeviceStateError::KeyDerivationFailed)?;
        Ok(Self { bytes })
    }

    fn digest(&self, canonical_request: &[u8]) -> Result<[u8; 32], DeviceStateError> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut digest = [0_u8; 32];
        hkdf.expand(canonical_request, &mut digest)
            .map_err(|_| DeviceStateError::KeyDerivationFailed)?;
        Ok(digest)
    }
}

impl fmt::Debug for ApprovalDigestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalDigestKey(<redacted>)")
    }
}

impl Drop for ApprovalDigestKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

struct EncodedSqlCipherKey {
    bytes: [u8; RAW_KEY_LITERAL_LENGTH],
}

impl EncodedSqlCipherKey {
    fn derive(root_key: &DeviceRootKey) -> Result<Self, DeviceStateError> {
        let hkdf = Hkdf::<Sha256>::new(None, root_key.expose());
        let mut derived = [0_u8; 32];
        hkdf.expand(DATABASE_KEY_DOMAIN, &mut derived)
            .map_err(|_| DeviceStateError::KeyDerivationFailed)?;

        let mut bytes = [0_u8; RAW_KEY_LITERAL_LENGTH];
        bytes[0] = b'x';
        bytes[1] = b'\'';
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (index, value) in derived.iter().copied().enumerate() {
            bytes[2 + index * 2] = HEX[usize::from(value >> 4)];
            bytes[3 + index * 2] = HEX[usize::from(value & 0x0f)];
        }
        bytes[RAW_KEY_LITERAL_LENGTH - 1] = b'\'';
        derived.zeroize();
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8; RAW_KEY_LITERAL_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedSqlCipherKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedSqlCipherKey(<redacted>)")
    }
}

impl Drop for EncodedSqlCipherKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

struct IncompleteDatabase {
    database_path: PathBuf,
    armed: bool,
}

impl IncompleteDatabase {
    fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for IncompleteDatabase {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.database_path);
            for (path, _) in database_sidecars(&self.database_path) {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn open_connection(path: &Path) -> Result<Connection, DeviceStateError> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Open, error))
}

fn key_and_configure(
    connection: &Connection,
    root_key: &DeviceRootKey,
) -> Result<SqlCipherVersion, DeviceStateError> {
    let encoded_key = EncodedSqlCipherKey::derive(root_key)?;
    sqlcipher_ffi::set_raw_key(connection, encoded_key.as_bytes()).map_err(|_| {
        DeviceStateError::Database {
            operation: DeviceStateDatabaseOperation::Key,
            category: DeviceStateDatabaseErrorCategory::Other,
        }
    })?;

    connection
        .execute_batch(
            "PRAGMA cipher_memory_security = ON;
             PRAGMA cipher_use_hmac = ON;
             PRAGMA cipher_plaintext_header_size = 0;",
        )
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Configure, error))?;
    verify_pragma_text(connection, "PRAGMA cipher_log_level = NONE", "NONE")?;

    let version_text: String = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(|_| DeviceStateError::UnsupportedSqlCipher { major: 0 })?;
    let version = parse_sqlcipher_version(&version_text)
        .ok_or(DeviceStateError::UnsupportedSqlCipher { major: 0 })?;
    if version.major != DEVICE_STATE_SQLCIPHER_MAJOR {
        return Err(DeviceStateError::UnsupportedSqlCipher {
            major: version.major,
        });
    }
    verify_pragma_i64(connection, "PRAGMA cipher_memory_security", 1)?;
    verify_pragma_i64(connection, "PRAGMA cipher_use_hmac", 1)?;
    verify_pragma_i64(connection, "PRAGMA cipher_plaintext_header_size", 0)?;
    Ok(version)
}

fn authenticate_empty_database(connection: &Connection) -> Result<(), DeviceStateError> {
    let table_count: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(|_| DeviceStateError::AuthenticationFailed)?;
    if table_count != 0 {
        return Err(DeviceStateError::AlreadyInitialized);
    }
    Ok(())
}

fn authenticate_existing_database(connection: &Connection) -> Result<(), DeviceStateError> {
    connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|_| ())
        .map_err(|_| DeviceStateError::AuthenticationFailed)
}

fn initialize_schema(
    connection: &mut Connection,
    created_at: StateTimestamp,
) -> Result<(), DeviceStateError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(|error| {
            map_database_error(DeviceStateDatabaseOperation::InitializeSchema, error)
        })?;
    transaction
        .execute_batch(CREATE_SCHEMA_V1)
        .map_err(|error| {
            map_database_error(DeviceStateDatabaseOperation::InitializeSchema, error)
        })?;
    transaction
        .execute_batch(MIGRATE_SCHEMA_V1_TO_V2)
        .map_err(|error| {
            map_database_error(DeviceStateDatabaseOperation::InitializeSchema, error)
        })?;
    transaction
        .execute(
            "INSERT INTO device_settings (
                singleton,
                apps_tools_paused,
                audit_retention_days,
                created_at_ms,
                updated_at_ms
             ) VALUES (1, 0, ?1, ?2, ?2)",
            params![
                i64::from(DEFAULT_AUDIT_RETENTION_DAYS),
                created_at.unix_millis()
            ],
        )
        .map_err(map_write_error)?;
    transaction
        .commit()
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::InitializeSchema, error))
}

fn configure_authenticated_connection(connection: &Connection) -> Result<(), DeviceStateError> {
    connection
        .busy_timeout(DATABASE_BUSY_TIMEOUT)
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Configure, error))?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA temp_store = MEMORY;
             PRAGMA synchronous = FULL;
             PRAGMA wal_autocheckpoint = 100;",
        )
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Configure, error))?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Configure, error))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(DeviceStateError::Database {
            operation: DeviceStateDatabaseOperation::Configure,
            category: DeviceStateDatabaseErrorCategory::Other,
        });
    }
    verify_pragma_i64(connection, "PRAGMA foreign_keys", 1)?;
    verify_pragma_i64(connection, "PRAGMA secure_delete", 1)?;
    verify_pragma_i64(connection, "PRAGMA trusted_schema", 0)?;
    verify_pragma_i64(connection, "PRAGMA temp_store", 2)?;
    verify_pragma_i64(connection, "PRAGMA synchronous", 2)?;
    Ok(())
}

fn verify_pragma_i64(
    connection: &Connection,
    pragma: &str,
    expected: i64,
) -> Result<(), DeviceStateError> {
    let value = connection
        .query_row(pragma, [], |row| match row.get_ref(0)? {
            ValueRef::Integer(value) => Ok(value),
            ValueRef::Text(value) => std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(0, "pragma".to_owned(), Type::Text)
                }),
            value => Err(rusqlite::Error::InvalidColumnType(
                0,
                "pragma".to_owned(),
                value.data_type(),
            )),
        })
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Configure, error))?;
    if value != expected {
        return Err(DeviceStateError::Database {
            operation: DeviceStateDatabaseOperation::Configure,
            category: DeviceStateDatabaseErrorCategory::Other,
        });
    }
    Ok(())
}

fn verify_pragma_text(
    connection: &Connection,
    pragma: &str,
    expected: &str,
) -> Result<(), DeviceStateError> {
    let value: String = connection
        .query_row(pragma, [], |row| row.get(0))
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Configure, error))?;
    if value != expected {
        return Err(DeviceStateError::Database {
            operation: DeviceStateDatabaseOperation::Configure,
            category: DeviceStateDatabaseErrorCategory::Other,
        });
    }
    Ok(())
}

fn verify_schema(connection: &Connection) -> Result<(), DeviceStateError> {
    let version = read_schema_version(connection)?;
    if version != CURRENT_DEVICE_SCHEMA_VERSION {
        return Err(DeviceStateError::UnsupportedSchema {
            found: version,
            supported: CURRENT_DEVICE_SCHEMA_VERSION,
        });
    }

    verify_required_tables(connection, REQUIRED_TABLES)
}

fn verify_required_tables(
    connection: &Connection,
    required_tables: &[&str],
) -> Result<(), DeviceStateError> {
    for required in required_tables {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM sqlite_schema
                    WHERE type = 'table' AND name = ?1
                )",
                [required],
                |row| row.get(0),
            )
            .map_err(|error| {
                map_database_error(DeviceStateDatabaseOperation::VerifySchema, error)
            })?;
        if !exists {
            return Err(DeviceStateError::CorruptSchema);
        }
    }
    Ok(())
}

fn migrate_schema(connection: &mut Connection) -> Result<(), DeviceStateError> {
    let version = read_schema_version(connection)?;
    match version {
        CURRENT_DEVICE_SCHEMA_VERSION => Ok(()),
        1 => {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Exclusive)
                .map_err(|error| {
                    map_database_error(DeviceStateDatabaseOperation::InitializeSchema, error)
                })?;
            verify_required_tables(&transaction, REQUIRED_TABLES_V1)?;
            transaction
                .execute_batch(MIGRATE_SCHEMA_V1_TO_V2)
                .map_err(|error| {
                    map_database_error(DeviceStateDatabaseOperation::InitializeSchema, error)
                })?;
            transaction.commit().map_err(|error| {
                map_database_error(DeviceStateDatabaseOperation::InitializeSchema, error)
            })
        }
        found => Err(DeviceStateError::UnsupportedSchema {
            found,
            supported: CURRENT_DEVICE_SCHEMA_VERSION,
        }),
    }
}

fn read_schema_version(connection: &Connection) -> Result<i64, DeviceStateError> {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::VerifySchema, error))
}

fn verify_authenticated_database(connection: &Connection) -> Result<(), DeviceStateError> {
    verify_schema(connection)?;

    verify_database_integrity(connection)
}

fn verify_database_integrity(connection: &Connection) -> Result<(), DeviceStateError> {
    let mut statement = connection
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(|_| DeviceStateError::AuthenticationFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| DeviceStateError::AuthenticationFailed)?;
    if rows
        .next()
        .map_err(|_| DeviceStateError::AuthenticationFailed)?
        .is_some()
    {
        return Err(DeviceStateError::AuthenticationFailed);
    }
    drop(rows);
    drop(statement);

    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| DeviceStateError::AuthenticationFailed)?;
    if quick_check != "ok" {
        return Err(DeviceStateError::AuthenticationFailed);
    }
    Ok(())
}

fn parse_sqlcipher_version(value: &str) -> Option<SqlCipherVersion> {
    let base = value.split_whitespace().next()?;
    let mut parts = base.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some(SqlCipherVersion {
        major,
        minor,
        patch,
    })
}

#[cfg(unix)]
fn validate_state_directory(path: &Path) -> Result<(), DeviceStateError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path).map_err(|error| DeviceStateError::Io {
        entry: DeviceStateFileEntry::StateDirectory,
        operation: DeviceStateFileOperation::Inspect,
        kind: error.kind(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(DeviceStateError::SymbolicLink {
            entry: DeviceStateFileEntry::StateDirectory,
        });
    }
    if !metadata.is_dir() {
        return Err(DeviceStateError::UnexpectedFileType {
            entry: DeviceStateFileEntry::StateDirectory,
        });
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(DeviceStateError::UnexpectedOwner {
            entry: DeviceStateFileEntry::StateDirectory,
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode != PRIVATE_DIRECTORY_MODE {
        return Err(DeviceStateError::InsecurePermissions {
            entry: DeviceStateFileEntry::StateDirectory,
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_state_directory(_path: &Path) -> Result<(), DeviceStateError> {
    Err(DeviceStateError::UnsupportedPlatform)
}

fn ensure_new_database_paths_available(database_path: &Path) -> Result<(), DeviceStateError> {
    match fs::symlink_metadata(database_path) {
        Ok(_) => {
            validate_private_file(database_path, DeviceStateFileEntry::Database)?;
            return Err(DeviceStateError::AlreadyInitialized);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(DeviceStateError::Io {
                entry: DeviceStateFileEntry::Database,
                operation: DeviceStateFileOperation::Inspect,
                kind: error.kind(),
            });
        }
    }
    for (path, entry) in database_sidecars(database_path) {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                validate_private_file(&path, entry)?;
                return Err(DeviceStateError::AlreadyInitialized);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(DeviceStateError::Io {
                    entry,
                    operation: DeviceStateFileOperation::Inspect,
                    kind: error.kind(),
                });
            }
        }
    }
    Ok(())
}

fn validate_existing_database_paths(database_path: &Path) -> Result<(), DeviceStateError> {
    match fs::symlink_metadata(database_path) {
        Ok(_) => validate_private_file(database_path, DeviceStateFileEntry::Database)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(DeviceStateError::Missing);
        }
        Err(error) => {
            return Err(DeviceStateError::Io {
                entry: DeviceStateFileEntry::Database,
                operation: DeviceStateFileOperation::Inspect,
                kind: error.kind(),
            });
        }
    }
    for (path, entry) in database_sidecars(database_path) {
        validate_optional_private_file(&path, entry)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_database_file(path: &Path) -> Result<(), DeviceStateError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .read(true)
        .write(true)
        .mode(PRIVATE_FILE_MODE);
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            DeviceStateError::AlreadyInitialized
        } else {
            DeviceStateError::Io {
                entry: DeviceStateFileEntry::Database,
                operation: DeviceStateFileOperation::Create,
                kind: error.kind(),
            }
        }
    })?;
    file.sync_all().map_err(|error| DeviceStateError::Io {
        entry: DeviceStateFileEntry::Database,
        operation: DeviceStateFileOperation::Create,
        kind: error.kind(),
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).map_err(|error| {
        DeviceStateError::Io {
            entry: DeviceStateFileEntry::Database,
            operation: DeviceStateFileOperation::SetPermissions,
            kind: error.kind(),
        }
    })?;
    validate_private_file(path, DeviceStateFileEntry::Database)
}

#[cfg(not(unix))]
fn create_private_database_file(_path: &Path) -> Result<(), DeviceStateError> {
    Err(DeviceStateError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_private_file(path: &Path, entry: DeviceStateFileEntry) -> Result<(), DeviceStateError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path).map_err(|error| DeviceStateError::Io {
        entry,
        operation: DeviceStateFileOperation::Inspect,
        kind: error.kind(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(DeviceStateError::SymbolicLink { entry });
    }
    if !metadata.is_file() {
        return Err(DeviceStateError::UnexpectedFileType { entry });
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(DeviceStateError::UnexpectedOwner { entry });
    }
    let mode = metadata.mode() & 0o777;
    if mode != PRIVATE_FILE_MODE {
        return Err(DeviceStateError::InsecurePermissions { entry, mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file(
    _path: &Path,
    _entry: DeviceStateFileEntry,
) -> Result<(), DeviceStateError> {
    Err(DeviceStateError::UnsupportedPlatform)
}

fn validate_optional_private_file(
    path: &Path,
    entry: DeviceStateFileEntry,
) -> Result<(), DeviceStateError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_file(path, entry),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DeviceStateError::Io {
            entry,
            operation: DeviceStateFileOperation::Inspect,
            kind: error.kind(),
        }),
    }
}

fn remove_existing_state_files(
    state_directory: &Path,
) -> Result<DeviceStateRemoval, DeviceStateError> {
    validate_state_directory(state_directory)?;
    let database_path = state_directory.join(DEVICE_STATE_DATABASE_FILENAME);
    validate_optional_private_file(&database_path, DeviceStateFileEntry::Database)?;
    let sidecars = database_sidecars(&database_path);
    for (path, entry) in &sidecars {
        validate_optional_private_file(path, *entry)?;
    }

    let mut managed_files_removed = 0_usize;
    for (path, entry) in sidecars.into_iter().chain(std::iter::once((
        database_path,
        DeviceStateFileEntry::Database,
    ))) {
        if remove_optional_private_file(&path, entry)? {
            managed_files_removed = managed_files_removed.saturating_add(1);
        }
    }
    sync_state_directory(state_directory)?;
    Ok(DeviceStateRemoval {
        managed_files_removed,
    })
}

fn remove_optional_private_file(
    path: &Path,
    entry: DeviceStateFileEntry,
) -> Result<bool, DeviceStateError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_file(path, entry)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(DeviceStateError::Io {
                entry,
                operation: DeviceStateFileOperation::Inspect,
                kind: error.kind(),
            });
        }
    }

    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(DeviceStateError::Io {
                entry,
                operation: DeviceStateFileOperation::Remove,
                kind: error.kind(),
            });
        }
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Err(DeviceStateError::RemovalVerificationFailed { entry }),
        Err(error) => Err(DeviceStateError::Io {
            entry,
            operation: DeviceStateFileOperation::Inspect,
            kind: error.kind(),
        }),
    }
}

fn sync_state_directory(state_directory: &Path) -> Result<(), DeviceStateError> {
    let directory = File::open(state_directory).map_err(|error| DeviceStateError::Io {
        entry: DeviceStateFileEntry::StateDirectory,
        operation: DeviceStateFileOperation::Sync,
        kind: error.kind(),
    })?;
    directory.sync_all().map_err(|error| DeviceStateError::Io {
        entry: DeviceStateFileEntry::StateDirectory,
        operation: DeviceStateFileOperation::Sync,
        kind: error.kind(),
    })
}

fn verify_database_header(path: &Path) -> Result<(), DeviceStateError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| DeviceStateError::Io {
        entry: DeviceStateFileEntry::Database,
        operation: DeviceStateFileOperation::Inspect,
        kind: error.kind(),
    })?;
    if metadata.len() < SQLITE_PLAINTEXT_HEADER.len() as u64 {
        return Err(DeviceStateError::TruncatedDatabase);
    }

    let mut file = File::open(path).map_err(|error| DeviceStateError::Io {
        entry: DeviceStateFileEntry::Database,
        operation: DeviceStateFileOperation::ReadHeader,
        kind: error.kind(),
    })?;
    let mut header = [0_u8; 16];
    file.read_exact(&mut header)
        .map_err(|error| DeviceStateError::Io {
            entry: DeviceStateFileEntry::Database,
            operation: DeviceStateFileOperation::ReadHeader,
            kind: error.kind(),
        })?;
    if &header == SQLITE_PLAINTEXT_HEADER {
        return Err(DeviceStateError::PlaintextDatabase);
    }
    Ok(())
}

fn database_sidecars(database_path: &Path) -> [(PathBuf, DeviceStateFileEntry); 2] {
    let mut write_ahead_log = database_path.as_os_str().to_os_string();
    write_ahead_log.push("-wal");
    let mut shared_memory = database_path.as_os_str().to_os_string();
    shared_memory.push("-shm");
    [
        (
            PathBuf::from(write_ahead_log),
            DeviceStateFileEntry::WriteAheadLog,
        ),
        (
            PathBuf::from(shared_memory),
            DeviceStateFileEntry::SharedMemory,
        ),
    ]
}

fn map_write_error(error: rusqlite::Error) -> DeviceStateError {
    match &error {
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation =>
        {
            DeviceStateError::Conflict
        }
        _ => map_database_error(DeviceStateDatabaseOperation::Write, error),
    }
}

fn map_database_error(
    operation: DeviceStateDatabaseOperation,
    error: rusqlite::Error,
) -> DeviceStateError {
    let category = match error {
        rusqlite::Error::SqliteFailure(inner, _) => match inner.code {
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                DeviceStateDatabaseErrorCategory::Busy
            }
            ErrorCode::ConstraintViolation => DeviceStateDatabaseErrorCategory::Constraint,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => {
                DeviceStateDatabaseErrorCategory::Corrupt
            }
            ErrorCode::PermissionDenied
            | ErrorCode::ReadOnly
            | ErrorCode::SystemIoFailure
            | ErrorCode::DiskFull
            | ErrorCode::CannotOpen => DeviceStateDatabaseErrorCategory::Unavailable,
            _ => DeviceStateDatabaseErrorCategory::Other,
        },
        _ => DeviceStateDatabaseErrorCategory::Other,
    };
    DeviceStateError::Database {
        operation,
        category,
    }
}

fn query_models<P, W, M, F, G>(
    connection: &Connection,
    sql: &str,
    parameters: P,
    read_wire: F,
    into_model: G,
) -> Result<Vec<M>, DeviceStateError>
where
    P: rusqlite::Params,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<W>,
    G: Fn(W) -> Result<M, DeviceStateError>,
{
    let mut statement = connection
        .prepare(sql)
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
    let rows = statement
        .query_map(parameters, read_wire)
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
    let wires = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
    wires.into_iter().map(into_model).collect()
}

struct ConsumerWire {
    consumer_id: String,
    pairing_public_key: Vec<u8>,
    label: String,
    executable_name: Option<String>,
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    code_signature_digest: Option<Vec<u8>>,
    created_at_ms: i64,
}

impl ConsumerWire {
    fn into_model(self) -> Result<Consumer, DeviceStateError> {
        Consumer::with_id(
            parse_local_id(&self.consumer_id)?,
            vec_to_array(self.pairing_public_key)?,
            self.label,
            ObservedConsumerIdentity::new(
                self.executable_name,
                self.bundle_identifier,
                self.team_identifier,
                self.code_signature_digest.map(vec_to_array).transpose()?,
            )
            .map_err(DeviceStateError::from)?,
            parse_timestamp(self.created_at_ms)?,
        )
        .map_err(DeviceStateError::from)
    }
}

fn read_consumer_wire(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsumerWire> {
    Ok(ConsumerWire {
        consumer_id: row.get(0)?,
        pairing_public_key: row.get(1)?,
        label: row.get(2)?,
        executable_name: row.get(3)?,
        bundle_identifier: row.get(4)?,
        team_identifier: row.get(5)?,
        code_signature_digest: row.get(6)?,
        created_at_ms: row.get(7)?,
    })
}

struct AccessRuleWire {
    access_rule_id: String,
    consumer_id: String,
    vault_id: String,
    credential_id: String,
    secret_field_id: String,
    capability_name: String,
    capability_version: i64,
    confirmation_policy: String,
    expires_at_ms: Option<i64>,
    created_at_ms: i64,
}

impl AccessRuleWire {
    fn into_model(self) -> Result<AccessRule, DeviceStateError> {
        let lifetime = self
            .expires_at_ms
            .map(parse_timestamp)
            .transpose()?
            .map_or(RuleLifetime::Persistent, RuleLifetime::Until);
        AccessRule::with_id(
            parse_local_id(&self.access_rule_id)?,
            parse_authorization_target(
                &self.consumer_id,
                &self.vault_id,
                &self.credential_id,
                &self.secret_field_id,
                &self.capability_name,
                self.capability_version,
            )?,
            parse_enum(&self.confirmation_policy)?,
            lifetime,
            parse_timestamp(self.created_at_ms)?,
        )
        .map_err(DeviceStateError::from)
    }
}

fn read_access_rule_wire(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccessRuleWire> {
    Ok(AccessRuleWire {
        access_rule_id: row.get(0)?,
        consumer_id: row.get(1)?,
        vault_id: row.get(2)?,
        credential_id: row.get(3)?,
        secret_field_id: row.get(4)?,
        capability_name: row.get(5)?,
        capability_version: row.get(6)?,
        confirmation_policy: row.get(7)?,
        expires_at_ms: row.get(8)?,
        created_at_ms: row.get(9)?,
    })
}

fn insert_access_rule_row(
    connection: &Connection,
    rule: &AccessRule,
) -> Result<(), DeviceStateError> {
    let target = rule.target();
    let field = target.field_scope();
    let expires_at = match rule.lifetime() {
        RuleLifetime::Persistent => None,
        RuleLifetime::Until(value) => Some(value.unix_millis()),
    };
    connection
        .execute(
            "INSERT INTO access_rules (
                access_rule_id,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                confirmation_policy,
                expires_at_ms,
                created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rule.access_rule_id().to_string(),
                target.consumer_id().to_string(),
                field.vault_id().to_string(),
                field.credential_id().to_string(),
                field.secret_field_id().to_string(),
                target.capability().name().as_str(),
                i64::from(target.capability().version()),
                rule.confirmation_policy().as_str(),
                expires_at,
                rule.created_at().unix_millis(),
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn access_rule_for_target_from_connection(
    connection: &Connection,
    target: AuthorizationTarget,
) -> Result<Option<AccessRule>, DeviceStateError> {
    let field = target.field_scope();
    let rules = query_models(
        connection,
        "SELECT
            access_rule_id,
            consumer_id,
            vault_id,
            credential_id,
            secret_field_id,
            capability_name,
            capability_version,
            confirmation_policy,
            expires_at_ms,
            created_at_ms
         FROM access_rules
         WHERE consumer_id = ?1
           AND vault_id = ?2
           AND credential_id = ?3
           AND secret_field_id = ?4
           AND capability_name = ?5
           AND capability_version = ?6
         ORDER BY created_at_ms, access_rule_id
         LIMIT 2",
        params![
            target.consumer_id().to_string(),
            field.vault_id().to_string(),
            field.credential_id().to_string(),
            field.secret_field_id().to_string(),
            target.capability().name().as_str(),
            i64::from(target.capability().version()),
        ],
        read_access_rule_wire,
        AccessRuleWire::into_model,
    )?;
    match rules.as_slice() {
        [] => Ok(None),
        [rule] => Ok(Some(rule.clone())),
        _ => Err(DeviceStateError::CorruptSchema),
    }
}

struct UseGrantWire {
    use_grant_id: String,
    consumer_id: String,
    vault_id: String,
    credential_id: String,
    secret_field_id: String,
    capability_name: String,
    capability_version: i64,
    source_rule_id: Option<String>,
    vault_session_id: String,
    grant_scope: String,
    created_at_ms: i64,
    expires_at_ms: i64,
}

impl UseGrantWire {
    fn into_model(self) -> Result<UseGrant, DeviceStateError> {
        UseGrant::with_id(
            parse_local_id(&self.use_grant_id)?,
            parse_authorization_target(
                &self.consumer_id,
                &self.vault_id,
                &self.credential_id,
                &self.secret_field_id,
                &self.capability_name,
                self.capability_version,
            )?,
            self.source_rule_id
                .as_deref()
                .map(parse_local_id)
                .transpose()?,
            parse_local_id(&self.vault_session_id)?,
            parse_enum(&self.grant_scope)?,
            parse_timestamp(self.created_at_ms)?,
            parse_timestamp(self.expires_at_ms)?,
        )
        .map_err(DeviceStateError::from)
    }
}

fn insert_use_grant_row(connection: &Connection, grant: &UseGrant) -> Result<(), DeviceStateError> {
    let target = grant.target();
    let field = target.field_scope();
    let remaining_uses = match grant.scope() {
        GrantScope::OneOperation => Some(1_i64),
        GrantScope::UnlockSession => None,
    };
    connection
        .execute(
            "INSERT INTO use_grants (
                use_grant_id,
                consumer_id,
                vault_id,
                credential_id,
                secret_field_id,
                capability_name,
                capability_version,
                source_rule_id,
                vault_session_id,
                grant_scope,
                remaining_uses,
                created_at_ms,
                expires_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                grant.use_grant_id().to_string(),
                target.consumer_id().to_string(),
                field.vault_id().to_string(),
                field.credential_id().to_string(),
                field.secret_field_id().to_string(),
                target.capability().name().as_str(),
                i64::from(target.capability().version()),
                grant.source_rule_id().map(|value| value.to_string()),
                grant.vault_session_id().to_string(),
                grant.scope().as_str(),
                remaining_uses,
                grant.created_at().unix_millis(),
                grant.expires_at().unix_millis(),
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn read_use_grant_wire(row: &rusqlite::Row<'_>) -> rusqlite::Result<UseGrantWire> {
    Ok(UseGrantWire {
        use_grant_id: row.get(0)?,
        consumer_id: row.get(1)?,
        vault_id: row.get(2)?,
        credential_id: row.get(3)?,
        secret_field_id: row.get(4)?,
        capability_name: row.get(5)?,
        capability_version: row.get(6)?,
        source_rule_id: row.get(7)?,
        vault_session_id: row.get(8)?,
        grant_scope: row.get(9)?,
        created_at_ms: row.get(10)?,
        expires_at_ms: row.get(11)?,
    })
}

struct UsageProfileWire {
    usage_profile_id: String,
    consumer_id: String,
    label: String,
    capability_name: String,
    capability_version: i64,
    definition_version: i64,
    placement_json: String,
    created_at_ms: i64,
}

impl UsageProfileWire {
    fn into_model(self) -> Result<UsageProfile, DeviceStateError> {
        if self.definition_version != i64::from(CURRENT_USAGE_PROFILE_DEFINITION_VERSION) {
            return Err(DeviceStateError::CorruptRecord);
        }
        let placement: UsagePlacement = serde_json::from_str(&self.placement_json)
            .map_err(|_| DeviceStateError::CorruptRecord)?;
        UsageProfile::with_id(
            parse_local_id(&self.usage_profile_id)?,
            parse_local_id(&self.consumer_id)?,
            self.label,
            parse_capability(&self.capability_name, self.capability_version)?,
            placement,
            parse_timestamp(self.created_at_ms)?,
        )
        .map_err(DeviceStateError::from)
    }
}

fn read_usage_profile_wire(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsageProfileWire> {
    Ok(UsageProfileWire {
        usage_profile_id: row.get(0)?,
        consumer_id: row.get(1)?,
        label: row.get(2)?,
        capability_name: row.get(3)?,
        capability_version: row.get(4)?,
        definition_version: row.get(5)?,
        placement_json: row.get(6)?,
        created_at_ms: row.get(7)?,
    })
}

struct ApprovalColumns {
    consumer_id: String,
    pairing_public_key: Option<Vec<u8>>,
    executable_name: Option<String>,
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    code_signature_digest: Option<Vec<u8>>,
    vault_id: Option<String>,
    credential_id: Option<String>,
    secret_field_id: Option<String>,
    capability_name: Option<&'static str>,
    capability_version: Option<i64>,
}

impl ApprovalColumns {
    fn from_subject(subject: &ApprovalSubject) -> Self {
        match subject {
            ApprovalSubject::Pairing {
                consumer_id,
                pairing_public_key,
                observed_identity,
            } => Self {
                consumer_id: consumer_id.to_string(),
                pairing_public_key: Some(pairing_public_key.to_vec()),
                executable_name: observed_identity.executable_name().map(ToOwned::to_owned),
                bundle_identifier: observed_identity.bundle_identifier().map(ToOwned::to_owned),
                team_identifier: observed_identity.team_identifier().map(ToOwned::to_owned),
                code_signature_digest: observed_identity
                    .code_signature_digest()
                    .map(|value| value.to_vec()),
                vault_id: None,
                credential_id: None,
                secret_field_id: None,
                capability_name: None,
                capability_version: None,
            },
            ApprovalSubject::Unlock {
                consumer_id,
                vault_id,
            } => Self {
                consumer_id: consumer_id.to_string(),
                pairing_public_key: None,
                executable_name: None,
                bundle_identifier: None,
                team_identifier: None,
                code_signature_digest: None,
                vault_id: Some(vault_id.to_string()),
                credential_id: None,
                secret_field_id: None,
                capability_name: None,
                capability_version: None,
            },
            ApprovalSubject::Access { target } => {
                let field = target.field_scope();
                Self {
                    consumer_id: target.consumer_id().to_string(),
                    pairing_public_key: None,
                    executable_name: None,
                    bundle_identifier: None,
                    team_identifier: None,
                    code_signature_digest: None,
                    vault_id: Some(field.vault_id().to_string()),
                    credential_id: Some(field.credential_id().to_string()),
                    secret_field_id: Some(field.secret_field_id().to_string()),
                    capability_name: Some(target.capability().name().as_str()),
                    capability_version: Some(i64::from(target.capability().version())),
                }
            }
            ApprovalSubject::CredentialAccess {
                consumer_id,
                vault_id,
                capability,
            } => Self {
                consumer_id: consumer_id.to_string(),
                pairing_public_key: None,
                executable_name: None,
                bundle_identifier: None,
                team_identifier: None,
                code_signature_digest: None,
                vault_id: Some(vault_id.to_string()),
                credential_id: None,
                secret_field_id: None,
                capability_name: Some(capability.name().as_str()),
                capability_version: Some(i64::from(capability.version())),
            },
        }
    }
}

const APPROVAL_SELECT_BY_ID: &str = "
    SELECT
        approval_request_id,
        approval_kind,
        consumer_id,
        pairing_public_key,
        executable_name,
        bundle_identifier,
        team_identifier,
        code_signature_digest,
        vault_id,
        credential_id,
        secret_field_id,
        capability_name,
        capability_version,
        coalescing_digest,
        approval_status,
        created_at_ms,
        expires_at_ms,
        resolved_at_ms
    FROM approvals
    WHERE approval_request_id = ?1";

const APPROVAL_SELECT_PENDING: &str = "
    SELECT
        approval_request_id,
        approval_kind,
        consumer_id,
        pairing_public_key,
        executable_name,
        bundle_identifier,
        team_identifier,
        code_signature_digest,
        vault_id,
        credential_id,
        secret_field_id,
        capability_name,
        capability_version,
        coalescing_digest,
        approval_status,
        created_at_ms,
        expires_at_ms,
        resolved_at_ms
    FROM approvals
    WHERE approval_status = 'pending'
    ORDER BY expires_at_ms, approval_request_id";

struct ApprovalWire {
    approval_request_id: String,
    approval_kind: String,
    consumer_id: String,
    pairing_public_key: Option<Vec<u8>>,
    executable_name: Option<String>,
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    code_signature_digest: Option<Vec<u8>>,
    vault_id: Option<String>,
    credential_id: Option<String>,
    secret_field_id: Option<String>,
    capability_name: Option<String>,
    capability_version: Option<i64>,
    coalescing_digest: Vec<u8>,
    approval_status: String,
    created_at_ms: i64,
    expires_at_ms: i64,
    resolved_at_ms: Option<i64>,
}

impl ApprovalWire {
    fn into_model(self) -> Result<ApprovalRequest, DeviceStateError> {
        let kind: ApprovalKind = parse_enum(&self.approval_kind)?;
        let consumer_id = parse_local_id(&self.consumer_id)?;
        let subject = match kind {
            ApprovalKind::Pairing => ApprovalSubject::Pairing {
                consumer_id,
                pairing_public_key: vec_to_array(
                    self.pairing_public_key
                        .ok_or(DeviceStateError::CorruptRecord)?,
                )?,
                observed_identity: ObservedConsumerIdentity::new(
                    self.executable_name,
                    self.bundle_identifier,
                    self.team_identifier,
                    self.code_signature_digest.map(vec_to_array).transpose()?,
                )
                .map_err(|_| DeviceStateError::CorruptRecord)?,
            },
            ApprovalKind::Unlock => ApprovalSubject::Unlock {
                consumer_id,
                vault_id: parse_core_id(
                    self.vault_id
                        .as_deref()
                        .ok_or(DeviceStateError::CorruptRecord)?,
                )?,
            },
            ApprovalKind::Access => ApprovalSubject::Access {
                target: parse_authorization_target(
                    &self.consumer_id,
                    self.vault_id
                        .as_deref()
                        .ok_or(DeviceStateError::CorruptRecord)?,
                    self.credential_id
                        .as_deref()
                        .ok_or(DeviceStateError::CorruptRecord)?,
                    self.secret_field_id
                        .as_deref()
                        .ok_or(DeviceStateError::CorruptRecord)?,
                    self.capability_name
                        .as_deref()
                        .ok_or(DeviceStateError::CorruptRecord)?,
                    self.capability_version
                        .ok_or(DeviceStateError::CorruptRecord)?,
                )?,
            },
            ApprovalKind::CredentialAccess => ApprovalSubject::CredentialAccess {
                consumer_id,
                vault_id: parse_core_id(
                    self.vault_id
                        .as_deref()
                        .ok_or(DeviceStateError::CorruptRecord)?,
                )?,
                capability: parse_capability(
                    self.capability_name
                        .as_deref()
                        .ok_or(DeviceStateError::CorruptRecord)?,
                    self.capability_version
                        .ok_or(DeviceStateError::CorruptRecord)?,
                )?,
            },
        };

        ApprovalRequest::with_id(
            parse_local_id(&self.approval_request_id)?,
            subject,
            vec_to_array(self.coalescing_digest)?,
            parse_enum(&self.approval_status)?,
            parse_timestamp(self.created_at_ms)?,
            parse_timestamp(self.expires_at_ms)?,
            self.resolved_at_ms.map(parse_timestamp).transpose()?,
        )
        .map_err(|_| DeviceStateError::CorruptRecord)
    }
}

fn read_approval_wire(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalWire> {
    Ok(ApprovalWire {
        approval_request_id: row.get(0)?,
        approval_kind: row.get(1)?,
        consumer_id: row.get(2)?,
        pairing_public_key: row.get(3)?,
        executable_name: row.get(4)?,
        bundle_identifier: row.get(5)?,
        team_identifier: row.get(6)?,
        code_signature_digest: row.get(7)?,
        vault_id: row.get(8)?,
        credential_id: row.get(9)?,
        secret_field_id: row.get(10)?,
        capability_name: row.get(11)?,
        capability_version: row.get(12)?,
        coalescing_digest: row.get(13)?,
        approval_status: row.get(14)?,
        created_at_ms: row.get(15)?,
        expires_at_ms: row.get(16)?,
        resolved_at_ms: row.get(17)?,
    })
}

fn approval_from_connection(
    connection: &Connection,
    approval_request_id: ApprovalRequestId,
) -> Result<Option<ApprovalRequest>, DeviceStateError> {
    let wire = connection
        .query_row(
            APPROVAL_SELECT_BY_ID,
            [approval_request_id.to_string()],
            read_approval_wire,
        )
        .optional()
        .map_err(|error| map_database_error(DeviceStateDatabaseOperation::Read, error))?;
    wire.map(ApprovalWire::into_model).transpose()
}

fn allow_once_grant_matches_subject(grant: &UseGrant, subject: &ApprovalSubject) -> bool {
    authorization_target_matches_subject(grant.target(), subject)
}

fn authorization_target_matches_subject(
    target: AuthorizationTarget,
    subject: &ApprovalSubject,
) -> bool {
    match subject {
        ApprovalSubject::Access {
            target: expected_target,
        } => target == *expected_target,
        ApprovalSubject::CredentialAccess {
            consumer_id,
            vault_id,
            capability,
        } => {
            target.consumer_id() == *consumer_id
                && target.field_scope().vault_id() == *vault_id
                && target.capability() == *capability
        }
        ApprovalSubject::Pairing { .. } | ApprovalSubject::Unlock { .. } => false,
    }
}

struct AuditWire {
    audit_event_id: String,
    occurred_at_ms: i64,
    event_kind: String,
    consumer_id: Option<String>,
    vault_id: Option<String>,
    credential_id: Option<String>,
    secret_field_id: Option<String>,
    capability_name: Option<String>,
    capability_version: Option<i64>,
    decision: String,
    confirmation_method: String,
    use_grant_id: Option<String>,
}

impl AuditWire {
    fn into_model(self) -> Result<AuditEvent, DeviceStateError> {
        let field_scope = match (self.vault_id, self.credential_id, self.secret_field_id) {
            (None, None, None) => None,
            (Some(vault_id), Some(credential_id), Some(secret_field_id)) => {
                Some(CredentialFieldScope::new(
                    parse_core_id(&vault_id)?,
                    parse_core_id(&credential_id)?,
                    parse_core_id(&secret_field_id)?,
                ))
            }
            _ => return Err(DeviceStateError::CorruptRecord),
        };
        let capability = match (self.capability_name, self.capability_version) {
            (None, None) => None,
            (Some(name), Some(version)) => Some(parse_capability(&name, version)?),
            _ => return Err(DeviceStateError::CorruptRecord),
        };
        let scope = AuditScope::new(
            self.consumer_id
                .as_deref()
                .map(parse_local_id)
                .transpose()?,
            field_scope,
            capability,
            self.use_grant_id
                .as_deref()
                .map(parse_local_id)
                .transpose()?,
        );
        Ok(AuditEvent::with_id(
            parse_local_id(&self.audit_event_id)?,
            parse_timestamp(self.occurred_at_ms)?,
            parse_enum(&self.event_kind)?,
            scope,
            parse_enum(&self.decision)?,
            parse_enum(&self.confirmation_method)?,
        ))
    }
}

fn read_audit_wire(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditWire> {
    Ok(AuditWire {
        audit_event_id: row.get(0)?,
        occurred_at_ms: row.get(1)?,
        event_kind: row.get(2)?,
        consumer_id: row.get(3)?,
        vault_id: row.get(4)?,
        credential_id: row.get(5)?,
        secret_field_id: row.get(6)?,
        capability_name: row.get(7)?,
        capability_version: row.get(8)?,
        decision: row.get(9)?,
        confirmation_method: row.get(10)?,
        use_grant_id: row.get(11)?,
    })
}

fn parse_authorization_target(
    consumer_id: &str,
    vault_id: &str,
    credential_id: &str,
    secret_field_id: &str,
    capability_name: &str,
    capability_version: i64,
) -> Result<AuthorizationTarget, DeviceStateError> {
    Ok(AuthorizationTarget::new(
        parse_local_id(consumer_id)?,
        CredentialFieldScope::new(
            parse_core_id(vault_id)?,
            parse_core_id(credential_id)?,
            parse_core_id(secret_field_id)?,
        ),
        parse_capability(capability_name, capability_version)?,
    ))
}

fn parse_capability(name: &str, version: i64) -> Result<Capability, DeviceStateError> {
    let version = u16::try_from(version).map_err(|_| DeviceStateError::CorruptRecord)?;
    Capability::new(parse_enum(name)?, version).map_err(DeviceStateError::from)
}

fn parse_timestamp(value: i64) -> Result<StateTimestamp, DeviceStateError> {
    StateTimestamp::from_unix_millis(value).map_err(|_| DeviceStateError::CorruptRecord)
}

fn parse_local_id<T>(value: &str) -> Result<T, DeviceStateError>
where
    T: FromStr<Err = LocalIdParseError>,
{
    value.parse().map_err(|_| DeviceStateError::CorruptRecord)
}

fn parse_core_id<T>(value: &str) -> Result<T, DeviceStateError>
where
    T: FromStr,
{
    value.parse().map_err(|_| DeviceStateError::CorruptRecord)
}

fn parse_enum<T>(value: &str) -> Result<T, DeviceStateError>
where
    T: FromStr,
{
    value.parse().map_err(|_| DeviceStateError::CorruptRecord)
}

fn vec_to_array<const N: usize>(value: Vec<u8>) -> Result<[u8; N], DeviceStateError> {
    value
        .try_into()
        .map_err(|_| DeviceStateError::CorruptRecord)
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    use psw_core::{
        CreateVaultRequest, CredentialId, SecretBytes, SecretFieldId, VaultCore, VaultId,
    };

    use super::*;
    use crate::grant_invalidation::BrokerGrantInvalidator;
    use crate::machine_access::{
        BrokerMachineAccessError, BrokerMachineAccessGate, BrokerMachineAccessTransition,
    };
    use crate::state_model::{
        AuditDecision, AuditEventKind, CapabilityName, ConfirmationMethod, ConfirmationPolicy,
        VaultSessionId,
    };
    use crate::vault_session::{
        BrokerVaultLockState, BrokerVaultSessionError, BrokerVaultSessionManager,
    };
    use crate::ControllerSigningKey;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestStateDirectory {
        path: PathBuf,
    }

    impl TestStateDirectory {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keptnear-state-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create state directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .expect("protect state directory");
            Self { path }
        }

        fn database_path(&self) -> PathBuf {
            self.path.join(DEVICE_STATE_DATABASE_FILENAME)
        }
    }

    impl Drop for TestStateDirectory {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn root_key(byte: u8) -> DeviceRootKey {
        DeviceRootKey::from_stored_bytes(vec![byte; 32]).expect("test root key")
    }

    fn timestamp(value: i64) -> StateTimestamp {
        StateTimestamp::from_unix_millis(value).expect("test timestamp")
    }

    fn sample_consumer(created_at: StateTimestamp) -> Consumer {
        Consumer::new(
            [7_u8; 32],
            "Codex local adapter".to_owned(),
            ObservedConsumerIdentity::new(
                Some("codex".to_owned()),
                Some("com.openai.codex".to_owned()),
                Some("OPENAI".to_owned()),
                Some([8_u8; 32]),
            )
            .expect("observed identity"),
            created_at,
        )
        .expect("Consumer")
    }

    fn sample_target(consumer_id: ConsumerId) -> AuthorizationTarget {
        AuthorizationTarget::new(
            consumer_id,
            CredentialFieldScope::new(
                VaultId::generate(),
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::ProcessRun),
        )
    }

    #[test]
    fn concurrent_connections_consume_one_operation_grant_once() {
        let state = TestStateDirectory::new("atomic-grant");
        let key = root_key(10);
        let first_store = DeviceStateStore::initialize_at(&state.path, &key, timestamp(100))
            .expect("initialize encrypted state");
        let consumer = sample_consumer(timestamp(110));
        first_store
            .insert_consumer(&consumer)
            .expect("insert Consumer");
        let target = sample_target(consumer.consumer_id());
        let vault_session_id = VaultSessionId::generate();
        let grant = UseGrant::new(
            target,
            None,
            vault_session_id,
            GrantScope::OneOperation,
            timestamp(120),
            timestamp(500),
        )
        .expect("grant");
        let grant_id = grant.use_grant_id();
        first_store.insert_use_grant(&grant).expect("insert grant");
        let second_store =
            DeviceStateStore::open_at(&state.path, &root_key(10)).expect("second connection");
        let barrier = Arc::new(Barrier::new(2));

        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            first_store.authorize_stored_use_grant(
                grant_id,
                target,
                vault_session_id,
                timestamp(130),
            )
        });
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            second_store.authorize_stored_use_grant(
                grant_id,
                target,
                vault_session_id,
                timestamp(130),
            )
        });
        let results = [
            first.join().expect("first thread").expect("first result"),
            second
                .join()
                .expect("second thread")
                .expect("second result"),
        ];

        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, StoredUseGrantAuthorization::Authorized(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, StoredUseGrantAuthorization::Unavailable))
                .count(),
            1
        );
    }

    #[test]
    fn initializes_encrypted_schema_and_reopens_with_the_same_key() {
        let state = TestStateDirectory::new("initialize");
        let key = root_key(11);
        let store = DeviceStateStore::initialize_at(&state.path, &key, timestamp(100))
            .expect("initialize encrypted state");

        assert_eq!(store.schema_version().expect("schema"), 2);
        assert_eq!(store.sqlcipher_version().major(), 4);
        assert!(!store.apps_tools_paused().expect("pause"));
        assert_eq!(
            store.audit_retention_days().expect("retention"),
            DEFAULT_AUDIT_RETENTION_DAYS
        );
        assert_private_file(&state.database_path());

        let database_bytes = fs::read(state.database_path()).expect("read encrypted database");
        assert!(database_bytes.len() >= 16);
        assert_ne!(&database_bytes[..16], SQLITE_PLAINTEXT_HEADER);
        assert!(!contains_bytes(&database_bytes, b"CREATE TABLE consumers"));

        drop(store);
        let reopened =
            DeviceStateStore::open_at(&state.path, &key).expect("reopen encrypted state");
        assert_eq!(reopened.schema_version().expect("schema"), 2);
        assert_eq!(reopened.sqlcipher_version().major(), 4);
    }

    #[test]
    fn migrates_authenticated_v1_state_and_rejects_future_schema() {
        let state = TestStateDirectory::new("schema-migration");
        let key = root_key(31);
        let store = DeviceStateStore::initialize_at(&state.path, &key, timestamp(100))
            .expect("initialize encrypted state");
        store
            .connection
            .execute_batch("DROP TABLE controller_authority; PRAGMA user_version = 1;")
            .expect("construct authenticated v1 fixture");
        drop(store);

        let migrated = DeviceStateStore::open_at(&state.path, &key).expect("migrate v1 state");
        assert_eq!(migrated.schema_version().expect("schema"), 2);
        assert_eq!(
            migrated
                .controller_authority_record()
                .expect("controller record"),
            None
        );
        migrated
            .connection
            .execute_batch("PRAGMA user_version = 3;")
            .expect("seed future version");
        drop(migrated);
        assert_eq!(
            DeviceStateStore::open_at(&state.path, &key).unwrap_err(),
            DeviceStateError::UnsupportedSchema {
                found: 3,
                supported: 2,
            }
        );
    }

    #[test]
    fn corrupt_v1_state_is_not_migrated_before_integrity_check() {
        let state = TestStateDirectory::new("corrupt-v1-migration");
        let key = root_key(33);
        let store = DeviceStateStore::initialize_at(&state.path, &key, timestamp(100))
            .expect("initialize encrypted state");
        store
            .connection
            .execute_batch(
                "CREATE TABLE corruption_target(payload BLOB) STRICT;
                 INSERT INTO corruption_target(payload) VALUES(zeroblob(32768));
                 DROP TABLE controller_authority;
                 PRAGMA user_version = 1;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("construct multi-page authenticated v1 fixture");
        let read_pragma = |pragma| {
            store
                .connection
                .query_row(pragma, [], |row| match row.get_ref(0)? {
                    ValueRef::Integer(value) => Ok(value),
                    ValueRef::Text(value) => std::str::from_utf8(value)
                        .ok()
                        .and_then(|value| value.parse::<i64>().ok())
                        .ok_or(rusqlite::Error::InvalidQuery),
                    _ => Err(rusqlite::Error::InvalidQuery),
                })
                .expect("integer pragma")
        };
        let page_size = read_pragma("PRAGMA page_size");
        let page_count = read_pragma("PRAGMA page_count");
        assert!(page_count > 1);
        let tamper_offset =
            u64::try_from((page_count - 1) * page_size + 100).expect("positive database offset");
        drop(store);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(state.database_path())
            .expect("open database for tamper");
        file.seek(SeekFrom::Start(tamper_offset))
            .expect("seek non-schema page");
        file.write_all(&[0xff]).expect("tamper non-schema page");
        file.sync_all().expect("sync tamper");
        drop(file);

        assert_eq!(
            DeviceStateStore::open_at(&state.path, &key).expect_err("reject corrupt v1 state"),
            DeviceStateError::AuthenticationFailed
        );

        let connection = open_connection(&state.database_path()).expect("reopen page one");
        key_and_configure(&connection, &key).expect("key database");
        authenticate_existing_database(&connection).expect("authenticate schema page");
        assert_eq!(read_schema_version(&connection).expect("schema version"), 1);
    }

    #[test]
    fn controller_public_record_round_trips_without_private_material() {
        let state = TestStateDirectory::new("controller-record");
        let key = root_key(32);
        let store = DeviceStateStore::initialize_at(&state.path, &key, timestamp(100))
            .expect("initialize encrypted state");
        let signing_key = ControllerSigningKey::from_stored_bytes(vec![0x44; 32])
            .expect("controller signing key");
        let record = ControllerAuthorityRecord::new(signing_key.public_key(), timestamp(110));

        assert_eq!(store.controller_authority_record().expect("empty"), None);
        store
            .insert_controller_authority_record(record)
            .expect("insert record");
        assert_eq!(
            store.controller_authority_record().expect("record"),
            Some(record)
        );
        assert!(store.insert_controller_authority_record(record).is_err());
        assert!(store
            .remove_controller_authority_record()
            .expect("remove record"));
        assert!(!store
            .remove_controller_authority_record()
            .expect("already absent"));
    }

    #[test]
    fn round_trips_every_device_state_record_family() {
        let state = TestStateDirectory::new("round-trip");
        let key = root_key(12);
        let mut store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");

        let consumer = sample_consumer(timestamp(110));
        store.insert_consumer(&consumer).expect("insert Consumer");
        assert_eq!(
            store
                .consumer(consumer.consumer_id())
                .expect("load Consumer"),
            Some(consumer.clone())
        );
        assert_eq!(
            store.consumers().expect("list Consumers"),
            vec![consumer.clone()]
        );

        let target = sample_target(consumer.consumer_id());
        let rule = AccessRule::new(
            target,
            ConfirmationPolicy::OncePerUnlockSession,
            RuleLifetime::Persistent,
            timestamp(120),
        )
        .expect("rule");
        store.insert_access_rule(&rule).expect("insert rule");
        assert_eq!(
            store
                .access_rules_for_consumer(consumer.consumer_id())
                .expect("rules"),
            vec![rule.clone()]
        );

        let grant = UseGrant::new(
            target,
            Some(rule.access_rule_id()),
            VaultSessionId::generate(),
            GrantScope::UnlockSession,
            timestamp(130),
            timestamp(500),
        )
        .expect("grant");
        store.insert_use_grant(&grant).expect("insert grant");
        assert_eq!(
            store
                .use_grants_for_consumer(consumer.consumer_id())
                .expect("grants"),
            vec![grant.clone()]
        );

        let profile = UsageProfile::new(
            consumer.consumer_id(),
            "GitHub CLI".to_owned(),
            Capability::v1(CapabilityName::ProcessRun),
            UsagePlacement::ProcessEnvironment {
                variable_name: "GH_TOKEN".to_owned(),
            },
            timestamp(140),
        )
        .expect("profile");
        store
            .insert_usage_profile(&profile)
            .expect("insert profile");
        assert_eq!(
            store
                .usage_profiles_for_consumer(consumer.consumer_id())
                .expect("profiles"),
            vec![profile.clone()]
        );

        let approval = ApprovalRequest::pending(
            ApprovalSubject::Access { target },
            [13_u8; 32],
            timestamp(150),
            timestamp(600),
        )
        .expect("approval");
        store.insert_approval(&approval).expect("insert approval");
        assert_eq!(
            store
                .approval(approval.approval_request_id())
                .expect("approval"),
            Some(approval.clone())
        );
        assert_eq!(
            store.pending_approvals().expect("pending"),
            vec![approval.clone()]
        );
        assert!(matches!(
            store
                .resolve_pending_approval(
                    approval.approval_request_id(),
                    ApprovalStatus::Approved,
                    timestamp(160),
                )
                .expect("resolve"),
            StoredApprovalResolution::Resolved(_)
        ));
        let resolved = store
            .approval(approval.approval_request_id())
            .expect("resolved approval")
            .expect("approval exists");
        assert_eq!(resolved.status(), ApprovalStatus::Approved);
        assert_eq!(resolved.resolved_at(), Some(timestamp(160)));

        let audit = AuditEvent::new(
            timestamp(170),
            AuditEventKind::CredentialUse,
            AuditScope::new(
                Some(consumer.consumer_id()),
                Some(target.field_scope()),
                Some(target.capability()),
                Some(grant.use_grant_id()),
            ),
            AuditDecision::Allowed,
            ConfirmationMethod::PersistentRule,
        );
        store.append_audit_event(&audit).expect("append audit");
        assert_eq!(
            store.recent_audit_events(10).expect("audit"),
            vec![audit.clone()]
        );
        assert_eq!(
            store.recent_audit_events(0),
            Err(DeviceStateError::InvalidQueryLimit)
        );

        store
            .set_apps_tools_paused(true, timestamp(180))
            .expect("pause");
        assert!(store.apps_tools_paused().expect("paused"));
        store
            .set_audit_retention_days(30, timestamp(190))
            .expect("retention");
        assert_eq!(store.audit_retention_days().expect("retention"), 30);

        assert!(store
            .remove_consumer(consumer.consumer_id())
            .expect("remove Consumer"));
        assert!(store.consumers().expect("Consumers").is_empty());
        assert!(store
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("rules")
            .is_empty());
        assert!(store
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("grants")
            .is_empty());
        assert!(store
            .usage_profiles_for_consumer(consumer.consumer_id())
            .expect("profiles")
            .is_empty());
        assert_eq!(
            store.recent_audit_events(10).expect("retained audit"),
            vec![audit]
        );
    }

    #[test]
    fn custom_usage_profiles_are_consumer_scoped_encrypted_and_removable() {
        let state = TestStateDirectory::new("custom-usage-profiles");
        let key = root_key(13);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");
        let first_consumer = sample_consumer(timestamp(110));
        let second_consumer = Consumer::new(
            [14_u8; 32],
            "Second local adapter".to_owned(),
            ObservedConsumerIdentity::default(),
            timestamp(111),
        )
        .expect("second Consumer");
        store
            .insert_consumer(&first_consumer)
            .expect("insert first Consumer");
        store
            .insert_consumer(&second_consumer)
            .expect("insert second Consumer");

        let label_marker = "KN custom profile label 9fbc82b4";
        let variable_marker = "KN_CUSTOM_PROFILE_ENV_9FBC82B4";
        let header_marker = "X-KN-Custom-Profile-9fbc82b4";
        let first_profile = UsageProfile::new(
            first_consumer.consumer_id(),
            label_marker.to_owned(),
            Capability::v1(CapabilityName::ProcessRun),
            UsagePlacement::ProcessEnvironment {
                variable_name: variable_marker.to_owned(),
            },
            timestamp(120),
        )
        .expect("first custom profile");
        let second_profile = UsageProfile::new(
            second_consumer.consumer_id(),
            "Second API placement".to_owned(),
            Capability::v1(CapabilityName::HttpRequest),
            UsagePlacement::HttpHeader {
                header_name: header_marker.to_owned(),
            },
            timestamp(121),
        )
        .expect("second custom profile");
        store
            .insert_usage_profile(&first_profile)
            .expect("insert first profile");
        store
            .insert_usage_profile(&second_profile)
            .expect("insert second profile");

        let portable_vault = state.path.join("unrelated.pswvault");
        let portable_bytes = b"portable-vault-sentinel-must-remain";
        write_private(&portable_vault, portable_bytes);

        assert_eq!(
            store
                .usage_profiles_for_consumer(first_consumer.consumer_id())
                .expect("first profiles"),
            vec![first_profile.clone()]
        );
        assert_eq!(
            store
                .usage_profiles_for_consumer(second_consumer.consumer_id())
                .expect("second profiles"),
            vec![second_profile.clone()]
        );
        drop(store);

        let reopened =
            DeviceStateStore::open_at(&state.path, &key).expect("reopen encrypted state");
        assert_eq!(
            reopened
                .usage_profiles_for_consumer(first_consumer.consumer_id())
                .expect("restored first profiles"),
            vec![first_profile.clone()]
        );
        assert!(reopened
            .remove_usage_profile(first_profile.usage_profile_id())
            .expect("remove exact custom profile"));
        assert!(!reopened
            .remove_usage_profile(first_profile.usage_profile_id())
            .expect("repeat exact removal"));
        assert!(reopened
            .usage_profiles_for_consumer(first_consumer.consumer_id())
            .expect("first profiles after removal")
            .is_empty());
        assert_eq!(
            reopened
                .usage_profiles_for_consumer(second_consumer.consumer_id())
                .expect("second profiles after removal"),
            vec![second_profile]
        );
        assert_eq!(
            fs::read(&portable_vault).expect("read unrelated portable vault"),
            portable_bytes
        );

        for (path, _) in std::iter::once((state.database_path(), DeviceStateFileEntry::Database))
            .chain(database_sidecars(&state.database_path()))
        {
            if path.exists() {
                let bytes = fs::read(path).expect("read managed database file");
                for marker in [label_marker, variable_marker, header_marker] {
                    assert!(
                        !contains_bytes(&bytes, marker.as_bytes()),
                        "custom Usage Profile marker escaped SQLCipher"
                    );
                }
            }
        }
    }

    #[test]
    fn active_authorized_credential_projection_is_vault_scoped_and_deduplicated() {
        let state = TestStateDirectory::new("authorized-credential-projection");
        let key = root_key(62);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");
        let consumer = sample_consumer(timestamp(105));
        store.insert_consumer(&consumer).expect("insert Consumer");

        let vault_id = VaultId::generate();
        let authorized_credential_id = CredentialId::generate();
        let expired_credential_id = CredentialId::generate();
        let other_vault_credential_id = CredentialId::generate();
        let targets = [
            AuthorizationTarget::new(
                consumer.consumer_id(),
                CredentialFieldScope::new(
                    vault_id,
                    authorized_credential_id,
                    SecretFieldId::generate(),
                ),
                Capability::v1(CapabilityName::ProcessRun),
            ),
            AuthorizationTarget::new(
                consumer.consumer_id(),
                CredentialFieldScope::new(
                    vault_id,
                    authorized_credential_id,
                    SecretFieldId::generate(),
                ),
                Capability::v1(CapabilityName::HttpRequest),
            ),
            AuthorizationTarget::new(
                consumer.consumer_id(),
                CredentialFieldScope::new(
                    vault_id,
                    expired_credential_id,
                    SecretFieldId::generate(),
                ),
                Capability::v1(CapabilityName::ProcessRun),
            ),
            AuthorizationTarget::new(
                consumer.consumer_id(),
                CredentialFieldScope::new(
                    VaultId::generate(),
                    other_vault_credential_id,
                    SecretFieldId::generate(),
                ),
                Capability::v1(CapabilityName::ProcessRun),
            ),
        ];
        let rules = [
            AccessRule::new(
                targets[0],
                ConfirmationPolicy::EveryUse,
                RuleLifetime::Persistent,
                timestamp(110),
            )
            .expect("first rule"),
            AccessRule::new(
                targets[1],
                ConfirmationPolicy::OncePerUnlockSession,
                RuleLifetime::Persistent,
                timestamp(111),
            )
            .expect("second rule"),
            AccessRule::new(
                targets[2],
                ConfirmationPolicy::EveryUse,
                RuleLifetime::Until(timestamp(150)),
                timestamp(112),
            )
            .expect("expired rule"),
            AccessRule::new(
                targets[3],
                ConfirmationPolicy::EveryUse,
                RuleLifetime::Persistent,
                timestamp(113),
            )
            .expect("other vault rule"),
        ];
        for rule in &rules {
            store.insert_access_rule(rule).expect("insert rule");
        }

        assert_eq!(
            store
                .active_authorized_credential_ids_for_vault(vault_id, timestamp(200))
                .expect("active credential projection"),
            BTreeSet::from([authorized_credential_id])
        );
        assert_eq!(
            store
                .active_authorized_credential_ids_for_vault(vault_id, timestamp(120))
                .expect("earlier credential projection"),
            BTreeSet::from([authorized_credential_id, expired_credential_id])
        );
    }

    #[test]
    fn audit_writes_enforce_age_retention_and_a_monotonic_watermark() {
        let state = TestStateDirectory::new("audit-age-retention");
        let key = root_key(52);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(0)).expect("initialize");
        let day = AUDIT_RETENTION_DAY_MILLIS;

        store
            .set_audit_retention_days(2, timestamp(10 * day))
            .expect("configure retention");
        let before_cutoff = AuditEvent::new(
            timestamp(8 * day - 1),
            AuditEventKind::Pause,
            AuditScope::default(),
            AuditDecision::Paused,
            ConfirmationMethod::None,
        );
        let at_cutoff = AuditEvent::new(
            timestamp(8 * day),
            AuditEventKind::Pause,
            AuditScope::default(),
            AuditDecision::Paused,
            ConfirmationMethod::None,
        );
        let current = AuditEvent::new(
            timestamp(10 * day),
            AuditEventKind::Pause,
            AuditScope::default(),
            AuditDecision::Resumed,
            ConfirmationMethod::None,
        );

        store
            .append_audit_event(&before_cutoff)
            .expect("append expired event");
        store
            .append_audit_event(&at_cutoff)
            .expect("append boundary event");
        store
            .append_audit_event(&current)
            .expect("append current event");
        assert_eq!(
            store.recent_audit_events(10).expect("retained events"),
            vec![current.clone(), at_cutoff]
        );

        assert_eq!(
            store
                .enforce_audit_retention(timestamp(13 * day))
                .expect("startup retention"),
            2
        );
        let rollback_clock_event = AuditEvent::new(
            timestamp(10 * day),
            AuditEventKind::Pause,
            AuditScope::default(),
            AuditDecision::Paused,
            ConfirmationMethod::None,
        );
        store
            .append_audit_event(&rollback_clock_event)
            .expect("append after clock rollback");
        assert!(store
            .recent_audit_events(10)
            .expect("events after rollback")
            .is_empty());
    }

    #[test]
    fn lowering_audit_retention_prunes_in_the_same_transaction() {
        let state = TestStateDirectory::new("audit-retention-change");
        let key = root_key(53);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(0)).expect("initialize");
        let day = AUDIT_RETENTION_DAY_MILLIS;
        store
            .set_audit_retention_days(30, timestamp(40 * day))
            .expect("configure broad retention");
        let older = AuditEvent::new(
            timestamp(20 * day),
            AuditEventKind::Authorization,
            AuditScope::default(),
            AuditDecision::Denied,
            ConfirmationMethod::None,
        );
        let boundary = AuditEvent::new(
            timestamp(39 * day),
            AuditEventKind::Authorization,
            AuditScope::default(),
            AuditDecision::Allowed,
            ConfirmationMethod::UserApproval,
        );
        store.append_audit_event(&older).expect("append older");
        store
            .append_audit_event(&boundary)
            .expect("append boundary");

        store
            .set_audit_retention_days(1, timestamp(40 * day))
            .expect("lower retention");
        assert_eq!(
            store.recent_audit_events(10).expect("retained events"),
            vec![boundary]
        );
        assert_eq!(
            store.set_audit_retention_days(0, timestamp(40 * day)),
            Err(DeviceStateError::InvalidModel {
                reason: "audit retention must be between 1 and 3650 days",
            })
        );
        assert_eq!(store.audit_retention_days().expect("retention"), 1);
    }

    #[test]
    fn audit_retention_applies_an_absolute_event_count_bound() {
        let state = TestStateDirectory::new("audit-count-retention");
        let key = root_key(54);
        let mut store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(0)).expect("initialize");
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin seed transaction");
        for occurred_at in 0..=MAX_RETAINED_AUDIT_EVENTS {
            let event = AuditEvent::new(
                timestamp(i64::try_from(occurred_at).expect("timestamp range")),
                AuditEventKind::Pairing,
                AuditScope::default(),
                AuditDecision::Pending,
                ConfirmationMethod::None,
            );
            insert_audit_event(&transaction, &event).expect("seed event");
        }
        transaction.commit().expect("commit seed events");

        let newest_timestamp =
            i64::try_from(MAX_RETAINED_AUDIT_EVENTS + 1).expect("timestamp range");
        let newest = AuditEvent::new(
            timestamp(newest_timestamp),
            AuditEventKind::Pairing,
            AuditScope::default(),
            AuditDecision::Allowed,
            ConfirmationMethod::UserApproval,
        );
        store.append_audit_event(&newest).expect("bounded append");

        let count: i64 = store
            .connection
            .query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))
            .expect("event count");
        let oldest_timestamp: i64 = store
            .connection
            .query_row("SELECT MIN(occurred_at_ms) FROM audit_events", [], |row| {
                row.get(0)
            })
            .expect("oldest event");
        assert_eq!(
            usize::try_from(count).expect("count range"),
            MAX_RETAINED_AUDIT_EVENTS
        );
        assert_eq!(oldest_timestamp, 2);
        assert_eq!(
            store.recent_audit_events(1).expect("newest event"),
            vec![newest]
        );
    }

    #[test]
    fn session_invalidation_matches_both_vault_and_unlock_session() {
        let state = TestStateDirectory::new("session-invalidation");
        let key = root_key(13);
        let mut store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");
        let consumer = sample_consumer(timestamp(110));
        store.insert_consumer(&consumer).expect("insert Consumer");

        let first_vault = VaultId::generate();
        let second_vault = VaultId::generate();
        let first_session = VaultSessionId::generate();
        let second_session = VaultSessionId::generate();
        let first_target = AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(
                first_vault,
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::ProcessRun),
        );
        let second_target = AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(
                second_vault,
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::ProcessRun),
        );
        let matching = UseGrant::new(
            first_target,
            None,
            first_session,
            GrantScope::OneOperation,
            timestamp(120),
            timestamp(500),
        )
        .expect("matching grant");
        let other_session = UseGrant::new(
            first_target,
            None,
            second_session,
            GrantScope::OneOperation,
            timestamp(121),
            timestamp(500),
        )
        .expect("other-session grant");
        let other_vault = UseGrant::new(
            second_target,
            None,
            first_session,
            GrantScope::OneOperation,
            timestamp(122),
            timestamp(500),
        )
        .expect("other-vault grant");
        for grant in [&matching, &other_session, &other_vault] {
            store.insert_use_grant(grant).expect("insert grant");
        }

        assert_eq!(
            store
                .invalidate_use_grants_for_sessions(&[(first_vault, first_session)])
                .expect("invalidate session"),
            1
        );
        assert_eq!(
            store
                .use_grants_for_consumer(consumer.consumer_id())
                .expect("remaining grants"),
            vec![other_session, other_vault]
        );
        assert_eq!(
            store
                .invalidate_all_use_grants()
                .expect("invalidate every grant"),
            2
        );
        assert!(store
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("empty grants")
            .is_empty());
    }

    #[test]
    fn field_removal_revokes_rules_all_grant_sources_and_approvals_only_in_scope() {
        let state = TestStateDirectory::new("field-invalidation");
        let key = root_key(14);
        let mut store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");
        let consumer = sample_consumer(timestamp(110));
        store.insert_consumer(&consumer).expect("insert Consumer");
        let vault_id = VaultId::generate();
        let credential_id = CredentialId::generate();
        let removed_scope =
            CredentialFieldScope::new(vault_id, credential_id, SecretFieldId::generate());
        let retained_scope =
            CredentialFieldScope::new(vault_id, credential_id, SecretFieldId::generate());
        let removed_target = AuthorizationTarget::new(
            consumer.consumer_id(),
            removed_scope,
            Capability::v1(CapabilityName::ProcessRun),
        );
        let retained_target = AuthorizationTarget::new(
            consumer.consumer_id(),
            retained_scope,
            Capability::v1(CapabilityName::ProcessRun),
        );
        let removed_rule = AccessRule::new(
            removed_target,
            ConfirmationPolicy::OncePerUnlockSession,
            RuleLifetime::Persistent,
            timestamp(120),
        )
        .expect("removed rule");
        let retained_rule = AccessRule::new(
            retained_target,
            ConfirmationPolicy::OncePerUnlockSession,
            RuleLifetime::Persistent,
            timestamp(121),
        )
        .expect("retained rule");
        store
            .insert_access_rule(&removed_rule)
            .expect("insert removed rule");
        store
            .insert_access_rule(&retained_rule)
            .expect("insert retained rule");

        let sourced_grant = UseGrant::new(
            removed_target,
            Some(removed_rule.access_rule_id()),
            VaultSessionId::generate(),
            GrantScope::UnlockSession,
            timestamp(130),
            timestamp(500),
        )
        .expect("sourced grant");
        let allow_once_grant = UseGrant::new(
            removed_target,
            None,
            VaultSessionId::generate(),
            GrantScope::OneOperation,
            timestamp(131),
            timestamp(500),
        )
        .expect("allow-once grant");
        let retained_grant = UseGrant::new(
            retained_target,
            Some(retained_rule.access_rule_id()),
            VaultSessionId::generate(),
            GrantScope::UnlockSession,
            timestamp(132),
            timestamp(500),
        )
        .expect("retained grant");
        for grant in [&sourced_grant, &allow_once_grant, &retained_grant] {
            store.insert_use_grant(grant).expect("insert grant");
        }

        let removed_approval = ApprovalRequest::pending(
            ApprovalSubject::Access {
                target: removed_target,
            },
            [21_u8; 32],
            timestamp(140),
            timestamp(600),
        )
        .expect("removed approval");
        let retained_approval = ApprovalRequest::pending(
            ApprovalSubject::Access {
                target: retained_target,
            },
            [22_u8; 32],
            timestamp(141),
            timestamp(600),
        )
        .expect("retained approval");
        store
            .insert_approval(&removed_approval)
            .expect("insert removed approval");
        store
            .insert_approval(&retained_approval)
            .expect("insert retained approval");

        let removed = store
            .remove_field_authorization(removed_scope)
            .expect("remove field authorization");
        assert_eq!(removed.access_rules_removed(), 1);
        assert_eq!(removed.use_grants_removed(), 2);
        assert_eq!(removed.approvals_removed(), 1);
        assert_eq!(
            store
                .access_rules_for_consumer(consumer.consumer_id())
                .expect("remaining rules"),
            vec![retained_rule]
        );
        assert_eq!(
            store
                .use_grants_for_consumer(consumer.consumer_id())
                .expect("remaining grants"),
            vec![retained_grant]
        );
        assert_eq!(
            store.pending_approvals().expect("remaining approvals"),
            vec![retained_approval]
        );
    }

    #[test]
    fn consumer_removal_revokes_sourced_and_allow_once_grants() {
        let state = TestStateDirectory::new("consumer-invalidation");
        let key = root_key(15);
        let mut store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");
        let consumer = sample_consumer(timestamp(110));
        store.insert_consumer(&consumer).expect("insert Consumer");
        let target = sample_target(consumer.consumer_id());
        let rule = AccessRule::new(
            target,
            ConfirmationPolicy::AutomaticWhileUnlocked,
            RuleLifetime::Persistent,
            timestamp(120),
        )
        .expect("rule");
        store.insert_access_rule(&rule).expect("insert rule");
        let sourced = UseGrant::new(
            target,
            Some(rule.access_rule_id()),
            VaultSessionId::generate(),
            GrantScope::UnlockSession,
            timestamp(130),
            timestamp(500),
        )
        .expect("sourced grant");
        let allow_once = UseGrant::new(
            target,
            None,
            VaultSessionId::generate(),
            GrantScope::OneOperation,
            timestamp(131),
            timestamp(500),
        )
        .expect("allow-once grant");
        store.insert_use_grant(&sourced).expect("insert sourced");
        store
            .insert_use_grant(&allow_once)
            .expect("insert allow once");

        assert!(
            BrokerGrantInvalidator::remove_consumer(&mut store, consumer.consumer_id())
                .expect("remove Consumer")
        );
        assert!(store
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("grants")
            .is_empty());
        assert!(store
            .access_rules_for_consumer(consumer.consumer_id())
            .expect("rules")
            .is_empty());
    }

    #[test]
    fn lock_events_and_device_reset_invalidate_persisted_grants() {
        let state = TestStateDirectory::new("lifecycle-invalidation");
        let vault_root = TestStateDirectory::new("lifecycle-vault");
        let key = root_key(16);
        let mut store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");
        let password = SecretBytes::new(b"session password".to_vec());
        let vault_path = vault_root.path.join("Lifecycle.pswvault");
        let locked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Lifecycle".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault");
        let vault_id = locked.metadata.vault_id.expect("stable vault identity");
        drop(locked);

        let sessions = BrokerVaultSessionManager::new(Duration::from_secs(60)).expect("sessions");
        sessions.open_vault(&vault_path).expect("open vault");
        let first_session = sessions
            .unlock_with_master_password(vault_id, password.clone())
            .expect("unlock vault")
            .vault_session_id()
            .expect("session identity");
        let consumer = sample_consumer(timestamp(110));
        store.insert_consumer(&consumer).expect("insert Consumer");
        let target = AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(
                vault_id,
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::ProcessRun),
        );
        let first_grant = UseGrant::new(
            target,
            None,
            first_session,
            GrantScope::UnlockSession,
            timestamp(120),
            timestamp(500),
        )
        .expect("first grant");
        store
            .insert_use_grant(&first_grant)
            .expect("insert first grant");

        sessions.lock_vault(vault_id).expect("manual lock");
        let synchronized = BrokerGrantInvalidator::synchronize_lock_events(&sessions, &mut store)
            .expect("synchronize lock");
        assert_eq!(synchronized.lock_events_processed(), 1);
        assert_eq!(synchronized.use_grants_removed(), 1);
        assert!(!synchronized.invalidated_all_use_grants());
        assert_eq!(
            BrokerGrantInvalidator::synchronize_lock_events(&sessions, &mut store)
                .expect("idempotent synchronize"),
            Default::default()
        );

        let second_session = sessions
            .unlock_with_master_password(vault_id, password)
            .expect("second unlock")
            .vault_session_id()
            .expect("second session identity");
        let second_grant = UseGrant::new(
            target,
            None,
            second_session,
            GrantScope::UnlockSession,
            timestamp(130),
            timestamp(500),
        )
        .expect("second grant");
        store
            .insert_use_grant(&second_grant)
            .expect("insert second grant");

        let reset = BrokerGrantInvalidator::prepare_device_data_reset(&sessions, &mut store)
            .expect("prepare reset");
        assert!(reset.invalidated_all_use_grants());
        assert_eq!(reset.lock_events_processed(), 1);
        assert_eq!(reset.use_grants_removed(), 1);
        assert!(sessions.is_shutdown().expect("shutdown"));
        assert_eq!(
            sessions.snapshot(vault_id),
            Err(BrokerVaultSessionError::ShutDown)
        );
        assert!(store
            .use_grants_for_consumer(consumer.consumer_id())
            .expect("grants")
            .is_empty());
    }

    #[test]
    fn global_pause_persists_without_revoking_authorization_or_locking_human_session() {
        let state = TestStateDirectory::new("global-pause");
        let vault_root = TestStateDirectory::new("global-pause-vault");
        let key = root_key(17);
        let mut store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(100)).expect("initialize");
        let password = SecretBytes::new(b"pause password".to_vec());
        let vault_path = vault_root.path.join("Pause.pswvault");
        let locked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Pause".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault");
        let vault_id = locked.metadata.vault_id.expect("stable vault identity");
        drop(locked);

        let sessions = BrokerVaultSessionManager::new(Duration::from_secs(60)).expect("sessions");
        sessions.open_vault(&vault_path).expect("open vault");
        let session_id = sessions
            .unlock_with_master_password(vault_id, password)
            .expect("unlock vault")
            .vault_session_id()
            .expect("session identity");
        let consumer = sample_consumer(timestamp(110));
        store.insert_consumer(&consumer).expect("insert Consumer");
        let target = AuthorizationTarget::new(
            consumer.consumer_id(),
            CredentialFieldScope::new(
                vault_id,
                CredentialId::generate(),
                SecretFieldId::generate(),
            ),
            Capability::v1(CapabilityName::ProcessRun),
        );
        let rule = AccessRule::new(
            target,
            ConfirmationPolicy::AutomaticWhileUnlocked,
            RuleLifetime::Persistent,
            timestamp(120),
        )
        .expect("rule");
        let grant = UseGrant::new(
            target,
            Some(rule.access_rule_id()),
            session_id,
            GrantScope::UnlockSession,
            timestamp(130),
            timestamp(500),
        )
        .expect("grant");
        store.insert_access_rule(&rule).expect("insert rule");
        store.insert_use_grant(&grant).expect("insert grant");

        let gate = BrokerMachineAccessGate::from_device_state(&store).expect("load gate");
        gate.authorize_machine_operation()
            .expect("initial machine access");
        assert_eq!(
            gate.set_paused(&store, true, timestamp(300))
                .expect("pause"),
            BrokerMachineAccessTransition::Paused
        );
        assert!(matches!(
            gate.authorize_machine_operation(),
            Err(BrokerMachineAccessError::Paused)
        ));
        assert_eq!(
            sessions
                .snapshot(vault_id)
                .expect("human session")
                .lock_state(),
            BrokerVaultLockState::Unlocked
        );
        assert_eq!(
            store
                .access_rules_for_consumer(consumer.consumer_id())
                .expect("rules"),
            vec![rule.clone()]
        );
        assert_eq!(
            store
                .use_grants_for_consumer(consumer.consumer_id())
                .expect("grants"),
            vec![grant.clone()]
        );

        drop(gate);
        drop(store);
        store = DeviceStateStore::open_at(&state.path, &key).expect("reopen state");
        let reloaded = BrokerMachineAccessGate::from_device_state(&store).expect("reload gate");
        assert!(reloaded.is_paused().expect("persisted pause"));
        assert_eq!(
            reloaded
                .set_paused(&store, false, timestamp(200))
                .expect("resume with clock rollback"),
            BrokerMachineAccessTransition::Resumed
        );
        reloaded
            .authorize_machine_operation()
            .expect("resumed machine access");
        let persisted_update: i64 = store
            .connection
            .query_row(
                "SELECT updated_at_ms FROM device_settings WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("persisted update time");
        assert_eq!(persisted_update, 300);
        assert_eq!(
            store
                .access_rules_for_consumer(consumer.consumer_id())
                .expect("retained rules"),
            vec![rule]
        );
        assert_eq!(
            store
                .use_grants_for_consumer(consumer.consumer_id())
                .expect("retained grants"),
            vec![grant]
        );
        assert_eq!(
            sessions
                .snapshot(vault_id)
                .expect("still unlocked")
                .lock_state(),
            BrokerVaultLockState::Unlocked
        );
        sessions.shutdown().expect("shutdown");
    }

    #[test]
    fn wrong_or_modified_key_material_fails_without_replacing_state() {
        let state = TestStateDirectory::new("wrong-key");
        let key = root_key(21);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(1)).expect("initialize");
        drop(store);
        let before = fs::read(state.database_path()).expect("read before");

        let wrong_key = root_key(22);
        assert_eq!(
            DeviceStateStore::open_at(&state.path, &wrong_key).expect_err("reject wrong key"),
            DeviceStateError::AuthenticationFailed
        );
        assert_eq!(fs::read(state.database_path()).expect("read after"), before);
    }

    #[test]
    fn rejects_plaintext_truncated_symlinked_and_broad_database_files() {
        let key = root_key(31);

        let plaintext = TestStateDirectory::new("plaintext");
        let mut plaintext_bytes = vec![0_u8; 4096];
        plaintext_bytes[..16].copy_from_slice(SQLITE_PLAINTEXT_HEADER);
        write_private(&plaintext.database_path(), &plaintext_bytes);
        assert_eq!(
            DeviceStateStore::open_at(&plaintext.path, &key).expect_err("reject plaintext"),
            DeviceStateError::PlaintextDatabase
        );

        let truncated = TestStateDirectory::new("truncated");
        write_private(&truncated.database_path(), b"short");
        assert_eq!(
            DeviceStateStore::open_at(&truncated.path, &key).expect_err("reject truncated"),
            DeviceStateError::TruncatedDatabase
        );

        let linked = TestStateDirectory::new("symlink");
        let target = linked.path.join("target.db");
        write_private(&target, &[1_u8; 32]);
        symlink(&target, linked.database_path()).expect("create database symlink");
        let error =
            DeviceStateStore::open_at(&linked.path, &key).expect_err("reject database symlink");
        assert_eq!(
            error,
            DeviceStateError::SymbolicLink {
                entry: DeviceStateFileEntry::Database
            }
        );
        assert!(!error
            .to_string()
            .contains(linked.path.to_string_lossy().as_ref()));

        let broad = TestStateDirectory::new("broad");
        let store =
            DeviceStateStore::initialize_at(&broad.path, &key, timestamp(1)).expect("initialize");
        drop(store);
        fs::set_permissions(broad.database_path(), fs::Permissions::from_mode(0o644))
            .expect("broaden database");
        assert_eq!(
            DeviceStateStore::open_at(&broad.path, &key).expect_err("reject broad mode"),
            DeviceStateError::InsecurePermissions {
                entry: DeviceStateFileEntry::Database,
                mode: 0o644
            }
        );
    }

    #[test]
    fn refuses_unsupported_or_incomplete_authenticated_schema() {
        let version_state = TestStateDirectory::new("schema-version");
        let key = root_key(41);
        let store = DeviceStateStore::initialize_at(&version_state.path, &key, timestamp(1))
            .expect("initialize");
        store
            .connection
            .execute_batch("PRAGMA user_version = 99")
            .expect("change schema version");
        drop(store);
        assert_eq!(
            DeviceStateStore::open_at(&version_state.path, &key)
                .expect_err("reject schema version"),
            DeviceStateError::UnsupportedSchema {
                found: 99,
                supported: CURRENT_DEVICE_SCHEMA_VERSION
            }
        );

        let missing_state = TestStateDirectory::new("schema-missing");
        let store = DeviceStateStore::initialize_at(&missing_state.path, &key, timestamp(1))
            .expect("initialize");
        store
            .connection
            .execute_batch("DROP TABLE usage_profiles")
            .expect("remove required table");
        drop(store);
        assert_eq!(
            DeviceStateStore::open_at(&missing_state.path, &key)
                .expect_err("reject incomplete schema"),
            DeviceStateError::CorruptSchema
        );
    }

    #[test]
    fn detects_ciphertext_modification_with_page_authentication() {
        let state = TestStateDirectory::new("tampered");
        let key = root_key(51);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(1)).expect("initialize");
        drop(store);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(state.database_path())
            .expect("open database for tamper");
        file.seek(SeekFrom::Start(100)).expect("seek");
        file.write_all(&[0xff]).expect("tamper");
        file.sync_all().expect("sync tamper");
        drop(file);

        assert_eq!(
            DeviceStateStore::open_at(&state.path, &key).expect_err("reject tamper"),
            DeviceStateError::AuthenticationFailed
        );
    }

    #[test]
    fn pending_approval_digest_is_unique_but_reusable_after_resolution() {
        let state = TestStateDirectory::new("approval-coalescing");
        let key = root_key(61);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(1)).expect("initialize");
        let consumer = sample_consumer(timestamp(2));
        store.insert_consumer(&consumer).expect("Consumer");
        let target = sample_target(consumer.consumer_id());
        let digest = [62_u8; 32];
        let first = ApprovalRequest::pending(
            ApprovalSubject::Access { target },
            digest,
            timestamp(3),
            timestamp(30),
        )
        .expect("first");
        let duplicate = ApprovalRequest::pending(
            ApprovalSubject::Access { target },
            digest,
            timestamp(4),
            timestamp(31),
        )
        .expect("duplicate");
        store.insert_approval(&first).expect("first insert");
        assert_eq!(
            store.insert_approval(&duplicate),
            Err(DeviceStateError::Conflict)
        );
        assert!(matches!(
            store
                .resolve_pending_approval(
                    first.approval_request_id(),
                    ApprovalStatus::Denied,
                    timestamp(5),
                )
                .expect("resolve"),
            StoredApprovalResolution::Resolved(_)
        ));
        store
            .insert_approval(&duplicate)
            .expect("digest reusable after terminal decision");
    }

    #[test]
    fn encrypted_files_do_not_contain_seeded_record_or_schema_markers() {
        let state = TestStateDirectory::new("markers");
        let key = root_key(71);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(1)).expect("initialize");
        let marker = "KN_DEVICE_STATE_MARKER_9fbc82b4";
        let consumer = Consumer::new(
            [72_u8; 32],
            marker.to_owned(),
            ObservedConsumerIdentity::default(),
            timestamp(2),
        )
        .expect("Consumer");
        store.insert_consumer(&consumer).expect("insert marker");
        let audit = AuditEvent::new(
            timestamp(3),
            AuditEventKind::Pairing,
            AuditScope::new(Some(consumer.consumer_id()), None, None, None),
            AuditDecision::Allowed,
            ConfirmationMethod::UserApproval,
        );
        let audit_event_id = audit.audit_event_id().to_string();
        store.append_audit_event(&audit).expect("append audit");

        for (path, _) in std::iter::once((state.database_path(), DeviceStateFileEntry::Database))
            .chain(database_sidecars(&state.database_path()))
        {
            if path.exists() {
                let bytes = fs::read(path).expect("read managed database file");
                assert!(!contains_bytes(&bytes, marker.as_bytes()));
                assert!(!contains_bytes(&bytes, audit_event_id.as_bytes()));
                assert!(!contains_bytes(&bytes, b"pairing_public_key"));
                assert!(!contains_bytes(&bytes, b"access_rules"));
                assert!(!contains_bytes(&bytes, b"audit_events"));
            }
        }
    }

    #[test]
    fn removal_prevalidates_every_sidecar_before_deleting_the_database() {
        let state = TestStateDirectory::new("clear-prevalidation");
        let key = root_key(75);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(1)).expect("initialize");
        drop(store);
        let database_before = fs::read(state.database_path()).expect("database before");
        let [(write_ahead_log, _), _] = database_sidecars(&state.database_path());
        let _ = fs::remove_file(&write_ahead_log);
        let target = state.path.join("unmanaged-target");
        write_private(&target, b"must remain");
        symlink(&target, &write_ahead_log).expect("unsafe WAL symlink");

        assert_eq!(
            remove_existing_state_files(&state.path).expect_err("reject unsafe WAL"),
            DeviceStateError::SymbolicLink {
                entry: DeviceStateFileEntry::WriteAheadLog
            }
        );
        assert_eq!(
            fs::read(state.database_path()).expect("database after"),
            database_before
        );
        assert_eq!(fs::read(target).expect("unmanaged target"), b"must remain");
    }

    #[test]
    fn hkdf_and_raw_key_literal_contract_is_stable_and_redacted() {
        let root =
            DeviceRootKey::from_stored_bytes((0_u8..32).collect()).expect("construct fixed root");
        let encoded = EncodedSqlCipherKey::derive(&root).expect("derive");
        assert_eq!(
            std::str::from_utf8(encoded.as_bytes()).expect("ASCII"),
            "x'12b969d1bcd27e8c177aadf3eb3037b3f3205aeece90a0eb3b76a6fd1d43e780'"
        );
        assert_eq!(format!("{encoded:?}"), "EncodedSqlCipherKey(<redacted>)");
        assert!(!format!("{root:?}").contains("000102"));
    }

    #[test]
    fn all_database_sidecars_remain_owner_only() {
        let state = TestStateDirectory::new("sidecars");
        let key = root_key(81);
        let store =
            DeviceStateStore::initialize_at(&state.path, &key, timestamp(1)).expect("initialize");
        let consumer = sample_consumer(timestamp(2));
        store.insert_consumer(&consumer).expect("write state");
        store.verify_managed_files().expect("verify files");
        assert_private_file(&state.database_path());
        for (path, _) in database_sidecars(&state.database_path()) {
            if path.exists() {
                assert_private_file(&path);
            }
        }
    }

    #[test]
    fn sidecar_paths_preserve_non_utf8_database_names() {
        let database = PathBuf::from(OsString::from_vec(vec![
            b'd', b'e', b'v', b'i', b'c', b'e', b'-', 0xff, b'.', b'd', b'b',
        ]));
        let [(wal, _), (shared_memory, _)] = database_sidecars(&database);

        let mut expected_wal = database.as_os_str().as_bytes().to_vec();
        expected_wal.extend_from_slice(b"-wal");
        let mut expected_shared_memory = database.as_os_str().as_bytes().to_vec();
        expected_shared_memory.extend_from_slice(b"-shm");
        assert_eq!(wal.as_os_str().as_bytes(), expected_wal);
        assert_eq!(shared_memory.as_os_str().as_bytes(), expected_shared_memory);
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options
            .create_new(true)
            .read(true)
            .write(true)
            .mode(PRIVATE_FILE_MODE);
        let mut file = options.open(path).expect("create private file");
        file.write_all(bytes).expect("write private file");
        file.sync_all().expect("sync private file");
        fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("protect private file");
    }

    fn assert_private_file(path: &Path) {
        let metadata = fs::symlink_metadata(path).expect("inspect private file");
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o777, PRIVATE_FILE_MODE);
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
