use std::fmt::{Debug, Display, Formatter};

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::controller_authority_contract::{
    derive_controller_id, ControllerAuthorityPresence, CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE,
    CONTROLLER_PUBLIC_KEY_LENGTH, CONTROLLER_SIGNATURE_LENGTH, CONTROLLER_SIGNING_SEED_LENGTH,
};
use crate::{ControllerId, StateTimestamp};

/// Public Broker record for the one approved human-controller authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerAuthorityRecord {
    controller_id: ControllerId,
    public_key: [u8; CONTROLLER_PUBLIC_KEY_LENGTH],
    created_at: StateTimestamp,
}

impl ControllerAuthorityRecord {
    /// Creates the canonical public record derived from an Ed25519 public key.
    #[must_use]
    pub fn new(public_key: [u8; CONTROLLER_PUBLIC_KEY_LENGTH], created_at: StateTimestamp) -> Self {
        Self {
            controller_id: ControllerId::from_bytes(derive_controller_id(&public_key)),
            public_key,
            created_at,
        }
    }

    /// Returns the derived stable controller identity.
    #[must_use]
    pub const fn controller_id(self) -> ControllerId {
        self.controller_id
    }

    /// Returns the public Ed25519 verification key.
    #[must_use]
    pub const fn public_key(self) -> [u8; CONTROLLER_PUBLIC_KEY_LENGTH] {
        self.public_key
    }

    /// Returns when this public authority was first approved.
    #[must_use]
    pub const fn created_at(self) -> StateTimestamp {
        self.created_at
    }
}

/// Opaque controller signature that does not format authentication bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ControllerSignature([u8; CONTROLLER_SIGNATURE_LENGTH]);

impl ControllerSignature {
    /// Builds a signature from an exact Ed25519 byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CONTROLLER_SIGNATURE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns signature bytes for strict verification.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTROLLER_SIGNATURE_LENGTH] {
        &self.0
    }
}

impl Debug for ControllerSignature {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerSignature(<redacted>)")
    }
}

/// Non-cloneable controller signing seed cleared when dropped.
pub struct ControllerSigningKey {
    seed: [u8; CONTROLLER_SIGNING_SEED_LENGTH],
}

impl ControllerSigningKey {
    fn generate() -> Self {
        let mut seed = [0_u8; CONTROLLER_SIGNING_SEED_LENGTH];
        OsRng.fill_bytes(&mut seed);
        Self { seed }
    }

    pub(crate) fn from_stored_bytes(mut bytes: Vec<u8>) -> Result<Self, ControllerKeyStoreError> {
        if bytes.len() != CONTROLLER_SIGNING_SEED_LENGTH {
            let actual_length = bytes.len();
            bytes.zeroize();
            return Err(ControllerKeyStoreError::InvalidSeedLength { actual_length });
        }
        let mut seed = [0_u8; CONTROLLER_SIGNING_SEED_LENGTH];
        seed.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self { seed })
    }

    /// Returns the public Ed25519 key without exposing the seed.
    #[must_use]
    pub fn public_key(&self) -> [u8; CONTROLLER_PUBLIC_KEY_LENGTH] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    /// Returns the stable public identity derived from the verification key.
    #[must_use]
    pub fn controller_id(&self) -> ControllerId {
        ControllerId::from_bytes(derive_controller_id(&self.public_key()))
    }

    /// Signs one already-domain-separated controller transcript.
    #[must_use]
    pub fn sign(&self, transcript: &[u8]) -> ControllerSignature {
        ControllerSignature::from_bytes(
            SigningKey::from_bytes(&self.seed)
                .sign(transcript)
                .to_bytes(),
        )
    }

    pub(crate) fn expose_seed(&self) -> &[u8; CONTROLLER_SIGNING_SEED_LENGTH] {
        &self.seed
    }

    fn matches(&self, other: &Self) -> bool {
        self.seed
            .iter()
            .zip(other.seed.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }
}

impl Debug for ControllerSigningKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerSigningKey(<redacted>)")
    }
}

impl Drop for ControllerSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Stable operation attempted against the restricted controller Keychain item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerKeyStoreOperation {
    /// Load the exact primary controller seed.
    LoadSeed,
    /// Add the first seed without replacing an existing item.
    CreateSeed,
    /// Delete the exact primary controller seed.
    DeleteSeed,
    /// Read the non-secret removal marker.
    LoadRemovalMarker,
    /// Add the removal marker before destructive authority clearing.
    CreateRemovalMarker,
    /// Delete the removal marker after verified authority absence.
    DeleteRemovalMarker,
}

/// Sanitized restricted-Keychain failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControllerKeyStoreError {
    /// Add-only creation found an existing item.
    AlreadyExists,
    /// Stored seed material was not exactly 32 bytes.
    InvalidSeedLength {
        /// Observed stored byte count.
        actual_length: usize,
    },
    /// The removal marker had an unexpected value.
    InvalidRemovalMarker,
    /// The current platform does not provide the required access-group Keychain.
    UnsupportedPlatform,
    /// Security.framework returned a value-free status code.
    Platform {
        /// Operating-system status code.
        status: i32,
    },
}

impl Display for ControllerKeyStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("controller key already exists"),
            Self::InvalidSeedLength { actual_length } => write!(
                formatter,
                "stored controller key has invalid length ({actual_length} bytes)"
            ),
            Self::InvalidRemovalMarker => {
                formatter.write_str("controller removal marker is invalid")
            }
            Self::UnsupportedPlatform => formatter.write_str("controller Keychain is unsupported"),
            Self::Platform { status } => {
                write!(formatter, "controller Keychain failed with status {status}")
            }
        }
    }
}

impl std::error::Error for ControllerKeyStoreError {}

/// Restricted storage used only for the device-local human-controller seed.
pub trait ControllerKeyStore {
    /// Loads the exact existing seed without creating replacement material.
    fn load_seed(&self) -> Result<Option<ControllerSigningKey>, ControllerKeyStoreError>;
    /// Adds one seed and refuses to overwrite an existing item.
    fn create_seed(&self, key: &ControllerSigningKey) -> Result<(), ControllerKeyStoreError>;
    /// Deletes the exact seed item, returning false when absent.
    fn delete_seed(&self) -> Result<bool, ControllerKeyStoreError>;
    /// Reports whether the exact protected removal marker exists.
    fn removal_pending(&self) -> Result<bool, ControllerKeyStoreError>;
    /// Adds the exact marker and refuses a conflicting value.
    fn create_removal_marker(&self) -> Result<(), ControllerKeyStoreError>;
    /// Deletes the exact marker, returning false when absent.
    fn delete_removal_marker(&self) -> Result<bool, ControllerKeyStoreError>;
}

impl<T> ControllerKeyStore for &T
where
    T: ControllerKeyStore + ?Sized,
{
    fn load_seed(&self) -> Result<Option<ControllerSigningKey>, ControllerKeyStoreError> {
        (*self).load_seed()
    }

    fn create_seed(&self, key: &ControllerSigningKey) -> Result<(), ControllerKeyStoreError> {
        (*self).create_seed(key)
    }

    fn delete_seed(&self) -> Result<bool, ControllerKeyStoreError> {
        (*self).delete_seed()
    }

    fn removal_pending(&self) -> Result<bool, ControllerKeyStoreError> {
        (*self).removal_pending()
    }

    fn create_removal_marker(&self) -> Result<(), ControllerKeyStoreError> {
        (*self).create_removal_marker()
    }

    fn delete_removal_marker(&self) -> Result<bool, ControllerKeyStoreError> {
        (*self).delete_removal_marker()
    }
}

/// Sanitized controller-authority bootstrap failure.
#[derive(Debug)]
pub enum ControllerAuthorityError {
    /// A removal sequence is pending and is the only permitted transition.
    RemovalPending,
    /// One authority side is absent or the public identities disagree.
    IncompleteAuthority,
    /// Seed creation raced or read-back did not match the generated seed.
    CreationVerificationFailed,
    /// Destructive removal was completed without first establishing provenance.
    RemovalNotStarted,
    /// Marker, seed deletion, or final absence could not be verified.
    RemovalVerificationFailed,
    /// A restricted Keychain operation failed.
    Store {
        /// Stable attempted operation.
        operation: ControllerKeyStoreOperation,
        /// Sanitized storage failure.
        source: ControllerKeyStoreError,
    },
}

impl Display for ControllerAuthorityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RemovalPending => formatter.write_str("controller removal is pending"),
            Self::IncompleteAuthority => formatter.write_str("controller authority is incomplete"),
            Self::CreationVerificationFailed => {
                formatter.write_str("controller key creation could not be verified")
            }
            Self::RemovalNotStarted => formatter.write_str("controller removal was not started"),
            Self::RemovalVerificationFailed => {
                formatter.write_str("controller removal could not be verified")
            }
            Self::Store { operation, source } => {
                write!(formatter, "controller {operation:?} failed: {source}")
            }
        }
    }
}

impl std::error::Error for ControllerAuthorityError {}

/// Permitted next step after fail-closed authority inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerBootstrapMode {
    /// A new seed was created and must complete signed public-record bootstrap.
    BootstrapNew,
    /// A prior seed exists without a record and may resume signed bootstrap.
    ResumeBootstrap,
    /// Complete matching authority may perform ordinary authentication.
    AuthenticateExisting,
}

/// Loaded controller seed plus the only permitted next authentication mode.
pub struct PreparedControllerAuthority {
    mode: ControllerBootstrapMode,
    key: ControllerSigningKey,
}

impl PreparedControllerAuthority {
    /// Returns whether bootstrap or ordinary authentication is permitted.
    #[must_use]
    pub const fn mode(&self) -> ControllerBootstrapMode {
        self.mode
    }

    /// Returns the loaded signing key without exposing its seed bytes.
    #[must_use]
    pub const fn key(&self) -> &ControllerSigningKey {
        &self.key
    }
}

impl Debug for PreparedControllerAuthority {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedControllerAuthority")
            .field("mode", &self.mode)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Explicit controller-authority lifecycle without any load-or-create path.
pub struct ControllerAuthorityManager<S> {
    store: S,
}

impl<S> ControllerAuthorityManager<S>
where
    S: ControllerKeyStore,
{
    /// Creates a manager around the exact restricted Keychain store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Inspects both authority sides without mutating either one.
    pub fn presence(
        &self,
        record: Option<ControllerAuthorityRecord>,
    ) -> Result<ControllerAuthorityPresence, ControllerAuthorityError> {
        if self.load_removal_marker()? {
            return Ok(ControllerAuthorityPresence::RemovalPending);
        }
        let key = self.load_seed()?;
        Ok(match (key.as_ref(), record) {
            (None, None) => ControllerAuthorityPresence::Absent,
            (Some(_), None) => ControllerAuthorityPresence::KeyOnly,
            (None, Some(_)) => ControllerAuthorityPresence::RecordOnly,
            (Some(key), Some(record))
                if key.controller_id() == record.controller_id()
                    && key.public_key() == record.public_key() =>
            {
                ControllerAuthorityPresence::CompleteMatching
            }
            (Some(_), Some(_)) => ControllerAuthorityPresence::CompleteMismatched,
        })
    }

    /// Prepares explicit enablement while refusing one-sided regeneration.
    pub fn prepare_for_explicit_enable(
        &self,
        record: Option<ControllerAuthorityRecord>,
    ) -> Result<PreparedControllerAuthority, ControllerAuthorityError> {
        if self.load_removal_marker()? {
            return Err(ControllerAuthorityError::RemovalPending);
        }
        match (self.load_seed()?, record) {
            (None, None) => self.create_and_verify_seed(),
            (Some(key), None) => Ok(PreparedControllerAuthority {
                mode: ControllerBootstrapMode::ResumeBootstrap,
                key,
            }),
            (None, Some(_)) => Err(ControllerAuthorityError::IncompleteAuthority),
            (Some(key), Some(record))
                if key.controller_id() == record.controller_id()
                    && key.public_key() == record.public_key() =>
            {
                Ok(PreparedControllerAuthority {
                    mode: ControllerBootstrapMode::AuthenticateExisting,
                    key,
                })
            }
            (Some(_), Some(_)) => Err(ControllerAuthorityError::IncompleteAuthority),
        }
    }

    /// Loads authority for a challenge without creating or replacing a seed.
    pub fn prepare_for_challenge(
        &self,
        record: Option<ControllerAuthorityRecord>,
    ) -> Result<PreparedControllerAuthority, ControllerAuthorityError> {
        if self.load_removal_marker()? {
            return Err(ControllerAuthorityError::RemovalPending);
        }
        match (self.load_seed()?, record) {
            (None, None) | (None, Some(_)) => Err(ControllerAuthorityError::IncompleteAuthority),
            (Some(key), None) => Ok(PreparedControllerAuthority {
                mode: ControllerBootstrapMode::ResumeBootstrap,
                key,
            }),
            (Some(key), Some(record))
                if key.controller_id() == record.controller_id()
                    && key.public_key() == record.public_key() =>
            {
                Ok(PreparedControllerAuthority {
                    mode: ControllerBootstrapMode::AuthenticateExisting,
                    key,
                })
            }
            (Some(_), Some(_)) => Err(ControllerAuthorityError::IncompleteAuthority),
        }
    }

    /// Creates or resumes the durable marker that must precede authority removal.
    pub fn begin_or_resume_removal(&self) -> Result<(), ControllerAuthorityError> {
        if !self.load_removal_marker()? {
            match self.store.create_removal_marker() {
                Ok(()) | Err(ControllerKeyStoreError::AlreadyExists) => {}
                Err(source) => {
                    return Err(ControllerAuthorityError::Store {
                        operation: ControllerKeyStoreOperation::CreateRemovalMarker,
                        source,
                    });
                }
            }
        }
        if self.load_removal_marker()? {
            Ok(())
        } else {
            Err(ControllerAuthorityError::RemovalVerificationFailed)
        }
    }

    /// Deletes and verifies the seed, then removes the durable marker last.
    pub fn complete_pending_removal(&self) -> Result<bool, ControllerAuthorityError> {
        if !self.load_removal_marker()? {
            return Err(ControllerAuthorityError::RemovalNotStarted);
        }
        let seed_removed =
            self.store
                .delete_seed()
                .map_err(|source| ControllerAuthorityError::Store {
                    operation: ControllerKeyStoreOperation::DeleteSeed,
                    source,
                })?;
        if self.load_seed()?.is_some() {
            return Err(ControllerAuthorityError::RemovalVerificationFailed);
        }
        self.store
            .delete_removal_marker()
            .map_err(|source| ControllerAuthorityError::Store {
                operation: ControllerKeyStoreOperation::DeleteRemovalMarker,
                source,
            })?;
        if self.load_removal_marker()? {
            return Err(ControllerAuthorityError::RemovalVerificationFailed);
        }
        Ok(seed_removed)
    }

    fn create_and_verify_seed(
        &self,
    ) -> Result<PreparedControllerAuthority, ControllerAuthorityError> {
        let key = ControllerSigningKey::generate();
        self.store
            .create_seed(&key)
            .map_err(|source| ControllerAuthorityError::Store {
                operation: ControllerKeyStoreOperation::CreateSeed,
                source,
            })?;
        let stored = self
            .store
            .load_seed()
            .map_err(|source| ControllerAuthorityError::Store {
                operation: ControllerKeyStoreOperation::LoadSeed,
                source,
            })?
            .ok_or(ControllerAuthorityError::CreationVerificationFailed)?;
        if !key.matches(&stored) {
            return Err(ControllerAuthorityError::CreationVerificationFailed);
        }
        Ok(PreparedControllerAuthority {
            mode: ControllerBootstrapMode::BootstrapNew,
            key: stored,
        })
    }

    fn load_seed(&self) -> Result<Option<ControllerSigningKey>, ControllerAuthorityError> {
        self.store
            .load_seed()
            .map_err(|source| ControllerAuthorityError::Store {
                operation: ControllerKeyStoreOperation::LoadSeed,
                source,
            })
    }

    fn load_removal_marker(&self) -> Result<bool, ControllerAuthorityError> {
        self.store
            .removal_pending()
            .map_err(|source| ControllerAuthorityError::Store {
                operation: ControllerKeyStoreOperation::LoadRemovalMarker,
                source,
            })
    }
}

/// Returns whether bytes are the exact non-secret removal marker value.
#[must_use]
pub fn is_controller_removal_marker(bytes: &[u8]) -> bool {
    bytes == CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        seed: RefCell<Option<Vec<u8>>>,
        marker: Cell<bool>,
        creates: Cell<usize>,
    }

    impl MemoryStore {
        fn with_seed(byte: u8) -> Self {
            Self {
                seed: RefCell::new(Some(vec![byte; CONTROLLER_SIGNING_SEED_LENGTH])),
                ..Self::default()
            }
        }
    }

    impl ControllerKeyStore for MemoryStore {
        fn load_seed(&self) -> Result<Option<ControllerSigningKey>, ControllerKeyStoreError> {
            self.seed
                .borrow()
                .as_ref()
                .map(|seed| ControllerSigningKey::from_stored_bytes(seed.clone()))
                .transpose()
        }

        fn create_seed(&self, key: &ControllerSigningKey) -> Result<(), ControllerKeyStoreError> {
            self.creates.set(self.creates.get() + 1);
            let mut seed = self.seed.borrow_mut();
            if seed.is_some() {
                return Err(ControllerKeyStoreError::AlreadyExists);
            }
            *seed = Some(key.expose_seed().to_vec());
            Ok(())
        }

        fn delete_seed(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(self.seed.borrow_mut().take().is_some())
        }

        fn removal_pending(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(self.marker.get())
        }

        fn create_removal_marker(&self) -> Result<(), ControllerKeyStoreError> {
            if self.marker.replace(true) {
                return Err(ControllerKeyStoreError::AlreadyExists);
            }
            Ok(())
        }

        fn delete_removal_marker(&self) -> Result<bool, ControllerKeyStoreError> {
            Ok(self.marker.replace(false))
        }
    }

    fn timestamp() -> StateTimestamp {
        StateTimestamp::from_unix_millis(100).expect("timestamp")
    }

    #[test]
    fn absent_authority_creates_once_and_key_only_resumes_without_regeneration() {
        let manager = ControllerAuthorityManager::new(MemoryStore::default());
        assert!(matches!(
            manager.prepare_for_challenge(None),
            Err(ControllerAuthorityError::IncompleteAuthority)
        ));
        assert_eq!(manager.store.creates.get(), 0);

        let prepared = manager
            .prepare_for_explicit_enable(None)
            .expect("prepare new authority");
        assert_eq!(prepared.mode(), ControllerBootstrapMode::BootstrapNew);
        assert_eq!(manager.store.creates.get(), 1);
        drop(prepared);

        let resumed = manager
            .prepare_for_challenge(None)
            .expect("challenge resumes prepared bootstrap");
        assert_eq!(resumed.mode(), ControllerBootstrapMode::ResumeBootstrap);
        assert_eq!(manager.store.creates.get(), 1);
    }

    #[test]
    fn record_only_mismatch_and_removal_pending_never_create_a_seed() {
        let record_key = ControllerSigningKey::from_stored_bytes(vec![7; 32]).expect("record key");
        let record = ControllerAuthorityRecord::new(record_key.public_key(), timestamp());

        let manager = ControllerAuthorityManager::new(MemoryStore::default());
        assert!(matches!(
            manager.prepare_for_explicit_enable(Some(record)),
            Err(ControllerAuthorityError::IncompleteAuthority)
        ));
        assert_eq!(manager.store.creates.get(), 0);

        let mismatch = ControllerAuthorityManager::new(MemoryStore::with_seed(8));
        assert!(matches!(
            mismatch.prepare_for_explicit_enable(Some(record)),
            Err(ControllerAuthorityError::IncompleteAuthority)
        ));
        assert_eq!(mismatch.store.creates.get(), 0);

        let pending = ControllerAuthorityManager::new(MemoryStore::default());
        pending.store.marker.set(true);
        assert!(matches!(
            pending.prepare_for_explicit_enable(None),
            Err(ControllerAuthorityError::RemovalPending)
        ));
        assert_eq!(pending.store.creates.get(), 0);
    }

    #[test]
    fn complete_matching_authority_authenticates_without_rotation() {
        let store = MemoryStore::with_seed(9);
        let key = store.load_seed().expect("load").expect("seed");
        let record = ControllerAuthorityRecord::new(key.public_key(), timestamp());
        drop(key);
        let manager = ControllerAuthorityManager::new(store);
        let prepared = manager
            .prepare_for_explicit_enable(Some(record))
            .expect("matching authority");
        assert_eq!(
            prepared.mode(),
            ControllerBootstrapMode::AuthenticateExisting
        );
        assert_eq!(manager.store.creates.get(), 0);
    }

    #[test]
    fn removal_marker_precedes_verified_seed_deletion_and_is_removed_last() {
        let manager = ControllerAuthorityManager::new(MemoryStore::with_seed(10));
        manager.begin_or_resume_removal().expect("begin removal");
        assert!(manager.store.marker.get());
        assert!(manager.store.seed.borrow().is_some());
        manager.begin_or_resume_removal().expect("resume removal");

        assert!(manager
            .complete_pending_removal()
            .expect("complete removal"));
        assert!(manager.store.seed.borrow().is_none());
        assert!(!manager.store.marker.get());
        assert!(matches!(
            manager.complete_pending_removal(),
            Err(ControllerAuthorityError::RemovalNotStarted)
        ));
    }

    #[test]
    fn stored_seed_length_and_removal_marker_are_strict() {
        assert_eq!(
            ControllerSigningKey::from_stored_bytes(vec![0; 31]).unwrap_err(),
            ControllerKeyStoreError::InvalidSeedLength { actual_length: 31 }
        );
        assert!(is_controller_removal_marker(
            CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE
        ));
        assert!(!is_controller_removal_marker(b"removal-pending-v1"));
    }
}
