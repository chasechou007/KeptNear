use std::fmt;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Length of the device-local root key in bytes.
pub const DEVICE_ROOT_KEY_LENGTH: usize = 32;

/// Opaque device-local root key owned by the Broker.
///
/// The key is intentionally non-cloneable, never formats its bytes, and clears
/// its backing memory when dropped.
pub struct DeviceRootKey {
    bytes: [u8; DEVICE_ROOT_KEY_LENGTH],
}

impl DeviceRootKey {
    fn generate() -> Self {
        let mut bytes = [0_u8; DEVICE_ROOT_KEY_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub(crate) fn from_stored_bytes(mut bytes: Vec<u8>) -> Result<Self, DeviceKeyStoreError> {
        if bytes.len() != DEVICE_ROOT_KEY_LENGTH {
            let actual_length = bytes.len();
            bytes.zeroize();
            return Err(DeviceKeyStoreError::InvalidKeyLength { actual_length });
        }

        let mut key = [0_u8; DEVICE_ROOT_KEY_LENGTH];
        key.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self { bytes: key })
    }

    pub(crate) fn expose(&self) -> &[u8; DEVICE_ROOT_KEY_LENGTH] {
        &self.bytes
    }

    fn matches(&self, other: &Self) -> bool {
        self.bytes
            .iter()
            .zip(other.bytes.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }
}

impl fmt::Debug for DeviceRootKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceRootKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for DeviceRootKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for DeviceRootKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Operation attempted against the platform credential store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceKeyStoreOperation {
    /// Load the existing device root key.
    Load,
    /// Create the first device root key.
    Create,
    /// Delete the device root key during explicit local-data clearing.
    Delete,
}

impl DeviceKeyStoreOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }
}

/// Sanitized platform credential-store failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceKeyStoreError {
    /// A device root key already exists and was not overwritten.
    AlreadyExists,
    /// Stored key material is not exactly 256 bits.
    InvalidKeyLength {
        /// Observed byte length.
        actual_length: usize,
    },
    /// The current platform does not provide the required credential store.
    UnsupportedPlatform,
    /// A platform credential-store operation failed.
    Platform {
        /// Operating-system status code.
        status: i32,
    },
}

impl fmt::Display for DeviceKeyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("device root key already exists"),
            Self::InvalidKeyLength { actual_length } => write!(
                formatter,
                "stored device root key has invalid length ({actual_length} bytes)"
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("platform credential store is unsupported")
            }
            Self::Platform { status } => {
                write!(
                    formatter,
                    "platform credential store failed with status {status}"
                )
            }
        }
    }
}

impl std::error::Error for DeviceKeyStoreError {}

/// Device-root-key lifecycle failure.
#[derive(Debug)]
pub enum DeviceKeyError {
    /// No device root key exists.
    Missing,
    /// Initialization was requested after a key already existed.
    AlreadyInitialized,
    /// Creation succeeded, but read-back did not return the created key.
    VerificationFailed,
    /// Deletion reported completion, but the item remained available.
    DeletionVerificationFailed,
    /// A platform credential-store operation failed.
    Store {
        /// Attempted operation.
        operation: DeviceKeyStoreOperation,
        /// Sanitized underlying failure.
        source: DeviceKeyStoreError,
    },
}

impl fmt::Display for DeviceKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("device root key is missing"),
            Self::AlreadyInitialized => {
                formatter.write_str("device root key is already initialized")
            }
            Self::VerificationFailed => {
                formatter.write_str("created device root key failed read-back verification")
            }
            Self::DeletionVerificationFailed => {
                formatter.write_str("deleted device root key remained available")
            }
            Self::Store { operation, source } => {
                write!(
                    formatter,
                    "{} device root key failed: {source}",
                    operation.label()
                )
            }
        }
    }
}

impl std::error::Error for DeviceKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store { source, .. } => Some(source),
            Self::Missing
            | Self::AlreadyInitialized
            | Self::VerificationFailed
            | Self::DeletionVerificationFailed => None,
        }
    }
}

/// Platform credential store used exclusively for the Broker device root key.
pub trait DeviceKeyStore {
    /// Loads the existing key without creating replacement material.
    fn load(&self) -> Result<Option<DeviceRootKey>, DeviceKeyStoreError>;

    /// Atomically creates the key and refuses to overwrite an existing item.
    fn create_new(&self, key: &DeviceRootKey) -> Result<(), DeviceKeyStoreError>;

    /// Deletes the stable item, returning false when it is already absent.
    fn delete(&self) -> Result<bool, DeviceKeyStoreError>;
}

/// Explicit device-root-key initialization and loading boundary.
///
/// There is deliberately no `load_or_create` operation. Callers must first
/// decide whether they are initializing new device state or opening existing
/// state so a missing Keychain item can never silently replace an existing
/// database key.
pub struct DeviceKeyManager<S> {
    store: S,
}

impl<S> DeviceKeyManager<S>
where
    S: DeviceKeyStore,
{
    /// Creates a manager around one platform credential store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Loads a previously initialized device root key.
    pub fn load_existing(&self) -> Result<DeviceRootKey, DeviceKeyError> {
        self.store
            .load()
            .map_err(|source| DeviceKeyError::Store {
                operation: DeviceKeyStoreOperation::Load,
                source,
            })?
            .ok_or(DeviceKeyError::Missing)
    }

    /// Generates and stores the first device root key.
    ///
    /// The method refuses an existing key, uses operating-system randomness,
    /// and verifies the stored value before returning it.
    pub fn initialize_new(&self) -> Result<DeviceRootKey, DeviceKeyError> {
        if self
            .store
            .load()
            .map_err(|source| DeviceKeyError::Store {
                operation: DeviceKeyStoreOperation::Load,
                source,
            })?
            .is_some()
        {
            return Err(DeviceKeyError::AlreadyInitialized);
        }

        let key = DeviceRootKey::generate();
        self.store.create_new(&key).map_err(|source| {
            if source == DeviceKeyStoreError::AlreadyExists {
                DeviceKeyError::AlreadyInitialized
            } else {
                DeviceKeyError::Store {
                    operation: DeviceKeyStoreOperation::Create,
                    source,
                }
            }
        })?;

        let stored = self
            .store
            .load()
            .map_err(|source| DeviceKeyError::Store {
                operation: DeviceKeyStoreOperation::Load,
                source,
            })?
            .ok_or(DeviceKeyError::VerificationFailed)?;

        if !key.matches(&stored) {
            return Err(DeviceKeyError::VerificationFailed);
        }

        Ok(key)
    }

    /// Deletes and verifies absence of the device root key.
    ///
    /// This operation is idempotent but must be called only by the explicit
    /// local-data-clear workflow after encrypted device-state files are gone.
    pub fn delete_existing(&self) -> Result<bool, DeviceKeyError> {
        let removed = self
            .store
            .delete()
            .map_err(|source| DeviceKeyError::Store {
                operation: DeviceKeyStoreOperation::Delete,
                source,
            })?;
        if self
            .store
            .load()
            .map_err(|source| DeviceKeyError::Store {
                operation: DeviceKeyStoreOperation::Delete,
                source,
            })?
            .is_some()
        {
            return Err(DeviceKeyError::DeletionVerificationFailed);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct MemoryDeviceKeyStore {
        bytes: RefCell<Option<Vec<u8>>>,
        load_error: RefCell<Option<DeviceKeyStoreError>>,
        create_error: RefCell<Option<DeviceKeyStoreError>>,
        delete_error: RefCell<Option<DeviceKeyStoreError>>,
        replacement_after_create: RefCell<Option<Vec<u8>>>,
        retain_after_delete: RefCell<bool>,
    }

    impl MemoryDeviceKeyStore {
        fn with_bytes(bytes: Vec<u8>) -> Self {
            Self {
                bytes: RefCell::new(Some(bytes)),
                ..Self::default()
            }
        }
    }

    impl DeviceKeyStore for MemoryDeviceKeyStore {
        fn load(&self) -> Result<Option<DeviceRootKey>, DeviceKeyStoreError> {
            if let Some(error) = self.load_error.borrow_mut().take() {
                return Err(error);
            }
            self.bytes
                .borrow()
                .as_ref()
                .map(|bytes| DeviceRootKey::from_stored_bytes(bytes.clone()))
                .transpose()
        }

        fn create_new(&self, key: &DeviceRootKey) -> Result<(), DeviceKeyStoreError> {
            if let Some(error) = self.create_error.borrow_mut().take() {
                return Err(error);
            }
            let mut stored = self.bytes.borrow_mut();
            if stored.is_some() {
                return Err(DeviceKeyStoreError::AlreadyExists);
            }
            *stored = Some(
                self.replacement_after_create
                    .borrow_mut()
                    .take()
                    .unwrap_or_else(|| key.expose().to_vec()),
            );
            Ok(())
        }

        fn delete(&self) -> Result<bool, DeviceKeyStoreError> {
            if let Some(error) = self.delete_error.borrow_mut().take() {
                return Err(error);
            }
            let exists = self.bytes.borrow().is_some();
            if !*self.retain_after_delete.borrow() {
                self.bytes.borrow_mut().take();
            }
            Ok(exists)
        }
    }

    #[test]
    fn initializes_and_verifies_one_random_root_key() {
        let store = MemoryDeviceKeyStore::default();
        let manager = DeviceKeyManager::new(store);

        let key = manager.initialize_new().expect("initialize device key");

        assert_eq!(key.expose().len(), DEVICE_ROOT_KEY_LENGTH);
        assert!(key.expose().iter().any(|byte| *byte != 0));
        let loaded = manager.load_existing().expect("load device key");
        assert!(key.matches(&loaded));
    }

    #[test]
    fn missing_key_fails_without_generating_replacement() {
        let store = MemoryDeviceKeyStore::default();
        let manager = DeviceKeyManager::new(store);

        assert!(matches!(
            manager.load_existing(),
            Err(DeviceKeyError::Missing)
        ));
        assert!(manager.store.bytes.borrow().is_none());
    }

    #[test]
    fn initialization_refuses_to_replace_existing_key() {
        let existing = vec![7_u8; DEVICE_ROOT_KEY_LENGTH];
        let store = MemoryDeviceKeyStore::with_bytes(existing.clone());
        let manager = DeviceKeyManager::new(store);

        assert!(matches!(
            manager.initialize_new(),
            Err(DeviceKeyError::AlreadyInitialized)
        ));
        assert_eq!(manager.store.bytes.borrow().as_ref(), Some(&existing));
    }

    #[test]
    fn concurrent_duplicate_is_reported_as_already_initialized() {
        let store = MemoryDeviceKeyStore::default();
        *store.create_error.borrow_mut() = Some(DeviceKeyStoreError::AlreadyExists);
        let manager = DeviceKeyManager::new(store);

        assert!(matches!(
            manager.initialize_new(),
            Err(DeviceKeyError::AlreadyInitialized)
        ));
    }

    #[test]
    fn malformed_stored_key_fails_closed() {
        let store = MemoryDeviceKeyStore::with_bytes(vec![9_u8; 31]);
        let manager = DeviceKeyManager::new(store);

        assert!(matches!(
            manager.load_existing(),
            Err(DeviceKeyError::Store {
                operation: DeviceKeyStoreOperation::Load,
                source: DeviceKeyStoreError::InvalidKeyLength { actual_length: 31 },
            })
        ));
    }

    #[test]
    fn read_back_mismatch_fails_closed() {
        let store = MemoryDeviceKeyStore::default();
        *store.replacement_after_create.borrow_mut() = Some(vec![3_u8; DEVICE_ROOT_KEY_LENGTH]);
        let manager = DeviceKeyManager::new(store);

        assert!(matches!(
            manager.initialize_new(),
            Err(DeviceKeyError::VerificationFailed)
        ));
    }

    #[test]
    fn deletion_is_idempotent_and_verified() {
        let store = MemoryDeviceKeyStore::with_bytes(vec![4_u8; DEVICE_ROOT_KEY_LENGTH]);
        let manager = DeviceKeyManager::new(store);

        assert!(manager.delete_existing().expect("delete existing"));
        assert!(!manager.delete_existing().expect("delete missing"));
        assert!(matches!(
            manager.load_existing(),
            Err(DeviceKeyError::Missing)
        ));
    }

    #[test]
    fn failed_or_unverified_deletion_never_reports_success() {
        let store = MemoryDeviceKeyStore::with_bytes(vec![5_u8; DEVICE_ROOT_KEY_LENGTH]);
        *store.delete_error.borrow_mut() = Some(DeviceKeyStoreError::Platform { status: -1 });
        let manager = DeviceKeyManager::new(store);
        assert!(matches!(
            manager.delete_existing(),
            Err(DeviceKeyError::Store {
                operation: DeviceKeyStoreOperation::Delete,
                ..
            })
        ));
        assert!(manager.load_existing().is_ok());

        *manager.store.retain_after_delete.borrow_mut() = true;
        assert!(matches!(
            manager.delete_existing(),
            Err(DeviceKeyError::DeletionVerificationFailed)
        ));
        assert!(manager.load_existing().is_ok());
    }

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let mut key =
            DeviceRootKey::from_stored_bytes(vec![0xab; DEVICE_ROOT_KEY_LENGTH]).expect("key");
        let debug = format!("{key:?}");

        assert_eq!(debug, "DeviceRootKey { bytes: \"<redacted>\" }");
        assert!(!debug.contains("171"));
        assert!(!debug.contains("ab"));

        key.zeroize();
        assert_eq!(key.expose(), &[0_u8; DEVICE_ROOT_KEY_LENGTH]);
    }
}
