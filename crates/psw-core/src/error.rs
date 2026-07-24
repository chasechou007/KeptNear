use std::fmt::{Display, Formatter};
use std::io;

/// Result type used by the vault core.
pub type VaultResult<T> = Result<T, VaultError>;

/// Errors returned by the vault core API.
#[derive(Debug)]
pub enum VaultError {
    /// A filesystem operation failed.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Underlying IO error.
        source: io::Error,
    },
    /// The requested operation has an API boundary but no implementation yet.
    NotImplemented {
        /// Operation name.
        operation: &'static str,
    },
    /// The vault path is missing required structure or metadata.
    InvalidVault {
        /// Human-readable reason.
        reason: String,
    },
    /// Cryptographic operation failed.
    Crypto {
        /// Operation being performed.
        operation: &'static str,
        /// Human-readable reason.
        reason: String,
    },
    /// The vault format is newer than this client supports.
    UnsupportedFormat {
        /// Version found on disk.
        found: u32,
        /// Maximum supported version.
        supported: u32,
    },
    /// The vault is locked and plaintext data is unavailable.
    Locked,
    /// Requested item does not exist in the active vault view.
    ItemNotFound {
        /// Item identifier.
        id: String,
    },
    /// The supplied credentials did not unlock the vault.
    InvalidCredentials,
}

impl VaultError {
    /// Creates an IO error with operation context.
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    /// Creates a not-implemented marker for staged development.
    pub fn not_implemented(operation: &'static str) -> Self {
        Self::NotImplemented { operation }
    }
}

impl Display for VaultError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { operation, source } => {
                write!(
                    formatter,
                    "filesystem operation '{operation}' failed: {source}"
                )
            }
            Self::NotImplemented { operation } => {
                write!(formatter, "operation '{operation}' is not implemented yet")
            }
            Self::InvalidVault { reason } => write!(formatter, "invalid vault: {reason}"),
            Self::Crypto { operation, reason } => {
                write!(
                    formatter,
                    "cryptographic operation '{operation}' failed: {reason}"
                )
            }
            Self::UnsupportedFormat { found, supported } => write!(
                formatter,
                "unsupported vault format version {found}; supported up to {supported}"
            ),
            Self::Locked => write!(formatter, "vault is locked"),
            Self::ItemNotFound { id } => write!(formatter, "item '{id}' was not found"),
            Self::InvalidCredentials => write!(formatter, "invalid vault credentials"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::NotImplemented { .. }
            | Self::InvalidVault { .. }
            | Self::Crypto { .. }
            | Self::UnsupportedFormat { .. }
            | Self::Locked
            | Self::ItemNotFound { .. }
            | Self::InvalidCredentials => None,
        }
    }
}
