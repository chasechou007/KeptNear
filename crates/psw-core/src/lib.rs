#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Core vault API for the PSW local-first password manager.
//!
//! This crate owns the security-sensitive boundary: vault format, key handling,
//! item persistence, sync metadata, import conversion, and search. UI clients
//! should call coarse-grained APIs here instead of reimplementing vault logic.

mod api;
mod credential_model;
mod crypto;
mod error;
mod export;
mod import;
mod migration;
#[allow(dead_code)]
mod record;
mod recovery;
mod revision;
mod safe_fs;
mod stable_id;
mod storage;
mod totp;
mod types;

pub use api::{
    ConflictCandidateCredentialField, ConflictCandidateField, ConflictCandidateSummary,
    ConflictFieldSelection, ConflictMergeRequest, CreateVaultRequest, CredentialListItem,
    ExportItemsRequest, ImportCommitRequest, ImportPreview, ImportPreviewRequest, LockedVault,
    OpenVaultRequest, PasswordHealthAudit, PasswordHealthIssue, PasswordHealthIssueKind,
    PendingRecoveryRotation, PendingRecoverySetup, PreparedCredentialUpdate, RecoverVaultRequest,
    RejectedSyncRecordFile, RejectedSyncRecordKind, RestoreVaultBackupRequest, SearchQuery,
    SyncQuarantineReport, SyncRefreshReport, TotpCode, UnlockRequest, UnlockedVault,
    VaultBackupResult, VaultCore, VaultFormatMigrationResult, VaultRestoreResult,
};
pub use credential_model::{
    built_in_credential_template, Credential, CredentialDraft, CredentialEdit, CredentialField,
    CredentialFieldEdit, CredentialFieldValue, CredentialModelParseError, CredentialSummary,
    CredentialTemplateDefinition, CredentialUseCapability, CredentialValidationError,
    LegacyCredentialConversionError, SecretFieldKind, SecretFieldSummary,
    BUILT_IN_CREDENTIAL_TEMPLATES,
};
pub use error::{VaultError, VaultResult};
pub use export::{ExportOmission, ExportOmissionReason, ExportResult};
pub use recovery::{
    create_recovery_envelope, decrypt_recovery_envelope, RecoveryEnvelope, RecoveryKey,
    RecoveryKeyParseError, RecoveryKit,
};
pub use revision::{
    ContentDigest, ContentDigestParseError, CredentialLifecycle, CredentialRevision,
    CredentialRevisionError, CredentialRevisionSummary,
};
pub use stable_id::{
    CredentialId, DeviceId, RecoveryKeyId, RevisionId, SecretFieldId, StableIdParseError, VaultId,
};
pub use totp::normalize_totp_secret;
pub use types::{
    ConflictId, CreditCardItem, ItemId, ItemRevision, ItemStatus, ItemSummary, ItemType, LoginItem,
    SecretBytes, SecureNoteItem, SoftwareLicenseItem, TombstoneId, VaultItem, VaultItemContent,
    VaultItemDraft, VaultMetadata, CURRENT_RECORD_FORMAT_VERSION, CURRENT_VAULT_FORMAT_VERSION,
};
