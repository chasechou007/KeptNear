#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Core vault API for the PSW local-first password manager.
//!
//! This crate owns the security-sensitive boundary: vault format, key handling,
//! item persistence, sync metadata, import conversion, and search. UI clients
//! should call coarse-grained APIs here instead of reimplementing vault logic.

mod api;
mod crypto;
mod error;
mod export;
mod import;
#[allow(dead_code)]
mod record;
mod storage;
mod totp;
mod types;

pub use api::{
    ConflictCandidateField, ConflictCandidateSummary, ConflictFieldSelection, ConflictMergeRequest,
    CreateVaultRequest, ExportItemsRequest, ImportCommitRequest, ImportPreview,
    ImportPreviewRequest, LockedVault, OpenVaultRequest, PasswordHealthAudit, PasswordHealthIssue,
    PasswordHealthIssueKind, RejectedSyncRecordFile, RejectedSyncRecordKind,
    RestoreVaultBackupRequest, SearchQuery, SyncQuarantineReport, SyncRefreshReport, TotpCode,
    UnlockRequest, UnlockedVault, VaultBackupResult, VaultCore, VaultRestoreResult,
};
pub use error::{VaultError, VaultResult};
pub use export::ExportResult;
pub use totp::normalize_totp_secret;
pub use types::{
    ConflictId, CreditCardItem, ItemId, ItemRevision, ItemStatus, ItemSummary, ItemType, LoginItem,
    SecretBytes, SecureNoteItem, SoftwareLicenseItem, TombstoneId, VaultItem, VaultItemContent,
    VaultItemDraft, VaultMetadata,
};
