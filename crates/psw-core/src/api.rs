use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::credential_model::{
    CredentialDraft, CredentialFieldValue, TEMPLATE_CREDIT_CARD, TEMPLATE_LOGIN,
    TEMPLATE_SECURE_NOTE, TEMPLATE_SOFTWARE_LICENSE,
};
use crate::error::{VaultError, VaultResult};
use crate::export::{
    export_credentials_to_file, ExportCredential, ExportOmissionReason, ExportResult,
    ExportSnapshot,
};
use crate::import::parse_import_file;
use crate::migration::migrate_v1_vault_directory;
use crate::record::{
    decrypt_item_record, decrypt_target_credential_record, encrypt_item_record,
    encrypt_target_credential_record, parse_target_credential_record, EncryptedItemRecord,
};
use crate::revision::{ContentDigest, CredentialLifecycle, CredentialRevision};
use crate::safe_fs::{read_regular_file_limited, MAX_ENCRYPTED_RECORD_FILE_BYTES};
use crate::storage::{
    backup_vault_directory, change_master_password, commit_recovery_envelope_rotation,
    create_local_unlock_material, create_recovery_envelope_rotation, create_vault_directory,
    load_item_records, load_tombstone_records, open_vault_directory,
    recover_vault_key_and_rewrap_master_password, recovery_envelope_key_id,
    restore_vault_backup_directory, unlock_vault_key, unlock_vault_key_with_local_material,
    validate_required_structure, write_item_record, write_target_credential_record,
    write_tombstone_record,
};
use crate::totp::{generate_totp_code, normalize_totp_secret};
use crate::types::{
    ConflictId, ItemId, ItemRevision, ItemStatus, ItemSummary, SecretBytes, VaultItem,
    VaultItemContent, VaultItemDraft, VaultMetadata, SOURCE_RECORD_FORMAT_VERSION,
    SOURCE_VAULT_FORMAT_VERSION, TARGET_RECORD_FORMAT_VERSION, TARGET_VAULT_FORMAT_VERSION,
};

const ITEMS_DIR_NAME: &str = "items";
const TOMBSTONES_DIR_NAME: &str = "tombstones";
const QUARANTINE_DIR_NAME: &str = "quarantine";

/// Entry point for host clients.
#[derive(Clone, Debug, Default)]
pub struct VaultCore;

impl VaultCore {
    /// Creates a new core facade.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Creates a new vault and returns it in locked state.
    pub fn create_vault(&self, request: CreateVaultRequest) -> VaultResult<LockedVault> {
        let metadata = create_vault_directory(
            &request.path,
            request.display_name,
            &request.master_password,
        )?;
        Ok(LockedVault {
            path: request.path,
            metadata,
        })
    }

    /// Opens an existing vault and returns it in locked state.
    pub fn open_vault(&self, request: OpenVaultRequest) -> VaultResult<LockedVault> {
        let metadata = open_vault_directory(&request.path)?;
        Ok(LockedVault {
            path: request.path,
            metadata,
        })
    }

    /// Restores a portable encrypted vault backup into a new local vault path.
    pub fn restore_vault_backup(
        &self,
        request: RestoreVaultBackupRequest,
    ) -> VaultResult<VaultRestoreResult> {
        open_vault_directory(&request.source_path)?;
        let report =
            restore_vault_backup_directory(&request.source_path, &request.destination_path)?;
        Ok(VaultRestoreResult {
            copied_item_files: report.copied_item_files,
            copied_attachment_files: report.copied_attachment_files,
            copied_tombstone_files: report.copied_tombstone_files,
        })
    }
}

/// Request to create a new vault directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateVaultRequest {
    /// Target vault directory path.
    pub path: PathBuf,
    /// Optional user-visible vault name.
    pub display_name: Option<String>,
    /// Master password used to wrap the generated vault key.
    pub master_password: SecretBytes,
}

/// Request to open an existing vault directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenVaultRequest {
    /// Existing vault directory path.
    pub path: PathBuf,
}

/// Request to restore a portable encrypted vault backup to a new directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreVaultBackupRequest {
    /// Source encrypted backup vault directory.
    pub source_path: PathBuf,
    /// Destination vault directory to create or fill if empty.
    pub destination_path: PathBuf,
}

/// Request to unlock a locked vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnlockRequest {
    /// Master password bytes supplied by the user.
    pub master_password: crate::types::SecretBytes,
}

/// Request to recover a locked vault and establish a new master password.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverVaultRequest {
    /// Offline recovery authority supplied by the user.
    pub recovery_key: crate::recovery::RecoveryKey,
    /// New master password that will wrap the existing random vault key.
    pub new_master_password: crate::types::SecretBytes,
}

/// Unconfirmed recovery material returned by first-time recovery initialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRecoverySetup {
    /// Offline recovery authority that must be explicitly saved and confirmed.
    pub recovery_key: crate::recovery::RecoveryKey,
    /// Non-secret identity of the installed recovery-key generation.
    pub recovery_key_id: crate::stable_id::RecoveryKeyId,
    vault_id: crate::stable_id::VaultId,
}

impl PendingRecoverySetup {
    /// Renders this pending authority for an explicit display or export workflow.
    #[must_use]
    pub fn recovery_kit(&self, generated_at_unix_seconds: u64) -> crate::recovery::RecoveryKit {
        crate::recovery::RecoveryKit::render(
            &self.recovery_key,
            self.vault_id,
            self.recovery_key_id,
            generated_at_unix_seconds,
        )
    }
}

/// Unconfirmed recovery-key rotation material held only in memory.
///
/// The current recovery envelope remains authoritative until this value is
/// consumed by [`UnlockedVault::commit_recovery_rotation`]. Dropping it
/// cancels the rotation and zeroizes its recovery authority.
pub struct PendingRecoveryRotation {
    recovery_key: crate::recovery::RecoveryKey,
    recovery_key_id: crate::stable_id::RecoveryKeyId,
    previous_recovery_key_id: crate::stable_id::RecoveryKeyId,
    candidate_envelope: crate::recovery::RecoveryEnvelope,
}

impl PendingRecoveryRotation {
    /// Returns the unconfirmed recovery authority for an explicit custody workflow.
    #[must_use]
    pub fn recovery_key(&self) -> &crate::recovery::RecoveryKey {
        &self.recovery_key
    }

    /// Returns the non-secret identity of the candidate recovery-key generation.
    #[must_use]
    pub fn recovery_key_id(&self) -> crate::stable_id::RecoveryKeyId {
        self.recovery_key_id
    }

    /// Renders this candidate for an explicit display or export workflow.
    #[must_use]
    pub fn recovery_kit(&self, generated_at_unix_seconds: u64) -> crate::recovery::RecoveryKit {
        crate::recovery::RecoveryKit::render(
            &self.recovery_key,
            self.candidate_envelope.vault_id(),
            self.recovery_key_id,
            generated_at_unix_seconds,
        )
    }
}

impl Debug for PendingRecoveryRotation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRecoveryRotation")
            .field("recovery_key", &self.recovery_key)
            .field("recovery_key_id", &self.recovery_key_id)
            .finish_non_exhaustive()
    }
}

/// A vault that has been identified on disk but is not unlocked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedVault {
    /// Vault path on local disk.
    pub path: PathBuf,
    /// Public vault metadata.
    pub metadata: VaultMetadata,
}

impl LockedVault {
    /// Returns the current non-secret recovery-key generation, if configured.
    pub fn recovery_key_id(&self) -> VaultResult<Option<crate::stable_id::RecoveryKeyId>> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "offline recovery requires a current-format vault identity".to_owned(),
            })?;
        recovery_envelope_key_id(&self.path, vault_id)
    }

    /// Unlocks a vault and returns an unlocked session.
    pub fn unlock(self, request: UnlockRequest) -> VaultResult<UnlockedVault> {
        let vault_key = crate::storage::unlock_vault_key(&self.path, &request.master_password)?;
        Ok(self.unlock_with_vault_key(vault_key))
    }

    /// Unlocks a vault using local-only unlock material from a prior session.
    pub fn unlock_with_local_material(
        self,
        local_unlock_material: SecretBytes,
    ) -> VaultResult<UnlockedVault> {
        let vault_key = unlock_vault_key_with_local_material(&self.path, &local_unlock_material)?;
        Ok(self.unlock_with_vault_key(vault_key))
    }

    /// Recovers this vault and atomically replaces its master-password envelope.
    pub fn recover(self, request: RecoverVaultRequest) -> VaultResult<UnlockedVault> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "offline recovery requires a current-format vault identity".to_owned(),
            })?;
        let vault_key = recover_vault_key_and_rewrap_master_password(
            &self.path,
            vault_id,
            &request.recovery_key,
            &request.new_master_password,
        )?;
        Ok(self.unlock_with_vault_key(vault_key))
    }

    fn unlock_with_vault_key(self, vault_key: SecretBytes) -> UnlockedVault {
        UnlockedVault {
            path: self.path,
            metadata: self.metadata,
            vault_key,
        }
    }
}

/// An unlocked vault session containing access to decrypted item operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnlockedVault {
    /// Vault path on local disk.
    pub path: PathBuf,
    /// Public vault metadata.
    pub metadata: VaultMetadata,
    vault_key: SecretBytes,
}

/// Non-secret result metadata for an encrypted local vault backup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VaultBackupResult {
    /// Number of encrypted item record files copied.
    pub copied_item_files: usize,
    /// Number of attachment files copied.
    pub copied_attachment_files: usize,
    /// Number of encrypted tombstone record files copied.
    pub copied_tombstone_files: usize,
}

/// Non-secret result metadata for an encrypted local vault restore.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VaultRestoreResult {
    /// Number of encrypted item record files copied.
    pub copied_item_files: usize,
    /// Number of attachment files copied.
    pub copied_attachment_files: usize,
    /// Number of encrypted tombstone record files copied.
    pub copied_tombstone_files: usize,
}

/// Non-secret result of an explicit one-way vault-format migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultFormatMigrationResult {
    /// Target vault metadata installed at the original vault path.
    pub metadata: VaultMetadata,
    /// Retained verified encrypted v1/v1 backup path.
    pub backup_path: PathBuf,
    /// Number of non-deleted encrypted revisions migrated.
    pub migrated_item_records: usize,
    /// Number of encrypted deletion revisions migrated.
    pub migrated_tombstone_records: usize,
    /// Number of attachment files preserved.
    pub copied_attachment_files: usize,
    /// Whether an encrypted recovery sibling remains for manual cleanup.
    pub cleanup_required: bool,
}

/// Non-secret local password health audit for login items.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PasswordHealthAudit {
    /// Number of login items with saved passwords that were checked.
    pub checked_login_passwords: usize,
    /// Number of checked login passwords reported as weak.
    pub weak_passwords: usize,
    /// Number of checked login passwords reused by at least one other login.
    pub reused_passwords: usize,
    /// Non-secret issue rows for affected login items.
    pub issues: Vec<PasswordHealthIssue>,
}

/// Non-secret password health issue for one login item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordHealthIssue {
    /// Affected item identifier.
    pub item_id: ItemId,
    /// Affected item title. This is already visible in unlocked item lists.
    pub title: String,
    /// Issue kind.
    pub kind: PasswordHealthIssueKind,
    /// Number of items sharing the same password for reused-password issues.
    pub reuse_group_size: Option<usize>,
}

/// Password health issue category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordHealthIssueKind {
    /// Password matches a conservative local weak-password heuristic.
    WeakPassword,
    /// Password is exactly reused by two or more login items.
    ReusedPassword,
}

/// Non-secret human-side list row for one current-format credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialListItem {
    /// Authenticated revision identity represented by this list row.
    pub revision_id: crate::RevisionId,
    /// Active, archived, deleted, or derived conflict state.
    pub status: ItemStatus,
    /// Value-free credential metadata and stable field identities.
    pub credential: crate::CredentialSummary,
}

/// Validated, memory-only update awaiting Secret Field authorization cleanup.
///
/// Preparing an update performs all ordinary model, conflict, revision, and
/// writable-vault checks without changing the vault. Callers may then revoke
/// authorization for `removed_secret_field_ids` before committing, ensuring a
/// deleted Secret Field is never persisted while stale machine access remains.
pub struct PreparedCredentialUpdate {
    expected_revision_id: crate::RevisionId,
    revision: CredentialRevision,
    removed_secret_field_ids: Vec<crate::SecretFieldId>,
}

impl PreparedCredentialUpdate {
    /// Returns the immutable vault identity for authorization cleanup.
    #[must_use]
    pub const fn vault_id(&self) -> crate::VaultId {
        self.revision.credential().vault_id()
    }

    /// Returns the immutable credential identity being updated.
    #[must_use]
    pub const fn credential_id(&self) -> crate::CredentialId {
        self.revision.credential().credential_id()
    }

    /// Returns exact Secret Field identities omitted by the new ordered field list.
    #[must_use]
    pub fn removed_secret_field_ids(&self) -> &[crate::SecretFieldId] {
        &self.removed_secret_field_ids
    }
}

impl UnlockedVault {
    /// Returns the current non-secret recovery-key generation, if configured.
    pub fn recovery_key_id(&self) -> VaultResult<Option<crate::stable_id::RecoveryKeyId>> {
        LockedVault {
            path: self.path.clone(),
            metadata: self.metadata.clone(),
        }
        .recovery_key_id()
    }

    /// Installs the first recovery envelope and returns unconfirmed offline authority.
    ///
    /// This operation refuses to replace an existing envelope. Callers must keep
    /// setup visibly pending until the returned authority is explicitly saved
    /// and confirmed.
    pub fn begin_recovery_setup(&self) -> VaultResult<PendingRecoverySetup> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "offline recovery requires a current-format vault identity".to_owned(),
            })?;
        let (recovery_key, envelope) = crate::storage::create_and_write_recovery_envelope(
            &self.path,
            vault_id,
            &self.vault_key,
        )?;
        Ok(PendingRecoverySetup {
            recovery_key,
            recovery_key_id: envelope.recovery_key_id(),
            vault_id,
        })
    }

    /// Creates an in-memory recovery-key candidate without replacing current authority.
    ///
    /// Callers must export and confirm the returned authority before consuming
    /// the candidate with [`Self::commit_recovery_rotation`]. Dropping the
    /// candidate leaves the current recovery key valid.
    pub fn begin_recovery_rotation(&self) -> VaultResult<PendingRecoveryRotation> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "offline recovery requires a current-format vault identity".to_owned(),
            })?;
        let (recovery_key, candidate_envelope, previous_recovery_key_id) =
            create_recovery_envelope_rotation(&self.path, vault_id, &self.vault_key)?;
        Ok(PendingRecoveryRotation {
            recovery_key_id: candidate_envelope.recovery_key_id(),
            recovery_key,
            previous_recovery_key_id,
            candidate_envelope,
        })
    }

    /// Atomically installs a previously confirmed recovery-key candidate.
    ///
    /// The commit is rejected if another rotation has changed recovery
    /// authority since the candidate was created.
    pub fn commit_recovery_rotation(&self, pending: PendingRecoveryRotation) -> VaultResult<()> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "offline recovery requires a current-format vault identity".to_owned(),
            })?;
        commit_recovery_envelope_rotation(
            &self.path,
            vault_id,
            &self.vault_key,
            pending.previous_recovery_key_id,
            &pending.recovery_key,
            &pending.candidate_envelope,
        )
    }

    /// Returns local-only unlock material for this unlocked vault session.
    pub fn local_unlock_material(&self) -> VaultResult<SecretBytes> {
        create_local_unlock_material(&self.path, &self.vault_key)
    }

    /// Changes the master password by rewrapping the current vault key.
    pub fn change_master_password(
        &self,
        current_master_password: SecretBytes,
        new_master_password: SecretBytes,
    ) -> VaultResult<()> {
        change_master_password(&self.path, &current_master_password, &new_master_password)
    }

    /// Creates a portable encrypted backup copy of this vault.
    pub fn backup_to(&self, destination_path: PathBuf) -> VaultResult<VaultBackupResult> {
        let report = backup_vault_directory(&self.path, &destination_path)?;
        Ok(VaultBackupResult {
            copied_item_files: report.copied_item_files,
            copied_attachment_files: report.copied_attachment_files,
            copied_tombstone_files: report.copied_tombstone_files,
        })
    }

    /// Consumes an unlocked v1/v1 session and explicitly migrates it to v2/v2.
    ///
    /// The retained encrypted backup is verified before the source path is
    /// replaced. The resulting current-format vault supports ordinary writes.
    pub fn migrate_to_target_format(
        self,
        backup_path: PathBuf,
    ) -> VaultResult<VaultFormatMigrationResult> {
        let report = migrate_v1_vault_directory(&self.path, &backup_path, &self.vault_key)?;
        Ok(VaultFormatMigrationResult {
            metadata: report.metadata,
            backup_path: report.backup_path,
            migrated_item_records: report.migrated_item_records,
            migrated_tombstone_records: report.migrated_tombstone_records,
            copied_attachment_files: report.copied_attachment_files,
            cleanup_required: report.cleanup_required,
        })
    }

    /// Locks the vault and drops the unlocked session.
    #[must_use]
    pub fn lock(self) -> LockedVault {
        LockedVault {
            path: self.path,
            metadata: self.metadata,
        }
    }

    /// Lists item summaries visible to the current unlocked session.
    pub fn list_items(&self) -> VaultResult<Vec<ItemSummary>> {
        let mut summaries: Vec<_> = self
            .latest_items()?
            .into_iter()
            .filter(|item| matches!(item.status, ItemStatus::Active | ItemStatus::Conflicted(_)))
            .map(|item| ItemSummary::from_item(&item))
            .collect();
        summaries.sort_by(|left, right| {
            left.title
                .to_lowercase()
                .cmp(&right.title.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(summaries)
    }

    /// Reads one decrypted item by ID.
    pub fn get_item(&self, _id: &ItemId) -> VaultResult<VaultItem> {
        self.latest_item(_id)
    }

    /// Reads one current-format credential summary by stable identity.
    ///
    /// This does not provide a vault catalog. Deleted, archived, conflicted, or
    /// unknown credentials do not produce metadata.
    pub fn credential_summary(
        &self,
        credential_id: crate::CredentialId,
    ) -> VaultResult<Option<crate::CredentialSummary>> {
        let Some(revision) = self.active_credential_revision(credential_id)? else {
            return Ok(None);
        };
        revision
            .credential()
            .summary()
            .map(Some)
            .map_err(|error| VaultError::InvalidVault {
                reason: error.to_string(),
            })
    }

    /// Reads one exact active Secret Field for the trusted execution boundary.
    ///
    /// The lookup requires all stable identities plus the expected kind.
    /// Missing, archived, deleted, changed-kind, and unrelated fields return
    /// `None`; conflicted or structurally invalid credentials fail closed.
    pub fn credential_secret_field(
        &self,
        credential_id: crate::CredentialId,
        secret_field_id: crate::SecretFieldId,
        expected_kind: crate::SecretFieldKind,
    ) -> VaultResult<Option<crate::SecretBytes>> {
        let Some(revision) = self.active_credential_revision(credential_id)? else {
            return Ok(None);
        };
        let secret = revision
            .credential()
            .draft()
            .secret_fields()
            .find_map(|field| match &field.value {
                crate::CredentialFieldValue::Secret {
                    secret_field_id: current_id,
                    kind,
                    secret,
                } if *current_id == secret_field_id && *kind == expected_kind => {
                    Some(secret.clone())
                }
                crate::CredentialFieldValue::Text { .. }
                | crate::CredentialFieldValue::Secret { .. } => None,
            });
        Ok(secret)
    }

    /// Lists active current-format credential summaries for a trusted human
    /// control plane.
    ///
    /// Secret values remain excluded. Archived, deleted, and conflicted
    /// credentials are omitted so they cannot be selected for new machine
    /// authorization.
    pub fn active_credential_summaries(&self) -> VaultResult<Vec<crate::CredentialSummary>> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "stable current-format credential listing",
            ));
        }
        let mut summaries = self
            .active_credential_head_revisions()?
            .into_iter()
            .map(|revision| {
                revision
                    .credential()
                    .summary()
                    .map_err(|error| VaultError::InvalidVault {
                        reason: error.to_string(),
                    })
            })
            .collect::<VaultResult<Vec<_>>>()?;
        summaries.sort_by(|left, right| {
            left.title
                .to_lowercase()
                .cmp(&right.title.to_lowercase())
                .then_with(|| left.credential_id.cmp(&right.credential_id))
        });
        Ok(summaries)
    }

    /// Matches active current-format Credentials for a trusted human control
    /// plane while returning only value-free summaries.
    ///
    /// Matching may inspect authenticated non-secret text fields such as
    /// usernames, URLs, and notes, but Secret Field values never participate
    /// and no matching text value is copied into the result.
    pub fn active_credential_summaries_matching(
        &self,
        query: &str,
    ) -> VaultResult<Vec<crate::CredentialSummary>> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "stable current-format credential matching",
            ));
        }
        let normalized = Zeroizing::new(query.trim().to_lowercase());
        let mut summaries = self
            .active_credential_head_revisions()?
            .into_iter()
            .filter(|revision| credential_matches_query(revision.credential(), &normalized))
            .map(|revision| {
                revision
                    .credential()
                    .summary()
                    .map_err(|error| VaultError::InvalidVault {
                        reason: error.to_string(),
                    })
            })
            .collect::<VaultResult<Vec<_>>>()?;
        summaries.sort_by(|left, right| {
            left.title
                .to_lowercase()
                .cmp(&right.title.to_lowercase())
                .then_with(|| left.credential_id.cmp(&right.credential_id))
        });
        Ok(summaries)
    }

    /// Lists current-format credentials for the trusted human control plane.
    ///
    /// Secret and text field values are excluded. Conflicted credentials
    /// produce one deterministic list row marked as conflicted while retaining
    /// every encrypted head on disk.
    pub fn list_credential_items(
        &self,
        include_archived: bool,
    ) -> VaultResult<Vec<CredentialListItem>> {
        self.credential_items_matching(None, include_archived)
    }

    /// Searches current-format credentials for the trusted human control plane.
    ///
    /// Matching may inspect authenticated non-secret text fields and secure
    /// note bodies for human-search compatibility. Other secret kinds remain
    /// excluded, and results remain value-free.
    pub fn search_credential_items(
        &self,
        query: SearchQuery,
    ) -> VaultResult<Vec<CredentialListItem>> {
        let needle = Zeroizing::new(query.text.trim().to_lowercase());
        self.credential_items_matching(Some(&needle), query.include_archived)
    }

    /// Reads one non-conflicted current-format credential revision for the
    /// trusted human control plane.
    pub fn credential_revision(
        &self,
        credential_id: crate::CredentialId,
    ) -> VaultResult<CredentialRevision> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "current-format credential detail",
            ));
        }
        let (revisions, _) = self.load_target_revisions_with_report()?;
        let mut matches = target_head_revisions(revisions)
            .into_iter()
            .filter(|revision| revision.credential().credential_id() == credential_id);
        let Some(revision) = matches.next() else {
            return Err(VaultError::ItemNotFound {
                id: credential_id.to_string(),
            });
        };
        if matches.next().is_some() {
            return Err(VaultError::InvalidVault {
                reason: "credential has multiple current revisions".to_owned(),
            });
        }
        if revision.lifecycle() == CredentialLifecycle::Deleted {
            return Err(VaultError::ItemNotFound {
                id: credential_id.to_string(),
            });
        }
        Ok(revision)
    }

    /// Creates one credential directly in the extensible current-format model.
    ///
    /// This path never converts through the frozen v1 item enum. Presentation
    /// template identifiers remain open strings and are not authorization
    /// identities.
    pub fn create_credential(
        &mut self,
        draft: crate::CredentialDraft,
    ) -> VaultResult<CredentialListItem> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "current-format credential creation",
            ));
        }
        validate_credential_draft_for_write(&draft)?;
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "current vault metadata is missing its stable identity".to_owned(),
            })?;
        let credential =
            crate::Credential::new(vault_id, draft).map_err(|error| VaultError::InvalidVault {
                reason: error.to_string(),
            })?;
        let revision = CredentialRevision::initial(credential, crate::DeviceId::generate())
            .map_err(|error| VaultError::InvalidVault {
                reason: error.to_string(),
            })?;
        let current_revisions = self.target_revisions()?;
        if current_revisions.iter().any(|current| {
            current.revision_id() == revision.revision_id()
                || current.credential().credential_id() == revision.credential().credential_id()
        }) {
            return Err(VaultError::InvalidVault {
                reason: "generated current-format credential identity already exists".to_owned(),
            });
        }
        let record = encrypt_target_credential_record(&self.vault_key, &revision)?;
        write_target_credential_record(&self.path, &record, CredentialLifecycle::Active)?;
        credential_list_item(revision, ItemStatus::Active)
    }

    /// Validates an update without reading unchanged Secret Field values out to
    /// the caller or mutating the vault.
    ///
    /// Existing fields retain their immutable identities. Secret fields omitted
    /// from the complete edit are reported so the trusted control plane can
    /// revoke their machine authorization before calling
    /// [`Self::commit_credential_update`].
    pub fn prepare_credential_update(
        &self,
        credential_id: crate::CredentialId,
        expected_revision_id: crate::RevisionId,
        edit: crate::CredentialEdit,
    ) -> VaultResult<PreparedCredentialUpdate> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "current-format credential editing",
            ));
        }
        let (revisions, current) = self.target_credential_head_for_write(credential_id)?;
        if current.revision_id() != expected_revision_id {
            return Err(VaultError::InvalidVault {
                reason: "item changed on disk; refresh sync before editing".to_owned(),
            });
        }
        if current.lifecycle() != CredentialLifecycle::Active {
            return Err(VaultError::InvalidVault {
                reason: "only active credentials can be edited".to_owned(),
            });
        }

        let (draft, removed_secret_field_ids) = edit
            .materialize(current.credential().draft())
            .map_err(|error| VaultError::InvalidVault {
                reason: error.to_string(),
            })?;
        validate_credential_draft_for_write(&draft)?;
        let credential =
            crate::Credential::with_id(current.credential().vault_id(), credential_id, draft)
                .map_err(|error| VaultError::InvalidVault {
                    reason: error.to_string(),
                })?;
        let revision = CredentialRevision::descendant_with_lifecycle(
            credential,
            crate::DeviceId::generate(),
            vec![expected_revision_id],
            current.lifecycle(),
        )
        .map_err(|error| VaultError::InvalidVault {
            reason: error.to_string(),
        })?;
        if revisions
            .iter()
            .any(|candidate| candidate.revision_id() == revision.revision_id())
        {
            return Err(VaultError::InvalidVault {
                reason: "generated current-format revision identity already exists".to_owned(),
            });
        }
        Ok(PreparedCredentialUpdate {
            expected_revision_id,
            revision,
            removed_secret_field_ids,
        })
    }

    /// Commits one previously validated credential update.
    ///
    /// The current head is rechecked immediately before writing, so a sync
    /// change between prepare and commit fails as a stale edit. Authorization
    /// may already have been conservatively revoked in that rare race.
    pub fn commit_credential_update(
        &mut self,
        prepared: PreparedCredentialUpdate,
    ) -> VaultResult<CredentialListItem> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "current-format credential editing",
            ));
        }
        let credential_id = prepared.credential_id();
        let (revisions, current) = self.target_credential_head_for_write(credential_id)?;
        if current.revision_id() != prepared.expected_revision_id {
            return Err(VaultError::InvalidVault {
                reason: "item changed on disk; refresh sync before editing".to_owned(),
            });
        }
        if current.lifecycle() != CredentialLifecycle::Active
            || prepared.revision.lifecycle() != CredentialLifecycle::Active
            || prepared.vault_id() != current.credential().vault_id()
            || prepared.revision.parent_revision_ids() != [prepared.expected_revision_id]
        {
            return Err(VaultError::InvalidVault {
                reason: "prepared credential update no longer matches the current item".to_owned(),
            });
        }
        if revisions
            .iter()
            .any(|candidate| candidate.revision_id() == prepared.revision.revision_id())
        {
            return Err(VaultError::InvalidVault {
                reason: "current vault already contains the prepared revision".to_owned(),
            });
        }

        let record = encrypt_target_credential_record(&self.vault_key, &prepared.revision)?;
        write_target_credential_record(&self.path, &record, CredentialLifecycle::Active)?;
        credential_list_item(prepared.revision, ItemStatus::Active)
    }

    /// Sets favorite state on any current-format credential without converting
    /// its extensible fields through the legacy item model.
    pub fn set_credential_favorite_with_expected_revision(
        &mut self,
        credential_id: crate::CredentialId,
        expected_revision_id: crate::RevisionId,
        favorite: bool,
    ) -> VaultResult<CredentialListItem> {
        let (revisions, current) = self.target_credential_head_for_write(credential_id)?;
        ensure_credential_expected_revision(&current, expected_revision_id)?;
        let mut draft = current.credential().draft().clone();
        draft.favorite = favorite;
        self.write_credential_descendant(&revisions, &current, draft, current.lifecycle())
    }

    /// Archives an active current-format credential while preserving every
    /// stable identity and encrypted field value.
    pub fn archive_credential_with_expected_revision(
        &mut self,
        credential_id: crate::CredentialId,
        expected_revision_id: crate::RevisionId,
    ) -> VaultResult<CredentialListItem> {
        let (revisions, current) = self.target_credential_head_for_write(credential_id)?;
        ensure_credential_expected_revision(&current, expected_revision_id)?;
        if current.lifecycle() != CredentialLifecycle::Active {
            return Err(VaultError::InvalidVault {
                reason: "only active credentials can be archived".to_owned(),
            });
        }
        self.write_credential_descendant(
            &revisions,
            &current,
            current.credential().draft().clone(),
            CredentialLifecycle::Archived,
        )
    }

    /// Restores an archived current-format credential as a new active revision.
    pub fn restore_credential(
        &mut self,
        credential_id: crate::CredentialId,
    ) -> VaultResult<CredentialListItem> {
        let (revisions, current) = self.target_credential_head_for_write(credential_id)?;
        if current.lifecycle() != CredentialLifecycle::Archived {
            return Err(VaultError::InvalidVault {
                reason: "only archived items can be restored".to_owned(),
            });
        }
        self.write_credential_descendant(
            &revisions,
            &current,
            current.credential().draft().clone(),
            CredentialLifecycle::Active,
        )
    }

    /// Deletes a current-format credential by writing an authenticated
    /// tombstone revision with the same credential and Secret Field identities.
    pub fn delete_credential_with_expected_revision(
        &mut self,
        credential_id: crate::CredentialId,
        expected_revision_id: crate::RevisionId,
    ) -> VaultResult<()> {
        let (revisions, current) = self.target_credential_head_for_write(credential_id)?;
        ensure_credential_expected_revision(&current, expected_revision_id)?;
        self.write_credential_descendant(
            &revisions,
            &current,
            current.credential().draft().clone(),
            CredentialLifecycle::Deleted,
        )
        .map(|_| ())
    }

    /// Duplicates one current-format credential under a new credential identity.
    ///
    /// Every Secret Field also receives a fresh identity, so machine
    /// authorization is never inherited by the copy.
    pub fn duplicate_credential_with_expected_revision(
        &mut self,
        credential_id: crate::CredentialId,
        expected_revision_id: crate::RevisionId,
        title: String,
    ) -> VaultResult<CredentialListItem> {
        let (revisions, current) = self.target_credential_head_for_write(credential_id)?;
        ensure_credential_expected_revision(&current, expected_revision_id)?;
        if title.trim().is_empty() {
            return Err(VaultError::InvalidVault {
                reason: "credential title must not be empty".to_owned(),
            });
        }
        let mut draft = current.credential().draft().clone();
        draft.title = title.trim().to_owned();
        let mut allocated_secret_field_ids = BTreeSet::new();
        for field in &mut draft.fields {
            let crate::CredentialFieldValue::Secret {
                secret_field_id, ..
            } = &mut field.value
            else {
                continue;
            };
            *secret_field_id = loop {
                let candidate = crate::SecretFieldId::generate();
                if allocated_secret_field_ids.insert(candidate) {
                    break candidate;
                }
            };
        }
        validate_credential_draft_for_write(&draft)?;
        let credential =
            crate::Credential::new(current.credential().vault_id(), draft).map_err(|error| {
                VaultError::InvalidVault {
                    reason: error.to_string(),
                }
            })?;
        let revision = CredentialRevision::initial(credential, crate::DeviceId::generate())
            .map_err(|error| VaultError::InvalidVault {
                reason: error.to_string(),
            })?;
        if revisions.iter().any(|candidate| {
            candidate.revision_id() == revision.revision_id()
                || candidate.credential().credential_id() == revision.credential().credential_id()
        }) {
            return Err(VaultError::InvalidVault {
                reason: "generated current-format credential identity already exists".to_owned(),
            });
        }
        let record = encrypt_target_credential_record(&self.vault_key, &revision)?;
        write_target_credential_record(&self.path, &record, CredentialLifecycle::Active)?;
        credential_list_item(revision, ItemStatus::Active)
    }

    /// Creates a new item.
    pub fn create_item(&mut self, mut draft: VaultItemDraft) -> VaultResult<ItemSummary> {
        normalize_draft(&mut draft)?;
        let item = VaultItem {
            id: self.new_item_id(),
            revision: self.new_item_revision(),
            parent_revision: None,
            status: ItemStatus::Active,
            draft,
        };
        self.save_item_revision(&item)?;
        Ok(ItemSummary::from_item(&item))
    }

    /// Updates an existing item.
    pub fn update_item(
        &mut self,
        id: &ItemId,
        mut draft: VaultItemDraft,
    ) -> VaultResult<ItemSummary> {
        normalize_draft(&mut draft)?;
        let existing = self.latest_item(id)?;
        ensure_item_not_conflicted(&existing)?;
        self.update_item_from_existing(existing, draft)
    }

    /// Updates an existing item only if its latest revision matches expectation.
    pub fn update_item_with_expected_revision(
        &mut self,
        id: &ItemId,
        expected_revision: &ItemRevision,
        mut draft: VaultItemDraft,
    ) -> VaultResult<ItemSummary> {
        normalize_draft(&mut draft)?;
        let existing = self.latest_item(id)?;
        ensure_item_not_conflicted(&existing)?;
        ensure_expected_revision(&existing, expected_revision)?;
        self.update_item_from_existing(existing, draft)
    }

    fn update_item_from_existing(
        &self,
        existing: VaultItem,
        draft: VaultItemDraft,
    ) -> VaultResult<ItemSummary> {
        let item = VaultItem {
            id: existing.id,
            revision: self.new_item_revision(),
            parent_revision: Some(existing.revision),
            status: existing.status,
            draft,
        };
        self.save_item_revision(&item)?;
        Ok(ItemSummary::from_item(&item))
    }

    /// Deletes an item by writing a tombstone.
    pub fn delete_item(&mut self, id: &ItemId) -> VaultResult<()> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        self.delete_item_from_existing(&mut item)
    }

    /// Deletes an item only if its latest revision matches expectation.
    pub fn delete_item_with_expected_revision(
        &mut self,
        id: &ItemId,
        expected_revision: &ItemRevision,
    ) -> VaultResult<()> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        ensure_expected_revision(&item, expected_revision)?;
        self.delete_item_from_existing(&mut item)
    }

    fn delete_item_from_existing(&self, item: &mut VaultItem) -> VaultResult<()> {
        item.parent_revision = Some(item.revision.clone());
        item.revision = self.new_item_revision();
        item.status = ItemStatus::Deleted;
        if self.uses_target_format() {
            return self.save_item_revision(item);
        }
        let record = encrypt_item_record(&self.vault_key, item)?;
        write_tombstone_record(&self.path, &record)
    }

    /// Archives an item by writing a new archived revision.
    pub fn archive_item(&mut self, id: &ItemId) -> VaultResult<ItemSummary> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        self.archive_item_from_existing(&mut item)
    }

    /// Archives an item only if its latest revision matches expectation.
    pub fn archive_item_with_expected_revision(
        &mut self,
        id: &ItemId,
        expected_revision: &ItemRevision,
    ) -> VaultResult<ItemSummary> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        ensure_expected_revision(&item, expected_revision)?;
        self.archive_item_from_existing(&mut item)
    }

    fn archive_item_from_existing(&self, item: &mut VaultItem) -> VaultResult<ItemSummary> {
        item.parent_revision = Some(item.revision.clone());
        item.revision = self.new_item_revision();
        item.status = ItemStatus::Archived;
        self.save_item_revision(item)?;
        Ok(ItemSummary::from_item(item))
    }

    /// Restores an archived item by writing a new active revision.
    pub fn restore_item(&mut self, id: &ItemId) -> VaultResult<ItemSummary> {
        let mut item = self.latest_item(id)?;
        if item.status != ItemStatus::Archived {
            return Err(VaultError::InvalidVault {
                reason: "only archived items can be restored".to_owned(),
            });
        }
        item.parent_revision = Some(item.revision.clone());
        item.revision = self.new_item_revision();
        item.status = ItemStatus::Active;
        self.save_item_revision(&item)?;
        Ok(ItemSummary::from_item(&item))
    }

    /// Sets an item's favorite flag by writing a new revision.
    pub fn set_favorite(&mut self, id: &ItemId, favorite: bool) -> VaultResult<ItemSummary> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        self.set_favorite_from_existing(&mut item, favorite)
    }

    /// Sets an item's favorite flag only if its latest revision matches expectation.
    pub fn set_favorite_with_expected_revision(
        &mut self,
        id: &ItemId,
        expected_revision: &ItemRevision,
        favorite: bool,
    ) -> VaultResult<ItemSummary> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        ensure_expected_revision(&item, expected_revision)?;
        self.set_favorite_from_existing(&mut item, favorite)
    }

    fn set_favorite_from_existing(
        &self,
        item: &mut VaultItem,
        favorite: bool,
    ) -> VaultResult<ItemSummary> {
        item.parent_revision = Some(item.revision.clone());
        item.revision = self.new_item_revision();
        item.draft.favorite = favorite;
        self.save_item_revision(item)?;
        Ok(ItemSummary::from_item(item))
    }

    /// Replaces an item's tags by writing a new revision.
    pub fn set_tags(&mut self, id: &ItemId, tags: Vec<String>) -> VaultResult<ItemSummary> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        self.set_tags_from_existing(&mut item, tags)
    }

    /// Replaces tags only if the latest item revision matches expectation.
    pub fn set_tags_with_expected_revision(
        &mut self,
        id: &ItemId,
        expected_revision: &ItemRevision,
        tags: Vec<String>,
    ) -> VaultResult<ItemSummary> {
        let mut item = self.latest_item(id)?;
        ensure_item_not_conflicted(&item)?;
        ensure_expected_revision(&item, expected_revision)?;
        self.set_tags_from_existing(&mut item, tags)
    }

    fn set_tags_from_existing(
        &self,
        item: &mut VaultItem,
        tags: Vec<String>,
    ) -> VaultResult<ItemSummary> {
        item.parent_revision = Some(item.revision.clone());
        item.revision = self.new_item_revision();
        item.draft.tags = tags;
        self.save_item_revision(item)?;
        Ok(ItemSummary::from_item(item))
    }

    /// Searches unlocked item metadata and content intended for search.
    pub fn search(&self, query: SearchQuery) -> VaultResult<Vec<ItemSummary>> {
        let needle = query.text.trim().to_lowercase();
        if needle.is_empty() {
            if query.include_archived {
                let mut summaries: Vec<_> = self
                    .latest_items()?
                    .into_iter()
                    .filter(|item| item.status != ItemStatus::Deleted)
                    .map(|item| ItemSummary::from_item(&item))
                    .collect();
                summaries.sort_by(|left, right| {
                    left.title
                        .to_lowercase()
                        .cmp(&right.title.to_lowercase())
                        .then_with(|| left.id.cmp(&right.id))
                });
                return Ok(summaries);
            }
            return self.list_items();
        }

        let mut summaries: Vec<_> = self
            .latest_items()?
            .into_iter()
            .filter(|item| {
                query.include_archived
                    || matches!(item.status, ItemStatus::Active | ItemStatus::Conflicted(_))
            })
            .filter(|item| item.status != ItemStatus::Deleted)
            .filter(|item| item_matches_query(item, &needle))
            .map(|item| ItemSummary::from_item(&item))
            .collect();
        summaries.sort_by(|left, right| {
            left.title
                .to_lowercase()
                .cmp(&right.title.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(summaries)
    }

    /// Generates a TOTP code for a login item at the current system time.
    pub fn totp_code(&self, id: &ItemId) -> VaultResult<TotpCode> {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| VaultError::InvalidVault {
                reason: format!("system clock before unix epoch: {error}"),
            })?
            .as_secs();
        self.totp_code_at(id, unix_time)
    }

    /// Generates a TOTP code for a login item at a specific Unix timestamp.
    pub fn totp_code_at(&self, id: &ItemId, unix_time: u64) -> VaultResult<TotpCode> {
        let item = self.latest_item(id)?;
        let VaultItemContent::Login(login) = item.draft.content else {
            return Err(VaultError::InvalidVault {
                reason: "TOTP is only available for login items".to_owned(),
            });
        };
        let Some(secret) = login.totp_secret else {
            return Err(VaultError::InvalidVault {
                reason: "login item has no TOTP secret".to_owned(),
            });
        };
        generate_totp_code(&secret, unix_time, 6, 30)
    }

    /// Reloads encrypted records that changed on disk.
    pub fn refresh_from_disk(&mut self) -> VaultResult<SyncRefreshReport> {
        validate_required_structure(&self.path)?;
        if self.uses_target_format() {
            let (revisions, report) = self.load_target_revisions_with_report()?;
            if report.rejected_records != 0 {
                return Ok(report);
            }

            let merged_revisions = plan_automatic_target_merges(&revisions)?;
            if merged_revisions.is_empty() {
                return Ok(report);
            }
            for revision in merged_revisions {
                let lifecycle = revision.lifecycle();
                let record = encrypt_target_credential_record(&self.vault_key, &revision)?;
                write_target_credential_record(&self.path, &record, lifecycle)?;
            }
            return self
                .load_target_revisions_with_report()
                .map(|(_, report)| report);
        }
        Ok(self.load_candidate_items()?.report)
    }

    /// Moves rejected encrypted sync records into a vault-local quarantine batch.
    pub fn quarantine_rejected_records(&mut self) -> VaultResult<SyncQuarantineReport> {
        if self.uses_target_format() {
            return self.quarantine_rejected_target_records();
        }
        self.ensure_legacy_write_format()?;
        let batch_dir = self
            .path
            .join(QUARANTINE_DIR_NAME)
            .join(format!("rejected_{}", new_revision()));
        let mut report = SyncQuarantineReport::default();
        quarantine_rejected_records_from_dir(
            &self.path.join(ITEMS_DIR_NAME),
            &batch_dir.join(ITEMS_DIR_NAME),
            &self.vault_key,
            QuarantineRecordKind::Item,
            &mut report,
        )?;
        quarantine_rejected_records_from_dir(
            &self.path.join(TOMBSTONES_DIR_NAME),
            &batch_dir.join(TOMBSTONES_DIR_NAME),
            &self.vault_key,
            QuarantineRecordKind::Tombstone,
            &mut report,
        )?;
        Ok(report)
    }

    fn quarantine_rejected_target_records(&self) -> VaultResult<SyncQuarantineReport> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "current vault metadata is missing its stable identity".to_owned(),
            })?;
        let item_records = load_target_records_from_dir(
            &self.path.join(ITEMS_DIR_NAME),
            &self.vault_key,
            vault_id,
            TargetRecordDirectory::Items,
        )?;
        let tombstone_records = load_target_records_from_dir(
            &self.path.join(TOMBSTONES_DIR_NAME),
            &self.vault_key,
            vault_id,
            TargetRecordDirectory::Tombstones,
        )?;
        let mut report = SyncQuarantineReport::default();
        if item_records.rejected_files.is_empty() && tombstone_records.rejected_files.is_empty() {
            return Ok(report);
        }

        let batch_dir = self
            .path
            .join(QUARANTINE_DIR_NAME)
            .join(format!("rejected_{}", new_revision()));
        move_rejected_target_files(
            &self.path.join(ITEMS_DIR_NAME),
            &batch_dir.join(ITEMS_DIR_NAME),
            item_records.rejected_files,
            &mut report.moved_item_records,
        )?;
        move_rejected_target_files(
            &self.path.join(TOMBSTONES_DIR_NAME),
            &batch_dir.join(TOMBSTONES_DIR_NAME),
            tombstone_records.rejected_files,
            &mut report.moved_tombstone_records,
        )?;
        report.moved_records = report.moved_item_records + report.moved_tombstone_records;
        Ok(report)
    }

    /// Resolves a detected conflict by keeping or writing a selected item version.
    pub fn resolve_conflict(&mut self, conflict_id: &ConflictId) -> VaultResult<ItemSummary> {
        let candidate = self
            .conflict_candidate_items(conflict_id)?
            .into_iter()
            .max_by(|left, right| left.revision.cmp(&right.revision))
            .ok_or_else(|| VaultError::ItemNotFound {
                id: conflict_id.0.clone(),
            })?;
        self.resolve_conflict_with_item(candidate)
    }

    /// Returns candidate summaries for a detected conflict.
    pub fn conflict_candidates(
        &self,
        conflict_id: &ConflictId,
    ) -> VaultResult<Vec<ConflictCandidateSummary>> {
        if self.uses_target_format() {
            let candidate_revisions = self.target_conflict_head_revisions(conflict_id)?;
            let legacy_candidates = target_conflict_legacy_candidates(&candidate_revisions);
            let mut candidates = candidate_revisions
                .iter()
                .cloned()
                .map(|revision| {
                    ConflictCandidateSummary::from_target_candidate_group(
                        revision,
                        &candidate_revisions,
                        legacy_candidates.as_deref(),
                    )
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                right
                    .revision
                    .cmp(&left.revision)
                    .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
            });
            return Ok(candidates);
        }

        let candidate_items = self.conflict_candidate_items(conflict_id)?;
        let mut candidates: Vec<_> = candidate_items
            .iter()
            .cloned()
            .map(|item| ConflictCandidateSummary::from_candidate_group(item, &candidate_items))
            .collect();
        candidates.sort_by(|left, right| {
            right
                .revision
                .cmp(&left.revision)
                .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
        });
        Ok(candidates)
    }

    /// Resolves a detected conflict by keeping the selected candidate revision.
    pub fn resolve_conflict_candidate(
        &mut self,
        conflict_id: &ConflictId,
        selected_revision: &ItemRevision,
    ) -> VaultResult<ItemSummary> {
        let candidate = self
            .conflict_candidate_items(conflict_id)?
            .into_iter()
            .find(|item| &item.revision == selected_revision)
            .ok_or_else(|| VaultError::ItemNotFound {
                id: selected_revision.0.clone(),
            })?;
        self.resolve_conflict_with_item(candidate)
    }

    /// Resolves a current-format conflict by appending a descendant that keeps
    /// one complete typed credential revision.
    pub fn resolve_credential_conflict_candidate(
        &mut self,
        conflict_id: &ConflictId,
        selected_revision: &ItemRevision,
    ) -> VaultResult<CredentialListItem> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "current-format credential conflict resolution",
            ));
        }
        let selected_revision = parse_target_revision_id(selected_revision)?;
        let heads = self.target_conflict_head_revisions(conflict_id)?;
        self.resolve_target_conflict_head(heads, selected_revision)
    }

    /// Resolves a detected conflict by merging explicitly safe fields from selected candidates.
    pub fn resolve_conflict_merge(
        &mut self,
        request: ConflictMergeRequest,
    ) -> VaultResult<ItemSummary> {
        let candidates = self.conflict_candidate_items(&request.conflict_id)?;
        let mut resolved = candidates
            .iter()
            .find(|item| item.revision == request.base_revision)
            .cloned()
            .ok_or_else(|| VaultError::ItemNotFound {
                id: request.base_revision.0.clone(),
            })?;

        for selection in request.field_selections {
            let source = candidates
                .iter()
                .find(|item| item.revision == selection.revision)
                .ok_or_else(|| VaultError::ItemNotFound {
                    id: selection.revision.0.clone(),
                })?;
            apply_safe_conflict_field(&mut resolved, source, &selection.field_label)?;
        }

        self.resolve_conflict_with_item(resolved)
    }

    fn resolve_conflict_with_item(&self, mut resolved: VaultItem) -> VaultResult<ItemSummary> {
        resolved.parent_revision = Some(resolved.revision);
        resolved.revision = self.new_item_revision();
        resolved.status = ItemStatus::Active;
        if self.uses_target_format() {
            let credential_id = parse_target_credential_id(&resolved.id)?;
            let parents = self
                .target_head_revisions()?
                .into_iter()
                .filter(|revision| revision.credential().credential_id() == credential_id)
                .map(|revision| revision.revision_id())
                .collect::<Vec<_>>();
            if parents.len() < 2 {
                return Err(VaultError::ItemNotFound {
                    id: resolved.id.0.clone(),
                });
            }
            self.save_target_item_revision(&resolved, Some(parents))?;
        } else {
            self.save_item_revision(&resolved)?;
        }
        Ok(ItemSummary::from_item(&resolved))
    }

    /// Builds an import preview for a supported export file.
    pub fn preview_import(&self, request: ImportPreviewRequest) -> VaultResult<ImportPreview> {
        let parsed = parse_import_file(&request.source_path, &request.source_format)?;
        let duplicate_records = self.count_duplicates(&parsed.drafts)?;
        Ok(ImportPreview {
            importable_records: parsed.drafts.len(),
            skipped_records: parsed.skipped_records,
            duplicate_records,
            warnings: parsed.warnings,
        })
    }

    /// Commits a previously previewed import into the vault.
    pub fn commit_import(&mut self, request: ImportCommitRequest) -> VaultResult<ImportPreview> {
        let parsed = parse_import_file(&request.source_path, &request.source_format)?;
        let existing_keys = self.duplicate_keys()?;
        let mut imported = 0;
        let mut duplicate_records = 0;
        let mut skipped_records = parsed.skipped_records;
        for draft in parsed.drafts {
            let duplicate = existing_keys.contains(&duplicate_key(&draft));
            if duplicate {
                duplicate_records += 1;
                if !request.keep_duplicates {
                    skipped_records += 1;
                    continue;
                }
            }
            if self.uses_target_format() {
                self.create_credential(draft)?;
            } else {
                let legacy_draft =
                    VaultItemDraft::try_from(draft).map_err(|error| VaultError::InvalidVault {
                        reason: format!(
                            "imported credential cannot be written to v1 vault: {error}"
                        ),
                    })?;
                self.create_item(legacy_draft)?;
            }
            imported += 1;
        }
        Ok(ImportPreview {
            importable_records: imported,
            skipped_records,
            duplicate_records,
            warnings: parsed.warnings,
        })
    }

    /// Reauthenticates and exports supported non-deleted vault items to a plaintext file.
    pub fn export_items(&self, request: ExportItemsRequest) -> VaultResult<ExportResult> {
        let reauthenticated_vault_key =
            unlock_vault_key(&self.path, &request.current_master_password)?;
        if reauthenticated_vault_key != self.vault_key {
            return Err(VaultError::InvalidCredentials);
        }
        let snapshot = self.export_snapshot()?;
        export_credentials_to_file(&request.destination_path, &request.export_format, snapshot)
    }

    /// Computes a local, non-secret password health audit for login items.
    pub fn password_health_audit(&self) -> VaultResult<PasswordHealthAudit> {
        let items = self
            .latest_items()?
            .into_iter()
            .filter(|item| item.status != ItemStatus::Deleted)
            .collect::<Vec<_>>();
        let mut checked = Vec::<(&VaultItem, &SecretBytes)>::new();
        let mut password_groups = BTreeMap::<Vec<u8>, Vec<usize>>::new();

        for item in &items {
            let VaultItemContent::Login(login) = &item.draft.content else {
                continue;
            };
            let Some(password) = &login.password else {
                continue;
            };
            if password.expose().is_empty() {
                continue;
            }
            let index = checked.len();
            checked.push((item, password));
            password_groups
                .entry(password.expose().to_vec())
                .or_default()
                .push(index);
        }

        let mut issues = Vec::new();
        let mut weak_passwords = 0;
        let mut reused_passwords = 0;

        for (item, password) in &checked {
            let VaultItemContent::Login(login) = &item.draft.content else {
                continue;
            };
            if password_is_weak(
                password.expose(),
                &item.draft.title,
                login.username.as_deref(),
            ) {
                weak_passwords += 1;
                issues.push(PasswordHealthIssue {
                    item_id: item.id.clone(),
                    title: item.draft.title.clone(),
                    kind: PasswordHealthIssueKind::WeakPassword,
                    reuse_group_size: None,
                });
            }
        }

        for group in password_groups.values().filter(|group| group.len() > 1) {
            reused_passwords += group.len();
            for index in group {
                let item = checked[*index].0;
                issues.push(PasswordHealthIssue {
                    item_id: item.id.clone(),
                    title: item.draft.title.clone(),
                    kind: PasswordHealthIssueKind::ReusedPassword,
                    reuse_group_size: Some(group.len()),
                });
            }
        }

        Ok(PasswordHealthAudit {
            checked_login_passwords: checked.len(),
            weak_passwords,
            reused_passwords,
            issues,
        })
    }

    fn latest_items(&self) -> VaultResult<Vec<VaultItem>> {
        let candidates = self.candidate_items()?;
        let conflicts = detect_conflicts(&candidates)?;
        let mut latest = BTreeMap::<ItemId, VaultItem>::new();
        for item in leaf_items(&candidates) {
            latest
                .entry(item.id.clone())
                .and_modify(|existing| {
                    if existing.revision < item.revision {
                        *existing = item.clone();
                    }
                })
                .or_insert(item);
        }
        for (id, conflict_id) in conflicts {
            if let Some(item) = latest.get_mut(&id) {
                item.status = ItemStatus::Conflicted(conflict_id);
            }
        }
        Ok(latest.into_values().collect())
    }

    fn candidate_items(&self) -> VaultResult<Vec<VaultItem>> {
        Ok(self.load_candidate_items()?.items)
    }

    fn load_candidate_items(&self) -> VaultResult<CandidateLoad> {
        if self.uses_target_format() {
            return self.load_target_candidate_items();
        }
        let item_records = load_item_records(&self.path)?;
        let tombstone_records = load_tombstone_records(&self.path)?;
        let mut report = SyncRefreshReport {
            rejected_records: item_records.rejected_records + tombstone_records.rejected_records,
            rejected_item_records: item_records.rejected_records,
            rejected_tombstone_records: tombstone_records.rejected_records,
            rejected_record_files: rejected_record_file_summaries(
                RejectedSyncRecordKind::Item,
                item_records.rejected_record_files,
            )
            .into_iter()
            .chain(rejected_record_file_summaries(
                RejectedSyncRecordKind::Tombstone,
                tombstone_records.rejected_record_files,
            ))
            .collect(),
            ..SyncRefreshReport::default()
        };
        let mut items = Vec::new();
        for loaded in item_records.records {
            match decrypt_item_record(&self.vault_key, &loaded.record) {
                Ok(item) => {
                    report.loaded_items += 1;
                    if item.status != ItemStatus::Deleted {
                        items.push(item);
                    }
                }
                Err(_) => {
                    report.rejected_records += 1;
                    report.rejected_item_records += 1;
                    report.rejected_record_files.push(RejectedSyncRecordFile {
                        kind: RejectedSyncRecordKind::Item,
                        file_name: loaded.file_name,
                    });
                }
            }
        }
        let mut tombstones = BTreeMap::<ItemId, ItemRevision>::new();
        for loaded in tombstone_records.records {
            match decrypt_item_record(&self.vault_key, &loaded.record) {
                Ok(tombstone) => {
                    if tombstone.status != ItemStatus::Deleted {
                        continue;
                    }
                    report.applied_tombstones += 1;
                    tombstones
                        .entry(tombstone.id)
                        .and_modify(|revision| {
                            if *revision < tombstone.revision {
                                *revision = tombstone.revision.clone();
                            }
                        })
                        .or_insert(tombstone.revision);
                }
                Err(_) => {
                    report.rejected_records += 1;
                    report.rejected_tombstone_records += 1;
                    report.rejected_record_files.push(RejectedSyncRecordFile {
                        kind: RejectedSyncRecordKind::Tombstone,
                        file_name: loaded.file_name,
                    });
                }
            }
        }
        items.retain(|item| {
            tombstones
                .get(&item.id)
                .is_none_or(|deleted_revision| deleted_revision < &item.revision)
        });
        report.detected_conflicts = detect_conflicts(&items)?.len();
        Ok(CandidateLoad { items, report })
    }

    fn load_target_candidate_items(&self) -> VaultResult<CandidateLoad> {
        let (revisions, mut report) = self.load_target_revisions_with_report()?;

        let heads = target_head_revisions(revisions);
        let mut head_counts = BTreeMap::<crate::CredentialId, usize>::new();
        for revision in &heads {
            *head_counts
                .entry(revision.credential().credential_id())
                .or_default() += 1;
        }

        let mut items = Vec::new();
        for revision in heads {
            if revision.lifecycle() == CredentialLifecycle::Deleted {
                continue;
            }
            let credential_id = revision.credential().credential_id();
            let mut item = target_revision_to_legacy_item(revision, TargetRecordDirectory::Items)?;
            if head_counts.get(&credential_id).copied().unwrap_or_default() > 1 {
                item.status = ItemStatus::Conflicted(ConflictId(format!("conflict_{}", item.id.0)));
            }
            items.push(item);
        }
        report.detected_conflicts = head_counts.values().filter(|count| **count > 1).count();
        Ok(CandidateLoad { items, report })
    }

    fn load_target_revisions_with_report(
        &self,
    ) -> VaultResult<(Vec<CredentialRevision>, SyncRefreshReport)> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "target vault metadata is missing its stable identity".to_owned(),
            })?;
        let item_records = load_target_records_from_dir(
            &self.path.join(ITEMS_DIR_NAME),
            &self.vault_key,
            vault_id,
            TargetRecordDirectory::Items,
        )?;
        let tombstone_records = load_target_records_from_dir(
            &self.path.join(TOMBSTONES_DIR_NAME),
            &self.vault_key,
            vault_id,
            TargetRecordDirectory::Tombstones,
        )?;
        let mut report = SyncRefreshReport {
            loaded_items: item_records.revisions.len(),
            applied_tombstones: tombstone_records.revisions.len(),
            rejected_records: item_records.rejected_files.len()
                + tombstone_records.rejected_files.len(),
            rejected_item_records: item_records.rejected_files.len(),
            rejected_tombstone_records: tombstone_records.rejected_files.len(),
            rejected_record_files: rejected_record_file_summaries(
                RejectedSyncRecordKind::Item,
                item_records.rejected_files,
            )
            .into_iter()
            .chain(rejected_record_file_summaries(
                RejectedSyncRecordKind::Tombstone,
                tombstone_records.rejected_files,
            ))
            .collect(),
            ..SyncRefreshReport::default()
        };
        let mut revisions = item_records.revisions;
        revisions.extend(tombstone_records.revisions);
        validate_target_revision_graph(&revisions)?;

        let mut head_counts = BTreeMap::<crate::CredentialId, usize>::new();
        for revision in target_head_revisions(revisions.clone()) {
            *head_counts
                .entry(revision.credential().credential_id())
                .or_default() += 1;
        }
        report.detected_conflicts = head_counts.values().filter(|count| **count > 1).count();
        Ok((revisions, report))
    }

    fn uses_target_format(&self) -> bool {
        (
            self.metadata.vault_format_version,
            self.metadata.record_format_version,
        ) == (TARGET_VAULT_FORMAT_VERSION, TARGET_RECORD_FORMAT_VERSION)
    }

    fn new_item_id(&self) -> ItemId {
        if self.uses_target_format() {
            ItemId(crate::CredentialId::generate().to_string())
        } else {
            ItemId(random_id("item"))
        }
    }

    fn new_item_revision(&self) -> ItemRevision {
        if self.uses_target_format() {
            ItemRevision(crate::RevisionId::generate().to_string())
        } else {
            ItemRevision(new_revision())
        }
    }

    fn target_revisions(&self) -> VaultResult<Vec<CredentialRevision>> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "current vault metadata is missing its stable identity".to_owned(),
            })?;
        let item_records = load_target_records_from_dir(
            &self.path.join(ITEMS_DIR_NAME),
            &self.vault_key,
            vault_id,
            TargetRecordDirectory::Items,
        )?;
        let tombstone_records = load_target_records_from_dir(
            &self.path.join(TOMBSTONES_DIR_NAME),
            &self.vault_key,
            vault_id,
            TargetRecordDirectory::Tombstones,
        )?;
        if !item_records.rejected_files.is_empty() || !tombstone_records.rejected_files.is_empty() {
            return Err(VaultError::InvalidVault {
                reason: "current vault contains rejected records; repair or quarantine them before writing"
                    .to_owned(),
            });
        }
        let mut revisions = item_records.revisions;
        revisions.extend(tombstone_records.revisions);
        validate_target_revision_graph(&revisions)?;
        Ok(revisions)
    }

    fn target_credential_head_for_write(
        &self,
        credential_id: crate::CredentialId,
    ) -> VaultResult<(Vec<CredentialRevision>, CredentialRevision)> {
        let revisions = self.target_revisions()?;
        let mut matches = target_head_revisions(revisions.clone())
            .into_iter()
            .filter(|revision| revision.credential().credential_id() == credential_id);
        let Some(current) = matches.next() else {
            return Err(VaultError::ItemNotFound {
                id: credential_id.to_string(),
            });
        };
        if matches.next().is_some() {
            return Err(VaultError::InvalidVault {
                reason: "conflicted items must be resolved before ordinary item changes".to_owned(),
            });
        }
        if current.lifecycle() == CredentialLifecycle::Deleted {
            return Err(VaultError::ItemNotFound {
                id: credential_id.to_string(),
            });
        }
        Ok((revisions, current))
    }

    fn write_credential_descendant(
        &self,
        revisions: &[CredentialRevision],
        current: &CredentialRevision,
        draft: crate::CredentialDraft,
        lifecycle: CredentialLifecycle,
    ) -> VaultResult<CredentialListItem> {
        validate_credential_draft_for_write(&draft)?;
        let credential = crate::Credential::with_id(
            current.credential().vault_id(),
            current.credential().credential_id(),
            draft,
        )
        .map_err(|error| VaultError::InvalidVault {
            reason: error.to_string(),
        })?;
        let revision = CredentialRevision::descendant_with_lifecycle(
            credential,
            crate::DeviceId::generate(),
            vec![current.revision_id()],
            lifecycle,
        )
        .map_err(|error| VaultError::InvalidVault {
            reason: error.to_string(),
        })?;
        if revisions
            .iter()
            .any(|candidate| candidate.revision_id() == revision.revision_id())
        {
            return Err(VaultError::InvalidVault {
                reason: "generated current-format revision identity already exists".to_owned(),
            });
        }
        let record = encrypt_target_credential_record(&self.vault_key, &revision)?;
        write_target_credential_record(&self.path, &record, lifecycle)?;
        let status = match lifecycle {
            CredentialLifecycle::Active => ItemStatus::Active,
            CredentialLifecycle::Archived => ItemStatus::Archived,
            CredentialLifecycle::Deleted => ItemStatus::Deleted,
        };
        credential_list_item(revision, status)
    }

    fn target_head_revisions(&self) -> VaultResult<Vec<CredentialRevision>> {
        Ok(target_head_revisions(self.target_revisions()?))
    }

    fn target_conflict_head_revisions(
        &self,
        conflict_id: &ConflictId,
    ) -> VaultResult<Vec<CredentialRevision>> {
        let credential_id = parse_target_conflict_credential_id(conflict_id)?;
        let mut heads = self
            .target_head_revisions()?
            .into_iter()
            .filter(|revision| revision.credential().credential_id() == credential_id)
            .collect::<Vec<_>>();
        if heads.len() < 2 {
            return Err(VaultError::ItemNotFound {
                id: conflict_id.0.clone(),
            });
        }
        heads.sort_by_key(CredentialRevision::revision_id);
        Ok(heads)
    }

    fn resolve_target_conflict_head(
        &self,
        heads: Vec<CredentialRevision>,
        selected_revision: crate::RevisionId,
    ) -> VaultResult<CredentialListItem> {
        let selected = heads
            .iter()
            .find(|revision| revision.revision_id() == selected_revision)
            .ok_or_else(|| VaultError::ItemNotFound {
                id: selected_revision.to_string(),
            })?;
        let parents = heads
            .iter()
            .map(CredentialRevision::revision_id)
            .collect::<Vec<_>>();
        let resolved = CredentialRevision::descendant_with_lifecycle(
            selected.credential().clone(),
            crate::DeviceId::generate(),
            parents,
            selected.lifecycle(),
        )
        .map_err(|error| VaultError::InvalidVault {
            reason: error.to_string(),
        })?;
        if self
            .target_revisions()?
            .iter()
            .any(|revision| revision.revision_id() == resolved.revision_id())
        {
            return Err(VaultError::InvalidVault {
                reason: "generated conflict resolution revision identity already exists".to_owned(),
            });
        }
        let record = encrypt_target_credential_record(&self.vault_key, &resolved)?;
        write_target_credential_record(&self.path, &record, resolved.lifecycle())?;
        let status = match resolved.lifecycle() {
            CredentialLifecycle::Active => ItemStatus::Active,
            CredentialLifecycle::Archived => ItemStatus::Archived,
            CredentialLifecycle::Deleted => ItemStatus::Deleted,
        };
        credential_list_item(resolved, status)
    }

    fn active_credential_revision(
        &self,
        credential_id: crate::CredentialId,
    ) -> VaultResult<Option<CredentialRevision>> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "stable current-format credential lookup",
            ));
        }
        let mut matches = self
            .target_head_revisions()?
            .into_iter()
            .filter(|revision| revision.credential().credential_id() == credential_id);
        let Some(revision) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(VaultError::InvalidVault {
                reason: "credential has multiple current revisions".to_owned(),
            });
        }
        if revision.lifecycle() != CredentialLifecycle::Active {
            return Ok(None);
        }
        Ok(Some(revision))
    }

    fn active_credential_head_revisions(&self) -> VaultResult<Vec<CredentialRevision>> {
        let mut heads_by_credential = BTreeMap::new();
        for revision in self.target_head_revisions()? {
            heads_by_credential
                .entry(revision.credential().credential_id())
                .or_insert_with(Vec::new)
                .push(revision);
        }

        let mut active = Vec::new();
        for (_, mut heads) in heads_by_credential {
            if heads.len() != 1 {
                continue;
            }
            let revision = heads.pop().ok_or_else(|| VaultError::InvalidVault {
                reason: "credential head set changed while listing summaries".to_owned(),
            })?;
            if revision.lifecycle() == CredentialLifecycle::Active {
                active.push(revision);
            }
        }
        Ok(active)
    }

    fn credential_items_matching(
        &self,
        needle: Option<&str>,
        include_archived: bool,
    ) -> VaultResult<Vec<CredentialListItem>> {
        if !self.uses_target_format() {
            return Err(VaultError::not_implemented(
                "current-format credential listing",
            ));
        }
        let (revisions, _) = self.load_target_revisions_with_report()?;
        let mut heads_by_credential =
            BTreeMap::<crate::CredentialId, Vec<CredentialRevision>>::new();
        for revision in target_head_revisions(revisions) {
            heads_by_credential
                .entry(revision.credential().credential_id())
                .or_default()
                .push(revision);
        }

        let mut items = Vec::new();
        for (credential_id, mut heads) in heads_by_credential {
            heads.sort_by_key(CredentialRevision::revision_id);
            let is_conflicted = heads.len() > 1;
            let query_matches = needle.is_none_or(|needle| {
                heads
                    .iter()
                    .filter(|revision| revision.lifecycle() != CredentialLifecycle::Deleted)
                    .any(|revision| credential_matches_query(revision.credential(), needle))
            });
            if !query_matches {
                continue;
            }

            let Some(representative) = heads
                .into_iter()
                .rev()
                .find(|revision| revision.lifecycle() != CredentialLifecycle::Deleted)
            else {
                continue;
            };
            let status = if is_conflicted {
                ItemStatus::Conflicted(ConflictId(format!("conflict_{credential_id}")))
            } else {
                match representative.lifecycle() {
                    CredentialLifecycle::Active => ItemStatus::Active,
                    CredentialLifecycle::Archived => ItemStatus::Archived,
                    CredentialLifecycle::Deleted => continue,
                }
            };
            if status == ItemStatus::Archived && !include_archived {
                continue;
            }
            items.push(credential_list_item(representative, status)?);
        }
        items.sort_by(|left, right| {
            left.credential
                .title
                .to_lowercase()
                .cmp(&right.credential.title.to_lowercase())
                .then_with(|| {
                    left.credential
                        .credential_id
                        .cmp(&right.credential.credential_id)
                })
        });
        Ok(items)
    }

    fn save_target_item_revision(
        &self,
        item: &VaultItem,
        explicit_parents: Option<Vec<crate::RevisionId>>,
    ) -> VaultResult<()> {
        let vault_id = self
            .metadata
            .vault_id
            .ok_or_else(|| VaultError::InvalidVault {
                reason: "current vault metadata is missing its stable identity".to_owned(),
            })?;
        let credential_id = parse_target_credential_id(&item.id)?;
        let revision_id = parse_target_revision_id(&item.revision)?;
        let revisions = self.target_revisions()?;
        if revisions
            .iter()
            .any(|revision| revision.revision_id() == revision_id)
        {
            return Err(VaultError::InvalidVault {
                reason: "current vault already contains the requested revision identity".to_owned(),
            });
        }

        let mut parent_revision_ids = match explicit_parents {
            Some(parents) => parents,
            None => item
                .parent_revision
                .as_ref()
                .map(parse_target_revision_id)
                .transpose()?
                .into_iter()
                .collect(),
        };
        parent_revision_ids.sort_unstable();
        if parent_revision_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(VaultError::InvalidVault {
                reason: "current revision parents must be unique".to_owned(),
            });
        }

        let preferred_parent_id = item
            .parent_revision
            .as_ref()
            .map(parse_target_revision_id)
            .transpose()?;
        let mut parent_revisions = Vec::with_capacity(parent_revision_ids.len());
        for parent_revision_id in &parent_revision_ids {
            let parent = revisions
                .iter()
                .find(|revision| revision.revision_id() == *parent_revision_id)
                .ok_or_else(|| VaultError::InvalidVault {
                    reason: "current revision parent is not available in this vault".to_owned(),
                })?;
            if parent.credential().credential_id() != credential_id {
                return Err(VaultError::InvalidVault {
                    reason: "current revision parent belongs to another credential".to_owned(),
                });
            }
            parent_revisions.push(parent);
        }
        if parent_revision_ids.is_empty()
            && revisions
                .iter()
                .any(|revision| revision.credential().credential_id() == credential_id)
        {
            return Err(VaultError::InvalidVault {
                reason: "current credential identity already exists".to_owned(),
            });
        }

        let previous_draft = preferred_parent_id
            .and_then(|preferred| {
                parent_revisions
                    .iter()
                    .find(|revision| revision.revision_id() == preferred)
                    .copied()
            })
            .or_else(|| parent_revisions.first().copied())
            .map(|revision| revision.credential().draft());
        let draft = credential_draft_preserving_secret_ids(item.draft.clone(), previous_draft);
        let credential =
            crate::Credential::with_id(vault_id, credential_id, draft).map_err(|error| {
                VaultError::InvalidVault {
                    reason: error.to_string(),
                }
            })?;
        let lifecycle = match item.status {
            ItemStatus::Active => CredentialLifecycle::Active,
            ItemStatus::Archived => CredentialLifecycle::Archived,
            ItemStatus::Deleted => CredentialLifecycle::Deleted,
            ItemStatus::Conflicted(_) => {
                return Err(VaultError::InvalidVault {
                    reason: "derived conflict status cannot be persisted".to_owned(),
                })
            }
        };
        let revision = CredentialRevision::with_metadata_and_lifecycle(
            revision_id,
            parent_revision_ids,
            ContentDigest::for_credential(&credential),
            crate::DeviceId::generate(),
            lifecycle,
            credential,
        )
        .map_err(|error| VaultError::InvalidVault {
            reason: error.to_string(),
        })?;
        let record = encrypt_target_credential_record(&self.vault_key, &revision)?;
        write_target_credential_record(&self.path, &record, lifecycle)
    }

    fn ensure_legacy_write_format(&self) -> VaultResult<()> {
        if (
            self.metadata.vault_format_version,
            self.metadata.record_format_version,
        ) != (SOURCE_VAULT_FORMAT_VERSION, SOURCE_RECORD_FORMAT_VERSION)
        {
            return Err(VaultError::InvalidVault {
                reason: "vault format cannot use the legacy record writer".to_owned(),
            });
        }
        Ok(())
    }

    fn detected_conflicts(&self) -> VaultResult<BTreeMap<ItemId, ConflictId>> {
        let candidates = self.candidate_items()?;
        if self.uses_target_format() {
            return Ok(candidates
                .into_iter()
                .filter_map(|item| match item.status {
                    ItemStatus::Conflicted(conflict_id) => Some((item.id, conflict_id)),
                    _ => None,
                })
                .collect());
        }
        detect_conflicts(&candidates)
    }

    fn conflict_candidate_items(&self, conflict_id: &ConflictId) -> VaultResult<Vec<VaultItem>> {
        let id = conflict_item_id(conflict_id)?;
        let conflicts = self.detected_conflicts()?;
        if conflicts.get(&id) != Some(conflict_id) {
            return Err(VaultError::ItemNotFound {
                id: conflict_id.0.clone(),
            });
        }
        let item_candidates = self
            .candidate_items()?
            .into_iter()
            .filter(|item| item.id == id)
            .collect::<Vec<_>>();
        if self.uses_target_format() {
            if item_candidates.len() < 2 {
                return Err(VaultError::ItemNotFound {
                    id: conflict_id.0.clone(),
                });
            }
            return Ok(item_candidates);
        }
        let conflicting_revisions = conflicting_revisions(&item_candidates);
        let candidates = item_candidates
            .into_iter()
            .filter(|item| conflicting_revisions.contains(&item.revision))
            .collect::<Vec<_>>();
        if candidates.len() < 2 {
            return Err(VaultError::ItemNotFound {
                id: conflict_id.0.clone(),
            });
        }
        Ok(candidates)
    }

    fn count_duplicates(&self, drafts: &[CredentialDraft]) -> VaultResult<usize> {
        let existing = self.duplicate_keys()?;
        Ok(drafts
            .iter()
            .filter(|draft| existing.contains(&duplicate_key(draft)))
            .count())
    }

    fn duplicate_keys(&self) -> VaultResult<BTreeSet<String>> {
        if self.uses_target_format() {
            let (revisions, _) = self.load_target_revisions_with_report()?;
            return Ok(target_head_revisions(revisions)
                .into_iter()
                .filter(|revision| revision.lifecycle() != CredentialLifecycle::Deleted)
                .map(|revision| duplicate_key(revision.credential().draft()))
                .collect());
        }

        Ok(self
            .latest_items()?
            .into_iter()
            .filter(|item| item.status != ItemStatus::Deleted)
            .map(|item| duplicate_key(&CredentialDraft::from(item.draft)))
            .collect())
    }

    fn export_snapshot(&self) -> VaultResult<ExportSnapshot> {
        let mut snapshot = ExportSnapshot {
            source_vault_id: self.metadata.vault_id,
            ..ExportSnapshot::default()
        };
        if self.uses_target_format() {
            let (revisions, report) = self.load_target_revisions_with_report()?;
            snapshot.add_omission(
                ExportOmissionReason::RejectedRecord,
                report.rejected_records,
            );
            let mut heads_by_credential =
                BTreeMap::<crate::CredentialId, Vec<CredentialRevision>>::new();
            for revision in target_head_revisions(revisions) {
                heads_by_credential
                    .entry(revision.credential().credential_id())
                    .or_default()
                    .push(revision);
            }
            for (credential_id, mut heads) in heads_by_credential {
                if heads
                    .iter()
                    .all(|revision| revision.lifecycle() == CredentialLifecycle::Deleted)
                {
                    continue;
                }
                if heads.len() != 1 {
                    snapshot.add_omission(ExportOmissionReason::ConflictedCredential, 1);
                    continue;
                }
                let revision = heads.pop().ok_or_else(|| VaultError::InvalidVault {
                    reason: "credential export head set changed while building snapshot".to_owned(),
                })?;
                if revision.lifecycle() == CredentialLifecycle::Deleted {
                    continue;
                }
                snapshot.credentials.push(ExportCredential {
                    source_credential_id: Some(credential_id),
                    lifecycle: revision.lifecycle(),
                    draft: revision.credential().draft().clone(),
                });
            }
        } else {
            for item in self.latest_items()? {
                let lifecycle = match item.status {
                    ItemStatus::Active => CredentialLifecycle::Active,
                    ItemStatus::Archived => CredentialLifecycle::Archived,
                    ItemStatus::Deleted => continue,
                    ItemStatus::Conflicted(_) => {
                        snapshot.add_omission(ExportOmissionReason::ConflictedCredential, 1);
                        continue;
                    }
                };
                snapshot.credentials.push(ExportCredential {
                    source_credential_id: None,
                    lifecycle,
                    draft: CredentialDraft::from(item.draft),
                });
            }
        }
        snapshot.credentials.sort_by(|left, right| {
            left.draft
                .title
                .to_lowercase()
                .cmp(&right.draft.title.to_lowercase())
                .then_with(|| left.source_credential_id.cmp(&right.source_credential_id))
        });
        Ok(snapshot)
    }

    fn latest_item(&self, id: &ItemId) -> VaultResult<VaultItem> {
        self.latest_items()?
            .into_iter()
            .find(|item| &item.id == id && item.status != ItemStatus::Deleted)
            .ok_or_else(|| VaultError::ItemNotFound { id: id.0.clone() })
    }

    fn save_item_revision(&self, item: &VaultItem) -> VaultResult<()> {
        if self.uses_target_format() {
            return self.save_target_item_revision(item, None);
        }
        self.ensure_legacy_write_format()?;
        let record = encrypt_item_record(&self.vault_key, item)?;
        write_item_record(&self.path, &record)
    }
}

fn target_head_revisions(revisions: Vec<CredentialRevision>) -> Vec<CredentialRevision> {
    let head_revision_ids = logical_target_head_revision_ids(&revisions);
    let mut heads = revisions
        .into_iter()
        .filter(|revision| head_revision_ids.contains(&revision.revision_id()))
        .collect::<Vec<_>>();
    heads.sort_by_key(CredentialRevision::revision_id);
    heads
}

fn raw_target_head_revision_ids(revisions: &[CredentialRevision]) -> BTreeSet<crate::RevisionId> {
    let parent_revision_ids = revisions
        .iter()
        .flat_map(|revision| revision.parent_revision_ids().iter().copied())
        .collect::<BTreeSet<_>>();
    revisions
        .iter()
        .filter(|revision| !parent_revision_ids.contains(&revision.revision_id()))
        .map(CredentialRevision::revision_id)
        .collect()
}

fn logical_target_head_revision_ids(
    revisions: &[CredentialRevision],
) -> BTreeSet<crate::RevisionId> {
    let raw_head_ids = raw_target_head_revision_ids(revisions);
    let revisions_by_id = revisions
        .iter()
        .map(|revision| (revision.revision_id(), revision))
        .collect::<BTreeMap<_, _>>();
    let ancestor_ids_by_head = raw_head_ids
        .iter()
        .map(|revision_id| {
            (
                *revision_id,
                known_target_ancestor_ids(*revision_id, &revisions_by_id),
            )
        })
        .collect::<BTreeMap<_, _>>();

    raw_head_ids
        .iter()
        .copied()
        .filter(|head_id| {
            let head = revisions_by_id
                .get(head_id)
                .expect("raw target head must be present");
            !raw_head_ids.iter().copied().any(|other_id| {
                if other_id == *head_id {
                    return false;
                }
                let other = revisions_by_id
                    .get(&other_id)
                    .expect("other raw target head must be present");
                if target_revisions_semantically_equivalent(head, other) {
                    return other_id < *head_id;
                }
                ancestor_ids_by_head
                    .get(&other_id)
                    .expect("other raw target head ancestry must be present")
                    .iter()
                    .filter_map(|ancestor_id| revisions_by_id.get(ancestor_id))
                    .any(|ancestor| target_revisions_semantically_equivalent(head, ancestor))
            })
        })
        .collect()
}

fn target_revisions_semantically_equivalent(
    left: &CredentialRevision,
    right: &CredentialRevision,
) -> bool {
    left.revision_id() == right.revision_id()
        || (left.parent_revision_ids().len() >= 2
            && left.parent_revision_ids() == right.parent_revision_ids()
            && left.lifecycle() == right.lifecycle()
            && left.credential() == right.credential())
}

fn known_target_ancestor_ids(
    revision_id: crate::RevisionId,
    revisions_by_id: &BTreeMap<crate::RevisionId, &CredentialRevision>,
) -> BTreeSet<crate::RevisionId> {
    let mut ancestors = BTreeSet::new();
    let mut pending = revisions_by_id
        .get(&revision_id)
        .map(|revision| revision.parent_revision_ids().to_vec())
        .unwrap_or_default();
    while let Some(candidate) = pending.pop() {
        if !ancestors.insert(candidate) {
            continue;
        }
        if let Some(revision) = revisions_by_id.get(&candidate) {
            pending.extend(revision.parent_revision_ids().iter().copied());
        }
    }
    ancestors
}

fn plan_automatic_target_merges(
    revisions: &[CredentialRevision],
) -> VaultResult<Vec<CredentialRevision>> {
    let mut heads_by_credential = BTreeMap::<crate::CredentialId, Vec<CredentialRevision>>::new();
    for revision in target_head_revisions(revisions.to_vec()) {
        heads_by_credential
            .entry(revision.credential().credential_id())
            .or_default()
            .push(revision);
    }

    let mut known_revision_ids = revisions
        .iter()
        .map(CredentialRevision::revision_id)
        .collect::<BTreeSet<_>>();
    let mut planned = Vec::new();
    for (_, mut heads) in heads_by_credential {
        if heads.len() != 2 {
            continue;
        }
        heads.sort_by_key(CredentialRevision::revision_id);
        let right = heads.pop().expect("two target heads have a right side");
        let left = heads.pop().expect("two target heads have a left side");
        let Some(base) = unique_target_merge_base(revisions, &left, &right) else {
            continue;
        };
        let Some(credential) = merge_target_credentials(&base, &left, &right) else {
            continue;
        };
        let lifecycle = left.lifecycle();
        let parents = vec![left.revision_id(), right.revision_id()];
        let revision = CredentialRevision::descendant_with_lifecycle(
            credential,
            crate::DeviceId::generate(),
            parents,
            lifecycle,
        )
        .map_err(|error| VaultError::InvalidVault {
            reason: error.to_string(),
        })?;
        if !known_revision_ids.insert(revision.revision_id()) {
            return Err(VaultError::InvalidVault {
                reason: "generated automatic merge revision identity already exists".to_owned(),
            });
        }
        planned.push(revision);
    }
    Ok(planned)
}

fn unique_target_merge_base(
    revisions: &[CredentialRevision],
    left: &CredentialRevision,
    right: &CredentialRevision,
) -> Option<CredentialRevision> {
    if left.credential().vault_id() != right.credential().vault_id()
        || left.credential().credential_id() != right.credential().credential_id()
    {
        return None;
    }
    let revisions_by_id = revisions
        .iter()
        .map(|revision| (revision.revision_id(), revision))
        .collect::<BTreeMap<_, _>>();
    let left_ancestors = known_target_ancestor_ids(left.revision_id(), &revisions_by_id);
    let right_ancestors = known_target_ancestor_ids(right.revision_id(), &revisions_by_id);
    let candidates = left_ancestors
        .iter()
        .flat_map(|left_id| {
            right_ancestors.iter().filter_map(|right_id| {
                let left_base = revisions_by_id.get(left_id)?;
                let right_base = revisions_by_id.get(right_id)?;
                target_revisions_semantically_equivalent(left_base, right_base)
                    .then_some((*left_id, *right_id))
            })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }

    let ancestry_by_id = revisions_by_id
        .keys()
        .copied()
        .map(|revision_id| {
            let mut ancestry = known_target_ancestor_ids(revision_id, &revisions_by_id);
            ancestry.insert(revision_id);
            (revision_id, ancestry)
        })
        .collect::<BTreeMap<_, _>>();
    let mut maximal = candidates
        .iter()
        .copied()
        .filter(|candidate| {
            !candidates.iter().copied().any(|other| {
                if other == *candidate {
                    return false;
                }
                let left_descends = ancestry_by_id
                    .get(&other.0)
                    .is_some_and(|ancestry| ancestry.contains(&candidate.0));
                let right_descends = ancestry_by_id
                    .get(&other.1)
                    .is_some_and(|ancestry| ancestry.contains(&candidate.1));
                left_descends && right_descends
            })
        })
        .collect::<Vec<_>>();
    maximal.sort_unstable();
    let selected = *maximal.first()?;
    let selected_base = *revisions_by_id.get(&selected.0)?;
    if maximal.iter().skip(1).any(|candidate| {
        revisions_by_id
            .get(&candidate.0)
            .is_none_or(|base| !target_revisions_semantically_equivalent(selected_base, base))
    }) {
        return None;
    }
    Some(selected_base.clone())
}

fn merge_target_credentials(
    base: &CredentialRevision,
    left: &CredentialRevision,
    right: &CredentialRevision,
) -> Option<crate::Credential> {
    if base.credential().vault_id() != left.credential().vault_id()
        || base.credential().vault_id() != right.credential().vault_id()
        || base.credential().credential_id() != left.credential().credential_id()
        || base.credential().credential_id() != right.credential().credential_id()
        || left.lifecycle() != right.lifecycle()
        || left.lifecycle() == CredentialLifecycle::Deleted
    {
        return None;
    }
    let draft = merge_target_credential_drafts(
        base.credential().draft(),
        left.credential().draft(),
        right.credential().draft(),
    )?;
    validate_credential_draft_for_write(&draft).ok()?;
    crate::Credential::with_id(
        base.credential().vault_id(),
        base.credential().credential_id(),
        draft,
    )
    .ok()
}

fn merge_target_credential_drafts(
    base: &CredentialDraft,
    left: &CredentialDraft,
    right: &CredentialDraft,
) -> Option<CredentialDraft> {
    let base_shape = target_credential_draft_field_shape(base);
    if target_credential_draft_field_shape(left) != base_shape
        || target_credential_draft_field_shape(right) != base_shape
    {
        return None;
    }

    let mut merged_fields = base.fields.clone();
    let mut text_indexes = Vec::new();
    let mut base_text_fields = Vec::new();
    let mut left_text_fields = Vec::new();
    let mut right_text_fields = Vec::new();
    for (index, ((base_field, left_field), right_field)) in base
        .fields
        .iter()
        .zip(&left.fields)
        .zip(&right.fields)
        .enumerate()
    {
        match (&base_field.value, &left_field.value, &right_field.value) {
            (
                CredentialFieldValue::Text { .. },
                CredentialFieldValue::Text { .. },
                CredentialFieldValue::Text { .. },
            ) => {
                text_indexes.push(index);
                base_text_fields.push(base_field.clone());
                left_text_fields.push(left_field.clone());
                right_text_fields.push(right_field.clone());
            }
            (
                CredentialFieldValue::Secret {
                    secret_field_id: base_id,
                    ..
                },
                CredentialFieldValue::Secret {
                    secret_field_id: left_id,
                    ..
                },
                CredentialFieldValue::Secret {
                    secret_field_id: right_id,
                    ..
                },
            ) if base_id == left_id && base_id == right_id => {
                merged_fields[index] =
                    merge_exclusively_changed_component(base_field, left_field, right_field)?;
            }
            _ => return None,
        }
    }

    let merged_text_fields = merge_exclusively_changed_component(
        &base_text_fields,
        &left_text_fields,
        &right_text_fields,
    )?;
    for (index, field) in text_indexes.into_iter().zip(merged_text_fields) {
        merged_fields[index] = field;
    }

    Some(CredentialDraft {
        title: merge_three_way_component(&base.title, &left.title, &right.title)?,
        template_id: merge_three_way_component(
            &base.template_id,
            &left.template_id,
            &right.template_id,
        )?,
        fields: merged_fields,
        tags: merge_three_way_component(&base.tags, &left.tags, &right.tags)?,
        favorite: merge_three_way_component(&base.favorite, &left.favorite, &right.favorite)?,
    })
}

fn merge_three_way_component<T: Clone + Eq>(base: &T, left: &T, right: &T) -> Option<T> {
    if left == right {
        Some(left.clone())
    } else if left == base {
        Some(right.clone())
    } else if right == base {
        Some(left.clone())
    } else {
        None
    }
}

fn merge_exclusively_changed_component<T: Clone + Eq>(base: &T, left: &T, right: &T) -> Option<T> {
    match (left == base, right == base) {
        (true, true) => Some(base.clone()),
        (true, false) => Some(right.clone()),
        (false, true) => Some(left.clone()),
        (false, false) => None,
    }
}

/// Search request for unlocked vault content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchQuery {
    /// Raw query text.
    pub text: String,
    /// Whether archived items should be included.
    pub include_archived: bool,
}

/// Safe-enough summary for one candidate in a detected conflict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictCandidateSummary {
    /// Candidate item identifier.
    pub item_id: ItemId,
    /// Candidate revision identifier.
    pub revision: ItemRevision,
    /// Candidate title.
    pub title: String,
    /// Stable item type label.
    pub item_type: String,
    /// Optional open presentation template identifier for a typed credential.
    pub template_id: Option<String>,
    /// Candidate status label before resolution.
    pub status: String,
    /// Candidate favorite flag.
    pub favorite: bool,
    /// Candidate tags.
    pub tags: Vec<String>,
    /// Structured fields for comparing candidate versions without revealing high-risk secrets.
    pub comparison_fields: Vec<ConflictCandidateField>,
    /// Field labels that differ from at least one other conflict candidate.
    pub changed_fields: Vec<String>,
    /// Short type-specific preview that excludes passwords and TOTP secrets.
    pub preview: Option<String>,
    /// Ordered typed credential fields for current-format conflict comparison.
    pub credential_fields: Vec<ConflictCandidateCredentialField>,
    /// Whether the typed field identity or ordering differs between candidates.
    pub field_shape_changed: bool,
    /// Whether the legacy explicit non-secret field merge is available.
    pub supports_safe_field_merge: bool,
}

/// Request to resolve a conflict by choosing safe field values from candidate revisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictMergeRequest {
    /// Conflict identifier returned with the conflicted item.
    pub conflict_id: ConflictId,
    /// Candidate revision used as the base for secrets and unsupported fields.
    pub base_revision: ItemRevision,
    /// Safe fields to copy from selected candidate revisions.
    pub field_selections: Vec<ConflictFieldSelection>,
}

/// One safe field selection for a conflict merge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictFieldSelection {
    /// Stable field label, matching conflict candidate comparison labels.
    pub field_label: String,
    /// Candidate revision whose value should be copied for the field.
    pub revision: ItemRevision,
}

/// One safe display row for comparing conflict candidates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictCandidateField {
    /// User-facing field label.
    pub label: String,
    /// Display value when the value is safe for the conflict picker.
    pub value: Option<String>,
    /// Whether the underlying value exists but is intentionally hidden.
    pub redacted: bool,
}

/// One typed field in an unlocked current-format conflict comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConflictCandidateCredentialField {
    /// Searchable or presentational text.
    Text {
        /// Zero-based display position in the ordered credential field list.
        index: usize,
        /// Open provider-neutral semantic role.
        role: String,
        /// Optional user-visible label.
        label: Option<String>,
        /// Decrypted text available only inside the unlocked human control plane.
        text: String,
        /// Whether this complete field differs from at least one other candidate.
        changed: bool,
    },
    /// Secret-bearing field whose secret bytes remain excluded.
    Secret {
        /// Zero-based display position in the ordered credential field list.
        index: usize,
        /// Open provider-neutral semantic role.
        role: String,
        /// Optional user-visible label.
        label: Option<String>,
        /// Immutable identity of the independently authorizable secret field.
        secret_field_id: crate::SecretFieldId,
        /// Provider-neutral secret classification.
        secret_kind: crate::SecretFieldKind,
        /// Whether the encrypted field contains any secret bytes.
        has_value: bool,
        /// Whether this complete field differs from at least one other candidate.
        changed: bool,
    },
}

impl ConflictCandidateSummary {
    fn from_candidate_group(item: VaultItem, candidates: &[VaultItem]) -> Self {
        let preview = candidate_preview(&item.draft.content);
        let item_type = item.draft.item_type().as_search_label().to_owned();
        let changed_fields = candidate_changed_fields(&item, candidates);
        let comparison_fields = candidate_comparison_fields(&item, candidates, &item_type);
        Self {
            item_id: item.id,
            revision: item.revision,
            title: item.draft.title,
            item_type,
            template_id: None,
            status: item_status_label(&item.status),
            favorite: item.draft.favorite,
            tags: item.draft.tags,
            comparison_fields,
            changed_fields,
            preview,
            credential_fields: Vec::new(),
            field_shape_changed: false,
            supports_safe_field_merge: true,
        }
    }

    fn from_target_candidate_group(
        revision: CredentialRevision,
        candidates: &[CredentialRevision],
        legacy_candidates: Option<&[VaultItem]>,
    ) -> Self {
        let draft = revision.credential().draft();
        let legacy_summary = legacy_candidates.and_then(|items| {
            items
                .iter()
                .find(|item| item.revision.0 == revision.revision_id().to_string())
                .cloned()
                .map(|item| Self::from_candidate_group(item, items))
        });
        let comparison_fields = legacy_summary
            .as_ref()
            .map(|summary| summary.comparison_fields.clone())
            .unwrap_or_else(|| target_candidate_comparison_fields(draft));
        let changed_fields = legacy_summary
            .as_ref()
            .map(|summary| summary.changed_fields.clone())
            .unwrap_or_else(|| target_candidate_changed_components(&revision, candidates));
        let preview = legacy_summary.and_then(|summary| summary.preview);
        let template_id = draft.template_id.clone();
        let item_type = template_id
            .as_deref()
            .map(|value| value.replace('-', " "))
            .unwrap_or_else(|| "custom".to_owned());
        let field_shape = target_candidate_field_shape(&revision);
        let field_shape_changed = candidates
            .iter()
            .any(|candidate| target_candidate_field_shape(candidate) != field_shape);

        Self {
            item_id: ItemId(revision.credential().credential_id().to_string()),
            revision: ItemRevision(revision.revision_id().to_string()),
            title: draft.title.clone(),
            item_type,
            template_id,
            status: credential_lifecycle_label(revision.lifecycle()).to_owned(),
            favorite: draft.favorite,
            tags: draft.tags.clone(),
            comparison_fields,
            changed_fields,
            preview,
            credential_fields: target_candidate_credential_fields(&revision, candidates),
            field_shape_changed,
            supports_safe_field_merge: legacy_candidates.is_some(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
enum TargetConflictFieldShape {
    Text {
        role: String,
        label: Option<String>,
    },
    Secret {
        secret_field_id: crate::SecretFieldId,
        secret_kind: crate::SecretFieldKind,
    },
}

fn target_candidate_field_shape(revision: &CredentialRevision) -> Vec<TargetConflictFieldShape> {
    target_credential_draft_field_shape(revision.credential().draft())
}

fn target_credential_draft_field_shape(draft: &CredentialDraft) -> Vec<TargetConflictFieldShape> {
    draft
        .fields
        .iter()
        .map(|field| match &field.value {
            CredentialFieldValue::Text { .. } => TargetConflictFieldShape::Text {
                role: field.role.clone(),
                label: field.label.clone(),
            },
            CredentialFieldValue::Secret {
                secret_field_id,
                kind,
                ..
            } => TargetConflictFieldShape::Secret {
                secret_field_id: *secret_field_id,
                secret_kind: *kind,
            },
        })
        .collect()
}

fn target_candidate_credential_fields(
    revision: &CredentialRevision,
    candidates: &[CredentialRevision],
) -> Vec<ConflictCandidateCredentialField> {
    revision
        .credential()
        .draft()
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let changed = target_candidate_credential_field_changed(index, field, candidates);
            match &field.value {
                CredentialFieldValue::Text { text } => ConflictCandidateCredentialField::Text {
                    index,
                    role: field.role.clone(),
                    label: field.label.clone(),
                    text: text.clone(),
                    changed,
                },
                CredentialFieldValue::Secret {
                    secret_field_id,
                    kind,
                    secret,
                } => ConflictCandidateCredentialField::Secret {
                    index,
                    role: field.role.clone(),
                    label: field.label.clone(),
                    secret_field_id: *secret_field_id,
                    secret_kind: *kind,
                    has_value: !secret.expose().is_empty(),
                    changed,
                },
            }
        })
        .collect()
}

fn target_candidate_credential_field_changed(
    index: usize,
    field: &crate::CredentialField,
    candidates: &[CredentialRevision],
) -> bool {
    match &field.value {
        CredentialFieldValue::Text { .. } => candidates
            .iter()
            .any(|candidate| candidate.credential().draft().fields.get(index) != Some(field)),
        CredentialFieldValue::Secret {
            secret_field_id, ..
        } => candidates.iter().any(|candidate| {
            candidate
                .credential()
                .draft()
                .fields
                .iter()
                .find(|candidate_field| candidate_field.secret_field_id() == Some(*secret_field_id))
                != Some(field)
        }),
    }
}

fn target_candidate_changed_components(
    revision: &CredentialRevision,
    candidates: &[CredentialRevision],
) -> Vec<String> {
    let draft = revision.credential().draft();
    let others = candidates
        .iter()
        .filter(|candidate| candidate.revision_id() != revision.revision_id())
        .collect::<Vec<_>>();
    let mut changed = Vec::new();
    if others
        .iter()
        .any(|candidate| candidate.credential().draft().title != draft.title)
    {
        changed.push("title".to_owned());
    }
    if others
        .iter()
        .any(|candidate| candidate.credential().draft().template_id != draft.template_id)
    {
        changed.push("template".to_owned());
    }
    if others
        .iter()
        .any(|candidate| candidate.credential().draft().favorite != draft.favorite)
    {
        changed.push("favorite".to_owned());
    }
    if others
        .iter()
        .any(|candidate| candidate.credential().draft().tags != draft.tags)
    {
        changed.push("tags".to_owned());
    }
    if others
        .iter()
        .any(|candidate| candidate.credential().draft().fields != draft.fields)
    {
        changed.push("fields".to_owned());
    }
    changed
}

fn target_candidate_comparison_fields(draft: &CredentialDraft) -> Vec<ConflictCandidateField> {
    vec![
        comparison_value("title", &draft.title),
        comparison_optional("template", draft.template_id.clone()),
        comparison_value("favorite", if draft.favorite { "true" } else { "false" }),
        comparison_optional("tags", joined_values(&draft.tags)),
    ]
}

const fn credential_lifecycle_label(lifecycle: CredentialLifecycle) -> &'static str {
    match lifecycle {
        CredentialLifecycle::Active => "active",
        CredentialLifecycle::Archived => "archived",
        CredentialLifecycle::Deleted => "deleted",
    }
}

/// Summary of disk changes observed during a sync refresh.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncRefreshReport {
    /// Number of valid item files loaded.
    pub loaded_items: usize,
    /// Number of tombstones applied.
    pub applied_tombstones: usize,
    /// Number of conflicts detected.
    pub detected_conflicts: usize,
    /// Number of invalid or tampered records rejected.
    pub rejected_records: usize,
    /// Number of invalid or tampered item records rejected.
    pub rejected_item_records: usize,
    /// Number of invalid or tampered tombstone records rejected.
    pub rejected_tombstone_records: usize,
    /// Available local `.enc` file names for rejected sync records.
    pub rejected_record_files: Vec<RejectedSyncRecordFile>,
}

/// Non-secret local file summary for a rejected sync record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedSyncRecordFile {
    /// Rejected record category.
    pub kind: RejectedSyncRecordKind,
    /// Local file name only, never a full path.
    pub file_name: String,
}

/// Rejected encrypted record category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectedSyncRecordKind {
    /// Rejected item record file.
    Item,
    /// Rejected tombstone record file.
    Tombstone,
}

/// Summary of rejected encrypted sync records moved into quarantine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncQuarantineReport {
    /// Number of rejected item and tombstone records moved.
    pub moved_records: usize,
    /// Number of rejected item records moved.
    pub moved_item_records: usize,
    /// Number of rejected tombstone records moved.
    pub moved_tombstone_records: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CandidateLoad {
    items: Vec<VaultItem>,
    report: SyncRefreshReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetRecordDirectory {
    Items,
    Tombstones,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LoadedTargetRevisions {
    revisions: Vec<crate::CredentialRevision>,
    rejected_files: Vec<String>,
}

fn load_target_records_from_dir(
    directory: &Path,
    vault_key: &SecretBytes,
    expected_vault_id: crate::VaultId,
    expected_directory: TargetRecordDirectory,
) -> VaultResult<LoadedTargetRevisions> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| VaultError::io("read target records directory", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| VaultError::io("read target record entry", source))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    let mut loaded = LoadedTargetRevisions::default();
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("enc") {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let parsed = entry
            .file_type()
            .map_err(|source| VaultError::io("inspect target credential record", source))
            .and_then(|file_type| {
                if !file_type.is_file() {
                    return Err(VaultError::InvalidVault {
                        reason: "target credential record is not a regular file".to_owned(),
                    });
                }
                read_regular_file_limited(
                    &path,
                    MAX_ENCRYPTED_RECORD_FILE_BYTES,
                    "read target credential record",
                )
            })
            .and_then(|bytes| parse_target_credential_record(&bytes))
            .and_then(|record| {
                if record.vault_id != expected_vault_id {
                    return Err(VaultError::InvalidVault {
                        reason: "target record vault identity differs from metadata".to_owned(),
                    });
                }
                let expected_name = target_record_file_name(
                    record.credential_id,
                    record.revision_id,
                    expected_directory,
                );
                if file_name != expected_name {
                    return Err(VaultError::InvalidVault {
                        reason: "target record file name is not canonical".to_owned(),
                    });
                }
                decrypt_target_credential_record(vault_key, &record)
            })
            .and_then(|revision| {
                let actual_directory = match revision.lifecycle() {
                    CredentialLifecycle::Active | CredentialLifecycle::Archived => {
                        TargetRecordDirectory::Items
                    }
                    CredentialLifecycle::Deleted => TargetRecordDirectory::Tombstones,
                };
                if actual_directory != expected_directory {
                    return Err(VaultError::InvalidVault {
                        reason: "target revision lifecycle does not match its record directory"
                            .to_owned(),
                    });
                }
                Ok(revision)
            });
        match parsed {
            Ok(revision) => loaded.revisions.push(revision),
            Err(_) => loaded.rejected_files.push(file_name),
        }
    }
    Ok(loaded)
}

fn validate_target_revision_graph(revisions: &[crate::CredentialRevision]) -> VaultResult<()> {
    let mut owners = BTreeMap::<crate::RevisionId, crate::CredentialId>::new();
    let mut nodes = BTreeMap::<crate::RevisionId, &crate::CredentialRevision>::new();
    for revision in revisions {
        let revision_id = revision.revision_id();
        let credential_id = revision.credential().credential_id();
        if owners.insert(revision_id, credential_id).is_some() {
            return Err(VaultError::InvalidVault {
                reason: "target vault contains a duplicate revision identity".to_owned(),
            });
        }
        nodes.insert(revision_id, revision);
    }

    let mut known_parent_count = BTreeMap::<crate::RevisionId, usize>::new();
    let mut children = BTreeMap::<crate::RevisionId, Vec<crate::RevisionId>>::new();
    for revision in revisions {
        let revision_id = revision.revision_id();
        let credential_id = revision.credential().credential_id();
        let mut count = 0;
        for parent in revision.parent_revision_ids() {
            if let Some(parent_credential_id) = owners.get(parent) {
                if *parent_credential_id != credential_id {
                    return Err(VaultError::InvalidVault {
                        reason: "target revision parent belongs to another credential".to_owned(),
                    });
                }
                count += 1;
                children.entry(*parent).or_default().push(revision_id);
            }
        }
        known_parent_count.insert(revision_id, count);
    }

    let mut ready = known_parent_count
        .iter()
        .filter_map(|(revision_id, count)| (*count == 0).then_some(*revision_id))
        .collect::<Vec<_>>();
    let mut visited = 0;
    while let Some(revision_id) = ready.pop() {
        visited += 1;
        for child in children.get(&revision_id).into_iter().flatten() {
            let count = known_parent_count
                .get_mut(child)
                .expect("known target revision child");
            *count -= 1;
            if *count == 0 {
                ready.push(*child);
            }
        }
    }
    if visited != nodes.len() {
        return Err(VaultError::InvalidVault {
            reason: "target revision ancestry contains a cycle".to_owned(),
        });
    }
    Ok(())
}

fn target_revision_to_legacy_item(
    revision: crate::CredentialRevision,
    expected_directory: TargetRecordDirectory,
) -> VaultResult<VaultItem> {
    let lifecycle = revision.lifecycle();
    let actual_directory = match lifecycle {
        CredentialLifecycle::Active | CredentialLifecycle::Archived => TargetRecordDirectory::Items,
        CredentialLifecycle::Deleted => TargetRecordDirectory::Tombstones,
    };
    if actual_directory != expected_directory {
        return Err(VaultError::InvalidVault {
            reason: "target revision lifecycle does not match its record directory".to_owned(),
        });
    }

    let draft: VaultItemDraft = revision.credential().draft().clone().try_into().map_err(
        |error: crate::LegacyCredentialConversionError| VaultError::InvalidVault {
            reason: error.to_string(),
        },
    )?;
    let status = match lifecycle {
        CredentialLifecycle::Active => ItemStatus::Active,
        CredentialLifecycle::Archived => ItemStatus::Archived,
        CredentialLifecycle::Deleted => ItemStatus::Deleted,
    };
    Ok(VaultItem {
        id: ItemId(revision.credential().credential_id().to_string()),
        revision: ItemRevision(revision.revision_id().to_string()),
        parent_revision: (revision.parent_revision_ids().len() == 1)
            .then(|| ItemRevision(revision.parent_revision_ids()[0].to_string())),
        status,
        draft,
    })
}

fn target_conflict_legacy_candidates(revisions: &[CredentialRevision]) -> Option<Vec<VaultItem>> {
    if revisions
        .iter()
        .any(|revision| revision.lifecycle() == CredentialLifecycle::Deleted)
    {
        return None;
    }
    revisions
        .iter()
        .cloned()
        .map(|revision| target_revision_to_legacy_item(revision, TargetRecordDirectory::Items).ok())
        .collect()
}

fn parse_target_credential_id(item_id: &ItemId) -> VaultResult<crate::CredentialId> {
    item_id.0.parse().map_err(|_| VaultError::InvalidVault {
        reason: "current item identity is not a canonical credential identity".to_owned(),
    })
}

fn parse_target_conflict_credential_id(
    conflict_id: &ConflictId,
) -> VaultResult<crate::CredentialId> {
    let credential_id =
        conflict_id
            .0
            .strip_prefix("conflict_")
            .ok_or_else(|| VaultError::ItemNotFound {
                id: conflict_id.0.clone(),
            })?;
    credential_id.parse().map_err(|_| VaultError::ItemNotFound {
        id: conflict_id.0.clone(),
    })
}

fn parse_target_revision_id(revision: &ItemRevision) -> VaultResult<crate::RevisionId> {
    revision.0.parse().map_err(|_| VaultError::InvalidVault {
        reason: "current item revision is not a canonical revision identity".to_owned(),
    })
}

fn credential_draft_preserving_secret_ids(
    legacy_draft: VaultItemDraft,
    previous: Option<&crate::CredentialDraft>,
) -> crate::CredentialDraft {
    let mut draft = crate::CredentialDraft::from(legacy_draft);
    let Some(previous) = previous else {
        return draft;
    };

    let mut prior_ids =
        BTreeMap::<(String, crate::SecretFieldKind, usize), crate::SecretFieldId>::new();
    let mut prior_occurrences = BTreeMap::<(String, crate::SecretFieldKind), usize>::new();
    for field in &previous.fields {
        let crate::CredentialFieldValue::Secret {
            secret_field_id,
            kind,
            ..
        } = &field.value
        else {
            continue;
        };
        let slot = prior_occurrences
            .entry((field.role.clone(), *kind))
            .or_default();
        prior_ids.insert((field.role.clone(), *kind, *slot), *secret_field_id);
        *slot += 1;
    }

    let mut occurrences = BTreeMap::<(String, crate::SecretFieldKind), usize>::new();
    for field in &mut draft.fields {
        let crate::CredentialFieldValue::Secret {
            secret_field_id,
            kind,
            ..
        } = &mut field.value
        else {
            continue;
        };
        let slot = occurrences.entry((field.role.clone(), *kind)).or_default();
        if let Some(prior_id) = prior_ids.get(&(field.role.clone(), *kind, *slot)) {
            *secret_field_id = *prior_id;
        }
        *slot += 1;
    }
    draft
}

fn target_record_file_name(
    credential_id: crate::CredentialId,
    revision_id: crate::RevisionId,
    directory: TargetRecordDirectory,
) -> String {
    let stem = format!("{credential_id}_{revision_id}");
    match directory {
        TargetRecordDirectory::Items => format!("{stem}.enc"),
        TargetRecordDirectory::Tombstones => format!("tombstone_{stem}.enc"),
    }
}

fn rejected_record_file_summaries(
    kind: RejectedSyncRecordKind,
    file_names: Vec<String>,
) -> Vec<RejectedSyncRecordFile> {
    file_names
        .into_iter()
        .map(|file_name| RejectedSyncRecordFile { kind, file_name })
        .collect()
}

fn password_is_weak(password: &[u8], title: &str, username: Option<&str>) -> bool {
    let password_text = String::from_utf8_lossy(password);
    let normalized_password = password_text.trim().to_lowercase();
    if normalized_password.len() < 12 {
        return true;
    }
    if common_weak_password(&normalized_password) {
        return true;
    }
    if password_character_class_count(password_text.as_ref()) <= 1 {
        return true;
    }
    if contains_context_value(&normalized_password, title) {
        return true;
    }
    username
        .map(|username| contains_context_value(&normalized_password, username))
        .unwrap_or(false)
}

fn common_weak_password(normalized_password: &str) -> bool {
    matches!(
        normalized_password,
        "password"
            | "password1"
            | "password123"
            | "123456"
            | "12345678"
            | "123456789"
            | "qwerty"
            | "qwerty123"
            | "letmein"
            | "welcome"
            | "welcome1"
            | "admin"
            | "iloveyou"
            | "monkey"
            | "abc123"
    )
}

fn password_character_class_count(password: &str) -> usize {
    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digit = false;
    let mut has_other = false;
    for character in password.chars() {
        if character.is_ascii_lowercase() {
            has_lowercase = true;
        } else if character.is_ascii_uppercase() {
            has_uppercase = true;
        } else if character.is_ascii_digit() {
            has_digit = true;
        } else {
            has_other = true;
        }
    }
    [has_lowercase, has_uppercase, has_digit, has_other]
        .into_iter()
        .filter(|present| *present)
        .count()
}

fn contains_context_value(normalized_password: &str, value: &str) -> bool {
    let normalized_value = value.trim().to_lowercase();
    normalized_value.len() >= 4 && normalized_password.contains(&normalized_value)
}

/// Import preview request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportPreviewRequest {
    /// Source export path.
    pub source_path: PathBuf,
    /// Source format identifier such as `bitwarden-json` or `generic-login-csv`.
    pub source_format: String,
}

/// Request to commit a previewed import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportCommitRequest {
    /// Source export path.
    pub source_path: PathBuf,
    /// Source format identifier such as `bitwarden-json` or `generic-login-csv`.
    pub source_format: String,
    /// Whether likely duplicate records should be imported as separate items.
    pub keep_duplicates: bool,
}

/// Plaintext export request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportItemsRequest {
    /// Destination export path.
    pub destination_path: PathBuf,
    /// Export format identifier, such as `keptnear-json` or `bitwarden-json`.
    pub export_format: String,
    /// Current master password required immediately before plaintext export.
    pub current_master_password: SecretBytes,
}

/// Import preview and result counts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportPreview {
    /// Records that can be imported.
    pub importable_records: usize,
    /// Records skipped because they are unsupported or invalid.
    pub skipped_records: usize,
    /// Records likely to duplicate existing items.
    pub duplicate_records: usize,
    /// Human-readable warnings for the user.
    pub warnings: Vec<String>,
}

/// Generated TOTP code and timing metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpCode {
    /// Zero-padded numeric code.
    pub code: String,
    /// TOTP period in seconds.
    pub period_seconds: u64,
    /// Seconds remaining in the current period.
    pub remaining_seconds: u64,
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

fn new_revision() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let mut bytes = [0_u8; 8];
    OsRng.fill_bytes(&mut bytes);
    format!("rev_{nanos:032}_{}", hex::encode(bytes))
}

fn item_matches_query(item: &VaultItem, needle: &str) -> bool {
    let summary = ItemSummary::from_item(item);
    let mut haystacks = vec![
        summary.title,
        summary.item_type.as_search_label().to_owned(),
        summary.tags.join(" "),
    ];
    match &item.draft.content {
        VaultItemContent::Login(login) => {
            if let Some(username) = &login.username {
                haystacks.push(username.clone());
            }
            haystacks.extend(login.urls.iter().cloned());
            if let Some(notes) = &login.notes {
                haystacks.push(notes.clone());
            }
        }
        VaultItemContent::SecureNote(note) => {
            haystacks.push(note.body.clone());
        }
        VaultItemContent::SoftwareLicense(license) => {
            if let Some(product) = &license.product {
                haystacks.push(product.clone());
            }
            if let Some(licensed_to) = &license.licensed_to {
                haystacks.push(licensed_to.clone());
            }
            if let Some(notes) = &license.notes {
                haystacks.push(notes.clone());
            }
        }
        VaultItemContent::CreditCard(card) => {
            if let Some(cardholder_name) = &card.cardholder_name {
                haystacks.push(cardholder_name.clone());
            }
            if let Some(expiry_month) = card.expiry_month {
                haystacks.push(expiry_month.to_string());
            }
            if let Some(expiry_year) = card.expiry_year {
                haystacks.push(expiry_year.to_string());
            }
            if let Some(notes) = &card.notes {
                haystacks.push(notes.clone());
            }
        }
    }
    haystacks
        .into_iter()
        .any(|value| value.to_lowercase().contains(needle))
}

fn credential_matches_query(credential: &crate::Credential, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let draft = credential.draft();
    let searches_secure_note_body = draft.template_id.as_deref() == Some("secure-note");
    normalized_contains(&draft.title, needle)
        || draft
            .template_id
            .as_deref()
            .is_some_and(|value| normalized_contains(value, needle))
        || draft
            .tags
            .iter()
            .any(|value| normalized_contains(value, needle))
        || draft.fields.iter().any(|field| {
            normalized_contains(&field.role, needle)
                || field
                    .label
                    .as_deref()
                    .is_some_and(|value| normalized_contains(value, needle))
                || match &field.value {
                    crate::CredentialFieldValue::Text { text } => normalized_contains(text, needle),
                    crate::CredentialFieldValue::Secret { secret, .. }
                        if searches_secure_note_body && field.role == "body" =>
                    {
                        normalized_contains(
                            String::from_utf8_lossy(secret.expose()).as_ref(),
                            needle,
                        )
                    }
                    crate::CredentialFieldValue::Secret { .. } => false,
                }
        })
}

fn normalized_contains(value: &str, needle: &str) -> bool {
    Zeroizing::new(value.to_lowercase()).contains(needle)
}

fn candidate_changed_fields(item: &VaultItem, candidates: &[VaultItem]) -> Vec<String> {
    let mut fields = Vec::new();
    push_changed_field(
        &mut fields,
        "title",
        candidate_differs(item, candidates, |other| {
            other.draft.title != item.draft.title
        }),
    );
    push_changed_field(
        &mut fields,
        "item type",
        candidate_differs(item, candidates, |other| {
            other.draft.item_type() != item.draft.item_type()
        }),
    );
    push_changed_field(
        &mut fields,
        "status",
        candidate_differs(item, candidates, |other| other.status != item.status),
    );
    push_changed_field(
        &mut fields,
        "favorite",
        candidate_differs(item, candidates, |other| {
            other.draft.favorite != item.draft.favorite
        }),
    );
    push_changed_field(
        &mut fields,
        "tags",
        candidate_differs(item, candidates, |other| {
            other.draft.tags != item.draft.tags
        }),
    );

    match &item.draft.content {
        VaultItemContent::Login(login) => {
            push_changed_field(
                &mut fields,
                "username",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::Login(other_login) => other_login.username != login.username,
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "password",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::Login(other_login) => {
                        !secret_options_equal(&other_login.password, &login.password)
                    }
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "URLs",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::Login(other_login) => other_login.urls != login.urls,
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "notes",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::Login(other_login) => other_login.notes != login.notes,
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "TOTP",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::Login(other_login) => {
                        !secret_options_equal(&other_login.totp_secret, &login.totp_secret)
                    }
                    _ => false,
                }),
            );
        }
        VaultItemContent::SecureNote(note) => {
            push_changed_field(
                &mut fields,
                "body",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::SecureNote(other_note) => other_note.body != note.body,
                    _ => false,
                }),
            );
        }
        VaultItemContent::SoftwareLicense(license) => {
            push_changed_field(
                &mut fields,
                "product",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::SoftwareLicense(other_license) => {
                        other_license.product != license.product
                    }
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "licensed to",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::SoftwareLicense(other_license) => {
                        other_license.licensed_to != license.licensed_to
                    }
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "license key",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::SoftwareLicense(other_license) => {
                        !secret_options_equal(&other_license.license_key, &license.license_key)
                    }
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "notes",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::SoftwareLicense(other_license) => {
                        other_license.notes != license.notes
                    }
                    _ => false,
                }),
            );
        }
        VaultItemContent::CreditCard(card) => {
            push_changed_field(
                &mut fields,
                "cardholder name",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::CreditCard(other_card) => {
                        other_card.cardholder_name != card.cardholder_name
                    }
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "card number",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::CreditCard(other_card) => {
                        !secret_options_equal(&other_card.number, &card.number)
                    }
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "expiration",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::CreditCard(other_card) => {
                        other_card.expiry_month != card.expiry_month
                            || other_card.expiry_year != card.expiry_year
                    }
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "verification code",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::CreditCard(other_card) => !secret_options_equal(
                        &other_card.verification_code,
                        &card.verification_code,
                    ),
                    _ => false,
                }),
            );
            push_changed_field(
                &mut fields,
                "notes",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::CreditCard(other_card) => other_card.notes != card.notes,
                    _ => false,
                }),
            );
        }
    }
    fields
}

fn candidate_differs(
    item: &VaultItem,
    candidates: &[VaultItem],
    differs_from_item: impl Fn(&VaultItem) -> bool,
) -> bool {
    candidates
        .iter()
        .any(|other| other.revision != item.revision && differs_from_item(other))
}

fn push_changed_field(fields: &mut Vec<String>, label: &str, changed: bool) {
    if changed {
        fields.push(label.to_owned());
    }
}

fn apply_safe_conflict_field(
    target: &mut VaultItem,
    source: &VaultItem,
    field_label: &str,
) -> VaultResult<()> {
    match field_label {
        "title" => {
            target.draft.title = source.draft.title.clone();
            Ok(())
        }
        "favorite" => {
            target.draft.favorite = source.draft.favorite;
            Ok(())
        }
        "tags" => {
            target.draft.tags = source.draft.tags.clone();
            Ok(())
        }
        "username" => {
            let (VaultItemContent::Login(target_login), VaultItemContent::Login(source_login)) =
                (&mut target.draft.content, &source.draft.content)
            else {
                return unsupported_conflict_merge_field(field_label);
            };
            target_login.username = source_login.username.clone();
            Ok(())
        }
        "URLs" => {
            let (VaultItemContent::Login(target_login), VaultItemContent::Login(source_login)) =
                (&mut target.draft.content, &source.draft.content)
            else {
                return unsupported_conflict_merge_field(field_label);
            };
            target_login.urls = source_login.urls.clone();
            Ok(())
        }
        "cardholder name" => {
            let (
                VaultItemContent::CreditCard(target_card),
                VaultItemContent::CreditCard(source_card),
            ) = (&mut target.draft.content, &source.draft.content)
            else {
                return unsupported_conflict_merge_field(field_label);
            };
            target_card.cardholder_name = source_card.cardholder_name.clone();
            Ok(())
        }
        "expiration" => {
            let (
                VaultItemContent::CreditCard(target_card),
                VaultItemContent::CreditCard(source_card),
            ) = (&mut target.draft.content, &source.draft.content)
            else {
                return unsupported_conflict_merge_field(field_label);
            };
            target_card.expiry_month = source_card.expiry_month;
            target_card.expiry_year = source_card.expiry_year;
            Ok(())
        }
        "product" => {
            let (
                VaultItemContent::SoftwareLicense(target_license),
                VaultItemContent::SoftwareLicense(source_license),
            ) = (&mut target.draft.content, &source.draft.content)
            else {
                return unsupported_conflict_merge_field(field_label);
            };
            target_license.product = source_license.product.clone();
            Ok(())
        }
        "licensed to" => {
            let (
                VaultItemContent::SoftwareLicense(target_license),
                VaultItemContent::SoftwareLicense(source_license),
            ) = (&mut target.draft.content, &source.draft.content)
            else {
                return unsupported_conflict_merge_field(field_label);
            };
            target_license.licensed_to = source_license.licensed_to.clone();
            Ok(())
        }
        _ => unsupported_conflict_merge_field(field_label),
    }
}

fn unsupported_conflict_merge_field<T>(field_label: &str) -> VaultResult<T> {
    Err(VaultError::InvalidVault {
        reason: format!("unsupported conflict merge field '{field_label}'"),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuarantineRecordKind {
    Item,
    Tombstone,
}

fn move_rejected_target_files(
    records_dir: &Path,
    quarantine_dir: &Path,
    file_names: Vec<String>,
    moved: &mut usize,
) -> VaultResult<()> {
    for file_name in file_names {
        let source = records_dir.join(&file_name);
        if !source.is_file() {
            return Err(VaultError::InvalidVault {
                reason: "rejected target record disappeared before quarantine".to_owned(),
            });
        }
        fs::create_dir_all(quarantine_dir)
            .map_err(|source| VaultError::io("create quarantine directory", source))?;
        fs::rename(&source, quarantine_dir.join(file_name))
            .map_err(|source| VaultError::io("move rejected target record", source))?;
        *moved += 1;
    }
    Ok(())
}

fn quarantine_rejected_records_from_dir(
    records_dir: &Path,
    quarantine_dir: &Path,
    vault_key: &SecretBytes,
    kind: QuarantineRecordKind,
    report: &mut SyncQuarantineReport,
) -> VaultResult<()> {
    for entry in fs::read_dir(records_dir)
        .map_err(|source| VaultError::io("read sync record directory", source))?
    {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("enc") {
            continue;
        }
        if entry
            .file_type()
            .map(|file_type| !file_type.is_file())
            .unwrap_or(true)
        {
            continue;
        }
        if !encrypted_record_is_rejected(&path, vault_key) {
            continue;
        }

        fs::create_dir_all(quarantine_dir)
            .map_err(|source| VaultError::io("create quarantine directory", source))?;
        let destination = quarantine_dir.join(entry.file_name());
        fs::rename(&path, destination)
            .map_err(|source| VaultError::io("move rejected sync record", source))?;
        report.moved_records += 1;
        match kind {
            QuarantineRecordKind::Item => report.moved_item_records += 1,
            QuarantineRecordKind::Tombstone => report.moved_tombstone_records += 1,
        }
    }
    Ok(())
}

fn encrypted_record_is_rejected(path: &Path, vault_key: &SecretBytes) -> bool {
    let Ok(bytes) = read_regular_file_limited(
        path,
        MAX_ENCRYPTED_RECORD_FILE_BYTES,
        "read encrypted record",
    ) else {
        return true;
    };
    let Ok(record) = serde_json::from_slice::<EncryptedItemRecord>(&bytes) else {
        return true;
    };
    decrypt_item_record(vault_key, &record).is_err()
}

fn candidate_comparison_fields(
    item: &VaultItem,
    candidates: &[VaultItem],
    item_type: &str,
) -> Vec<ConflictCandidateField> {
    let mut fields = vec![
        comparison_value("title", &item.draft.title),
        comparison_value("item type", item_type),
        comparison_value("status", &item_status_label(&item.status)),
        comparison_value(
            "favorite",
            if item.draft.favorite { "true" } else { "false" },
        ),
        comparison_optional("tags", joined_values(&item.draft.tags)),
    ];

    match &item.draft.content {
        VaultItemContent::Login(login) => {
            fields.push(comparison_optional("username", login.username.clone()));
            fields.push(comparison_optional("URLs", joined_values(&login.urls)));
            fields.push(comparison_optional(
                "notes",
                login.notes.as_deref().map(truncate_preview),
            ));
            push_redacted_comparison_field(
                &mut fields,
                "password",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::Login(other_login) => {
                        !secret_options_equal(&other_login.password, &login.password)
                    }
                    _ => false,
                }),
            );
            push_redacted_comparison_field(
                &mut fields,
                "TOTP",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::Login(other_login) => {
                        !secret_options_equal(&other_login.totp_secret, &login.totp_secret)
                    }
                    _ => false,
                }),
            );
        }
        VaultItemContent::SecureNote(note) => {
            push_redacted_comparison_field(
                &mut fields,
                "body",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::SecureNote(other_note) => other_note.body != note.body,
                    _ => false,
                }),
            );
        }
        VaultItemContent::SoftwareLicense(license) => {
            fields.push(comparison_optional("product", license.product.clone()));
            fields.push(comparison_optional(
                "licensed to",
                license.licensed_to.clone(),
            ));
            fields.push(comparison_optional(
                "notes",
                license.notes.as_deref().map(truncate_preview),
            ));
            push_redacted_comparison_field(
                &mut fields,
                "license key",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::SoftwareLicense(other_license) => {
                        !secret_options_equal(&other_license.license_key, &license.license_key)
                    }
                    _ => false,
                }),
            );
        }
        VaultItemContent::CreditCard(card) => {
            fields.push(comparison_optional(
                "cardholder name",
                card.cardholder_name.clone(),
            ));
            fields.push(comparison_optional("expiration", card_expiration(card)));
            fields.push(comparison_optional(
                "notes",
                card.notes.as_deref().map(truncate_preview),
            ));
            push_redacted_comparison_field(
                &mut fields,
                "card number",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::CreditCard(other_card) => {
                        !secret_options_equal(&other_card.number, &card.number)
                    }
                    _ => false,
                }),
            );
            push_redacted_comparison_field(
                &mut fields,
                "verification code",
                candidate_differs(item, candidates, |other| match &other.draft.content {
                    VaultItemContent::CreditCard(other_card) => !secret_options_equal(
                        &other_card.verification_code,
                        &card.verification_code,
                    ),
                    _ => false,
                }),
            );
        }
    }
    fields
}

fn comparison_value(label: &str, value: &str) -> ConflictCandidateField {
    ConflictCandidateField {
        label: label.to_owned(),
        value: Some(value.to_owned()),
        redacted: false,
    }
}

fn comparison_optional(label: &str, value: Option<String>) -> ConflictCandidateField {
    ConflictCandidateField {
        label: label.to_owned(),
        value,
        redacted: false,
    }
}

fn push_redacted_comparison_field(
    fields: &mut Vec<ConflictCandidateField>,
    label: &str,
    changed: bool,
) {
    if changed {
        fields.push(ConflictCandidateField {
            label: label.to_owned(),
            value: None,
            redacted: true,
        });
    }
}

fn joined_values(values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| values.join(", "))
}

fn card_expiration(card: &crate::types::CreditCardItem) -> Option<String> {
    match (card.expiry_month, card.expiry_year) {
        (Some(month), Some(year)) => Some(format!("{month:02}/{year}")),
        (Some(month), None) => Some(format!("{month:02}")),
        (None, Some(year)) => Some(year.to_string()),
        (None, None) => None,
    }
}

fn secret_options_equal(left: &Option<SecretBytes>, right: &Option<SecretBytes>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.expose() == right.expose(),
        (None, None) => true,
        _ => false,
    }
}

fn candidate_preview(content: &VaultItemContent) -> Option<String> {
    match content {
        VaultItemContent::Login(login) => {
            let mut parts = Vec::new();
            if let Some(username) = login.username.as_deref().filter(|value| !value.is_empty()) {
                parts.push(format!("username: {username}"));
            }
            if let Some(url) = login.urls.first().filter(|value| !value.is_empty()) {
                parts.push(format!("url: {url}"));
            }
            if let Some(notes) = login.notes.as_deref().filter(|value| !value.is_empty()) {
                parts.push(format!("notes: {}", truncate_preview(notes)));
            }
            (!parts.is_empty()).then(|| parts.join(" | "))
        }
        VaultItemContent::SecureNote(_) => None,
        VaultItemContent::SoftwareLicense(_) | VaultItemContent::CreditCard(_) => None,
    }
}

fn truncate_preview(value: &str) -> String {
    const MAX_CHARS: usize = 120;
    let mut chars = value.chars();
    let preview: String = chars.by_ref().take(MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{preview}...")
    } else {
        preview
    }
}

fn item_status_label(status: &ItemStatus) -> String {
    match status {
        ItemStatus::Active => "active".to_owned(),
        ItemStatus::Archived => "archived".to_owned(),
        ItemStatus::Deleted => "deleted".to_owned(),
        ItemStatus::Conflicted(_) => "conflicted".to_owned(),
    }
}

fn normalize_draft(draft: &mut VaultItemDraft) -> VaultResult<()> {
    if let VaultItemContent::Login(login) = &mut draft.content {
        if let Some(secret) = login.totp_secret.take() {
            let input = String::from_utf8_lossy(secret.expose()).to_string();
            login.totp_secret = Some(normalize_totp_secret(&input)?);
        }
    }
    Ok(())
}

fn validate_credential_draft_for_write(draft: &crate::CredentialDraft) -> VaultResult<()> {
    if draft.title.trim().is_empty() {
        return Err(VaultError::InvalidVault {
            reason: "credential title must not be empty".to_owned(),
        });
    }
    if draft
        .template_id
        .as_deref()
        .is_some_and(|template_id| template_id.trim().is_empty())
    {
        return Err(VaultError::InvalidVault {
            reason: "credential template identifier must not be empty".to_owned(),
        });
    }
    if draft
        .fields
        .iter()
        .any(|field| field.role.trim().is_empty())
    {
        return Err(VaultError::InvalidVault {
            reason: "credential field role must not be empty".to_owned(),
        });
    }
    Ok(())
}

fn credential_list_item(
    revision: CredentialRevision,
    status: ItemStatus,
) -> VaultResult<CredentialListItem> {
    let revision_id = revision.revision_id();
    let credential = revision
        .credential()
        .summary()
        .map_err(|error| VaultError::InvalidVault {
            reason: error.to_string(),
        })?;
    Ok(CredentialListItem {
        revision_id,
        status,
        credential,
    })
}

fn conflict_item_id(conflict_id: &ConflictId) -> VaultResult<ItemId> {
    conflict_id
        .0
        .strip_prefix("conflict_")
        .map(|item_id| ItemId(item_id.to_owned()))
        .ok_or_else(|| VaultError::ItemNotFound {
            id: conflict_id.0.clone(),
        })
}

fn duplicate_key(draft: &CredentialDraft) -> String {
    let normalized_template = draft
        .template_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let mut username = String::new();
    let mut url = String::new();
    if normalized_template == TEMPLATE_LOGIN {
        username = duplicate_text_field(draft, "username")
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        url = duplicate_text_field(draft, "url")
            .unwrap_or_default()
            .trim()
            .to_lowercase();
    }
    let item_type = match normalized_template.as_str() {
        TEMPLATE_LOGIN => "login",
        TEMPLATE_SECURE_NOTE => "secure note",
        TEMPLATE_SOFTWARE_LICENSE => "software license",
        TEMPLATE_CREDIT_CARD => "credit card",
        _ => normalized_template.as_str(),
    };
    format!(
        "{}|{}|{}|{}",
        draft.title.trim().to_lowercase(),
        item_type,
        username,
        url
    )
}

fn duplicate_text_field<'a>(draft: &'a CredentialDraft, role: &str) -> Option<&'a str> {
    draft.fields.iter().find_map(|field| {
        if field.role != role {
            return None;
        }
        match &field.value {
            CredentialFieldValue::Text { text } => Some(text.as_str()),
            CredentialFieldValue::Secret { .. } => None,
        }
    })
}

fn detect_conflicts(items: &[VaultItem]) -> VaultResult<BTreeMap<ItemId, ConflictId>> {
    let items = leaf_items(items);
    let mut parent_groups = BTreeMap::<(ItemId, Option<ItemRevision>), Vec<ItemRevision>>::new();
    for item in &items {
        if item.status == ItemStatus::Deleted {
            continue;
        }
        parent_groups
            .entry((item.id.clone(), item.parent_revision.clone()))
            .or_default()
            .push(item.revision.clone());
    }

    let mut conflicts = BTreeMap::new();
    for ((id, _parent), revisions) in parent_groups {
        if revisions.len() > 1 {
            conflicts.insert(id.clone(), ConflictId(format!("conflict_{}", id.0)));
        }
    }
    Ok(conflicts)
}

fn conflicting_revisions(items: &[VaultItem]) -> Vec<ItemRevision> {
    let items = leaf_items(items);
    let mut parent_groups = BTreeMap::<Option<ItemRevision>, Vec<ItemRevision>>::new();
    for item in &items {
        if item.status == ItemStatus::Deleted {
            continue;
        }
        parent_groups
            .entry(item.parent_revision.clone())
            .or_default()
            .push(item.revision.clone());
    }
    parent_groups
        .into_values()
        .filter(|revisions| revisions.len() > 1)
        .flatten()
        .collect()
}

fn leaf_items(items: &[VaultItem]) -> Vec<VaultItem> {
    let parent_revisions = items
        .iter()
        .filter_map(|item| item.parent_revision.clone())
        .collect::<std::collections::BTreeSet<_>>();
    items
        .iter()
        .filter(|item| !parent_revisions.contains(&item.revision))
        .cloned()
        .collect()
}

fn ensure_item_not_conflicted(item: &VaultItem) -> VaultResult<()> {
    if matches!(item.status, ItemStatus::Conflicted(_)) {
        return Err(VaultError::InvalidVault {
            reason: "conflicted items must be resolved before ordinary item changes".to_owned(),
        });
    }
    Ok(())
}

fn ensure_expected_revision(item: &VaultItem, expected_revision: &ItemRevision) -> VaultResult<()> {
    if &item.revision != expected_revision {
        return Err(VaultError::InvalidVault {
            reason: "item changed on disk; refresh sync before editing".to_owned(),
        });
    }
    Ok(())
}

fn ensure_credential_expected_revision(
    revision: &CredentialRevision,
    expected_revision_id: crate::RevisionId,
) -> VaultResult<()> {
    if revision.revision_id() != expected_revision_id {
        return Err(VaultError::InvalidVault {
            reason: "item changed on disk; refresh sync before editing".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    use serde::Deserialize;
    use serde_json::Value;

    use super::{ITEMS_DIR_NAME, TOMBSTONES_DIR_NAME};
    use crate::credential_model::{TEMPLATE_CREDIT_CARD, TEMPLATE_LOGIN, TEMPLATE_SECURE_NOTE};
    use crate::{
        ConflictCandidateCredentialField, ConflictCandidateField, ConflictCandidateSummary,
        ConflictFieldSelection, ConflictId, ConflictMergeRequest, CreateVaultRequest,
        CredentialDraft, CredentialEdit, CredentialField, CredentialFieldEdit, CreditCardItem,
        ExportItemsRequest, ImportCommitRequest, ImportPreviewRequest, ItemId, ItemRevision,
        ItemStatus, LockedVault, LoginItem, OpenVaultRequest, PasswordHealthAudit,
        PasswordHealthIssueKind, RecoverVaultRequest, RejectedSyncRecordFile,
        RejectedSyncRecordKind, RestoreVaultBackupRequest, SearchQuery, SecretBytes,
        SecretFieldKind, SecureNoteItem, SoftwareLicenseItem, UnlockedVault, VaultCore, VaultItem,
        VaultItemContent, VaultItemDraft, VaultMetadata,
    };

    #[test]
    fn lock_returns_locked_vault_with_same_identity() {
        let unlocked = UnlockedVault {
            path: PathBuf::from("/tmp/example.pswvault"),
            metadata: VaultMetadata::current(Some("Example".to_owned())),
            vault_key: crate::SecretBytes::new(vec![7; 32]),
        };

        let locked: LockedVault = unlocked.lock();

        assert_eq!(locked.path, PathBuf::from("/tmp/example.pswvault"));
        assert_eq!(locked.metadata.display_name.as_deref(), Some("Example"));
    }

    #[test]
    fn target_revision_graph_rejects_cycles() {
        let vault_id = crate::VaultId::generate();
        let credential = crate::Credential::with_id(
            vault_id,
            crate::CredentialId::generate(),
            crate::CredentialDraft::from(login_draft("Cycle", "alice", false, vec![])),
        )
        .expect("create credential");
        let first_revision_id = crate::RevisionId::generate();
        let second_revision_id = crate::RevisionId::generate();
        let digest = crate::ContentDigest::for_credential(&credential);
        let first = crate::CredentialRevision::with_metadata_and_lifecycle(
            first_revision_id,
            vec![second_revision_id],
            digest,
            crate::DeviceId::generate(),
            crate::CredentialLifecycle::Active,
            credential.clone(),
        )
        .expect("create first revision");
        let second = crate::CredentialRevision::with_metadata_and_lifecycle(
            second_revision_id,
            vec![first_revision_id],
            digest,
            crate::DeviceId::generate(),
            crate::CredentialLifecycle::Active,
            credential,
        )
        .expect("create second revision");

        let error = super::validate_target_revision_graph(&[first, second])
            .expect_err("cyclic target revision graph must fail closed");

        assert!(matches!(
            error,
            crate::VaultError::InvalidVault { reason }
                if reason == "target revision ancestry contains a cycle"
        ));
    }

    #[test]
    fn target_revision_graph_rejects_cross_credential_parents() {
        let vault_id = crate::VaultId::generate();
        let first_credential = crate::Credential::with_id(
            vault_id,
            crate::CredentialId::generate(),
            crate::CredentialDraft::from(login_draft("First", "alice", false, vec![])),
        )
        .expect("create first credential");
        let second_credential = crate::Credential::with_id(
            vault_id,
            crate::CredentialId::generate(),
            crate::CredentialDraft::from(login_draft("Second", "bob", false, vec![])),
        )
        .expect("create second credential");
        let first =
            crate::CredentialRevision::initial(first_credential, crate::DeviceId::generate())
                .expect("create first revision");
        let second = crate::CredentialRevision::descendant(
            second_credential,
            crate::DeviceId::generate(),
            vec![first.revision_id()],
        )
        .expect("create second revision");

        let error = super::validate_target_revision_graph(&[first, second])
            .expect_err("cross-credential target parent must fail closed");

        assert!(matches!(
            error,
            crate::VaultError::InvalidVault { reason }
                if reason == "target revision parent belongs to another credential"
        ));
    }

    #[test]
    fn current_format_writes_stable_identity_and_revision_ancestry() {
        let temp_dir = unique_temp_dir("current_format_stable_identity");
        let vault_path = temp_dir.join("Current.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let locked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Current".to_owned()),
                master_password: password.clone(),
            })
            .expect("create current vault");
        assert_eq!(locked.metadata.vault_format_version, 2);
        assert_eq!(locked.metadata.record_format_version, 2);
        assert!(locked.metadata.vault_id.is_some());

        let mut unlocked = locked
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock current vault");
        let created = unlocked
            .create_item(login_draft_with_password(
                "Identity",
                "alice",
                "first-secret",
                false,
                vec!["identity"],
            ))
            .expect("create current credential");
        let initial_revision = unlocked
            .target_revisions()
            .expect("load initial revision")
            .pop()
            .expect("initial revision");
        let initial_secret_ids = initial_revision
            .credential()
            .draft()
            .secret_fields()
            .map(|field| field.secret_field_id().expect("secret field identity"))
            .collect::<Vec<_>>();

        let updated = unlocked
            .update_item(
                &created.id,
                login_draft_with_password(
                    "Identity",
                    "alice",
                    "second-secret",
                    true,
                    vec!["identity", "updated"],
                ),
            )
            .expect("update current credential");
        let revisions = unlocked
            .target_revisions()
            .expect("load current revision history");
        assert_eq!(revisions.len(), 2);
        let current_revision = revisions
            .iter()
            .find(|revision| revision.revision_id().to_string() == updated.revision.0)
            .expect("current revision");
        assert_eq!(
            current_revision.parent_revision_ids(),
            &[initial_revision.revision_id()]
        );
        assert_eq!(
            current_revision
                .credential()
                .draft()
                .secret_fields()
                .map(|field| field.secret_field_id().expect("secret field identity"))
                .collect::<Vec<_>>(),
            initial_secret_ids
        );
        assert_eq!(
            current_revision.credential().vault_id(),
            unlocked.metadata.vault_id.expect("metadata vault identity")
        );
        assert_eq!(
            current_revision.credential().credential_id().to_string(),
            created.id.0
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_auto_merges_provably_independent_target_changes() {
        let temp_dir = unique_temp_dir("target_three_way_independent");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut left_draft = base.credential().draft().clone();
        left_draft.title = "Deployment token renamed".to_owned();
        replace_target_test_secret(&mut left_draft, "token", b"left-token");
        let left = target_test_descendant(
            &base,
            left_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );

        let mut right_draft = base.credential().draft().clone();
        right_draft.tags.push("production".to_owned());
        replace_target_test_secret(&mut right_draft, "recovery", b"right-recovery");
        let right = target_test_descendant(
            &base,
            right_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);

        let report = unlocked.refresh_from_disk().expect("refresh and merge");
        assert_eq!(report.detected_conflicts, 0);
        assert_eq!(report.rejected_records, 0);
        assert_eq!(record_file_count(&unlocked.path, "items"), 4);

        let heads = unlocked
            .target_head_revisions()
            .expect("load merged target head");
        assert_eq!(heads.len(), 1);
        let merged = &heads[0];
        let mut expected_parents = vec![left.revision_id(), right.revision_id()];
        expected_parents.sort_unstable();
        assert_eq!(merged.parent_revision_ids(), expected_parents);
        assert_eq!(
            merged.credential().draft().title,
            "Deployment token renamed"
        );
        assert_eq!(
            merged.credential().draft().tags,
            vec!["developer", "production"]
        );
        assert_eq!(
            credential_secret_field(merged.credential().draft(), "token")
                .expect("merged token")
                .2,
            b"left-token"
        );
        assert_eq!(
            credential_secret_field(merged.credential().draft(), "recovery")
                .expect("merged recovery secret")
                .2,
            b"right-recovery"
        );

        let second_report = unlocked.refresh_from_disk().expect("repeat refresh");
        assert_eq!(second_report.detected_conflicts, 0);
        assert_eq!(record_file_count(&unlocked.path, "items"), 4);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_preserves_same_secret_field_changes_as_conflict() {
        let temp_dir = unique_temp_dir("target_three_way_same_secret");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut left_draft = base.credential().draft().clone();
        replace_target_test_secret(&mut left_draft, "token", b"left-token");
        let left = target_test_descendant(
            &base,
            left_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let mut right_draft = base.credential().draft().clone();
        replace_target_test_secret(&mut right_draft, "token", b"right-token");
        let right = target_test_descendant(
            &base,
            right_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );
        let heads = unlocked
            .target_head_revisions()
            .expect("load conflicting heads");
        assert_eq!(heads.len(), 2);
        assert_eq!(
            heads
                .iter()
                .map(crate::CredentialRevision::revision_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([left.revision_id(), right.revision_id()])
        );
        let mut secret_values = heads
            .iter()
            .map(|revision| {
                credential_secret_field(revision.credential().draft(), "token")
                    .expect("conflicting token")
                    .2
                    .to_vec()
            })
            .collect::<Vec<_>>();
        secret_values.sort();
        assert_eq!(
            secret_values,
            vec![b"left-token".to_vec(), b"right-token".to_vec()]
        );
        assert_eq!(record_file_count(&unlocked.path, "items"), 3);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn equal_single_parent_secret_edits_remain_two_conflict_heads() {
        let temp_dir = unique_temp_dir("target_three_way_equal_secret_edits");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut edited_draft = base.credential().draft().clone();
        replace_target_test_secret(&mut edited_draft, "token", b"same-new-token");
        let left = target_test_descendant(
            &base,
            edited_draft.clone(),
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let right = target_test_descendant(
            &base,
            edited_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );
        assert_eq!(
            unlocked
                .target_head_revisions()
                .expect("load equal edit heads")
                .iter()
                .map(crate::CredentialRevision::revision_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([left.revision_id(), right.revision_id()])
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_preserves_same_top_level_component_changes_as_conflict() {
        let temp_dir = unique_temp_dir("target_three_way_same_title");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut left_draft = base.credential().draft().clone();
        left_draft.title = "Left title".to_owned();
        let left = target_test_descendant(
            &base,
            left_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let mut right_draft = base.credential().draft().clone();
        right_draft.title = "Right title".to_owned();
        let right = target_test_descendant(
            &base,
            right_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );
        let heads = unlocked
            .target_head_revisions()
            .expect("load conflicting heads");
        assert_eq!(
            heads
                .iter()
                .map(|revision| revision.credential().draft().title.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["Left title", "Right title"])
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_preserves_delete_edit_conflict_in_both_record_directories() {
        let temp_dir = unique_temp_dir("target_three_way_delete_edit");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let credential_id = created.credential.credential_id;
        let base = unlocked
            .credential_revision(credential_id)
            .expect("load base revision");

        let mut edited_draft = base.credential().draft().clone();
        edited_draft.title = "Edited while deleting".to_owned();
        replace_target_test_secret(&mut edited_draft, "token", b"edited-token");
        let edited = target_test_descendant(
            &base,
            edited_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let deleted = target_test_descendant(
            &base,
            base.credential().draft().clone(),
            vec![base.revision_id()],
            crate::CredentialLifecycle::Deleted,
        );
        write_target_test_revision(&unlocked, &edited);
        write_target_test_revision(&unlocked, &deleted);
        let items_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));
        let tombstones_before =
            encrypted_directory_snapshot(&unlocked.path.join(TOMBSTONES_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            items_before
        );
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(TOMBSTONES_DIR_NAME)),
            tombstones_before
        );
        let heads = unlocked
            .target_head_revisions()
            .expect("load delete-edit heads");
        assert_eq!(heads.len(), 2);
        assert_eq!(
            heads
                .iter()
                .map(crate::CredentialRevision::revision_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([edited.revision_id(), deleted.revision_id()])
        );
        assert!(heads
            .iter()
            .any(|revision| revision.lifecycle() == crate::CredentialLifecycle::Active));
        assert!(heads
            .iter()
            .any(|revision| revision.lifecycle() == crate::CredentialLifecycle::Deleted));
        let listed = unlocked
            .list_credential_items(false)
            .expect("list delete-edit conflict");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].credential.credential_id, credential_id);
        assert!(matches!(listed[0].status, ItemStatus::Conflicted(_)));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn typed_conflict_candidates_redact_secrets_and_resolve_complete_custom_revision() {
        let temp_dir = unique_temp_dir("typed_conflict_candidates");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let credential_id = created.credential.credential_id;
        let base = unlocked
            .credential_revision(credential_id)
            .expect("load base revision");

        let mut left_draft = base.credential().draft().clone();
        left_draft.title = "Left deployment token".to_owned();
        replace_target_test_secret(&mut left_draft, "token", b"left-private-token");
        let left = target_test_descendant(
            &base,
            left_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let mut right_draft = base.credential().draft().clone();
        right_draft.title = "Right deployment token".to_owned();
        replace_target_test_secret(&mut right_draft, "token", b"right-private-token");
        let right = target_test_descendant(
            &base,
            right_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);
        unlocked.refresh_from_disk().expect("refresh conflict");
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));
        let conflict_id = ConflictId(format!("conflict_{credential_id}"));

        let candidates = unlocked
            .conflict_candidates(&conflict_id)
            .expect("load typed conflict candidates");
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.supports_safe_field_merge));
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.field_shape_changed));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.template_id.as_deref() == Some("api-token")));
        for candidate in &candidates {
            assert!(candidate.changed_fields.contains(&"title".to_owned()));
            assert!(candidate.changed_fields.contains(&"fields".to_owned()));
            let token = candidate
                .credential_fields
                .iter()
                .find(|field| {
                    matches!(
                        field,
                        ConflictCandidateCredentialField::Secret { role, .. }
                            if role == "token"
                    )
                })
                .expect("typed token field");
            assert!(matches!(
                token,
                ConflictCandidateCredentialField::Secret {
                    secret_kind: SecretFieldKind::ApiToken,
                    has_value: true,
                    changed: true,
                    ..
                }
            ));
            let debug = format!("{candidate:?}");
            assert!(!debug.contains("left-private-token"));
            assert!(!debug.contains("right-private-token"));
        }

        let stale_error = unlocked
            .resolve_credential_conflict_candidate(
                &conflict_id,
                &ItemRevision(base.revision_id().to_string()),
            )
            .expect_err("non-head candidate must be rejected");
        assert!(matches!(
            stale_error,
            crate::VaultError::ItemNotFound { .. }
        ));
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );

        let resolved = unlocked
            .resolve_credential_conflict_candidate(
                &conflict_id,
                &ItemRevision(left.revision_id().to_string()),
            )
            .expect("resolve selected typed conflict candidate");
        assert!(resolved.revision_id.to_string().starts_with("revision_"));
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("refresh resolved conflict")
                .detected_conflicts,
            0
        );
        let current = unlocked
            .credential_revision(credential_id)
            .expect("load resolved typed credential");
        assert_eq!(
            current
                .parent_revision_ids()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([left.revision_id(), right.revision_id()])
        );
        assert_eq!(
            credential_secret_field(current.credential().draft(), "token")
                .expect("resolved token")
                .2,
            b"left-private-token"
        );
        let encrypted_after = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));
        assert_eq!(encrypted_after.len(), encrypted_before.len() + 1);
        assert!(encrypted_before
            .iter()
            .all(|record| encrypted_after.contains(record)));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn typed_conflict_candidates_include_and_can_keep_deleted_revision() {
        let temp_dir = unique_temp_dir("typed_delete_conflict_candidates");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let credential_id = created.credential.credential_id;
        let base = unlocked
            .credential_revision(credential_id)
            .expect("load base revision");

        let mut edited_draft = base.credential().draft().clone();
        edited_draft.title = "Edited deployment token".to_owned();
        let edited = target_test_descendant(
            &base,
            edited_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let deleted = target_test_descendant(
            &base,
            base.credential().draft().clone(),
            vec![base.revision_id()],
            crate::CredentialLifecycle::Deleted,
        );
        write_target_test_revision(&unlocked, &edited);
        write_target_test_revision(&unlocked, &deleted);
        unlocked.refresh_from_disk().expect("refresh conflict");
        let conflict_id = ConflictId(format!("conflict_{credential_id}"));
        let items_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));
        let tombstones_before =
            encrypted_directory_snapshot(&unlocked.path.join(TOMBSTONES_DIR_NAME));

        let candidates = unlocked
            .conflict_candidates(&conflict_id)
            .expect("load delete-edit candidates");
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .any(|candidate| candidate.status == "active"));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.status == "deleted"));
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.supports_safe_field_merge));

        let resolved = unlocked
            .resolve_credential_conflict_candidate(
                &conflict_id,
                &ItemRevision(deleted.revision_id().to_string()),
            )
            .expect("keep deleted conflict candidate");
        assert_eq!(resolved.status, ItemStatus::Deleted);
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("refresh deleted resolution")
                .detected_conflicts,
            0
        );
        assert!(unlocked
            .list_credential_items(false)
            .expect("list after deleted resolution")
            .is_empty());
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            items_before
        );
        let tombstones_after =
            encrypted_directory_snapshot(&unlocked.path.join(TOMBSTONES_DIR_NAME));
        assert_eq!(tombstones_after.len(), tombstones_before.len() + 1);
        assert!(tombstones_before
            .iter()
            .all(|record| tombstones_after.contains(record)));
        let head = unlocked
            .target_head_revisions()
            .expect("load deleted resolution head")
            .pop()
            .expect("deleted resolution head");
        assert_eq!(head.lifecycle(), crate::CredentialLifecycle::Deleted);
        assert_eq!(
            head.parent_revision_ids()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([edited.revision_id(), deleted.revision_id()])
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn typed_conflict_candidates_report_reordered_text_field_layout() {
        let temp_dir = unique_temp_dir("typed_conflict_field_layout");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let credential_id = created.credential.credential_id;
        let base = unlocked
            .credential_revision(credential_id)
            .expect("load base revision");

        let mut left_draft = base.credential().draft().clone();
        replace_target_test_secret(&mut left_draft, "token", b"left-layout-token");
        let left = target_test_descendant(
            &base,
            left_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let mut right_draft = base.credential().draft().clone();
        right_draft.fields.swap(0, 1);
        let right = target_test_descendant(
            &base,
            right_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);

        let report = unlocked
            .refresh_from_disk()
            .expect("refresh field layout conflict");
        assert_eq!(report.detected_conflicts, 1);
        let candidates = unlocked
            .conflict_candidates(&ConflictId(format!("conflict_{credential_id}")))
            .expect("load field layout candidates");
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.field_shape_changed));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.changed_fields.contains(&"fields".to_owned())));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_preserves_concurrent_text_field_changes_without_stable_ids() {
        let temp_dir = unique_temp_dir("target_three_way_text_fields");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut left_draft = base.credential().draft().clone();
        let crate::CredentialFieldValue::Text { text } = &mut left_draft.fields[0].value else {
            panic!("expected account text field");
        };
        *text = "left-account".to_owned();
        let left = target_test_descendant(
            &base,
            left_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );

        let mut right_draft = base.credential().draft().clone();
        let crate::CredentialFieldValue::Text { text } = &mut right_draft.fields[1].value else {
            panic!("expected endpoint text field");
        };
        *text = "https://right.example.test".to_owned();
        let right = target_test_descendant(
            &base,
            right_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );
        assert_eq!(record_file_count(&unlocked.path, "items"), 3);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_preserves_independent_changes_when_common_base_is_missing() {
        let temp_dir = unique_temp_dir("target_three_way_missing_base");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let vault_id = unlocked.metadata.vault_id.expect("target vault identity");
        let credential_id = crate::CredentialId::generate();
        let missing_parent = crate::RevisionId::generate();

        let mut left_draft = target_merge_test_draft();
        left_draft.title = "Missing base left".to_owned();
        let left_credential = crate::Credential::with_id(vault_id, credential_id, left_draft)
            .expect("create left credential");
        let left = crate::CredentialRevision::descendant(
            left_credential,
            crate::DeviceId::generate(),
            vec![missing_parent],
        )
        .expect("create left revision");

        let mut right_draft = target_merge_test_draft();
        right_draft.tags.push("right".to_owned());
        let right_credential = crate::Credential::with_id(vault_id, credential_id, right_draft)
            .expect("create right credential");
        let right = crate::CredentialRevision::descendant(
            right_credential,
            crate::DeviceId::generate(),
            vec![missing_parent],
        )
        .expect("create right revision");
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(report.loaded_items, 2);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );
        assert_eq!(
            unlocked
                .target_head_revisions()
                .expect("load missing-base heads")
                .iter()
                .map(crate::CredentialRevision::revision_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([left.revision_id(), right.revision_id()])
        );
        assert_eq!(record_file_count(&unlocked.path, "items"), 2);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_preserves_changes_when_common_base_is_ambiguous() {
        let temp_dir = unique_temp_dir("target_three_way_ambiguous_base");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut first_base_draft = base.credential().draft().clone();
        first_base_draft.title = "First possible base".to_owned();
        let first_base = target_test_descendant(
            &base,
            first_base_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let mut second_base_draft = base.credential().draft().clone();
        second_base_draft.tags.push("second-base".to_owned());
        let second_base = target_test_descendant(
            &base,
            second_base_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let parents = vec![first_base.revision_id(), second_base.revision_id()];
        let mut left_draft = first_base.credential().draft().clone();
        left_draft.favorite = true;
        let left = target_test_descendant(
            &first_base,
            left_draft,
            parents.clone(),
            crate::CredentialLifecycle::Active,
        );
        let mut right_draft = second_base.credential().draft().clone();
        replace_target_test_secret(&mut right_draft, "recovery", b"ambiguous-right");
        let right = target_test_descendant(
            &second_base,
            right_draft,
            parents,
            crate::CredentialLifecycle::Active,
        );
        for revision in [&first_base, &second_base, &left, &right] {
            write_target_test_revision(&unlocked, revision);
        }
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );
        assert_eq!(
            unlocked
                .target_head_revisions()
                .expect("load ambiguous-base heads")
                .iter()
                .map(crate::CredentialRevision::revision_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([left.revision_id(), right.revision_id()])
        );
        assert_eq!(record_file_count(&unlocked.path, "items"), 5);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_preserves_all_three_concurrent_heads_without_guessing() {
        let temp_dir = unique_temp_dir("target_three_way_three_heads");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut revisions = Vec::new();
        for (title, role, replacement) in [
            ("First head", "token", b"first".as_slice()),
            ("Second head", "recovery", b"second".as_slice()),
            ("Third head", "token", b"third".as_slice()),
        ] {
            let mut draft = base.credential().draft().clone();
            draft.title = title.to_owned();
            replace_target_test_secret(&mut draft, role, replacement);
            let revision = target_test_descendant(
                &base,
                draft,
                vec![base.revision_id()],
                crate::CredentialLifecycle::Active,
            );
            write_target_test_revision(&unlocked, &revision);
            revisions.push(revision);
        }
        let encrypted_before = encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME));

        let report = unlocked.refresh_from_disk().expect("refresh conflict");
        assert_eq!(report.detected_conflicts, 1);
        assert_eq!(
            encrypted_directory_snapshot(&unlocked.path.join(ITEMS_DIR_NAME)),
            encrypted_before
        );
        assert_eq!(
            unlocked
                .target_head_revisions()
                .expect("load all three heads")
                .iter()
                .map(crate::CredentialRevision::revision_id)
                .collect::<BTreeSet<_>>(),
            revisions
                .iter()
                .map(crate::CredentialRevision::revision_id)
                .collect::<BTreeSet<_>>()
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn equivalent_independent_merge_revisions_converge_to_one_logical_head() {
        let temp_dir = unique_temp_dir("target_equivalent_merge_convergence");
        let mut unlocked = create_target_merge_test_vault(&temp_dir);
        let created = unlocked
            .create_credential(target_merge_test_draft())
            .expect("create credential");
        let base = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("load base revision");

        let mut left_draft = base.credential().draft().clone();
        left_draft.title = "Converged title".to_owned();
        let left = target_test_descendant(
            &base,
            left_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        let mut right_draft = base.credential().draft().clone();
        right_draft.tags.push("converged-tag".to_owned());
        let right = target_test_descendant(
            &base,
            right_draft,
            vec![base.revision_id()],
            crate::CredentialLifecycle::Active,
        );
        write_target_test_revision(&unlocked, &left);
        write_target_test_revision(&unlocked, &right);
        unlocked.refresh_from_disk().expect("create first merge");
        let first_merge = unlocked
            .target_head_revisions()
            .expect("load first merge")
            .pop()
            .expect("first merge revision");
        let duplicate_merge = target_test_descendant(
            &first_merge,
            first_merge.credential().draft().clone(),
            first_merge.parent_revision_ids().to_vec(),
            first_merge.lifecycle(),
        );
        write_target_test_revision(&unlocked, &duplicate_merge);

        let report = unlocked.refresh_from_disk().expect("normalize merge heads");
        assert_eq!(report.detected_conflicts, 0);
        let revisions = unlocked.target_revisions().expect("load all revisions");
        assert_eq!(super::raw_target_head_revision_ids(&revisions).len(), 2);
        let logical_head = unlocked
            .target_head_revisions()
            .expect("load canonical logical head")
            .pop()
            .expect("canonical logical head");

        let mut descendant_draft = logical_head.credential().draft().clone();
        descendant_draft.favorite = true;
        let descendant = target_test_descendant(
            &logical_head,
            descendant_draft,
            vec![logical_head.revision_id()],
            logical_head.lifecycle(),
        );
        write_target_test_revision(&unlocked, &descendant);

        let report = unlocked
            .refresh_from_disk()
            .expect("normalize alternate merge ancestor");
        assert_eq!(report.detected_conflicts, 0);
        let logical_heads = unlocked
            .target_head_revisions()
            .expect("load descendant logical head");
        assert_eq!(logical_heads.len(), 1);
        assert_eq!(logical_heads[0].revision_id(), descendant.revision_id());
        assert_eq!(record_file_count(&unlocked.path, "items"), 6);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn stable_credential_summary_returns_only_one_active_identity_without_secrets() {
        let temp_dir = unique_temp_dir("stable_credential_summary");
        let vault_path = temp_dir.join("Summary.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Summary".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock");
        let authorized = unlocked
            .create_item(login_draft_with_password(
                "Authorized credential",
                "alice",
                "authorized-secret",
                false,
                vec!["private-tag"],
            ))
            .expect("authorized credential");
        unlocked
            .create_item(login_draft_with_password(
                "Unrelated credential",
                "bob",
                "unrelated-secret",
                false,
                vec!["other"],
            ))
            .expect("unrelated credential");
        let credential_id = authorized.id.0.parse().expect("stable credential ID");

        let summary = unlocked
            .credential_summary(credential_id)
            .expect("summary")
            .expect("active credential");
        assert_eq!(summary.credential_id, credential_id);
        assert_eq!(summary.title, "Authorized credential");
        assert_eq!(summary.secret_fields.len(), 2);
        let serialized = serde_json::to_string(&summary).expect("serialize summary");
        assert!(!serialized.contains("authorized-secret"));
        assert!(!serialized.contains("unrelated-secret"));
        assert!(!serialized.contains("Unrelated credential"));
        assert!(unlocked
            .credential_summary(crate::CredentialId::generate())
            .expect("unknown lookup")
            .is_none());

        unlocked
            .archive_item(&authorized.id)
            .expect("archive credential");
        assert!(unlocked
            .credential_summary(credential_id)
            .expect("archived lookup")
            .is_none());
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn exact_active_secret_field_lookup_requires_every_identity_and_kind() {
        let temp_dir = unique_temp_dir("exact_active_secret_field");
        let vault_path = temp_dir.join("SecretField.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Secret field".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock");
        let secret_marker = b"KN_CORE_EXACT_SECRET_85";
        let created = unlocked
            .create_credential(CredentialDraft {
                title: "Release token".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![CredentialField::secret(
                    "token",
                    SecretFieldKind::ApiToken,
                    SecretBytes::new(secret_marker.to_vec()),
                )],
                tags: Vec::new(),
                favorite: false,
            })
            .expect("create credential");
        let credential_id = created.credential.credential_id;
        let secret_field_id = created.credential.secret_fields[0].secret_field_id;

        let secret = unlocked
            .credential_secret_field(credential_id, secret_field_id, SecretFieldKind::ApiToken)
            .expect("lookup")
            .expect("exact field");
        assert_eq!(secret.expose(), secret_marker);
        assert!(unlocked
            .credential_secret_field(credential_id, secret_field_id, SecretFieldKind::ApiKey,)
            .expect("wrong kind")
            .is_none());
        assert!(unlocked
            .credential_secret_field(
                credential_id,
                crate::SecretFieldId::generate(),
                SecretFieldKind::ApiToken,
            )
            .expect("wrong field")
            .is_none());
        assert!(unlocked
            .credential_secret_field(
                crate::CredentialId::generate(),
                secret_field_id,
                SecretFieldKind::ApiToken,
            )
            .expect("wrong credential")
            .is_none());

        unlocked
            .archive_credential_with_expected_revision(credential_id, created.revision_id)
            .expect("archive");
        assert!(unlocked
            .credential_secret_field(credential_id, secret_field_id, SecretFieldKind::ApiToken,)
            .expect("archived lookup")
            .is_none());
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn generic_credential_creation_round_trips_without_legacy_conversion() {
        let temp_dir = unique_temp_dir("generic_credential_creation");
        let vault_path = temp_dir.join("Generic.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Generic".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let secret_marker = "generic-api-token-secret-marker";
        let created = unlocked
            .create_credential(CredentialDraft {
                title: "Build automation".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![
                    CredentialField::secret(
                        "token",
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(secret_marker.as_bytes().to_vec()),
                    ),
                    CredentialField::text("expiry", "2028-06-30"),
                    CredentialField::text("notes", "Rotated by the account owner"),
                ],
                tags: vec!["development".to_owned()],
                favorite: true,
            })
            .expect("create generic credential");

        assert_eq!(created.credential.template_id.as_deref(), Some("api-token"));
        assert_eq!(created.credential.secret_fields.len(), 1);
        assert_eq!(
            created.credential.secret_fields[0].kind,
            SecretFieldKind::ApiToken
        );
        let serialized = serde_json::to_string(&created.credential).expect("serialize summary");
        assert!(!serialized.contains(secret_marker));
        assert!(!serialized.contains("2028-06-30"));

        let listed = unlocked
            .list_credential_items(false)
            .expect("list credentials");
        assert_eq!(listed, vec![created.clone()]);
        let matched = unlocked
            .search_credential_items(SearchQuery {
                text: "account owner".to_owned(),
                include_archived: false,
            })
            .expect("search credentials");
        assert_eq!(matched, vec![created.clone()]);
        let secret_search = unlocked
            .search_credential_items(SearchQuery {
                text: secret_marker.to_owned(),
                include_archived: false,
            })
            .expect("search secret marker");
        assert!(secret_search.is_empty());

        let detail = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("credential detail");
        assert_eq!(detail.revision_id(), created.revision_id);
        assert_eq!(
            detail.credential().draft().template_id.as_deref(),
            Some("api-token")
        );
        let reopened = unlocked.lock().unlock(crate::UnlockRequest {
            master_password: password,
        });
        let reopened = reopened.expect("reopen vault");
        assert_eq!(
            reopened
                .list_credential_items(false)
                .expect("list reopened credentials"),
            vec![created]
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn field_aware_credential_edit_preserves_replaces_adds_and_removes_secret_identities() {
        let temp_dir = unique_temp_dir("field_aware_credential_edit");
        let vault_path = temp_dir.join("FieldAware.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Field Aware".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock");
        let original_secret_field_id = crate::SecretFieldId::generate();
        let created = unlocked
            .create_credential(CredentialDraft {
                title: "Build API".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![
                    CredentialField::text("account", "chase"),
                    CredentialField::secret_with_id(
                        "token",
                        original_secret_field_id,
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"saved-secret-marker".to_vec()),
                    ),
                ],
                tags: vec!["development".to_owned()],
                favorite: false,
            })
            .expect("create credential");

        let prepared = unlocked
            .prepare_credential_update(
                created.credential.credential_id,
                created.revision_id,
                CredentialEdit {
                    title: "Build API renamed".to_owned(),
                    template_id: created.credential.template_id.clone(),
                    fields: vec![
                        CredentialFieldEdit::ExistingSecret {
                            role: "access-token".to_owned(),
                            label: Some("Build token".to_owned()),
                            secret_field_id: original_secret_field_id,
                            replacement: None,
                        },
                        CredentialFieldEdit::Text {
                            role: "account".to_owned(),
                            label: None,
                            text: "chasechou007".to_owned(),
                        },
                        CredentialFieldEdit::NewSecret {
                            role: "fallback".to_owned(),
                            label: Some("Fallback secret".to_owned()),
                            kind: SecretFieldKind::GenericSecret,
                            secret: SecretBytes::new(b"new-secret-marker".to_vec()),
                        },
                    ],
                    tags: vec!["development".to_owned(), "automation".to_owned()],
                    favorite: true,
                },
            )
            .expect("prepare edit");
        assert!(prepared.removed_secret_field_ids().is_empty());
        assert_eq!(prepared.credential_id(), created.credential.credential_id);
        let updated = unlocked
            .commit_credential_update(prepared)
            .expect("commit edit");
        assert_eq!(
            updated.credential.credential_id,
            created.credential.credential_id
        );
        assert_eq!(
            updated.credential.secret_fields[0].secret_field_id,
            original_secret_field_id
        );
        let added_secret_field_id = updated.credential.secret_fields[1].secret_field_id;
        assert_ne!(added_secret_field_id, original_secret_field_id);

        let detail = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("updated detail");
        assert_eq!(detail.credential().draft().title, "Build API renamed");
        assert_eq!(
            detail
                .credential()
                .draft()
                .fields
                .iter()
                .map(|field| field.role.as_str())
                .collect::<Vec<_>>(),
            vec!["access-token", "account", "fallback"]
        );
        let original_secret = detail
            .credential()
            .draft()
            .fields
            .iter()
            .find_map(|field| match &field.value {
                crate::CredentialFieldValue::Secret {
                    secret_field_id,
                    kind,
                    secret,
                } if *secret_field_id == original_secret_field_id => {
                    Some((*kind, secret.expose().to_vec()))
                }
                _ => None,
            })
            .expect("preserved secret");
        assert_eq!(original_secret.0, SecretFieldKind::ApiToken);
        assert_eq!(original_secret.1, b"saved-secret-marker");

        let prepared = unlocked
            .prepare_credential_update(
                created.credential.credential_id,
                updated.revision_id,
                CredentialEdit {
                    title: "Build API renamed".to_owned(),
                    template_id: updated.credential.template_id.clone(),
                    fields: vec![CredentialFieldEdit::ExistingSecret {
                        role: "access-token".to_owned(),
                        label: Some("Renamed token".to_owned()),
                        secret_field_id: original_secret_field_id,
                        replacement: Some(SecretBytes::new(b"replacement-secret-marker".to_vec())),
                    }],
                    tags: Vec::new(),
                    favorite: false,
                },
            )
            .expect("prepare replacement");
        assert_eq!(
            prepared.removed_secret_field_ids(),
            &[added_secret_field_id]
        );
        let replaced = unlocked
            .commit_credential_update(prepared)
            .expect("commit replacement");
        let detail = unlocked
            .credential_revision(created.credential.credential_id)
            .expect("replacement detail");
        let secret_fields = detail
            .credential()
            .draft()
            .secret_fields()
            .collect::<Vec<_>>();
        assert_eq!(secret_fields.len(), 1);
        assert_eq!(
            secret_fields[0].secret_field_id(),
            Some(original_secret_field_id)
        );
        assert!(matches!(
            &secret_fields[0].value,
            crate::CredentialFieldValue::Secret { secret, .. }
                if secret.expose() == b"replacement-secret-marker"
        ));

        let stale_error = match unlocked.prepare_credential_update(
            created.credential.credential_id,
            updated.revision_id,
            CredentialEdit {
                title: "Stale".to_owned(),
                template_id: None,
                fields: Vec::new(),
                tags: Vec::new(),
                favorite: false,
            },
        ) {
            Ok(_) => panic!("stale edit must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            stale_error,
            crate::VaultError::InvalidVault { reason }
                if reason == "item changed on disk; refresh sync before editing"
        ));
        assert_eq!(
            unlocked
                .credential_revision(created.credential.credential_id)
                .expect("current detail")
                .revision_id(),
            replaced.revision_id
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn generic_credential_lifecycle_preserves_identity_except_for_safe_duplicates() {
        let temp_dir = unique_temp_dir("generic_credential_lifecycle");
        let vault_path = temp_dir.join("Lifecycle.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Lifecycle".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock");
        let created = unlocked
            .create_credential(CredentialDraft {
                title: "Deployment credentials".to_owned(),
                template_id: Some("custom".to_owned()),
                fields: vec![
                    CredentialField::text("account", "release-bot"),
                    CredentialField::secret(
                        "token",
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(b"deployment-token-marker".to_vec()),
                    ),
                    CredentialField::secret(
                        "password",
                        SecretFieldKind::Password,
                        SecretBytes::new(b"deployment-password-marker".to_vec()),
                    ),
                ],
                tags: vec!["deployment".to_owned()],
                favorite: false,
            })
            .expect("create credential");
        let credential_id = created.credential.credential_id;
        let original_detail = unlocked
            .credential_revision(credential_id)
            .expect("original detail");
        let original_secret_fields = original_detail
            .credential()
            .draft()
            .secret_fields()
            .map(|field| {
                let crate::CredentialFieldValue::Secret {
                    secret_field_id,
                    secret,
                    ..
                } = &field.value
                else {
                    unreachable!("secret_fields only returns secret values");
                };
                (*secret_field_id, secret.expose().to_vec())
            })
            .collect::<Vec<_>>();

        let favorited = unlocked
            .set_credential_favorite_with_expected_revision(
                credential_id,
                created.revision_id,
                true,
            )
            .expect("favorite credential");
        assert!(favorited.credential.favorite);
        let favorited_detail = unlocked
            .credential_revision(credential_id)
            .expect("favorited detail");
        assert_eq!(
            favorited_detail
                .credential()
                .draft()
                .secret_fields()
                .map(|field| field.secret_field_id().expect("secret field identity"))
                .collect::<Vec<_>>(),
            original_secret_fields
                .iter()
                .map(|(field_id, _)| *field_id)
                .collect::<Vec<_>>()
        );
        let stale_error = unlocked
            .set_credential_favorite_with_expected_revision(
                credential_id,
                created.revision_id,
                false,
            )
            .expect_err("stale favorite must fail");
        assert!(matches!(
            stale_error,
            crate::VaultError::InvalidVault { reason }
                if reason == "item changed on disk; refresh sync before editing"
        ));

        let duplicate = unlocked
            .duplicate_credential_with_expected_revision(
                credential_id,
                favorited.revision_id,
                "Deployment credentials copy".to_owned(),
            )
            .expect("duplicate credential");
        assert_ne!(duplicate.credential.credential_id, credential_id);
        let duplicate_detail = unlocked
            .credential_revision(duplicate.credential.credential_id)
            .expect("duplicate detail");
        let duplicate_secret_fields = duplicate_detail
            .credential()
            .draft()
            .secret_fields()
            .map(|field| {
                let crate::CredentialFieldValue::Secret {
                    secret_field_id,
                    secret,
                    ..
                } = &field.value
                else {
                    unreachable!("secret_fields only returns secret values");
                };
                (*secret_field_id, secret.expose().to_vec())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            duplicate_secret_fields
                .iter()
                .map(|(_, secret)| secret)
                .collect::<Vec<_>>(),
            original_secret_fields
                .iter()
                .map(|(_, secret)| secret)
                .collect::<Vec<_>>()
        );
        assert!(duplicate_secret_fields.iter().all(|(duplicate_id, _)| {
            original_secret_fields
                .iter()
                .all(|(original_id, _)| duplicate_id != original_id)
        }));

        let archived = unlocked
            .archive_credential_with_expected_revision(credential_id, favorited.revision_id)
            .expect("archive credential");
        assert_eq!(archived.status, ItemStatus::Archived);
        let archived_detail = unlocked
            .credential_revision(credential_id)
            .expect("archived detail");
        assert_eq!(
            archived_detail.lifecycle(),
            crate::CredentialLifecycle::Archived
        );
        assert_eq!(
            archived_detail
                .credential()
                .draft()
                .secret_fields()
                .map(|field| field.secret_field_id().expect("secret field identity"))
                .collect::<Vec<_>>(),
            original_secret_fields
                .iter()
                .map(|(field_id, _)| *field_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            unlocked
                .list_credential_items(false)
                .expect("list active credentials")
                .iter()
                .map(|item| item.credential.credential_id)
                .collect::<Vec<_>>(),
            vec![duplicate.credential.credential_id]
        );

        let restored = unlocked
            .restore_credential(credential_id)
            .expect("restore credential");
        assert_eq!(restored.status, ItemStatus::Active);
        unlocked
            .delete_credential_with_expected_revision(credential_id, restored.revision_id)
            .expect("delete credential");
        assert!(matches!(
            unlocked.credential_revision(credential_id),
            Err(crate::VaultError::ItemNotFound { .. })
        ));
        assert_eq!(
            unlocked
                .list_credential_items(true)
                .expect("list remaining credentials")
                .iter()
                .map(|item| item.credential.credential_id)
                .collect::<Vec<_>>(),
            vec![duplicate.credential.credential_id]
        );
        let deleted_head = unlocked
            .target_head_revisions()
            .expect("target heads")
            .into_iter()
            .find(|revision| revision.credential().credential_id() == credential_id)
            .expect("deleted head");
        assert_eq!(
            deleted_head.lifecycle(),
            crate::CredentialLifecycle::Deleted
        );
        assert_eq!(
            deleted_head
                .credential()
                .draft()
                .secret_fields()
                .map(|field| field.secret_field_id().expect("secret field identity"))
                .collect::<Vec<_>>(),
            original_secret_fields
                .iter()
                .map(|(field_id, _)| *field_id)
                .collect::<Vec<_>>()
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn generic_credential_creation_rejects_empty_identity_hints() {
        let temp_dir = unique_temp_dir("generic_credential_validation");
        let vault_path = temp_dir.join("Validation.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Validation".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");

        for draft in [
            CredentialDraft {
                title: "  ".to_owned(),
                template_id: Some("custom".to_owned()),
                fields: Vec::new(),
                tags: Vec::new(),
                favorite: false,
            },
            CredentialDraft {
                title: "Custom".to_owned(),
                template_id: Some(" ".to_owned()),
                fields: Vec::new(),
                tags: Vec::new(),
                favorite: false,
            },
            CredentialDraft {
                title: "Custom".to_owned(),
                template_id: Some("custom".to_owned()),
                fields: vec![CredentialField::text(" ", "value")],
                tags: Vec::new(),
                favorite: false,
            },
        ] {
            assert!(unlocked.create_credential(draft).is_err());
        }
        assert!(unlocked
            .list_credential_items(false)
            .expect("list credentials")
            .is_empty());

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn active_credential_summaries_are_sorted_and_exclude_non_active_content() {
        let temp_dir = unique_temp_dir("active_credential_summaries");
        let vault_path = temp_dir.join("Candidates.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Candidates".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock");
        unlocked
            .create_item(login_draft_with_password(
                "Zulu",
                "zulu-user",
                "zulu-secret",
                false,
                vec!["last"],
            ))
            .expect("zulu");
        let archived = unlocked
            .create_item(login_draft_with_password(
                "Archived",
                "archived-user",
                "archived-secret",
                false,
                vec!["hidden"],
            ))
            .expect("archived");
        unlocked
            .create_item(login_draft_with_password(
                "alpha",
                "alpha-user",
                "alpha-secret",
                false,
                vec!["first"],
            ))
            .expect("alpha");
        unlocked.archive_item(&archived.id).expect("archive");

        let summaries = unlocked
            .active_credential_summaries()
            .expect("active summaries");
        assert_eq!(
            summaries
                .iter()
                .map(|summary| summary.title.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "Zulu"]
        );
        let serialized = serde_json::to_string(&summaries).expect("serialize summaries");
        for excluded in ["alpha-secret", "zulu-secret", "archived-secret", "Archived"] {
            assert!(!serialized.contains(excluded));
        }
        let username_match = unlocked
            .active_credential_summaries_matching("alpha-user")
            .expect("username match");
        assert_eq!(username_match.len(), 1);
        assert_eq!(username_match[0].title, "alpha");
        assert!(unlocked
            .active_credential_summaries_matching("alpha-secret")
            .expect("secret query")
            .is_empty());
        assert!(unlocked
            .active_credential_summaries_matching("archived-user")
            .expect("archived query")
            .is_empty());

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn local_unlock_material_reopens_vault_without_master_password() {
        let temp_dir = unique_temp_dir("local_unlock_material_reopens_vault");
        let vault_path = temp_dir.join("LocalUnlock.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Local Unlock".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");

        let local_unlock_material = unlocked
            .local_unlock_material()
            .expect("create local unlock material");
        assert_ne!(local_unlock_material.expose(), password.expose());
        assert_ne!(local_unlock_material.expose(), unlocked.vault_key.expose());
        assert!(vault_path.join("local_unlock.enc").is_file());

        let reopened = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open vault")
            .unlock_with_local_material(local_unlock_material)
            .expect("unlock with local material");

        assert_eq!(
            reopened.metadata.display_name.as_deref(),
            Some("Local Unlock")
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn local_unlock_material_requires_matching_envelope() {
        let temp_dir = unique_temp_dir("local_unlock_material_requires_envelope");
        let vault_path = temp_dir.join("LocalUnlock.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Local Unlock".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");

        let local_unlock_material = unlocked
            .local_unlock_material()
            .expect("create local unlock material");
        fs::remove_file(vault_path.join("local_unlock.enc")).expect("remove envelope");

        let error = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open vault")
            .unlock_with_local_material(local_unlock_material)
            .expect_err("missing envelope");

        assert!(matches!(error, crate::VaultError::Io { .. }));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn local_unlock_material_rejects_invalid_length() {
        let locked = LockedVault {
            path: PathBuf::from("/tmp/example.pswvault"),
            metadata: VaultMetadata::current(Some("Example".to_owned())),
        };

        let error = locked
            .unlock_with_local_material(SecretBytes::new(vec![1; 8]))
            .expect_err("invalid local unlock material");

        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));
    }

    #[test]
    fn encrypted_backup_copies_portable_vault_without_local_unlock_material() {
        let temp_dir = unique_temp_dir("encrypted_backup_copies_portable_vault");
        let vault_path = temp_dir.join("Source.pswvault");
        let backup_path = temp_dir.join("Backup.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());

        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Backup Source".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Email", "alice", false, vec!["personal"]))
            .expect("create item");
        fs::write(
            vault_path.join("attachments").join("receipt.bin"),
            b"attachment",
        )
        .expect("write attachment");
        unlocked
            .local_unlock_material()
            .expect("create local unlock material");
        assert!(vault_path.join("local_unlock.enc").is_file());
        let _recovery_key = install_test_recovery(&unlocked);
        let recovery_envelope =
            fs::read(vault_path.join("recovery.enc")).expect("read recovery envelope");

        let backup = unlocked
            .backup_to(backup_path.clone())
            .expect("backup vault");

        assert_eq!(backup.copied_item_files, 1);
        assert_eq!(backup.copied_attachment_files, 1);
        assert_eq!(backup.copied_tombstone_files, 0);
        assert!(backup_path.join("vault.json").is_file());
        assert!(backup_path.join("keys.enc").is_file());
        assert_eq!(
            fs::read(backup_path.join("recovery.enc")).expect("read backup recovery envelope"),
            recovery_envelope
        );
        assert!(backup_path.join("items").is_dir());
        assert!(backup_path
            .join("attachments")
            .join("receipt.bin")
            .is_file());
        assert!(backup_path.join("tombstones").is_dir());
        assert!(!backup_path.join("local_unlock.enc").exists());

        let reopened_backup = core
            .open_vault(OpenVaultRequest {
                path: backup_path.clone(),
            })
            .expect("open backup")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock backup");
        let items = reopened_backup.list_items().expect("list backup items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Email");

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn encrypted_backup_rejects_unsafe_destinations_without_copying_records() {
        let temp_dir = unique_temp_dir("encrypted_backup_rejects_unsafe_destinations");
        let vault_path = temp_dir.join("Source.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());

        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Backup Source".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let source_error = unlocked
            .backup_to(vault_path.clone())
            .expect_err("reject source destination");
        assert!(matches!(
            source_error,
            crate::VaultError::InvalidVault { .. }
        ));

        let nested_destination = vault_path.join("NestedBackup.pswvault");
        let nested_error = unlocked
            .backup_to(nested_destination.clone())
            .expect_err("reject nested destination");
        assert!(matches!(
            nested_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert!(!nested_destination.exists());

        let non_empty_destination = temp_dir.join("Existing.pswvault");
        fs::create_dir_all(&non_empty_destination).expect("create destination");
        fs::write(non_empty_destination.join("sentinel.txt"), b"keep").expect("write sentinel");
        let non_empty_error = unlocked
            .backup_to(non_empty_destination.clone())
            .expect_err("reject non-empty destination");
        assert!(matches!(
            non_empty_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert_eq!(
            fs::read(non_empty_destination.join("sentinel.txt")).expect("read sentinel"),
            b"keep"
        );

        let file_destination = temp_dir.join("file.pswvault");
        fs::write(&file_destination, b"not a directory").expect("write destination file");
        let file_error = unlocked
            .backup_to(file_destination)
            .expect_err("reject file destination");
        assert!(matches!(file_error, crate::VaultError::InvalidVault { .. }));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn encrypted_backup_restore_copies_portable_vault_without_local_unlock_material() {
        let temp_dir = unique_temp_dir("encrypted_backup_restore_copies_portable_vault");
        let source_path = temp_dir.join("Backup.pswvault");
        let restored_path = temp_dir.join("Restored.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());

        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: source_path.clone(),
                display_name: Some("Restore Source".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Email", "alice", false, vec!["restore"]))
            .expect("create item");
        fs::write(
            source_path.join("attachments").join("receipt.bin"),
            b"attachment",
        )
        .expect("write attachment");
        unlocked
            .local_unlock_material()
            .expect("create local unlock material");
        assert!(source_path.join("local_unlock.enc").is_file());
        let _recovery_key = install_test_recovery(&unlocked);
        let recovery_envelope =
            fs::read(source_path.join("recovery.enc")).expect("read recovery envelope");

        let restored = core
            .restore_vault_backup(RestoreVaultBackupRequest {
                source_path: source_path.clone(),
                destination_path: restored_path.clone(),
            })
            .expect("restore backup");

        assert_eq!(restored.copied_item_files, 1);
        assert_eq!(restored.copied_attachment_files, 1);
        assert_eq!(restored.copied_tombstone_files, 0);
        assert!(restored_path.join("vault.json").is_file());
        assert!(restored_path.join("keys.enc").is_file());
        assert_eq!(
            fs::read(restored_path.join("recovery.enc")).expect("read restored recovery envelope"),
            recovery_envelope
        );
        assert!(restored_path.join("items").is_dir());
        assert!(restored_path
            .join("attachments")
            .join("receipt.bin")
            .is_file());
        assert!(restored_path.join("tombstones").is_dir());
        assert!(!restored_path.join("local_unlock.enc").exists());

        let reopened = core
            .open_vault(OpenVaultRequest {
                path: restored_path.clone(),
            })
            .expect("open restored vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock restored vault");
        let items = reopened.list_items().expect("list restored items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Email");

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn encrypted_backup_restore_rejects_unsafe_destinations_without_copying_records() {
        let temp_dir = unique_temp_dir("encrypted_backup_restore_rejects_unsafe_destinations");
        let source_path = temp_dir.join("Backup.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());

        core.create_vault(CreateVaultRequest {
            path: source_path.clone(),
            display_name: Some("Restore Source".to_owned()),
            master_password: password,
        })
        .expect("create vault");

        let source_error = core
            .restore_vault_backup(RestoreVaultBackupRequest {
                source_path: source_path.clone(),
                destination_path: source_path.clone(),
            })
            .expect_err("reject source destination");
        assert!(matches!(
            source_error,
            crate::VaultError::InvalidVault { .. }
        ));

        let nested_destination = source_path.join("NestedRestore.pswvault");
        let nested_error = core
            .restore_vault_backup(RestoreVaultBackupRequest {
                source_path: source_path.clone(),
                destination_path: nested_destination.clone(),
            })
            .expect_err("reject nested destination");
        assert!(matches!(
            nested_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert!(!nested_destination.exists());

        let non_empty_destination = temp_dir.join("Existing.pswvault");
        fs::create_dir_all(&non_empty_destination).expect("create destination");
        fs::write(non_empty_destination.join("sentinel.txt"), b"keep").expect("write sentinel");
        let non_empty_error = core
            .restore_vault_backup(RestoreVaultBackupRequest {
                source_path: source_path.clone(),
                destination_path: non_empty_destination.clone(),
            })
            .expect_err("reject non-empty destination");
        assert!(matches!(
            non_empty_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert_eq!(
            fs::read(non_empty_destination.join("sentinel.txt")).expect("read sentinel"),
            b"keep"
        );

        let file_destination = temp_dir.join("file.pswvault");
        fs::write(&file_destination, b"not a directory").expect("write destination file");
        let file_error = core
            .restore_vault_backup(RestoreVaultBackupRequest {
                source_path,
                destination_path: file_destination,
            })
            .expect_err("reject file destination");
        assert!(matches!(file_error, crate::VaultError::InvalidVault { .. }));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_unlock_rewraps_master_key_without_rewriting_records() {
        let temp_dir = unique_temp_dir("recovery_unlock_rewraps_master_key");
        let vault_path = temp_dir.join("Recover.pswvault");
        let password = SecretBytes::new(b"forgotten master password".to_vec());
        let new_password = SecretBytes::new(b"replacement master password".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Recover".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let created = unlocked
            .create_item(login_draft("Email", "alice", false, vec!["recovery"]))
            .expect("create item");
        let recovery_key = install_test_recovery(&unlocked);
        let recovery_key_id = unlocked
            .recovery_key_id()
            .expect("read recovery key id")
            .expect("configured recovery key id");
        let records_before = encrypted_directory_snapshot(&vault_path.join("items"));
        let tombstones_before = encrypted_directory_snapshot(&vault_path.join("tombstones"));
        let recovery_before =
            fs::read(vault_path.join("recovery.enc")).expect("read recovery envelope");
        let master_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");

        let locked = unlocked.lock();
        assert_eq!(
            locked
                .recovery_key_id()
                .expect("read locked recovery status"),
            Some(recovery_key_id)
        );
        let recovered = locked
            .recover(RecoverVaultRequest {
                recovery_key,
                new_master_password: new_password.clone(),
            })
            .expect("recover vault");

        assert_eq!(
            recovered
                .get_item(&created.id)
                .expect("read recovered item")
                .draft
                .title,
            "Email"
        );
        assert_ne!(
            fs::read(vault_path.join("keys.enc")).expect("read recovered key envelope"),
            master_before
        );
        assert_eq!(
            fs::read(vault_path.join("recovery.enc")).expect("read retained recovery envelope"),
            recovery_before
        );
        assert_eq!(
            encrypted_directory_snapshot(&vault_path.join("items")),
            records_before
        );
        assert_eq!(
            encrypted_directory_snapshot(&vault_path.join("tombstones")),
            tombstones_before
        );
        assert!(matches!(
            core.open_vault(OpenVaultRequest {
                path: vault_path.clone()
            })
            .expect("open recovered vault")
            .unlock(crate::UnlockRequest {
                master_password: password
            })
            .expect_err("old password rejected"),
            crate::VaultError::InvalidCredentials
        ));
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open recovered vault")
        .unlock(crate::UnlockRequest {
            master_password: new_password,
        })
        .expect("new password unlocks");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_unlock_rejects_wrong_key_without_rewriting_master_envelope() {
        let temp_dir = unique_temp_dir("recovery_unlock_wrong_key");
        let vault_path = temp_dir.join("WrongRecovery.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let new_password = SecretBytes::new(b"rejected replacement password".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Wrong Recovery".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let _actual_recovery_key = install_test_recovery(&unlocked);
        let master_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");

        let error = unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key: crate::RecoveryKey::generate(),
                new_master_password: new_password.clone(),
            })
            .expect_err("wrong recovery key");

        assert!(matches!(error, crate::VaultError::InvalidCredentials));
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            master_before
        );
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open unchanged vault")
        .unlock(crate::UnlockRequest {
            master_password: password,
        })
        .expect("current password remains valid");
        assert!(matches!(
            core.open_vault(OpenVaultRequest {
                path: vault_path.clone()
            })
            .expect("open unchanged vault")
            .unlock(crate::UnlockRequest {
                master_password: new_password
            })
            .expect_err("replacement password rejected"),
            crate::VaultError::InvalidCredentials
        ));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_unlock_rejects_tampered_envelope_without_rewrite() {
        let temp_dir = unique_temp_dir("recovery_unlock_tampered_envelope");
        let vault_path = temp_dir.join("TamperedRecovery.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Tampered Recovery".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let recovery_key = install_test_recovery(&unlocked);
        let master_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");
        let recovery_path = vault_path.join("recovery.enc");
        let mut envelope: Value =
            serde_json::from_slice(&fs::read(&recovery_path).expect("read recovery envelope"))
                .expect("parse recovery envelope");
        let ciphertext = envelope["ciphertext_hex"]
            .as_str()
            .expect("ciphertext string");
        let first_nibble = if ciphertext.starts_with('0') {
            "1"
        } else {
            "0"
        };
        envelope["ciphertext_hex"] =
            serde_json::json!(format!("{first_nibble}{}", &ciphertext[1..]));
        fs::write(
            &recovery_path,
            serde_json::to_vec_pretty(&envelope).expect("serialize tampered envelope"),
        )
        .expect("write tampered envelope");

        let error = unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key,
                new_master_password: SecretBytes::new(b"replacement password".to_vec()),
            })
            .expect_err("tampered recovery envelope");

        assert!(matches!(error, crate::VaultError::InvalidCredentials));
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            master_before
        );
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open unchanged vault")
        .unlock(crate::UnlockRequest {
            master_password: password,
        })
        .expect("current password remains valid");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_unlock_write_failure_preserves_current_master_envelope() {
        let temp_dir = unique_temp_dir("recovery_unlock_write_failure");
        let vault_path = temp_dir.join("RecoveryWriteFailure.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Recovery Write Failure".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let recovery_key = install_test_recovery(&unlocked);
        let master_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");
        fs::create_dir(vault_path.join("keys.enc.tmp")).expect("block temporary key file");

        let error = unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key,
                new_master_password: SecretBytes::new(b"replacement password".to_vec()),
            })
            .expect_err("recovery key write failure");

        assert!(matches!(error, crate::VaultError::Io { .. }));
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            master_before
        );
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open unchanged vault")
        .unlock(crate::UnlockRequest {
            master_password: password,
        })
        .expect("current password remains valid");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_request_debug_redacts_recovery_and_master_material() {
        let recovery_key = crate::RecoveryKey::generate();
        let canonical = recovery_key.expose_canonical();
        let request = RecoverVaultRequest {
            recovery_key,
            new_master_password: SecretBytes::new(b"replacement-secret-marker".to_vec()),
        };
        let debug = format!("{request:?}");

        assert!(!debug.contains(&canonical));
        assert!(!debug.contains("replacement-secret-marker"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn recovery_setup_refuses_to_replace_existing_authority() {
        let temp_dir = unique_temp_dir("recovery_setup_refuses_replacement");
        let vault_path = temp_dir.join("RecoverySetup.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let new_password = SecretBytes::new(b"replacement master password".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Recovery Setup".to_owned()),
                master_password: password,
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: SecretBytes::new(b"current master password".to_vec()),
            })
            .expect("unlock vault");

        let first = unlocked
            .begin_recovery_setup()
            .expect("initialize recovery");
        let envelope_before =
            fs::read(vault_path.join("recovery.enc")).expect("read recovery envelope");
        let error = unlocked
            .begin_recovery_setup()
            .expect_err("replacement requires rotation flow");

        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));
        assert_eq!(
            fs::read(vault_path.join("recovery.enc")).expect("read retained recovery envelope"),
            envelope_before
        );
        unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key: first.recovery_key,
                new_master_password: new_password.clone(),
            })
            .expect("first recovery authority remains valid");
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open recovered vault")
        .unlock(crate::UnlockRequest {
            master_password: new_password,
        })
        .expect("new password unlocks");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn lost_initial_recovery_authority_cannot_recover_or_replace_master_envelope() {
        let temp_dir = unique_temp_dir("lost_initial_recovery_authority");
        let vault_path = temp_dir.join("LostRecoveryAuthority.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let rejected_password = SecretBytes::new(b"rejected replacement password".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Lost Recovery Authority".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");

        let pending = unlocked
            .begin_recovery_setup()
            .expect("install first recovery envelope");
        let recovery_key_id = pending.recovery_key_id;
        let master_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");
        drop(pending);

        assert_eq!(
            unlocked
                .recovery_key_id()
                .expect("read installed recovery status"),
            Some(recovery_key_id)
        );
        let error = unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key: crate::RecoveryKey::generate(),
                new_master_password: rejected_password.clone(),
            })
            .expect_err("lost recovery authority cannot be recreated from its envelope");

        assert!(matches!(error, crate::VaultError::InvalidCredentials));
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            master_before
        );
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open unchanged vault")
        .unlock(crate::UnlockRequest {
            master_password: password,
        })
        .expect("current password remains valid");
        assert!(matches!(
            core.open_vault(OpenVaultRequest {
                path: vault_path.clone()
            })
            .expect("open unchanged vault")
            .unlock(crate::UnlockRequest {
                master_password: rejected_password
            })
            .expect_err("rejected replacement password remains invalid"),
            crate::VaultError::InvalidCredentials
        ));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_rotation_candidate_is_memory_only_and_drop_keeps_old_key_valid() {
        let temp_dir = unique_temp_dir("recovery_rotation_candidate_is_memory_only");
        let vault_path = temp_dir.join("RotationCancel.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let new_password = SecretBytes::new(b"replacement master password".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Rotation Cancel".to_owned()),
                master_password: password,
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: SecretBytes::new(b"current master password".to_vec()),
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Email", "alice", false, vec!["rotation"]))
            .expect("create item");
        let old_recovery_key = install_test_recovery(&unlocked);
        let recovery_before =
            fs::read(vault_path.join("recovery.enc")).expect("read recovery envelope");
        let keys_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");
        let records_before = encrypted_directory_snapshot(&vault_path.join("items"));

        let pending = unlocked
            .begin_recovery_rotation()
            .expect("begin recovery rotation");
        let candidate_code = pending.recovery_key().expose_canonical();
        let debug = format!("{pending:?}");

        assert!(!debug.contains(&candidate_code));
        assert!(debug.contains("[REDACTED]"));
        assert_eq!(
            fs::read(vault_path.join("recovery.enc")).expect("read unchanged recovery envelope"),
            recovery_before
        );
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            keys_before
        );
        assert_eq!(
            encrypted_directory_snapshot(&vault_path.join("items")),
            records_before
        );

        drop(pending);
        unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key: old_recovery_key,
                new_master_password: new_password.clone(),
            })
            .expect("old recovery key remains valid after cancellation");
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open recovered vault")
        .unlock(crate::UnlockRequest {
            master_password: new_password,
        })
        .expect("replacement password unlocks");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_rotation_commit_replaces_only_recovery_authority() {
        let temp_dir = unique_temp_dir("recovery_rotation_commit");
        let vault_path = temp_dir.join("RotationCommit.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let recovered_password = SecretBytes::new(b"recovered master password".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Rotation Commit".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Email", "alice", false, vec!["rotation"]))
            .expect("create item");
        let old_recovery_key = install_test_recovery(&unlocked);
        let recovery_before =
            fs::read(vault_path.join("recovery.enc")).expect("read recovery envelope");
        let keys_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");
        let records_before = encrypted_directory_snapshot(&vault_path.join("items"));
        let tombstones_before = encrypted_directory_snapshot(&vault_path.join("tombstones"));

        let pending = unlocked
            .begin_recovery_rotation()
            .expect("begin recovery rotation");
        let new_recovery_key = pending.recovery_key().clone();
        let new_recovery_key_id = pending.recovery_key_id();
        unlocked
            .commit_recovery_rotation(pending)
            .expect("commit recovery rotation");

        let recovery_after =
            fs::read(vault_path.join("recovery.enc")).expect("read rotated recovery envelope");
        let parsed =
            crate::RecoveryEnvelope::parse_json(&recovery_after).expect("parse rotated envelope");
        assert_ne!(recovery_after, recovery_before);
        assert_eq!(parsed.recovery_key_id(), new_recovery_key_id);
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            keys_before
        );
        assert_eq!(
            encrypted_directory_snapshot(&vault_path.join("items")),
            records_before
        );
        assert_eq!(
            encrypted_directory_snapshot(&vault_path.join("tombstones")),
            tombstones_before
        );

        let old_error = unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key: old_recovery_key,
                new_master_password: recovered_password.clone(),
            })
            .expect_err("old recovery key must be rejected");
        assert!(matches!(old_error, crate::VaultError::InvalidCredentials));
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read retained key envelope"),
            keys_before
        );

        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open rotated vault")
        .recover(RecoverVaultRequest {
            recovery_key: new_recovery_key,
            new_master_password: recovered_password.clone(),
        })
        .expect("new recovery key recovers vault");
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open recovered vault")
        .unlock(crate::UnlockRequest {
            master_password: recovered_password,
        })
        .expect("recovered password unlocks");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_rotation_rejects_stale_candidate_without_replacement() {
        let temp_dir = unique_temp_dir("recovery_rotation_rejects_stale_candidate");
        let vault_path = temp_dir.join("RotationStale.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let recovered_password = SecretBytes::new(b"recovered master password".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Rotation Stale".to_owned()),
                master_password: password,
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: SecretBytes::new(b"current master password".to_vec()),
            })
            .expect("unlock vault");
        let _old_recovery_key = install_test_recovery(&unlocked);
        let winner = unlocked
            .begin_recovery_rotation()
            .expect("begin winning rotation");
        let winner_key = winner.recovery_key().clone();
        let stale = unlocked
            .begin_recovery_rotation()
            .expect("begin stale rotation");
        let stale_key = stale.recovery_key().clone();

        unlocked
            .commit_recovery_rotation(winner)
            .expect("commit winning rotation");
        let recovery_after_winner =
            fs::read(vault_path.join("recovery.enc")).expect("read winning envelope");
        let stale_error = unlocked
            .commit_recovery_rotation(stale)
            .expect_err("reject stale rotation");

        assert!(matches!(
            stale_error,
            crate::VaultError::InvalidVault { reason }
                if reason == "recovery rotation candidate is stale"
        ));
        assert_eq!(
            fs::read(vault_path.join("recovery.enc")).expect("read retained winning envelope"),
            recovery_after_winner
        );
        assert!(matches!(
            unlocked
                .clone()
                .lock()
                .recover(RecoverVaultRequest {
                    recovery_key: stale_key,
                    new_master_password: recovered_password.clone(),
                })
                .expect_err("stale candidate key is not authoritative"),
            crate::VaultError::InvalidCredentials
        ));
        unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key: winner_key,
                new_master_password: recovered_password,
            })
            .expect("winning recovery key remains authoritative");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_rotation_write_failure_preserves_old_authority() {
        let temp_dir = unique_temp_dir("recovery_rotation_write_failure");
        let vault_path = temp_dir.join("RotationWriteFailure.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let recovered_password = SecretBytes::new(b"recovered master password".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Rotation Write Failure".to_owned()),
                master_password: password,
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: SecretBytes::new(b"current master password".to_vec()),
            })
            .expect("unlock vault");
        let old_recovery_key = install_test_recovery(&unlocked);
        let pending = unlocked
            .begin_recovery_rotation()
            .expect("begin recovery rotation");
        let failed_candidate_key = pending.recovery_key().clone();
        let recovery_before =
            fs::read(vault_path.join("recovery.enc")).expect("read recovery envelope");
        fs::create_dir(vault_path.join("recovery.enc.tmp")).expect("block temporary recovery file");

        let write_error = unlocked
            .commit_recovery_rotation(pending)
            .expect_err("rotation write must fail");

        assert!(matches!(write_error, crate::VaultError::Io { .. }));
        assert_eq!(
            fs::read(vault_path.join("recovery.enc")).expect("read retained recovery envelope"),
            recovery_before
        );
        assert!(matches!(
            unlocked
                .clone()
                .lock()
                .recover(RecoverVaultRequest {
                    recovery_key: failed_candidate_key,
                    new_master_password: recovered_password.clone(),
                })
                .expect_err("uncommitted candidate key is rejected"),
            crate::VaultError::InvalidCredentials
        ));
        unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key: old_recovery_key,
                new_master_password: recovered_password,
            })
            .expect("old recovery key remains valid after write failure");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn recovery_unlock_requires_configured_envelope_and_nonempty_new_password() {
        let temp_dir = unique_temp_dir("recovery_unlock_requires_material");
        let vault_path = temp_dir.join("RecoveryRequired.pswvault");
        let password = SecretBytes::new(b"current master password".to_vec());
        let core = VaultCore::new();
        let locked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Recovery Required".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault");
        let master_before = fs::read(vault_path.join("keys.enc")).expect("read key envelope");

        let missing_error = locked
            .recover(RecoverVaultRequest {
                recovery_key: crate::RecoveryKey::generate(),
                new_master_password: SecretBytes::new(b"replacement password".to_vec()),
            })
            .expect_err("missing recovery envelope");
        assert!(matches!(
            missing_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            master_before
        );

        let unlocked = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let recovery_key = install_test_recovery(&unlocked);
        let empty_password_error = unlocked
            .lock()
            .recover(RecoverVaultRequest {
                recovery_key,
                new_master_password: SecretBytes::new(Vec::new()),
            })
            .expect_err("empty replacement password");
        assert!(matches!(
            empty_password_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert_eq!(
            fs::read(vault_path.join("keys.enc")).expect("read unchanged key envelope"),
            master_before
        );
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open unchanged vault")
        .unlock(crate::UnlockRequest {
            master_password: password,
        })
        .expect("current password remains valid");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn change_master_password_rewraps_key_envelope_without_rewriting_items() {
        let temp_dir = unique_temp_dir("change_master_password_rewraps");
        let vault_path = temp_dir.join("Rotate.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let new_password = SecretBytes::new(b"new correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Rotate".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let created = unlocked
            .create_item(login_draft("Email", "alice", false, vec!["personal"]))
            .expect("create item");
        let item_before = std::fs::read_dir(vault_path.join("items"))
            .expect("read items")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert_eq!(item_before.len(), 1);

        unlocked
            .change_master_password(password.clone(), new_password.clone())
            .expect("change master password");

        assert_eq!(
            unlocked.list_items().expect("list current session").len(),
            1
        );
        assert!(matches!(
            core.open_vault(OpenVaultRequest {
                path: vault_path.clone()
            })
            .expect("open vault")
            .unlock(crate::UnlockRequest {
                master_password: password
            })
            .expect_err("old password rejected"),
            crate::VaultError::InvalidCredentials
        ));

        let reopened = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open vault")
            .unlock(crate::UnlockRequest {
                master_password: new_password,
            })
            .expect("unlock with new password");
        assert_eq!(
            reopened
                .get_item(&created.id)
                .expect("read item")
                .draft
                .title,
            "Email"
        );
        let item_after = std::fs::read_dir(vault_path.join("items"))
            .expect("read items")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert_eq!(item_before, item_after);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn change_master_password_rejects_wrong_current_password_without_rewrite() {
        let temp_dir = unique_temp_dir("change_master_password_wrong_current");
        let vault_path = temp_dir.join("RotateReject.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let wrong_password = SecretBytes::new(b"wrong horse battery staple".to_vec());
        let new_password = SecretBytes::new(b"new correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Rotate Reject".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let before = std::fs::read(vault_path.join("keys.enc")).expect("read key envelope");

        let error = unlocked
            .change_master_password(wrong_password, new_password.clone())
            .expect_err("wrong current password");

        assert!(matches!(error, crate::VaultError::InvalidCredentials));
        let after = std::fs::read(vault_path.join("keys.enc")).expect("read key envelope");
        assert_eq!(before, after);
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open vault")
        .unlock(crate::UnlockRequest {
            master_password: password,
        })
        .expect("old password still works");
        assert!(matches!(
            core.open_vault(OpenVaultRequest {
                path: vault_path.clone()
            })
            .expect("open vault")
            .unlock(crate::UnlockRequest {
                master_password: new_password
            })
            .expect_err("new password rejected"),
            crate::VaultError::InvalidCredentials
        ));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn change_master_password_accepts_short_non_empty_new_password() {
        let temp_dir = unique_temp_dir("change_master_password_short_new");
        let vault_path = temp_dir.join("RotateShort.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let short_password = SecretBytes::new(b"short".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Rotate Short".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let before = std::fs::read(vault_path.join("keys.enc")).expect("read key envelope");

        unlocked
            .change_master_password(password.clone(), short_password.clone())
            .expect("short new password accepted");

        let after = std::fs::read(vault_path.join("keys.enc")).expect("read key envelope");
        assert_ne!(before, after);
        assert!(matches!(
            core.open_vault(OpenVaultRequest {
                path: vault_path.clone()
            })
            .expect("open vault")
            .unlock(crate::UnlockRequest {
                master_password: password
            })
            .expect_err("old password rejected"),
            crate::VaultError::InvalidCredentials
        ));
        core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open vault")
        .unlock(crate::UnlockRequest {
            master_password: short_password,
        })
        .expect("short password works");

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn unlocked_vault_manages_item_revisions_and_search() {
        let temp_dir = unique_temp_dir("unlocked_vault_manages_item_revisions_and_search");
        let vault_path = temp_dir.join("Items.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let locked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Items".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault");
        let mut unlocked = core
            .open_vault(OpenVaultRequest { path: vault_path })
            .expect("open vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft("Example", "alice", false, vec!["work"]))
            .expect("create item");
        assert_eq!(created.title, "Example");
        assert_eq!(unlocked.list_items().expect("list items").len(), 1);

        let updated = unlocked
            .update_item(
                &created.id,
                login_draft("Example Login", "alice", false, vec!["work"]),
            )
            .expect("update item");
        assert_eq!(updated.title, "Example Login");

        let favorite = unlocked
            .set_favorite(&created.id, true)
            .expect("set favorite");
        assert!(favorite.favorite);

        let tagged = unlocked
            .set_tags(&created.id, vec!["personal".to_owned()])
            .expect("set tags");
        assert_eq!(tagged.tags, vec!["personal"]);

        let search_results = unlocked
            .search(SearchQuery {
                text: "alice".to_owned(),
                include_archived: false,
            })
            .expect("search");
        assert_eq!(search_results.len(), 1);

        let totp = unlocked
            .totp_code_at(&created.id, 59)
            .expect("generate TOTP");
        assert_eq!(totp.code, "287082");

        let refresh = unlocked.refresh_from_disk().expect("refresh from disk");
        assert!(refresh.loaded_items >= 4);

        let archived = unlocked.archive_item(&created.id).expect("archive item");
        assert_eq!(archived.status, ItemStatus::Archived);
        assert!(unlocked.list_items().expect("list active items").is_empty());
        assert!(unlocked
            .search(SearchQuery {
                text: "alice".to_owned(),
                include_archived: false,
            })
            .expect("search active")
            .is_empty());

        unlocked.delete_item(&created.id).expect("delete item");
        let refresh = unlocked.refresh_from_disk().expect("refresh tombstone");
        assert!(refresh.applied_tombstones >= 1);
        assert!(matches!(
            unlocked.get_item(&created.id).expect_err("deleted item"),
            crate::VaultError::ItemNotFound { .. }
        ));

        let relocked = unlocked.lock();
        assert_eq!(relocked.metadata, locked.metadata);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn archived_items_can_be_restored_to_active_list() {
        let temp_dir = unique_temp_dir("archived_items_can_be_restored_to_active_list");
        let vault_path = temp_dir.join("Restore.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Restore".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft("Email", "alice", true, vec!["personal"]))
            .expect("create item");
        let active_restore = unlocked
            .restore_item(&created.id)
            .expect_err("restore active item");
        assert!(matches!(
            active_restore,
            crate::VaultError::InvalidVault { .. }
        ));

        unlocked.archive_item(&created.id).expect("archive item");
        assert!(unlocked.list_items().expect("active items").is_empty());

        let restored = unlocked.restore_item(&created.id).expect("restore item");

        assert_eq!(restored.status, ItemStatus::Active);
        assert!(restored.favorite);
        assert_eq!(restored.tags, vec!["personal"]);
        let active_items = unlocked.list_items().expect("list active items");
        assert_eq!(active_items.len(), 1);
        assert_eq!(active_items[0].id, created.id);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn login_totp_secret_can_be_created_updated_and_cleared() {
        let temp_dir = unique_temp_dir("login_totp_secret_can_be_created_updated_and_cleared");
        let vault_path = temp_dir.join("Totp.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("TOTP".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft_with_totp(
                "Email",
                "alice",
                false,
                vec!["work"],
                Some("gezd gnbv-gy3tqojqgezdgnbvgy3tqojq"),
            ))
            .expect("create login with TOTP");
        let initial_code = unlocked
            .totp_code_at(&created.id, 59)
            .expect("generate initial TOTP");
        assert_eq!(initial_code.code, "287082");
        let item = unlocked.get_item(&created.id).expect("get created item");
        let VaultItemContent::Login(login) = item.draft.content else {
            panic!("expected login item");
        };
        assert_eq!(
            login.totp_secret.expect("stored TOTP").expose(),
            b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );

        let summaries = unlocked.list_items().expect("list summaries");
        assert!(!format!("{summaries:?}").contains("GEZDGNBV"));
        assert!(unlocked
            .search(SearchQuery {
                text: "GEZDGNBV".to_owned(),
                include_archived: false,
            })
            .expect("search secret")
            .is_empty());

        let updated = unlocked
            .update_item(
                &created.id,
                login_draft_with_totp(
                    "Email",
                    "alice",
                    false,
                    vec!["work"],
                    Some("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
                ),
            )
            .expect("update TOTP secret");
        assert_eq!(updated.id, created.id);
        let updated_code = unlocked
            .totp_code_at(&created.id, 59)
            .expect("generate updated TOTP");
        assert_ne!(updated_code.code, initial_code.code);
        let item = unlocked.get_item(&created.id).expect("get updated item");
        let VaultItemContent::Login(login) = item.draft.content else {
            panic!("expected login item");
        };
        assert_eq!(
            login.totp_secret.expect("stored TOTP").expose(),
            b"JBSWY3DPEHPK3PXP"
        );

        unlocked
            .update_item(
                &created.id,
                login_draft_with_totp("Email", "alice", false, vec!["work"], None),
            )
            .expect("clear TOTP secret");
        assert!(matches!(
            unlocked
                .totp_code_at(&created.id, 59)
                .expect_err("cleared TOTP secret"),
            crate::VaultError::InvalidVault { .. }
        ));

        let item = unlocked.get_item(&created.id).expect("get cleared item");
        let VaultItemContent::Login(login) = item.draft.content else {
            panic!("expected login item");
        };
        assert!(login.totp_secret.is_none());

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn login_totp_secret_rejects_invalid_create_and_update() {
        let temp_dir = unique_temp_dir("login_totp_secret_rejects_invalid_create_and_update");
        let vault_path = temp_dir.join("TotpInvalid.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("TOTP Invalid".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let create_error = unlocked
            .create_item(login_draft_with_totp(
                "Bad",
                "alice",
                false,
                vec![],
                Some("not valid!"),
            ))
            .expect_err("invalid create");
        assert!(matches!(
            create_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert!(unlocked.list_items().expect("list items").is_empty());

        let created = unlocked
            .create_item(login_draft("Good", "alice", false, vec![]))
            .expect("create valid login");
        let update_error = unlocked
            .update_item(
                &created.id,
                login_draft_with_totp("Good", "alice", false, vec![], Some("not valid!")),
            )
            .expect_err("invalid update");
        assert!(matches!(
            update_error,
            crate::VaultError::InvalidVault { .. }
        ));
        assert_eq!(
            unlocked
                .totp_code_at(&created.id, 59)
                .expect("old secret remains")
                .code,
            "287082"
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn search_matches_secure_note_body_without_matching_login_password() {
        let temp_dir = unique_temp_dir("search_matches_secure_note_body");
        let vault_path = temp_dir.join("SearchNotes.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Search Notes".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        unlocked
            .create_item(login_draft("Email", "alice", false, vec![]))
            .expect("create login");
        unlocked
            .create_item(secure_note_draft(
                "Recovery Notes",
                "Rotated backup codes",
                vec![],
            ))
            .expect("create secure note");

        let note_results = unlocked
            .search(SearchQuery {
                text: "BACKUP CODES".to_owned(),
                include_archived: false,
            })
            .expect("search secure note body");
        assert_eq!(note_results.len(), 1);
        assert_eq!(note_results[0].title, "Recovery Notes");
        let credential_note_results = unlocked
            .search_credential_items(SearchQuery {
                text: "BACKUP CODES".to_owned(),
                include_archived: false,
            })
            .expect("search secure note body through credential model");
        assert_eq!(credential_note_results.len(), 1);
        assert_eq!(
            credential_note_results[0].credential.title,
            "Recovery Notes"
        );

        let password_results = unlocked
            .search(SearchQuery {
                text: "secret".to_owned(),
                include_archived: false,
            })
            .expect("search login password");
        assert!(
            password_results.is_empty(),
            "login password values must not be searchable"
        );
        assert!(
            unlocked
                .search_credential_items(SearchQuery {
                    text: "secret".to_owned(),
                    include_archived: false,
                })
                .expect("search login password through credential model")
                .is_empty(),
            "credential search must not index login password values"
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn search_matches_structured_non_secret_fields_without_matching_secrets() {
        let temp_dir = unique_temp_dir("search_matches_structured_non_secret_fields");
        let vault_path = temp_dir.join("SearchStructured.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Search Structured".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let mut login = login_draft_with_totp(
            "Team Portal",
            "carol",
            false,
            vec![],
            Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        );
        if let VaultItemContent::Login(login) = &mut login.content {
            login.password = Some(SecretBytes::new(b"never-search-login-password".to_vec()));
            login.notes = Some("Invoice approval workflow".to_owned());
        }
        unlocked.create_item(login).expect("create login");

        let mut card = credit_card_draft("Payment Card");
        if let VaultItemContent::CreditCard(card) = &mut card.content {
            card.cardholder_name = Some("Dana Traveller".to_owned());
            card.number = Some(SecretBytes::new(b"4999888877776666".to_vec()));
            card.verification_code = Some(SecretBytes::new(b"987".to_vec()));
            card.notes = Some("Airport lounge rewards".to_owned());
        }
        unlocked.create_item(card).expect("create credit card");

        let mut license = software_license_draft("Developer Seat");
        if let VaultItemContent::SoftwareLicense(license) = &mut license.content {
            license.product = Some("Vector Studio".to_owned());
            license.license_key = Some(SecretBytes::new(b"LIC-SECRET-2026".to_vec()));
            license.licensed_to = Some("design@example.com".to_owned());
            license.notes = Some("Renew Q4 finance".to_owned());
        }
        unlocked
            .create_item(license)
            .expect("create software license");

        for (query, expected_title) in [
            ("approval workflow", "Team Portal"),
            ("dana traveller", "Payment Card"),
            ("airport lounge", "Payment Card"),
            ("2030", "Payment Card"),
            ("vector studio", "Developer Seat"),
            ("design@example.com", "Developer Seat"),
            ("renew q4", "Developer Seat"),
        ] {
            let results = unlocked
                .search(SearchQuery {
                    text: query.to_owned(),
                    include_archived: false,
                })
                .expect("search non-secret field");
            assert_eq!(results.len(), 1, "query: {query}");
            assert_eq!(results[0].title, expected_title, "query: {query}");
        }

        for query in [
            "never-search-login-password",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "4999888877776666",
            "987",
            "LIC-SECRET-2026",
        ] {
            let results = unlocked
                .search(SearchQuery {
                    text: query.to_owned(),
                    include_archived: false,
                })
                .expect("search secret field");
            assert!(results.is_empty(), "secret query matched: {query}");
        }

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn concurrent_item_revisions_are_marked_and_resolved_as_conflict() {
        let temp_dir = unique_temp_dir("concurrent_item_revisions_are_marked");
        let vault_path = temp_dir.join("Conflicts.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Conflicts".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft("Base", "alice", false, vec!["sync"]))
            .expect("create item");
        let base = unlocked.get_item(&created.id).expect("get base item");

        let mut left = base.clone();
        left.parent_revision = Some(base.revision.clone());
        left.revision = unlocked.new_item_revision();
        left.draft.title = "Left".to_owned();
        let left_revision = left.revision.clone();
        unlocked.save_item_revision(&left).expect("save left fork");

        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = unlocked.new_item_revision();
        right.draft.title = "Right".to_owned();
        unlocked
            .save_item_revision(&right)
            .expect("save right fork");

        let items = unlocked.list_items().expect("list conflicted items");
        assert_eq!(items.len(), 1);
        let conflict_id = match &items[0].status {
            ItemStatus::Conflicted(conflict_id) => conflict_id.clone(),
            status => panic!("expected conflict status, got {status:?}"),
        };
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("refresh conflicts")
                .detected_conflicts,
            1
        );

        let candidates = unlocked
            .conflict_candidates(&conflict_id)
            .expect("conflict candidates");
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .any(|candidate| candidate.title == "Left" && candidate.revision == left_revision));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.item_id == created.id && candidate.item_type == "login"));
        assert!(matches!(
            unlocked
                .conflict_candidates(&ConflictId("conflict_missing".to_owned()))
                .expect_err("unknown conflict rejected"),
            crate::VaultError::ItemNotFound { .. }
        ));
        assert!(matches!(
            unlocked
                .resolve_conflict_candidate(&conflict_id, &ItemRevision("rev_missing".to_owned()))
                .expect_err("stale candidate rejected"),
            crate::VaultError::ItemNotFound { .. }
        ));

        let resolved = unlocked
            .resolve_conflict_candidate(&conflict_id, &left_revision)
            .expect("resolve selected conflict candidate");
        assert_eq!(resolved.status, ItemStatus::Active);
        assert_eq!(resolved.title, "Left");
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("refresh after selected resolution")
                .detected_conflicts,
            0
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn conflict_merge_combines_safe_login_fields_without_exposing_secrets() {
        let temp_dir = unique_temp_dir("conflict_merge_combines_safe_login_fields");
        let vault_path = temp_dir.join("ConflictMerge.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Conflict Merge".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft("Base", "base", false, vec!["base"]))
            .expect("create item");
        let base = unlocked.get_item(&created.id).expect("get base item");

        let mut left = base.clone();
        left.parent_revision = Some(base.revision.clone());
        left.revision = unlocked.new_item_revision();
        left.draft.title = "Left Title".to_owned();
        left.draft.favorite = false;
        left.draft.tags = vec!["left".to_owned()];
        let VaultItemContent::Login(left_login) = &mut left.draft.content else {
            panic!("expected login");
        };
        left_login.username = Some("left@example.com".to_owned());
        left_login.urls = vec!["https://left.example.com".to_owned()];
        left_login.password = Some(SecretBytes::new(b"left-secret".to_vec()));
        left_login.totp_secret = Some(SecretBytes::new(b"LEFTLEFTLEFTLEFT".to_vec()));
        let left_revision = left.revision.clone();
        unlocked.save_item_revision(&left).expect("save left fork");

        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = unlocked.new_item_revision();
        right.draft.title = "Right Title".to_owned();
        right.draft.favorite = true;
        right.draft.tags = vec!["right".to_owned(), "merged".to_owned()];
        let VaultItemContent::Login(right_login) = &mut right.draft.content else {
            panic!("expected login");
        };
        right_login.username = Some("right@example.com".to_owned());
        right_login.urls = vec!["https://right.example.com".to_owned()];
        right_login.password = Some(SecretBytes::new(b"right-secret".to_vec()));
        right_login.totp_secret = Some(SecretBytes::new(b"RIGHTRIGHTRIGHT".to_vec()));
        let right_revision = right.revision.clone();
        unlocked
            .save_item_revision(&right)
            .expect("save right fork");

        let conflict_id = match &unlocked.list_items().expect("list conflicted")[0].status {
            ItemStatus::Conflicted(conflict_id) => conflict_id.clone(),
            status => panic!("expected conflict status, got {status:?}"),
        };

        let unsafe_merge = unlocked
            .resolve_conflict_merge(ConflictMergeRequest {
                conflict_id: conflict_id.clone(),
                base_revision: left_revision.clone(),
                field_selections: vec![ConflictFieldSelection {
                    field_label: "password".to_owned(),
                    revision: right_revision.clone(),
                }],
            })
            .expect_err("unsafe field rejected");
        assert!(matches!(
            unsafe_merge,
            crate::VaultError::InvalidVault { .. }
        ));
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("conflict remains after unsafe merge")
                .detected_conflicts,
            1
        );

        std::thread::sleep(std::time::Duration::from_millis(1));
        let resolved = unlocked
            .resolve_conflict_merge(ConflictMergeRequest {
                conflict_id: conflict_id.clone(),
                base_revision: left_revision.clone(),
                field_selections: vec![
                    ConflictFieldSelection {
                        field_label: "title".to_owned(),
                        revision: right_revision.clone(),
                    },
                    ConflictFieldSelection {
                        field_label: "favorite".to_owned(),
                        revision: right_revision.clone(),
                    },
                    ConflictFieldSelection {
                        field_label: "tags".to_owned(),
                        revision: right_revision.clone(),
                    },
                    ConflictFieldSelection {
                        field_label: "username".to_owned(),
                        revision: right_revision.clone(),
                    },
                    ConflictFieldSelection {
                        field_label: "URLs".to_owned(),
                        revision: right_revision.clone(),
                    },
                ],
            })
            .expect("merge safe fields");
        assert_eq!(resolved.status, ItemStatus::Active);
        assert_eq!(resolved.title, "Right Title");
        assert!(resolved.favorite);
        assert_eq!(resolved.tags, vec!["right".to_owned(), "merged".to_owned()]);

        let merged = unlocked.get_item(&created.id).expect("get merged item");
        assert_eq!(
            merged.parent_revision, None,
            "the compatibility view must not collapse multi-parent ancestry"
        );
        let VaultItemContent::Login(login) = merged.draft.content else {
            panic!("expected login");
        };
        assert_eq!(login.username.as_deref(), Some("right@example.com"));
        assert_eq!(login.urls, vec!["https://right.example.com".to_owned()]);
        assert_eq!(
            login.password.expect("password from base").expose(),
            b"left-secret"
        );
        assert_eq!(
            login.totp_secret.expect("totp from base").expose(),
            b"LEFTLEFTLEFTLEFT"
        );
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("refresh after merged resolution")
                .detected_conflicts,
            0
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn conflicted_items_reject_ordinary_mutations_until_resolved() {
        let temp_dir = unique_temp_dir("conflicted_items_reject_mutations");
        let vault_path = temp_dir.join("ConflictGuard.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Conflict Guard".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft("Base", "alice", false, vec!["sync"]))
            .expect("create item");
        let base = unlocked.get_item(&created.id).expect("get base item");

        let mut left = base.clone();
        left.parent_revision = Some(base.revision.clone());
        left.revision = unlocked.new_item_revision();
        left.draft.title = "Left".to_owned();
        let left_revision = left.revision.clone();
        unlocked.save_item_revision(&left).expect("save left fork");

        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = unlocked.new_item_revision();
        right.draft.title = "Right".to_owned();
        unlocked
            .save_item_revision(&right)
            .expect("save right fork");

        let items = unlocked.list_items().expect("list conflicted items");
        let conflict_id = match &items[0].status {
            ItemStatus::Conflicted(conflict_id) => conflict_id.clone(),
            status => panic!("expected conflict status, got {status:?}"),
        };
        let item_records_before = record_file_count(&vault_path, "items");
        let tombstones_before = record_file_count(&vault_path, "tombstones");

        for error in [
            unlocked
                .update_item(
                    &created.id,
                    login_draft("Edited", "alice", false, vec!["sync"]),
                )
                .expect_err("conflicted update rejected"),
            unlocked
                .archive_item(&created.id)
                .expect_err("conflicted archive rejected"),
            unlocked
                .set_favorite(&created.id, true)
                .expect_err("conflicted favorite rejected"),
            unlocked
                .set_tags(&created.id, vec!["changed".to_owned()])
                .expect_err("conflicted tags rejected"),
            unlocked
                .delete_item(&created.id)
                .expect_err("conflicted delete rejected"),
        ] {
            match error {
                crate::VaultError::InvalidVault { reason } => {
                    assert!(reason.contains("conflicted items must be resolved"));
                }
                other => panic!("expected invalid vault guard error, got {other:?}"),
            }
        }
        assert_eq!(record_file_count(&vault_path, "items"), item_records_before);
        assert_eq!(
            record_file_count(&vault_path, "tombstones"),
            tombstones_before
        );

        let resolved = unlocked
            .resolve_conflict_candidate(&conflict_id, &left_revision)
            .expect("resolve selected conflict candidate");
        assert_eq!(resolved.status, ItemStatus::Active);
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("refresh after resolution")
                .detected_conflicts,
            0
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn expected_revision_guard_rejects_stale_mutations_without_writing_records() {
        let temp_dir = unique_temp_dir("expected_revision_guard_rejects_stale_mutations");
        let vault_path = temp_dir.join("RevisionGuard.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Revision Guard".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft("Base", "alice", false, vec!["sync"]))
            .expect("create item");
        let stale_revision = created.revision.clone();
        let remote = unlocked
            .update_item(
                &created.id,
                login_draft("Remote Update", "alice", false, vec!["sync"]),
            )
            .expect("simulate synced remote update");
        let item_records_before = record_file_count(&vault_path, "items");
        let tombstones_before = record_file_count(&vault_path, "tombstones");

        for error in [
            unlocked
                .update_item_with_expected_revision(
                    &created.id,
                    &stale_revision,
                    login_draft("Stale Update", "alice", false, vec!["sync"]),
                )
                .expect_err("stale update rejected"),
            unlocked
                .archive_item_with_expected_revision(&created.id, &stale_revision)
                .expect_err("stale archive rejected"),
            unlocked
                .set_favorite_with_expected_revision(&created.id, &stale_revision, true)
                .expect_err("stale favorite rejected"),
            unlocked
                .set_tags_with_expected_revision(
                    &created.id,
                    &stale_revision,
                    vec!["changed".to_owned()],
                )
                .expect_err("stale tags rejected"),
            unlocked
                .delete_item_with_expected_revision(&created.id, &stale_revision)
                .expect_err("stale delete rejected"),
        ] {
            match error {
                crate::VaultError::InvalidVault { reason } => {
                    assert!(reason.contains("item changed on disk"));
                }
                other => panic!("expected stale revision error, got {other:?}"),
            }
        }
        assert_eq!(record_file_count(&vault_path, "items"), item_records_before);
        assert_eq!(
            record_file_count(&vault_path, "tombstones"),
            tombstones_before
        );

        let favorited = unlocked
            .set_favorite_with_expected_revision(&created.id, &remote.revision, true)
            .expect("current favorite succeeds");
        assert!(favorited.favorite);
        let updated = unlocked
            .update_item_with_expected_revision(
                &created.id,
                &favorited.revision,
                login_draft("Current Update", "alice", true, vec!["sync"]),
            )
            .expect("current update succeeds");
        assert_eq!(updated.title, "Current Update");

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn conflict_candidate_changed_fields_cover_supported_item_types_without_secret_values() {
        let mut login_left = login_draft_with_totp(
            "Email",
            "alice",
            false,
            vec!["personal"],
            Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        );
        let mut login_right = login_draft_with_totp(
            "Email Work",
            "work@example.com",
            true,
            vec!["work"],
            Some("JBSWY3DPEHPK3PXP"),
        );
        let VaultItemContent::Login(login) = &mut login_left.content else {
            panic!("expected login");
        };
        login.notes = Some("left note".to_owned());
        let VaultItemContent::Login(login) = &mut login_right.content else {
            panic!("expected login");
        };
        login.password = Some(SecretBytes::new(b"changed-password".to_vec()));
        login.urls = vec!["https://work.example.com".to_owned()];
        login.notes = Some("right note".to_owned());
        let login_items = vec![
            test_item("item_login", "left", login_left),
            test_item("item_login", "right", login_right),
        ];
        let login_summary =
            ConflictCandidateSummary::from_candidate_group(login_items[0].clone(), &login_items);
        assert_eq!(
            login_summary.changed_fields,
            vec![
                "title".to_owned(),
                "favorite".to_owned(),
                "tags".to_owned(),
                "username".to_owned(),
                "password".to_owned(),
                "URLs".to_owned(),
                "notes".to_owned(),
                "TOTP".to_owned(),
            ]
        );
        assert_no_secret_field_label_values(&login_summary.changed_fields);
        assert_eq!(
            comparison_field(&login_summary.comparison_fields, "username").value,
            Some("alice".to_owned())
        );
        assert_eq!(
            comparison_field(&login_summary.comparison_fields, "URLs").value,
            Some("https://example.com".to_owned())
        );
        assert_eq!(
            comparison_field(&login_summary.comparison_fields, "notes").value,
            Some("left note".to_owned())
        );
        assert_redacted_field(&login_summary.comparison_fields, "password");
        assert_redacted_field(&login_summary.comparison_fields, "TOTP");
        assert!(!login_summary
            .preview
            .as_deref()
            .unwrap_or_default()
            .contains("changed-password"));

        let secure_note_items = vec![
            test_item(
                "item_note",
                "left",
                secure_note_draft("Recovery", "left body secret", vec![]),
            ),
            test_item(
                "item_note",
                "right",
                secure_note_draft("Recovery", "right body secret", vec![]),
            ),
        ];
        let note_summary = ConflictCandidateSummary::from_candidate_group(
            secure_note_items[0].clone(),
            &secure_note_items,
        );
        assert_eq!(note_summary.changed_fields, vec!["body".to_owned()]);
        assert_eq!(note_summary.preview, None);
        assert_redacted_field(&note_summary.comparison_fields, "body");
        assert!(
            !comparison_fields_joined(&note_summary.comparison_fields).contains("left body secret")
        );

        let card_left = credit_card_draft("Travel Card");
        let mut card_right = credit_card_draft("Travel Card");
        let VaultItemContent::CreditCard(card) = &mut card_right.content else {
            panic!("expected credit card");
        };
        card.cardholder_name = Some("Alice Changed".to_owned());
        card.number = Some(SecretBytes::new(b"5555555555554444".to_vec()));
        card.expiry_month = Some(12);
        card.expiry_year = Some(2032);
        card.verification_code = Some(SecretBytes::new(b"987".to_vec()));
        card.notes = Some("Changed travel card".to_owned());
        let card_items = vec![
            test_item("item_card", "left", card_left),
            test_item("item_card", "right", card_right),
        ];
        let card_summary =
            ConflictCandidateSummary::from_candidate_group(card_items[0].clone(), &card_items);
        assert_eq!(
            card_summary.changed_fields,
            vec![
                "cardholder name".to_owned(),
                "card number".to_owned(),
                "expiration".to_owned(),
                "verification code".to_owned(),
                "notes".to_owned(),
            ]
        );
        assert_no_secret_field_label_values(&card_summary.changed_fields);
        assert_eq!(
            comparison_field(&card_summary.comparison_fields, "cardholder name").value,
            Some("Alice Example".to_owned())
        );
        assert_eq!(
            comparison_field(&card_summary.comparison_fields, "expiration").value,
            Some("04/2030".to_owned())
        );
        assert_redacted_field(&card_summary.comparison_fields, "card number");
        assert_redacted_field(&card_summary.comparison_fields, "verification code");
        let card_comparison = comparison_fields_joined(&card_summary.comparison_fields);
        assert!(!card_comparison.contains("4111111111111111"));
        assert!(!card_comparison.contains("123"));

        let license_left = software_license_draft("Dev Tool");
        let mut license_right = software_license_draft("Dev Tool");
        let VaultItemContent::SoftwareLicense(license) = &mut license_right.content else {
            panic!("expected software license");
        };
        license.product = Some("Dev Tool Pro".to_owned());
        license.licensed_to = Some("Bob".to_owned());
        license.license_key = Some(SecretBytes::new(b"ZZZZ-YYYY-XXXX".to_vec()));
        license.notes = Some("Changed renewal".to_owned());
        let license_items = vec![
            test_item("item_license", "left", license_left),
            test_item("item_license", "right", license_right),
        ];
        let license_summary = ConflictCandidateSummary::from_candidate_group(
            license_items[0].clone(),
            &license_items,
        );
        assert_eq!(
            license_summary.changed_fields,
            vec![
                "product".to_owned(),
                "licensed to".to_owned(),
                "license key".to_owned(),
                "notes".to_owned(),
            ]
        );
        assert_no_secret_field_label_values(&license_summary.changed_fields);
        assert_eq!(
            comparison_field(&license_summary.comparison_fields, "product").value,
            Some("Product".to_owned())
        );
        assert_eq!(
            comparison_field(&license_summary.comparison_fields, "licensed to").value,
            Some("Alice".to_owned())
        );
        assert_redacted_field(&license_summary.comparison_fields, "license key");
        assert!(
            !comparison_fields_joined(&license_summary.comparison_fields)
                .contains("AAAA-BBBB-CCCC")
        );

        let identical_items = vec![
            test_item(
                "item_same",
                "left",
                login_draft("Same", "same@example.com", false, vec!["same"]),
            ),
            test_item(
                "item_same",
                "right",
                login_draft("Same", "same@example.com", false, vec!["same"]),
            ),
        ];
        let identical_summary = ConflictCandidateSummary::from_candidate_group(
            identical_items[0].clone(),
            &identical_items,
        );
        assert!(identical_summary.changed_fields.is_empty());
        assert!(identical_summary
            .comparison_fields
            .iter()
            .all(|field| !field.redacted));
    }

    #[test]
    fn independent_item_revisions_do_not_conflict() {
        let temp_dir = unique_temp_dir("independent_item_revisions_do_not_conflict");
        let vault_path = temp_dir.join("Independent.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Independent".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let first = unlocked
            .create_item(login_draft("First", "alice", false, vec!["sync"]))
            .expect("create first");
        let second = unlocked
            .create_item(login_draft("Second", "bob", false, vec!["sync"]))
            .expect("create second");
        unlocked
            .update_item(
                &first.id,
                login_draft("First Updated", "alice", false, vec!["sync"]),
            )
            .expect("update first");
        unlocked
            .update_item(
                &second.id,
                login_draft("Second Updated", "bob", false, vec!["sync"]),
            )
            .expect("update second");

        let refresh = unlocked.refresh_from_disk().expect("refresh");
        assert_eq!(refresh.detected_conflicts, 0);
        assert_eq!(unlocked.list_items().expect("list items").len(), 2);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn rejected_synced_item_records_do_not_block_valid_items() {
        let temp_dir = unique_temp_dir("rejected_synced_item_records");
        let vault_path = temp_dir.join("Sync.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Sync".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        let first = unlocked
            .create_item(login_draft("Tampered", "alice", false, vec!["sync"]))
            .expect("create first");
        let second = unlocked
            .create_item(login_draft("Trusted", "bob", false, vec!["sync"]))
            .expect("create second");

        let tampered_file_name = format!("{}_{}.enc", first.id.0, first.revision.0);
        tamper_record_ciphertext(&item_record_path(&vault_path, &first.id, &first.revision));
        fs::write(vault_path.join("items").join("malformed.enc"), b"{not-json")
            .expect("write malformed item");

        let refresh = unlocked.refresh_from_disk().expect("refresh with bad item");
        assert_eq!(refresh.rejected_records, 2);
        assert_eq!(refresh.rejected_item_records, 2);
        assert_eq!(refresh.rejected_tombstone_records, 0);
        let mut rejected_files = refresh.rejected_record_files.clone();
        rejected_files.sort_by(|left, right| left.file_name.cmp(&right.file_name));
        assert_eq!(
            rejected_files,
            vec![
                RejectedSyncRecordFile {
                    kind: RejectedSyncRecordKind::Item,
                    file_name: tampered_file_name,
                },
                RejectedSyncRecordFile {
                    kind: RejectedSyncRecordKind::Item,
                    file_name: "malformed.enc".to_owned(),
                },
            ]
        );
        assert!(refresh
            .rejected_record_files
            .iter()
            .all(|file| !file.file_name.contains('/')));
        assert_eq!(refresh.loaded_items, 1);
        assert_eq!(refresh.detected_conflicts, 0);
        let items = unlocked.list_items().expect("list trusted items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, second.id);
        assert_eq!(items[0].title, "Trusted");
        assert!(unlocked.get_item(&first.id).is_err());
        let credential_items = unlocked
            .list_credential_items(false)
            .expect("list trusted credentials");
        assert_eq!(credential_items.len(), 1);
        assert_eq!(
            credential_items[0].credential.credential_id.to_string(),
            second.id.0
        );
        let second_credential_id = second
            .id
            .0
            .parse()
            .expect("current-format credential identity");
        assert_eq!(
            unlocked
                .credential_revision(second_credential_id)
                .expect("read trusted credential detail")
                .credential()
                .draft()
                .title,
            "Trusted"
        );
        assert_eq!(
            unlocked
                .search(SearchQuery {
                    text: "bob".to_owned(),
                    include_archived: false,
                })
                .expect("search trusted items")
                .len(),
            1
        );
        assert_eq!(
            unlocked
                .search_credential_items(SearchQuery {
                    text: "bob".to_owned(),
                    include_archived: false,
                })
                .expect("search trusted credentials")
                .len(),
            1
        );
        let write_error = unlocked
            .create_credential(CredentialDraft {
                title: "Blocked write".to_owned(),
                template_id: Some("custom".to_owned()),
                fields: vec![CredentialField::secret(
                    "secret",
                    SecretFieldKind::GenericSecret,
                    SecretBytes::new(b"blocked-secret".to_vec()),
                )],
                tags: Vec::new(),
                favorite: false,
            })
            .expect_err("writes must remain blocked while rejected records exist");
        assert!(write_error
            .to_string()
            .contains("current vault contains rejected records"));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn rejected_synced_tombstones_do_not_hide_valid_items() {
        let temp_dir = unique_temp_dir("rejected_synced_tombstones");
        let vault_path = temp_dir.join("Sync.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Sync".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Trusted", "alice", false, vec!["sync"]))
            .expect("create item");
        let deleted = unlocked
            .create_item(login_draft("Deleted", "bob", false, vec!["sync"]))
            .expect("create deleted item");
        unlocked.delete_item(&deleted.id).expect("delete item");
        let tombstone_path = fs::read_dir(vault_path.join("tombstones"))
            .expect("read tombstones")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("enc"))
            .expect("tombstone path");
        let tampered_tombstone_file_name = tombstone_path
            .file_name()
            .expect("tombstone file name")
            .to_string_lossy()
            .into_owned();
        tamper_record_ciphertext(&tombstone_path);
        fs::write(
            vault_path
                .join("tombstones")
                .join("malformed_tombstone.enc"),
            b"{not-json",
        )
        .expect("write malformed tombstone");

        let refresh = unlocked
            .refresh_from_disk()
            .expect("refresh with bad tombstone");
        assert_eq!(refresh.rejected_records, 2);
        assert_eq!(refresh.rejected_item_records, 0);
        assert_eq!(refresh.rejected_tombstone_records, 2);
        let mut rejected_files = refresh.rejected_record_files.clone();
        rejected_files.sort_by(|left, right| left.file_name.cmp(&right.file_name));
        assert_eq!(
            rejected_files,
            vec![
                RejectedSyncRecordFile {
                    kind: RejectedSyncRecordKind::Tombstone,
                    file_name: "malformed_tombstone.enc".to_owned(),
                },
                RejectedSyncRecordFile {
                    kind: RejectedSyncRecordKind::Tombstone,
                    file_name: tampered_tombstone_file_name,
                },
            ]
        );
        assert!(refresh
            .rejected_record_files
            .iter()
            .all(|file| !file.file_name.contains('/')));
        assert_eq!(refresh.loaded_items, 2);
        assert_eq!(refresh.applied_tombstones, 0);
        let items = unlocked.list_items().expect("list trusted items");
        assert!(items.iter().any(|item| item.title == "Trusted"));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn quarantine_rejected_records_moves_bad_records_and_preserves_valid_items() {
        let temp_dir = unique_temp_dir("quarantine_rejected_records");
        let vault_path = temp_dir.join("Sync.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Sync".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        let tampered = unlocked
            .create_item(login_draft("Tampered", "alice", false, vec!["sync"]))
            .expect("create tampered item");
        let trusted = unlocked
            .create_item(login_draft("Trusted", "bob", false, vec!["sync"]))
            .expect("create trusted item");

        tamper_record_ciphertext(&item_record_path(
            &vault_path,
            &tampered.id,
            &tampered.revision,
        ));
        fs::write(
            vault_path
                .join("tombstones")
                .join("malformed_tombstone.enc"),
            b"{not-json",
        )
        .expect("write malformed tombstone");

        let refresh = unlocked.refresh_from_disk().expect("refresh with rejected");
        assert_eq!(refresh.rejected_records, 2);
        assert_eq!(refresh.rejected_item_records, 1);
        assert_eq!(refresh.rejected_tombstone_records, 1);

        let quarantine = unlocked
            .quarantine_rejected_records()
            .expect("quarantine rejected records");
        assert_eq!(quarantine.moved_records, 2);
        assert_eq!(quarantine.moved_item_records, 1);
        assert_eq!(quarantine.moved_tombstone_records, 1);
        assert_eq!(record_file_count(&vault_path, "quarantine"), 0);
        assert_eq!(
            record_file_count_recursive(&vault_path.join("quarantine")),
            2
        );

        let refresh = unlocked
            .refresh_from_disk()
            .expect("refresh after quarantine");
        assert_eq!(refresh.rejected_records, 0);
        assert_eq!(refresh.rejected_item_records, 0);
        assert_eq!(refresh.rejected_tombstone_records, 0);
        assert_eq!(refresh.loaded_items, 1);
        let items = unlocked.list_items().expect("list trusted items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, trusted.id);
        assert_eq!(items[0].title, "Trusted");

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn quarantine_rejected_records_reports_zero_when_no_bad_records_exist() {
        let temp_dir = unique_temp_dir("quarantine_rejected_records_zero");
        let vault_path = temp_dir.join("Sync.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Sync".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Trusted", "alice", false, vec!["sync"]))
            .expect("create trusted item");

        let quarantine = unlocked
            .quarantine_rejected_records()
            .expect("quarantine clean vault");
        assert_eq!(quarantine.moved_records, 0);
        assert_eq!(quarantine.moved_item_records, 0);
        assert_eq!(quarantine.moved_tombstone_records, 0);
        assert!(!vault_path.join("quarantine").exists());
        assert_eq!(
            unlocked
                .refresh_from_disk()
                .expect("refresh clean vault")
                .rejected_records,
            0
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn missing_required_sync_directories_still_fail_hard() {
        let temp_dir = unique_temp_dir("missing_required_sync_directories");
        let vault_path = temp_dir.join("Sync.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Sync".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        fs::remove_dir_all(vault_path.join("items")).expect("remove required items dir");

        let error = unlocked
            .refresh_from_disk()
            .expect_err("missing required directory");
        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn refresh_rejects_missing_required_metadata_key_and_attachment_paths() {
        for required_path in ["vault.json", "keys.enc", "attachments"] {
            let temp_dir = unique_temp_dir(&format!(
                "missing_required_{}",
                required_path.replace('.', "_")
            ));
            let vault_path = temp_dir.join("Sync.pswvault");
            let password = SecretBytes::new(b"correct horse battery staple".to_vec());
            let core = VaultCore::new();
            let mut unlocked = core
                .create_vault(CreateVaultRequest {
                    path: vault_path.clone(),
                    display_name: Some("Sync".to_owned()),
                    master_password: password.clone(),
                })
                .expect("create vault")
                .unlock(crate::UnlockRequest {
                    master_password: password,
                })
                .expect("unlock vault");
            let path = vault_path.join(required_path);
            if path.is_dir() {
                fs::remove_dir_all(&path).expect("remove required directory");
            } else {
                fs::remove_file(&path).expect("remove required file");
            }

            let error = unlocked
                .refresh_from_disk()
                .expect_err("missing required structure");
            assert!(
                matches!(error, crate::VaultError::InvalidVault { .. }),
                "expected InvalidVault for {required_path}, got {error:?}"
            );

            std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
        }
    }

    #[test]
    fn fixture_based_sync_scenarios_match_expected_outcomes() {
        let fixture = read_sync_fixture();

        for scenario in fixture.scenarios {
            match scenario.kind.as_str() {
                "independent" => run_fixture_independent_scenario(&scenario),
                "same-item-conflict" => run_fixture_conflict_scenario(&scenario),
                other => panic!("unsupported sync scenario kind {other}"),
            }
        }
    }

    fn run_fixture_independent_scenario(scenario: &SyncScenario) {
        let temp_dir = unique_temp_dir(&scenario.name);
        let vault_path = temp_dir.join("Sync.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Sync".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        let first = unlocked
            .create_item(login_draft("First", "alice", false, vec!["sync"]))
            .expect("create first");
        let second = unlocked
            .create_item(login_draft("Second", "bob", false, vec!["sync"]))
            .expect("create second");
        unlocked
            .update_item(
                &first.id,
                login_draft("First Updated", "alice", false, vec!["sync"]),
            )
            .expect("update first");
        unlocked
            .update_item(
                &second.id,
                login_draft("Second Updated", "bob", false, vec!["sync"]),
            )
            .expect("update second");

        let refresh = unlocked.refresh_from_disk().expect("refresh");
        assert_eq!(refresh.detected_conflicts, scenario.expected_conflicts);
        assert_eq!(
            unlocked.list_items().expect("list items").len(),
            scenario.expected_items
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    fn run_fixture_conflict_scenario(scenario: &SyncScenario) {
        let temp_dir = unique_temp_dir(&scenario.name);
        let vault_path = temp_dir.join("Sync.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Sync".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let created = unlocked
            .create_item(login_draft("Base", "alice", false, vec!["sync"]))
            .expect("create item");
        let base = unlocked.get_item(&created.id).expect("get base item");

        let mut left = base.clone();
        left.parent_revision = Some(base.revision.clone());
        left.revision = unlocked.new_item_revision();
        left.draft.title = "Left".to_owned();
        unlocked.save_item_revision(&left).expect("save left fork");

        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = unlocked.new_item_revision();
        right.draft.title = "Right".to_owned();
        unlocked
            .save_item_revision(&right)
            .expect("save right fork");

        let refresh = unlocked.refresh_from_disk().expect("refresh");
        assert_eq!(refresh.detected_conflicts, scenario.expected_conflicts);
        let items = unlocked.list_items().expect("list items");
        assert_eq!(items.len(), scenario.expected_items);
        assert!(matches!(items[0].status, ItemStatus::Conflicted(_)));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_import_preview_detects_duplicates_and_commit_skips_them() {
        let temp_dir = unique_temp_dir("bitwarden_import_preview_detects_duplicates");
        let vault_path = temp_dir.join("Import.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Import".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Example", "alice", false, vec!["work"]))
            .expect("create duplicate baseline");

        let source_path = fixture_path("bitwarden-basic.json");
        let preview = unlocked
            .preview_import(ImportPreviewRequest {
                source_path: source_path.clone(),
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
            })
            .expect("preview import");
        assert_eq!(preview.importable_records, 2);
        assert_eq!(preview.duplicate_records, 1);
        assert_eq!(preview.skipped_records, 1);

        let result = unlocked
            .commit_import(ImportCommitRequest {
                source_path,
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                keep_duplicates: false,
            })
            .expect("commit import");
        assert_eq!(result.importable_records, 1);
        assert_eq!(result.duplicate_records, 1);
        assert_eq!(result.skipped_records, 2);
        assert_eq!(unlocked.list_items().expect("list imported").len(), 2);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_import_persists_typed_fields_and_fresh_stable_identities() {
        let temp_dir = unique_temp_dir("bitwarden_import_persists_typed_fields");
        let vault_path = temp_dir.join("TypedImport.pswvault");
        let source_path = temp_dir.join("typed-bitwarden.json");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        fs::write(
            &source_path,
            r#"{
  "encrypted": false,
  "items": [
    {
      "id": "source-login-id",
      "type": 1,
      "name": "Example Login",
      "favorite": true,
      "notes": "Imported login",
      "login": {
        "username": "alice",
        "password": "login-secret",
        "totp": "JBSWY3DPEHPK3PXP",
        "uris": [{ "uri": "https://example.com" }]
      }
    },
    {
      "id": "source-note-id",
      "type": 2,
      "name": "Recovery Note",
      "notes": "offline recovery material"
    },
    {
      "id": "source-card-id",
      "type": 3,
      "name": "Travel Card",
      "notes": "travel only",
      "card": {
        "cardholderName": "Alice Example",
        "number": "4111111111111111",
        "expMonth": "04",
        "expYear": "2030",
        "code": "123"
      }
    }
  ]
}"#,
        )
        .expect("write import source");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Typed Import".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let records_before_preview = record_file_count(&vault_path, ITEMS_DIR_NAME);
        let preview = unlocked
            .preview_import(ImportPreviewRequest {
                source_path: source_path.clone(),
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
            })
            .expect("preview import");
        assert_eq!(preview.importable_records, 3);
        assert_eq!(preview.skipped_records, 0);
        assert_eq!(
            record_file_count(&vault_path, ITEMS_DIR_NAME),
            records_before_preview
        );

        let first_result = unlocked
            .commit_import(ImportCommitRequest {
                source_path: source_path.clone(),
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                keep_duplicates: true,
            })
            .expect("commit first import");
        assert_eq!(first_result.importable_records, 3);

        let first_items = unlocked
            .list_credential_items(false)
            .expect("list typed imports");
        assert_eq!(first_items.len(), 3);
        let login = first_items
            .iter()
            .find(|item| item.credential.title == "Example Login")
            .expect("find imported login");
        let note = first_items
            .iter()
            .find(|item| item.credential.title == "Recovery Note")
            .expect("find imported note");
        let card = first_items
            .iter()
            .find(|item| item.credential.title == "Travel Card")
            .expect("find imported card");

        let login_revision = unlocked
            .credential_revision(login.credential.credential_id)
            .expect("read imported login");
        let login_draft = login_revision.credential().draft();
        assert_eq!(login_draft.template_id.as_deref(), Some(TEMPLATE_LOGIN));
        assert_eq!(
            credential_text_field(login_draft, "username"),
            Some("alice")
        );
        assert_eq!(
            credential_text_field(login_draft, "url"),
            Some("https://example.com")
        );
        assert_eq!(
            credential_secret_field(login_draft, "password")
                .map(|(_, kind, secret)| (kind, secret)),
            Some((SecretFieldKind::Password, b"login-secret".as_slice()))
        );
        assert_eq!(
            credential_secret_field(login_draft, "totp-seed")
                .map(|(_, kind, secret)| (kind, secret)),
            Some((SecretFieldKind::TotpSeed, b"JBSWY3DPEHPK3PXP".as_slice()))
        );

        let note_revision = unlocked
            .credential_revision(note.credential.credential_id)
            .expect("read imported note");
        let note_draft = note_revision.credential().draft();
        assert_eq!(
            note_draft.template_id.as_deref(),
            Some(TEMPLATE_SECURE_NOTE)
        );
        assert_eq!(
            credential_secret_field(note_draft, "body").map(|(_, kind, secret)| (kind, secret)),
            Some((
                SecretFieldKind::GenericSecret,
                b"offline recovery material".as_slice()
            ))
        );

        let card_revision = unlocked
            .credential_revision(card.credential.credential_id)
            .expect("read imported card");
        let card_draft = card_revision.credential().draft();
        assert_eq!(
            card_draft.template_id.as_deref(),
            Some(TEMPLATE_CREDIT_CARD)
        );
        assert_eq!(
            credential_text_field(card_draft, "cardholder-name"),
            Some("Alice Example")
        );
        assert_eq!(credential_text_field(card_draft, "expiry-month"), Some("4"));
        assert_eq!(
            credential_text_field(card_draft, "expiry-year"),
            Some("2030")
        );
        assert_eq!(
            credential_secret_field(card_draft, "number").map(|(_, kind, secret)| (kind, secret)),
            Some((
                SecretFieldKind::GenericSecret,
                b"4111111111111111".as_slice()
            ))
        );
        assert_eq!(
            credential_secret_field(card_draft, "verification-code")
                .map(|(_, kind, secret)| (kind, secret)),
            Some((SecretFieldKind::GenericSecret, b"123".as_slice()))
        );

        let first_credential_ids = first_items
            .iter()
            .map(|item| item.credential.credential_id)
            .collect::<std::collections::BTreeSet<_>>();
        let first_secret_field_ids = first_items
            .iter()
            .flat_map(|item| item.credential.secret_fields.iter())
            .map(|field| field.secret_field_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            imported_secret_field_ids(
                &unlocked
                    .credential_revision(login.credential.credential_id)
                    .expect("reread imported login")
            ),
            imported_secret_field_ids(&login_revision)
        );

        let second_result = unlocked
            .commit_import(ImportCommitRequest {
                source_path,
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                keep_duplicates: true,
            })
            .expect("commit duplicate import");
        assert_eq!(second_result.importable_records, 3);
        assert_eq!(second_result.duplicate_records, 3);

        let all_items = unlocked
            .list_credential_items(false)
            .expect("list repeated imports");
        assert_eq!(all_items.len(), 6);
        let all_credential_ids = all_items
            .iter()
            .map(|item| item.credential.credential_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(all_credential_ids.len(), 6);
        let second_credential_ids = all_credential_ids
            .difference(&first_credential_ids)
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(second_credential_ids.len(), 3);

        let all_secret_field_ids = all_items
            .iter()
            .flat_map(|item| item.credential.secret_fields.iter())
            .map(|field| field.secret_field_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(all_secret_field_ids.len(), 10);
        assert!(first_secret_field_ids.is_subset(&all_secret_field_ids));
        assert_eq!(
            all_secret_field_ids
                .difference(&first_secret_field_ids)
                .count(),
            first_secret_field_ids.len()
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn import_duplicate_detection_accepts_custom_typed_credentials() {
        let temp_dir = unique_temp_dir("import_duplicate_detection_accepts_custom_typed");
        let vault_path = temp_dir.join("CustomTypedImport.pswvault");
        let source_path = fixture_path("bitwarden-basic.json");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Custom Typed Import".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let custom = unlocked
            .create_credential(CredentialDraft {
                title: "Build API".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![CredentialField::secret(
                    "token",
                    SecretFieldKind::ApiToken,
                    SecretBytes::new(b"custom-token".to_vec()),
                )],
                tags: vec!["automation".to_owned()],
                favorite: false,
            })
            .expect("create custom typed credential");
        unlocked
            .create_credential(CredentialDraft {
                title: "Example".to_owned(),
                template_id: Some(TEMPLATE_LOGIN.to_owned()),
                fields: vec![
                    CredentialField::text("username", "alice"),
                    CredentialField::secret(
                        "password",
                        SecretFieldKind::Password,
                        SecretBytes::new(b"existing-password".to_vec()),
                    ),
                    CredentialField::text("url", "https://example.com"),
                ],
                tags: Vec::new(),
                favorite: false,
            })
            .expect("create duplicate login baseline");

        let preview = unlocked
            .preview_import(ImportPreviewRequest {
                source_path: source_path.clone(),
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
            })
            .expect("preview alongside custom typed credential");
        assert_eq!(preview.importable_records, 2);
        assert_eq!(preview.duplicate_records, 1);
        assert_eq!(preview.skipped_records, 1);

        let result = unlocked
            .commit_import(ImportCommitRequest {
                source_path,
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                keep_duplicates: false,
            })
            .expect("commit alongside custom typed credential");
        assert_eq!(result.importable_records, 1);
        assert_eq!(result.duplicate_records, 1);
        assert_eq!(result.skipped_records, 2);

        let items = unlocked
            .list_credential_items(false)
            .expect("list typed credentials");
        assert_eq!(items.len(), 3);
        assert!(items
            .iter()
            .any(|item| item.credential.credential_id == custom.credential.credential_id));
        assert!(items
            .iter()
            .any(|item| item.credential.title == "Recovery Note"));
        assert_eq!(
            items
                .iter()
                .filter(|item| item.credential.title == "Example")
                .count(),
            1
        );

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_import_maps_folders_to_tags_without_changing_duplicate_identity() {
        let temp_dir = unique_temp_dir("bitwarden_import_maps_folders_to_tags");
        let vault_path = temp_dir.join("ImportFolders.pswvault");
        let source_path = temp_dir.join("bitwarden-folders.json");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        fs::write(
            &source_path,
            r#"{
  "encrypted": false,
  "folders": [
    { "id": "work", "name": "Work" },
    { "id": "blank", "name": "   " }
  ],
  "items": [
    {
      "type": 1,
      "name": "Example",
      "folderId": "work",
      "login": {
        "username": "alice",
        "password": "secret",
        "uris": [{ "uri": "https://example.com" }]
      }
    },
    {
      "type": 1,
      "name": "Unknown Folder",
      "folderId": "missing",
      "login": {
        "username": "unknown@example.com",
        "password": "secret",
        "uris": [{ "uri": "https://unknown.example" }]
      }
    },
    {
      "type": 1,
      "name": "Blank Folder",
      "folderId": "blank",
      "login": {
        "username": "blank@example.com",
        "password": "secret",
        "uris": [{ "uri": "https://blank.example" }]
      }
    },
    {
      "type": 2,
      "name": "Recovery Note",
      "folderId": "work",
      "notes": "Imported recovery material"
    },
    {
      "type": 3,
      "name": "Travel Card",
      "folderId": "work",
      "card": {
        "cardholderName": "Alice Example",
        "number": "4111111111111111"
      }
    }
  ]
}"#,
        )
        .expect("write import source");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Import Folders".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        unlocked
            .create_item(login_draft("Example", "alice", false, vec![]))
            .expect("create duplicate baseline");

        let preview = unlocked
            .preview_import(ImportPreviewRequest {
                source_path: source_path.clone(),
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
            })
            .expect("preview import");
        assert_eq!(preview.importable_records, 5);
        assert_eq!(preview.duplicate_records, 1);
        assert_eq!(preview.skipped_records, 0);

        let result = unlocked
            .commit_import(ImportCommitRequest {
                source_path,
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                keep_duplicates: false,
            })
            .expect("commit import");
        assert_eq!(result.importable_records, 4);
        assert_eq!(result.duplicate_records, 1);
        assert_eq!(result.skipped_records, 1);

        let items = unlocked.list_items().expect("list imported");
        assert_eq!(
            items.iter().filter(|item| item.title == "Example").count(),
            1
        );
        assert_eq!(
            items
                .iter()
                .find(|item| item.title == "Unknown Folder")
                .expect("find unknown folder item")
                .tags,
            Vec::<String>::new()
        );
        assert_eq!(
            items
                .iter()
                .find(|item| item.title == "Blank Folder")
                .expect("find blank folder item")
                .tags,
            Vec::<String>::new()
        );
        assert_eq!(
            items
                .iter()
                .find(|item| item.title == "Recovery Note")
                .expect("find tagged note")
                .tags,
            vec!["Work".to_owned()]
        );
        assert_eq!(
            items
                .iter()
                .find(|item| item.title == "Travel Card")
                .expect("find tagged card")
                .tags,
            vec!["Work".to_owned()]
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_import_normalizes_otpauth_totp_uri() {
        let temp_dir = unique_temp_dir("bitwarden_import_normalizes_otpauth_totp_uri");
        let vault_path = temp_dir.join("ImportTotp.pswvault");
        let source_path = temp_dir.join("bitwarden-totp-uri.json");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        fs::write(
            &source_path,
            r#"{
  "encrypted": false,
  "items": [
    {
      "type": 1,
      "name": "Email",
      "login": {
        "username": "alice",
        "password": "secret",
        "totp": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        "uris": [{ "uri": "https://example.com" }]
      }
    }
  ]
}"#,
        )
        .expect("write import source");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Import TOTP".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let result = unlocked
            .commit_import(ImportCommitRequest {
                source_path,
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                keep_duplicates: true,
            })
            .expect("commit import");

        assert_eq!(result.importable_records, 1);
        let summary = unlocked
            .list_items()
            .expect("list imported")
            .into_iter()
            .find(|item| item.title == "Email")
            .expect("find imported login");
        let imported = unlocked.get_item(&summary.id).expect("get imported login");
        let VaultItemContent::Login(login) = imported.draft.content else {
            panic!("expected login item");
        };
        assert_eq!(
            login.totp_secret.expect("stored TOTP").expose(),
            b"JBSWY3DPEHPK3PXP"
        );
        let code = unlocked
            .totp_code_at(&summary.id, 59)
            .expect("generate imported TOTP");
        assert_eq!(code.code.len(), 6);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn generic_login_csv_import_preserves_supported_fields_and_warnings() {
        let temp_dir = unique_temp_dir("generic_login_csv_import_preserves_fields");
        let vault_path = temp_dir.join("ImportCsv.pswvault");
        let source_path = fixture_path("generic-login.csv");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Import CSV".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let preview = unlocked
            .preview_import(ImportPreviewRequest {
                source_path: source_path.clone(),
                source_format: crate::import::GENERIC_LOGIN_CSV_FORMAT.to_owned(),
            })
            .expect("preview CSV import");
        assert_eq!(preview.importable_records, 2);
        assert_eq!(preview.skipped_records, 1);
        assert_eq!(preview.duplicate_records, 0);
        assert!(preview
            .warnings
            .iter()
            .any(|warning| warning.contains("Skipped CSV login row without a title")));
        assert!(preview
            .warnings
            .iter()
            .any(|warning| warning.contains("Skipped invalid TOTP secret")));

        let result = unlocked
            .commit_import(ImportCommitRequest {
                source_path,
                source_format: crate::import::GENERIC_LOGIN_CSV_FORMAT.to_owned(),
                keep_duplicates: true,
            })
            .expect("commit CSV import");
        assert_eq!(result.importable_records, 2);
        assert_eq!(result.skipped_records, 1);

        let email_summary = unlocked
            .list_items()
            .expect("list imported")
            .into_iter()
            .find(|item| item.title == "Email")
            .expect("find imported email");
        assert_eq!(
            email_summary.tags,
            vec!["Work".to_owned(), "personal".to_owned(), "mail".to_owned()]
        );
        let email = unlocked
            .get_item(&email_summary.id)
            .expect("get imported email");
        assert!(email.draft.favorite);
        let VaultItemContent::Login(login) = email.draft.content else {
            panic!("expected login item");
        };
        assert_eq!(login.username.as_deref(), Some("alice@example.com"));
        assert_eq!(
            login.password.expect("imported password").expose(),
            b"email-password"
        );
        assert_eq!(login.urls, vec!["https://mail.example.com".to_owned()]);
        assert_eq!(login.notes.as_deref(), Some("Primary inbox"));
        assert_eq!(
            login.totp_secret.expect("imported TOTP").expose(),
            b"JBSWY3DPEHPK3PXP"
        );

        let broken_summary = unlocked
            .list_items()
            .expect("list imported")
            .into_iter()
            .find(|item| item.title == "Broken OTP")
            .expect("find broken OTP login");
        assert_eq!(
            broken_summary.tags,
            vec!["Archive".to_owned(), "personal".to_owned()]
        );
        let broken = unlocked
            .get_item(&broken_summary.id)
            .expect("get broken OTP login");
        let VaultItemContent::Login(login) = broken.draft.content else {
            panic!("expected login item");
        };
        assert_eq!(login.username.as_deref(), Some("bob@example.com"));
        assert_eq!(
            login.password.expect("broken login password").expose(),
            b"broken-password"
        );
        assert!(login.totp_secret.is_none());

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn generic_login_csv_rejects_unsupported_header_layout() {
        let temp_dir = unique_temp_dir("generic_login_csv_rejects_unsupported_layout");
        let vault_path = temp_dir.join("ImportUnsupportedCsv.pswvault");
        let source_path = temp_dir.join("unsupported.csv");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        fs::write(
            &source_path,
            "Label,User,Secret\nEmail,alice@example.com,password\n",
        )
        .expect("write unsupported CSV");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Import Unsupported CSV".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let error = unlocked
            .preview_import(ImportPreviewRequest {
                source_path,
                source_format: crate::import::GENERIC_LOGIN_CSV_FORMAT.to_owned(),
            })
            .expect_err("unsupported CSV layout rejected");
        assert!(error
            .to_string()
            .contains("generic login CSV requires a title or name header"));

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_import_writes_credit_cards_and_skips_nameless_cards() {
        let temp_dir = unique_temp_dir("bitwarden_import_writes_credit_cards");
        let vault_path = temp_dir.join("ImportCards.pswvault");
        let source_path = temp_dir.join("bitwarden-cards.json");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        fs::write(
            &source_path,
            r#"{
  "encrypted": false,
  "items": [
    {
      "type": 3,
      "name": "Travel Card",
      "notes": "Travel rewards card",
      "favorite": true,
      "card": {
        "cardholderName": "Alice Example",
        "number": "4111111111111111",
        "expMonth": "04",
        "expYear": "2030",
        "code": "123"
      }
    },
    {
      "type": 3,
      "name": "Backup Card",
      "card": {
        "cardholderName": "Alice Backup",
        "number": "5555555555554444",
        "expMonth": "soon",
        "expYear": "later",
        "code": "987"
      }
    },
    {
      "type": 3,
      "name": "   ",
      "card": {
        "number": "4000000000000002"
      }
    }
  ]
}"#,
        )
        .expect("write import source");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Import Cards".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let preview = unlocked
            .preview_import(ImportPreviewRequest {
                source_path: source_path.clone(),
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
            })
            .expect("preview import");
        assert_eq!(preview.importable_records, 2);
        assert_eq!(preview.skipped_records, 1);
        assert!(preview
            .warnings
            .iter()
            .any(|warning| warning.contains("Skipped credit card without a name")));

        let result = unlocked
            .commit_import(ImportCommitRequest {
                source_path,
                source_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                keep_duplicates: true,
            })
            .expect("commit import");
        assert_eq!(result.importable_records, 2);
        assert_eq!(result.skipped_records, 1);

        let travel = unlocked
            .list_items()
            .expect("list imported")
            .into_iter()
            .find(|item| item.title == "Travel Card")
            .expect("find imported card");
        let item = unlocked.get_item(&travel.id).expect("get imported card");
        let VaultItemContent::CreditCard(card) = item.draft.content else {
            panic!("expected credit card item");
        };
        assert_eq!(card.cardholder_name.as_deref(), Some("Alice Example"));
        assert_eq!(
            card.number.expect("card number").expose(),
            b"4111111111111111"
        );
        assert_eq!(card.expiry_month, Some(4));
        assert_eq!(card.expiry_year, Some(2030));
        assert_eq!(card.verification_code.expect("card code").expose(), b"123");
        assert_eq!(card.notes.as_deref(), Some("Travel rewards card"));
        assert!(item.draft.favorite);

        let backup = unlocked
            .list_items()
            .expect("list imported")
            .into_iter()
            .find(|item| item.title == "Backup Card")
            .expect("find imported malformed card");
        let item = unlocked.get_item(&backup.id).expect("get malformed card");
        let VaultItemContent::CreditCard(card) = item.draft.content else {
            panic!("expected credit card item");
        };
        assert_eq!(card.cardholder_name.as_deref(), Some("Alice Backup"));
        assert_eq!(card.expiry_month, None);
        assert_eq!(card.expiry_year, None);
        assert_eq!(
            card.number.expect("backup card number").expose(),
            b"5555555555554444"
        );

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn keptnear_plaintext_export_preserves_typed_credentials_and_source_relationships() {
        let temp_dir = unique_temp_dir("keptnear_plaintext_export_preserves_typed");
        let vault_path = temp_dir.join("TypedExport.pswvault");
        let destination_path = temp_dir.join("typed-export.json");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Typed Export".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let token = unlocked
            .create_credential(CredentialDraft {
                title: "Build API".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![
                    CredentialField::secret(
                        "token",
                        SecretFieldKind::ApiToken,
                        SecretBytes::new(vec![0, 1, 2, 255]),
                    )
                    .with_label("Automation token"),
                    CredentialField::text("expiry", "2030-01-02"),
                ],
                tags: vec!["automation".to_owned(), "production".to_owned()],
                favorite: true,
            })
            .expect("create API token");
        let login = unlocked
            .create_credential(CredentialDraft {
                title: "Archived Login".to_owned(),
                template_id: Some(TEMPLATE_LOGIN.to_owned()),
                fields: vec![
                    CredentialField::text("username", "alice"),
                    CredentialField::secret(
                        "password",
                        SecretFieldKind::Password,
                        SecretBytes::new(b"archived-password".to_vec()),
                    ),
                ],
                tags: Vec::new(),
                favorite: false,
            })
            .expect("create login");
        unlocked
            .archive_credential_with_expected_revision(
                login.credential.credential_id,
                login.revision_id,
            )
            .expect("archive login");

        let result = unlocked
            .export_items(ExportItemsRequest {
                destination_path: destination_path.clone(),
                export_format: crate::export::KEPTNEAR_JSON_FORMAT.to_owned(),
                current_master_password: password,
            })
            .expect("export typed credentials");
        assert_eq!(result.exported_records, 2);
        assert_eq!(result.skipped_records, 0);
        assert!(result.omissions.is_empty());
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("plaintext secrets")));

        let exported: Value =
            serde_json::from_slice(&fs::read(destination_path).expect("read typed export"))
                .expect("parse typed export");
        assert_eq!(exported["format"], "keptnear-plaintext-export");
        assert_eq!(exported["version"], 1);
        assert!(exported["warning"]
            .as_str()
            .expect("warning")
            .contains("Base64 is reversible"));
        assert_eq!(
            exported["sourceVaultId"],
            unlocked
                .metadata
                .vault_id
                .expect("source vault identity")
                .to_string()
        );
        assert_eq!(
            exported["omissions"].as_array().expect("omissions").len(),
            0
        );

        let token_item = exported["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["title"] == "Build API")
            .expect("exported token");
        assert_eq!(
            token_item["sourceCredentialId"],
            token.credential.credential_id.to_string()
        );
        assert_eq!(token_item["status"], "active");
        assert_eq!(token_item["templateId"], "api-token");
        assert_eq!(token_item["tags"][0], "automation");
        assert_eq!(token_item["tags"][1], "production");
        assert_eq!(token_item["favorite"], true);
        let token_field = token_item["fields"]
            .as_array()
            .expect("token fields")
            .iter()
            .find(|field| field["role"] == "token")
            .expect("token field");
        assert_eq!(token_field["label"], "Automation token");
        assert_eq!(token_field["value"]["type"], "secret");
        assert_eq!(token_field["value"]["kind"], "api-token");
        assert_eq!(token_field["value"]["encoding"], "base64");
        assert_eq!(token_field["value"]["valueBase64"], "AAEC/w==");
        assert_eq!(
            token_field["value"]["sourceSecretFieldId"],
            token.credential.secret_fields[0]
                .secret_field_id
                .to_string()
        );
        let expiry_field = token_item["fields"]
            .as_array()
            .expect("token fields")
            .iter()
            .find(|field| field["role"] == "expiry")
            .expect("expiry field");
        assert_eq!(expiry_field["value"]["type"], "text");
        assert_eq!(expiry_field["value"]["text"], "2030-01-02");

        let archived = exported["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["title"] == "Archived Login")
            .expect("exported archived login");
        assert_eq!(archived["status"], "archived");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_export_reports_unrepresentable_typed_credentials_without_partial_items() {
        let temp_dir = unique_temp_dir("bitwarden_export_reports_typed_omissions");
        let vault_path = temp_dir.join("CompatibilityExport.pswvault");
        let destination_path = temp_dir.join("bitwarden.json");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Compatibility Export".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        unlocked
            .create_credential(CredentialDraft {
                title: "Supported Login".to_owned(),
                template_id: Some(TEMPLATE_LOGIN.to_owned()),
                fields: vec![
                    CredentialField::text("username", "alice"),
                    CredentialField::secret(
                        "password",
                        SecretFieldKind::Password,
                        SecretBytes::new(b"supported-password".to_vec()),
                    ),
                ],
                tags: Vec::new(),
                favorite: false,
            })
            .expect("create supported login");
        unlocked
            .create_credential(CredentialDraft {
                title: "Build API".to_owned(),
                template_id: Some("api-token".to_owned()),
                fields: vec![CredentialField::secret(
                    "token",
                    SecretFieldKind::ApiToken,
                    SecretBytes::new(b"must-not-be-partially-exported".to_vec()),
                )],
                tags: Vec::new(),
                favorite: false,
            })
            .expect("create unsupported template");
        unlocked
            .create_credential(CredentialDraft {
                title: "Extended Login".to_owned(),
                template_id: Some(TEMPLATE_LOGIN.to_owned()),
                fields: vec![
                    CredentialField::text("username", "bob"),
                    CredentialField::text("account-id", "not-representable"),
                ],
                tags: Vec::new(),
                favorite: false,
            })
            .expect("create unsupported field");

        let result = unlocked
            .export_items(ExportItemsRequest {
                destination_path: destination_path.clone(),
                export_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                current_master_password: password,
            })
            .expect("export compatible subset");
        assert_eq!(result.exported_records, 1);
        assert_eq!(result.skipped_records, 2);
        assert_eq!(
            result.omissions,
            vec![
                crate::ExportOmission {
                    reason: crate::ExportOmissionReason::UnsupportedTemplate,
                    count: 1,
                },
                crate::ExportOmission {
                    reason: crate::ExportOmissionReason::UnsupportedField,
                    count: 1,
                },
            ]
        );
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("Use keptnear-json")));

        let bytes = fs::read(destination_path).expect("read compatibility export");
        let exported: Value = serde_json::from_slice(&bytes).expect("parse compatibility export");
        assert_eq!(exported["items"].as_array().expect("items").len(), 1);
        assert_eq!(exported["items"][0]["name"], "Supported Login");
        let text = String::from_utf8(bytes).expect("UTF-8 compatibility export");
        assert!(!text.contains("must-not-be-partially-exported"));
        assert!(!text.contains("not-representable"));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn keptnear_plaintext_export_reports_conflicted_credentials() {
        let temp_dir = unique_temp_dir("keptnear_export_reports_conflicts");
        let vault_path = temp_dir.join("ConflictExport.pswvault");
        let destination_path = temp_dir.join("conflict-export.json");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let mut unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Conflict Export".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        let created = unlocked
            .create_item(login_draft("Base", "alice", false, vec![]))
            .expect("create base");
        let base = unlocked.get_item(&created.id).expect("get base");
        let mut left = base.clone();
        left.parent_revision = Some(base.revision.clone());
        left.revision = unlocked.new_item_revision();
        left.draft.title = "Left".to_owned();
        unlocked.save_item_revision(&left).expect("save left");
        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = unlocked.new_item_revision();
        right.draft.title = "Right".to_owned();
        unlocked.save_item_revision(&right).expect("save right");

        let result = unlocked
            .export_items(ExportItemsRequest {
                destination_path: destination_path.clone(),
                export_format: crate::export::KEPTNEAR_JSON_FORMAT.to_owned(),
                current_master_password: password,
            })
            .expect("export with conflict");
        assert_eq!(result.exported_records, 0);
        assert_eq!(result.skipped_records, 1);
        assert_eq!(
            result.omissions,
            vec![crate::ExportOmission {
                reason: crate::ExportOmissionReason::ConflictedCredential,
                count: 1,
            }]
        );

        let exported: Value =
            serde_json::from_slice(&fs::read(destination_path).expect("read export"))
                .expect("parse export");
        assert!(exported["items"].as_array().expect("items").is_empty());
        assert_eq!(exported["omissions"][0]["reason"], "conflicted-credential");
        assert_eq!(exported["omissions"][0]["count"], 1);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_export_writes_login_secure_note_and_archived_items() {
        let temp_dir = unique_temp_dir("bitwarden_export_writes_supported_items");
        let vault_path = temp_dir.join("Export.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Export".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");

        unlocked
            .create_item(login_draft("Email", "alice", true, vec!["work", "primary"]))
            .expect("create login");
        unlocked
            .create_item(secure_note_draft(
                "Recovery Notes",
                "offline backup codes",
                vec!["personal"],
            ))
            .expect("create secure note");
        let archived = unlocked
            .create_item(login_draft("Archived Login", "archived", false, vec![]))
            .expect("create archived login");
        unlocked
            .archive_item(&archived.id)
            .expect("archive login before export");

        let destination_path = temp_dir.join("export.json");
        let result = unlocked
            .export_items(ExportItemsRequest {
                destination_path: destination_path.clone(),
                export_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                current_master_password: password,
            })
            .expect("export items");

        assert_eq!(result.exported_records, 3);
        assert_eq!(result.skipped_records, 0);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("plaintext secrets")));
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("additional tags")));

        let exported: Value =
            serde_json::from_slice(&fs::read(destination_path).expect("read export"))
                .expect("parse export");
        assert_eq!(exported["encrypted"], false);
        assert_eq!(exported["items"].as_array().expect("items").len(), 3);
        assert!(exported["folders"]
            .as_array()
            .expect("folders")
            .iter()
            .any(|folder| folder["name"] == "work"));

        let email = exported_item(&exported, "Email");
        assert_eq!(email["type"], 1);
        assert_eq!(email["favorite"], true);
        assert_eq!(email["login"]["username"], "alice");
        assert_eq!(email["login"]["password"], "secret");
        assert_eq!(email["login"]["totp"], "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(email["login"]["uris"][0]["uri"], "https://example.com");

        let note = exported_item(&exported, "Recovery Notes");
        assert_eq!(note["type"], 2);
        assert_eq!(note["notes"], "offline backup codes");
        assert_eq!(note["secureNote"]["type"], 0);

        let archived = exported_item(&exported, "Archived Login");
        assert_eq!(archived["type"], 1);
        assert_eq!(archived["login"]["username"], "archived");

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_export_writes_credit_cards_and_software_licenses() {
        let temp_dir = unique_temp_dir("bitwarden_export_writes_structured_items");
        let vault_path = temp_dir.join("ExportStructured.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Export Structured".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");
        unlocked
            .create_item(software_license_draft("License"))
            .expect("create software license");
        unlocked
            .create_item(credit_card_draft("Travel Card"))
            .expect("create credit card");

        let destination_path = temp_dir.join("export.json");
        let result = unlocked
            .export_items(ExportItemsRequest {
                destination_path: destination_path.clone(),
                export_format: crate::import::BITWARDEN_JSON_FORMAT.to_owned(),
                current_master_password: password,
            })
            .expect("export items");

        assert_eq!(result.exported_records, 2);
        assert_eq!(result.skipped_records, 0);
        assert!(result.warnings.iter().any(
            |warning| warning.contains("Software license items were exported as secure notes")
        ));
        let exported: Value =
            serde_json::from_slice(&fs::read(destination_path).expect("read export"))
                .expect("parse export");
        assert_eq!(exported["items"].as_array().expect("items").len(), 2);
        assert!(exported["folders"]
            .as_array()
            .expect("folders")
            .iter()
            .any(|folder| folder["name"] == "finance"));

        let card = exported_item(&exported, "Travel Card");
        assert_eq!(card["type"], 3);
        assert_eq!(card["favorite"], true);
        assert_eq!(card["card"]["cardholderName"], "Alice Example");
        assert_eq!(card["card"]["number"], "4111111111111111");
        assert_eq!(card["card"]["expMonth"], "04");
        assert_eq!(card["card"]["expYear"], "2030");
        assert_eq!(card["card"]["code"], "123");
        assert_eq!(card["notes"], "Travel rewards card");

        let license = exported_item(&exported, "License");
        assert_eq!(license["type"], 2);
        assert_eq!(license["secureNote"]["type"], 0);
        let notes = license["notes"].as_str().expect("license notes");
        assert!(notes.contains("Product: Product"));
        assert!(notes.contains("Licensed to: Alice"));
        assert!(notes.contains("License key: AAAA-BBBB-CCCC"));
        assert!(notes.contains("Renewal due Q4"));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn bitwarden_export_rejects_unsupported_format_without_writing_file() {
        let temp_dir = unique_temp_dir("bitwarden_export_rejects_unsupported_format");
        let vault_path = temp_dir.join("ExportReject.pswvault");
        let destination_path = temp_dir.join("export.json");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Export Reject".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock vault");

        let error = unlocked
            .export_items(ExportItemsRequest {
                destination_path: destination_path.clone(),
                export_format: "unknown-format".to_owned(),
                current_master_password: password,
            })
            .expect_err("unsupported export format");

        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));
        assert!(!destination_path.exists());

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn plaintext_export_requires_current_master_password_before_writing() {
        let temp_dir = unique_temp_dir("plaintext_export_requires_reauthentication");
        let vault_path = temp_dir.join("ReauthenticatedExport.pswvault");
        let destination_path = temp_dir.join("export.json");
        let correct_password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let unlocked = VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Reauthenticated Export".to_owned()),
                master_password: correct_password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: correct_password,
            })
            .expect("unlock vault");
        let wrong_password_marker = "KN_EXPORT_WRONG_PASSWORD_11_3";
        let request = ExportItemsRequest {
            destination_path: destination_path.clone(),
            export_format: crate::export::KEPTNEAR_JSON_FORMAT.to_owned(),
            current_master_password: SecretBytes::new(wrong_password_marker.as_bytes().to_vec()),
        };

        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(wrong_password_marker));

        let error = unlocked
            .export_items(request)
            .expect_err("wrong current master password");
        assert!(matches!(error, crate::VaultError::InvalidCredentials));
        assert!(!destination_path.exists());

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn password_health_audit_reports_weak_and_reused_without_secrets() {
        let temp_dir = unique_temp_dir("password_health_audit_reports_issues");
        let vault_path = temp_dir.join("Health.pswvault");
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: vault_path,
                display_name: Some("Health".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");

        let weak_title = unlocked
            .create_item(login_draft_with_password(
                "Email",
                "alice@example.com",
                "EmailPassword2026!",
                false,
                vec![],
            ))
            .expect("create title weak login");
        let weak_username = unlocked
            .create_item(login_draft_with_password(
                "Bank",
                "alice",
                "alice-Strong-2026!",
                false,
                vec![],
            ))
            .expect("create username weak login");
        let reused_one = unlocked
            .create_item(login_draft_with_password(
                "Work",
                "work@example.com",
                "Shared-Password-123!",
                false,
                vec![],
            ))
            .expect("create reused login");
        let reused_two = unlocked
            .create_item(login_draft_with_password(
                "Forum",
                "forum@example.com",
                "Shared-Password-123!",
                false,
                vec![],
            ))
            .expect("create second reused login");
        let unique = unlocked
            .create_item(login_draft_with_password(
                "Unique",
                "unique@example.com",
                "Distinct-Strong-987!",
                false,
                vec![],
            ))
            .expect("create unique login");
        let missing_password = unlocked
            .create_item(login_draft_without_password(
                "No Password",
                "nopassword@example.com",
            ))
            .expect("create missing password login");
        let note = unlocked
            .create_item(secure_note_draft(
                "Recovery Notes",
                "offline backup codes",
                vec![],
            ))
            .expect("create secure note");

        let audit = unlocked.password_health_audit().expect("audit passwords");

        assert_eq!(audit.checked_login_passwords, 5);
        assert_eq!(audit.weak_passwords, 2);
        assert_eq!(audit.reused_passwords, 2);
        assert_eq!(audit.issues.len(), 4);
        assert_health_issue(
            &audit,
            &weak_title.id,
            "Email",
            PasswordHealthIssueKind::WeakPassword,
            None,
        );
        assert_health_issue(
            &audit,
            &weak_username.id,
            "Bank",
            PasswordHealthIssueKind::WeakPassword,
            None,
        );
        assert_health_issue(
            &audit,
            &reused_one.id,
            "Work",
            PasswordHealthIssueKind::ReusedPassword,
            Some(2),
        );
        assert_health_issue(
            &audit,
            &reused_two.id,
            "Forum",
            PasswordHealthIssueKind::ReusedPassword,
            Some(2),
        );
        assert!(audit.issues.iter().all(|issue| issue.item_id != unique.id
            && issue.item_id != missing_password.id
            && issue.item_id != note.id));

        let audit_debug = format!("{audit:?}");
        for forbidden in [
            "EmailPassword2026!",
            "alice-Strong-2026!",
            "Shared-Password-123!",
            "Distinct-Strong-987!",
            "alice@example.com",
            "work@example.com",
            "forum@example.com",
            "unique@example.com",
            "offline backup codes",
        ] {
            assert!(
                !audit_debug.contains(forbidden),
                "password health audit leaked secret or non-result metadata: {forbidden}"
            );
        }

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    fn login_draft(title: &str, username: &str, favorite: bool, tags: Vec<&str>) -> VaultItemDraft {
        login_draft_with_totp(
            title,
            username,
            favorite,
            tags,
            Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        )
    }

    fn login_draft_with_password(
        title: &str,
        username: &str,
        password: &str,
        favorite: bool,
        tags: Vec<&str>,
    ) -> VaultItemDraft {
        let mut draft = login_draft(title, username, favorite, tags);
        let VaultItemContent::Login(login) = &mut draft.content else {
            panic!("expected login draft");
        };
        login.password = Some(SecretBytes::new(password.as_bytes().to_vec()));
        draft
    }

    fn login_draft_without_password(title: &str, username: &str) -> VaultItemDraft {
        let mut draft = login_draft(title, username, false, vec![]);
        let VaultItemContent::Login(login) = &mut draft.content else {
            panic!("expected login draft");
        };
        login.password = None;
        draft
    }

    fn assert_health_issue(
        audit: &PasswordHealthAudit,
        item_id: &ItemId,
        title: &str,
        kind: PasswordHealthIssueKind,
        reuse_group_size: Option<usize>,
    ) {
        assert!(
            audit.issues.iter().any(|issue| issue.item_id == *item_id
                && issue.title == title
                && issue.kind == kind
                && issue.reuse_group_size == reuse_group_size),
            "missing password health issue for {title:?} with kind {kind:?}"
        );
    }

    fn login_draft_with_totp(
        title: &str,
        username: &str,
        favorite: bool,
        tags: Vec<&str>,
        totp_secret: Option<&str>,
    ) -> VaultItemDraft {
        VaultItemDraft {
            title: title.to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some(username.to_owned()),
                password: Some(SecretBytes::new(b"secret".to_vec())),
                urls: vec!["https://example.com".to_owned()],
                notes: None,
                totp_secret: totp_secret.map(|secret| SecretBytes::new(secret.as_bytes().to_vec())),
            }),
            tags: tags.into_iter().map(str::to_owned).collect(),
            favorite,
        }
    }

    fn secure_note_draft(title: &str, body: &str, tags: Vec<&str>) -> VaultItemDraft {
        VaultItemDraft {
            title: title.to_owned(),
            content: VaultItemContent::SecureNote(SecureNoteItem {
                body: body.to_owned(),
            }),
            tags: tags.into_iter().map(str::to_owned).collect(),
            favorite: false,
        }
    }

    fn software_license_draft(title: &str) -> VaultItemDraft {
        VaultItemDraft {
            title: title.to_owned(),
            content: VaultItemContent::SoftwareLicense(SoftwareLicenseItem {
                product: Some("Product".to_owned()),
                license_key: Some(SecretBytes::new(b"AAAA-BBBB-CCCC".to_vec())),
                licensed_to: Some("Alice".to_owned()),
                notes: Some("Renewal due Q4".to_owned()),
            }),
            tags: vec!["software".to_owned()],
            favorite: true,
        }
    }

    fn credit_card_draft(title: &str) -> VaultItemDraft {
        VaultItemDraft {
            title: title.to_owned(),
            content: VaultItemContent::CreditCard(CreditCardItem {
                cardholder_name: Some("Alice Example".to_owned()),
                number: Some(SecretBytes::new(b"4111111111111111".to_vec())),
                expiry_month: Some(4),
                expiry_year: Some(2030),
                verification_code: Some(SecretBytes::new(b"123".to_vec())),
                notes: Some("Travel rewards card".to_owned()),
            }),
            tags: vec!["finance".to_owned()],
            favorite: true,
        }
    }

    fn create_target_merge_test_vault(temp_dir: &std::path::Path) -> UnlockedVault {
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        VaultCore::new()
            .create_vault(CreateVaultRequest {
                path: temp_dir.join("Merge.pswvault"),
                display_name: Some("Merge".to_owned()),
                master_password: password.clone(),
            })
            .expect("create target merge test vault")
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock target merge test vault")
    }

    fn target_merge_test_draft() -> CredentialDraft {
        CredentialDraft {
            title: "Deployment token".to_owned(),
            template_id: Some("api-token".to_owned()),
            fields: vec![
                CredentialField::text("account", "alice"),
                CredentialField::text("endpoint", "https://example.test"),
                CredentialField::secret(
                    "token",
                    SecretFieldKind::ApiToken,
                    SecretBytes::new(b"base-token".to_vec()),
                ),
                CredentialField::secret(
                    "recovery",
                    SecretFieldKind::GenericSecret,
                    SecretBytes::new(b"base-recovery".to_vec()),
                ),
            ],
            tags: vec!["developer".to_owned()],
            favorite: false,
        }
    }

    fn replace_target_test_secret(draft: &mut CredentialDraft, role: &str, replacement: &[u8]) {
        let field = draft
            .fields
            .iter_mut()
            .find(|field| field.role == role)
            .unwrap_or_else(|| panic!("missing target test secret field {role}"));
        let crate::CredentialFieldValue::Secret { secret, .. } = &mut field.value else {
            panic!("target test field {role} is not secret");
        };
        *secret = SecretBytes::new(replacement.to_vec());
    }

    fn target_test_descendant(
        template: &crate::CredentialRevision,
        draft: CredentialDraft,
        parents: Vec<crate::RevisionId>,
        lifecycle: crate::CredentialLifecycle,
    ) -> crate::CredentialRevision {
        let credential = crate::Credential::with_id(
            template.credential().vault_id(),
            template.credential().credential_id(),
            draft,
        )
        .expect("create target test credential");
        crate::CredentialRevision::descendant_with_lifecycle(
            credential,
            crate::DeviceId::generate(),
            parents,
            lifecycle,
        )
        .expect("create target test descendant")
    }

    fn write_target_test_revision(unlocked: &UnlockedVault, revision: &crate::CredentialRevision) {
        let record = super::encrypt_target_credential_record(&unlocked.vault_key, revision)
            .expect("encrypt target test revision");
        super::write_target_credential_record(&unlocked.path, &record, revision.lifecycle())
            .expect("write target test revision");
    }

    fn test_item(id: &str, revision: &str, draft: VaultItemDraft) -> VaultItem {
        VaultItem {
            id: ItemId(id.to_owned()),
            revision: ItemRevision(test_revision(revision)),
            parent_revision: Some(ItemRevision(test_revision("base"))),
            status: ItemStatus::Active,
            draft,
        }
    }

    fn assert_no_secret_field_label_values(labels: &[String]) {
        let joined = labels.join(" ");
        for secret_fragment in [
            "changed-password",
            "JBSWY3DPEHPK3PXP",
            "5555555555554444",
            "987",
            "ZZZZ-YYYY-XXXX",
        ] {
            assert!(
                !joined.contains(secret_fragment),
                "changed-field labels leaked secret fragment {secret_fragment}"
            );
        }
    }

    fn comparison_field<'a>(
        fields: &'a [ConflictCandidateField],
        label: &str,
    ) -> &'a ConflictCandidateField {
        fields
            .iter()
            .find(|field| field.label == label)
            .unwrap_or_else(|| panic!("missing comparison field {label}"))
    }

    fn assert_redacted_field(fields: &[ConflictCandidateField], label: &str) {
        let field = comparison_field(fields, label);
        assert!(field.redacted, "{label} should be redacted");
        assert_eq!(field.value, None, "{label} should not include a value");
    }

    fn comparison_fields_joined(fields: &[ConflictCandidateField]) -> String {
        fields
            .iter()
            .filter_map(|field| field.value.as_deref())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn exported_item<'a>(exported: &'a Value, name: &str) -> &'a Value {
        exported["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["name"] == name)
            .expect("exported item")
    }

    fn item_record_path(
        vault_path: &std::path::Path,
        id: &ItemId,
        revision: &ItemRevision,
    ) -> std::path::PathBuf {
        vault_path
            .join("items")
            .join(format!("{}_{}.enc", id.0, revision.0))
    }

    fn tamper_record_ciphertext(path: &std::path::Path) {
        let mut record: Value =
            serde_json::from_slice(&fs::read(path).expect("read record")).expect("parse record");
        let ciphertext = record["ciphertext_hex"]
            .as_str()
            .expect("ciphertext")
            .as_bytes();
        let mut tampered = ciphertext.to_vec();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        record["ciphertext_hex"] =
            Value::String(String::from_utf8(tampered).expect("valid hex string"));
        fs::write(
            path,
            serde_json::to_vec_pretty(&record).expect("serialize tampered record"),
        )
        .expect("write tampered record");
    }

    fn install_test_recovery(unlocked: &UnlockedVault) -> crate::RecoveryKey {
        unlocked
            .begin_recovery_setup()
            .expect("install test recovery envelope")
            .recovery_key
    }

    fn encrypted_directory_snapshot(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut snapshot = fs::read_dir(path)
            .expect("read encrypted directory")
            .map(|entry| {
                let entry = entry.expect("read encrypted directory entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).expect("read encrypted file"),
                )
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        snapshot
    }

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "psw-core-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/imports")
            .join(name)
    }

    fn credential_text_field<'a>(draft: &'a CredentialDraft, role: &str) -> Option<&'a str> {
        draft.fields.iter().find_map(|field| {
            if field.role != role {
                return None;
            }
            match &field.value {
                crate::CredentialFieldValue::Text { text } => Some(text.as_str()),
                crate::CredentialFieldValue::Secret { .. } => None,
            }
        })
    }

    fn credential_secret_field<'a>(
        draft: &'a CredentialDraft,
        role: &str,
    ) -> Option<(crate::SecretFieldId, SecretFieldKind, &'a [u8])> {
        draft.fields.iter().find_map(|field| {
            if field.role != role {
                return None;
            }
            match &field.value {
                crate::CredentialFieldValue::Secret {
                    secret_field_id,
                    kind,
                    secret,
                } => Some((*secret_field_id, *kind, secret.expose())),
                crate::CredentialFieldValue::Text { .. } => None,
            }
        })
    }

    fn imported_secret_field_ids(
        revision: &crate::CredentialRevision,
    ) -> Vec<crate::SecretFieldId> {
        revision
            .credential()
            .draft()
            .secret_fields()
            .map(|field| {
                field
                    .secret_field_id()
                    .expect("stable secret field identity")
            })
            .collect()
    }

    fn record_file_count(vault_path: &std::path::Path, directory: &str) -> usize {
        std::fs::read_dir(vault_path.join(directory))
            .expect("read record directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_type()
                    .map(|file_type| file_type.is_file())
                    .unwrap_or(false)
            })
            .count()
    }

    fn record_file_count_recursive(path: &std::path::Path) -> usize {
        std::fs::read_dir(path)
            .expect("read record directory")
            .filter_map(Result::ok)
            .map(|entry| {
                if entry
                    .file_type()
                    .map(|file_type| file_type.is_dir())
                    .unwrap_or(false)
                {
                    record_file_count_recursive(&entry.path())
                } else if entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("enc")
                {
                    1
                } else {
                    0
                }
            })
            .sum()
    }

    fn read_sync_fixture() -> SyncFixture {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vaults/sync-scenarios.json");
        serde_json::from_slice(&std::fs::read(path).expect("read sync fixture"))
            .expect("parse sync fixture")
    }

    fn test_revision(label: &str) -> String {
        format!("rev_99999999999999999999999999999999_{label}")
    }

    #[derive(Debug, Deserialize)]
    struct SyncFixture {
        scenarios: Vec<SyncScenario>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SyncScenario {
        name: String,
        kind: String,
        expected_items: usize,
        expected_conflicts: usize,
    }
}
