use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};

use crate::error::{VaultError, VaultResult};
use crate::export::{export_items_to_file, ExportResult};
use crate::import::parse_import_file;
use crate::record::{decrypt_item_record, encrypt_item_record, EncryptedItemRecord};
use crate::storage::{
    backup_vault_directory, change_master_password, create_local_unlock_material,
    create_vault_directory, load_item_records, load_tombstone_records, open_vault_directory,
    restore_vault_backup_directory, unlock_vault_key_with_local_material,
    validate_required_structure, write_item_record, write_tombstone_record,
};
use crate::totp::{generate_totp_code, normalize_totp_secret};
use crate::types::{
    ConflictId, ItemId, ItemRevision, ItemStatus, ItemSummary, SecretBytes, VaultItem,
    VaultItemContent, VaultItemDraft, VaultMetadata,
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

/// A vault that has been identified on disk but is not unlocked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedVault {
    /// Vault path on local disk.
    pub path: PathBuf,
    /// Public vault metadata.
    pub metadata: VaultMetadata,
}

impl LockedVault {
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

impl UnlockedVault {
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

    /// Creates a new item.
    pub fn create_item(&mut self, mut draft: VaultItemDraft) -> VaultResult<ItemSummary> {
        normalize_draft(&mut draft)?;
        let item = VaultItem {
            id: ItemId(random_id("item")),
            revision: ItemRevision(new_revision()),
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
            revision: ItemRevision(new_revision()),
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
        item.revision = ItemRevision(new_revision());
        item.status = ItemStatus::Deleted;
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
        item.revision = ItemRevision(new_revision());
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
        item.revision = ItemRevision(new_revision());
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
        item.revision = ItemRevision(new_revision());
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
        item.revision = ItemRevision(new_revision());
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
        Ok(self.load_candidate_items()?.report)
    }

    /// Moves rejected encrypted sync records into a vault-local quarantine batch.
    pub fn quarantine_rejected_records(&mut self) -> VaultResult<SyncQuarantineReport> {
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
        resolved.revision = ItemRevision(new_revision());
        resolved.status = ItemStatus::Active;
        self.save_item_revision(&resolved)?;
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
            self.create_item(draft)?;
            imported += 1;
        }
        Ok(ImportPreview {
            importable_records: imported,
            skipped_records,
            duplicate_records,
            warnings: parsed.warnings,
        })
    }

    /// Exports supported non-deleted vault items to a plaintext file.
    pub fn export_items(&self, request: ExportItemsRequest) -> VaultResult<ExportResult> {
        let items = self
            .latest_items()?
            .into_iter()
            .filter(|item| item.status != ItemStatus::Deleted)
            .collect::<Vec<_>>();
        export_items_to_file(&request.destination_path, &request.export_format, &items)
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
        for item in candidates {
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
                .map_or(true, |deleted_revision| deleted_revision < &item.revision)
        });
        report.detected_conflicts = detect_conflicts(&items)?.len();
        Ok(CandidateLoad { items, report })
    }

    fn detected_conflicts(&self) -> VaultResult<BTreeMap<ItemId, ConflictId>> {
        detect_conflicts(&self.candidate_items()?)
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

    fn count_duplicates(&self, drafts: &[VaultItemDraft]) -> VaultResult<usize> {
        let existing = self.duplicate_keys()?;
        Ok(drafts
            .iter()
            .filter(|draft| existing.contains(&duplicate_key(draft)))
            .count())
    }

    fn duplicate_keys(&self) -> VaultResult<std::collections::BTreeSet<String>> {
        Ok(self
            .latest_items()?
            .into_iter()
            .filter(|item| item.status != ItemStatus::Deleted)
            .map(|item| duplicate_key(&item.draft))
            .collect())
    }

    fn latest_item(&self, id: &ItemId) -> VaultResult<VaultItem> {
        self.latest_items()?
            .into_iter()
            .find(|item| &item.id == id && item.status != ItemStatus::Deleted)
            .ok_or_else(|| VaultError::ItemNotFound { id: id.0.clone() })
    }

    fn save_item_revision(&self, item: &VaultItem) -> VaultResult<()> {
        let record = encrypt_item_record(&self.vault_key, item)?;
        write_item_record(&self.path, &record)
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
            status: item_status_label(&item.status),
            favorite: item.draft.favorite,
            tags: item.draft.tags,
            comparison_fields,
            changed_fields,
            preview,
        }
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
    /// Export format identifier, initially `bitwarden-json`.
    pub export_format: String,
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
    let Ok(bytes) = fs::read(path) else {
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

fn conflict_item_id(conflict_id: &ConflictId) -> VaultResult<ItemId> {
    conflict_id
        .0
        .strip_prefix("conflict_")
        .map(|item_id| ItemId(item_id.to_owned()))
        .ok_or_else(|| VaultError::ItemNotFound {
            id: conflict_id.0.clone(),
        })
}

fn duplicate_key(draft: &VaultItemDraft) -> String {
    let mut username = String::new();
    let mut url = String::new();
    if let VaultItemContent::Login(login) = &draft.content {
        username = login
            .username
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        url = login
            .urls
            .first()
            .map_or("", String::as_str)
            .trim()
            .to_lowercase();
    }
    format!(
        "{}|{}|{}|{}",
        draft.title.trim().to_lowercase(),
        draft.item_type().as_search_label(),
        username,
        url
    )
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde::Deserialize;
    use serde_json::Value;

    use crate::{
        ConflictCandidateField, ConflictCandidateSummary, ConflictFieldSelection, ConflictId,
        ConflictMergeRequest, CreateVaultRequest, CreditCardItem, ExportItemsRequest,
        ImportCommitRequest, ImportPreviewRequest, ItemId, ItemRevision, ItemStatus, LockedVault,
        LoginItem, OpenVaultRequest, PasswordHealthAudit, PasswordHealthIssueKind,
        RejectedSyncRecordFile, RejectedSyncRecordKind, RestoreVaultBackupRequest, SearchQuery,
        SecretBytes, SecureNoteItem, SoftwareLicenseItem, UnlockedVault, VaultCore, VaultItem,
        VaultItemContent, VaultItemDraft, VaultMetadata,
    };

    #[test]
    fn lock_returns_locked_vault_with_same_identity() {
        let unlocked = UnlockedVault {
            path: PathBuf::from("/tmp/example.pswvault"),
            metadata: VaultMetadata::experimental(Some("Example".to_owned())),
            vault_key: crate::SecretBytes::new(vec![7; 32]),
        };

        let locked: LockedVault = unlocked.lock();

        assert_eq!(locked.path, PathBuf::from("/tmp/example.pswvault"));
        assert_eq!(locked.metadata.display_name.as_deref(), Some("Example"));
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
            metadata: VaultMetadata::experimental(Some("Example".to_owned())),
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

        let backup = unlocked
            .backup_to(backup_path.clone())
            .expect("backup vault");

        assert_eq!(backup.copied_item_files, 1);
        assert_eq!(backup.copied_attachment_files, 1);
        assert_eq!(backup.copied_tombstone_files, 0);
        assert!(backup_path.join("vault.json").is_file());
        assert!(backup_path.join("keys.enc").is_file());
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
        left.revision = ItemRevision(super::new_revision());
        left.draft.title = "Left".to_owned();
        let left_revision = left.revision.clone();
        unlocked.save_item_revision(&left).expect("save left fork");

        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = ItemRevision(super::new_revision());
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
        left.revision = ItemRevision(super::new_revision());
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
        right.revision = ItemRevision(super::new_revision());
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
        assert_eq!(merged.parent_revision, Some(left_revision));
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
        left.revision = ItemRevision(test_revision("left"));
        left.draft.title = "Left".to_owned();
        let left_revision = left.revision.clone();
        unlocked.save_item_revision(&left).expect("save left fork");

        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = ItemRevision(test_revision("right"));
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
        left.revision = ItemRevision(test_revision("left"));
        left.draft.title = "Left".to_owned();
        unlocked.save_item_revision(&left).expect("save left fork");

        let mut right = base;
        right.parent_revision = Some(right.revision.clone());
        right.revision = ItemRevision(test_revision("right"));
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
                master_password: password,
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
                master_password: password,
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
                master_password: password,
            })
            .expect("unlock vault");

        let error = unlocked
            .export_items(ExportItemsRequest {
                destination_path: destination_path.clone(),
                export_format: "unknown-format".to_owned(),
            })
            .expect_err("unsupported export format");

        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));
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
