use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::credential_model::{Credential, CredentialDraft, CredentialFieldValue, SecretFieldKind};
use crate::error::{VaultError, VaultResult};
use crate::record::{
    decrypt_item_record, decrypt_target_credential_record, encrypt_target_credential_record,
    parse_target_credential_record, TargetEncryptedCredentialRecord,
};
use crate::revision::{ContentDigest, CredentialLifecycle, CredentialRevision};
use crate::safe_fs::{
    read_regular_file_limited, MAX_ENCRYPTED_RECORD_FILE_BYTES, MAX_VAULT_CONTROL_FILE_BYTES,
};
use crate::stable_id::{CredentialId, DeviceId, RevisionId, SecretFieldId, VaultId};
use crate::storage::{
    backup_vault_directory, load_item_records, load_tombstone_records, open_vault_directory,
};
use crate::types::{
    ItemId, ItemRevision, ItemStatus, SecretBytes, VaultItem, VaultMetadata,
    MIGRATION_SOURCE_FORMAT_PAIRS, TARGET_RECORD_FORMAT_VERSION, TARGET_VAULT_FORMAT_VERSION,
};

const METADATA_FILE: &str = "vault.json";
const KEYS_FILE: &str = "keys.enc";
const LOCAL_UNLOCK_FILE: &str = "local_unlock.enc";
const ITEMS_DIR: &str = "items";
const ATTACHMENTS_DIR: &str = "attachments";
const TOMBSTONES_DIR: &str = "tombstones";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VaultMigrationReport {
    pub(crate) metadata: VaultMetadata,
    pub(crate) backup_path: PathBuf,
    pub(crate) migrated_item_records: usize,
    pub(crate) migrated_tombstone_records: usize,
    pub(crate) copied_attachment_files: usize,
    pub(crate) cleanup_required: bool,
}

pub(crate) fn migrate_v1_vault_directory(
    source: &Path,
    backup_path: &Path,
    vault_key: &SecretBytes,
) -> VaultResult<VaultMigrationReport> {
    let source_metadata = validate_migration_source(source)?;
    if backup_path.exists() {
        return Err(invalid_vault(
            "pre-migration backup destination must not already exist",
        ));
    }

    let recovery_path = migration_sibling_path(source, "original", None)?;
    if recovery_path.exists() {
        return Err(invalid_vault(
            "an unresolved prior migration recovery directory exists",
        ));
    }
    if paths_resolve_to_same_location(backup_path, &recovery_path)? {
        return Err(invalid_vault(
            "pre-migration backup conflicts with the migration recovery path",
        ));
    }

    let source_snapshot = tree_manifest(source)?;
    let portable_snapshot = portable_manifest(source)?;
    let legacy_records = load_verified_legacy_records(source, vault_key)?;

    create_and_verify_backup(
        source,
        backup_path,
        vault_key,
        &portable_snapshot,
        &legacy_records,
    )?;

    if tree_manifest(source)? != source_snapshot {
        return Err(invalid_vault(
            "source vault changed while the pre-migration backup was created",
        ));
    }

    let vault_id = VaultId::generate();
    let device_id = DeviceId::generate();
    let migrated = migrate_legacy_records(legacy_records, vault_id, device_id)?;
    let target_metadata =
        VaultMetadata::current_with_vault_id(source_metadata.display_name.clone(), vault_id);
    let stage_path = migration_sibling_path(source, "stage", None)?;
    if stage_path.exists() {
        return Err(invalid_vault("migration staging directory already exists"));
    }

    let staged_result =
        stage_target_vault(source, &stage_path, &target_metadata, vault_key, &migrated);
    if let Err(error) = staged_result {
        remove_directory_if_present(&stage_path);
        return Err(error);
    }

    if tree_manifest(source)? != source_snapshot {
        remove_directory_if_present(&stage_path);
        return Err(invalid_vault(
            "source vault changed while the migration target was staged",
        ));
    }

    let installation = (|| {
        let target_counts =
            verify_target_vault(&stage_path, &target_metadata, vault_key, migrated.len())?;
        sync_tree(&stage_path)?;
        let cleanup_required =
            replace_vault_directory(source, &stage_path, &recovery_path, &source_snapshot)?;
        Ok::<_, VaultError>((target_counts, cleanup_required))
    })();
    let (target_counts, cleanup_required) = match installation {
        Ok(result) => result,
        Err(error) => {
            remove_directory_if_present(&stage_path);
            return Err(error);
        }
    };

    Ok(VaultMigrationReport {
        metadata: target_metadata,
        backup_path: backup_path.to_path_buf(),
        migrated_item_records: target_counts.item_records,
        migrated_tombstone_records: target_counts.tombstone_records,
        copied_attachment_files: count_files(&source.join(ATTACHMENTS_DIR))?,
        cleanup_required,
    })
}

fn validate_migration_source(source: &Path) -> VaultResult<VaultMetadata> {
    let metadata = open_vault_directory(source)?;
    let format_pair = (
        metadata.vault_format_version,
        metadata.record_format_version,
    );
    if !MIGRATION_SOURCE_FORMAT_PAIRS.contains(&format_pair) || metadata.vault_id.is_some() {
        return Err(invalid_vault(
            "vault is not the frozen v1/v1 migration source",
        ));
    }
    Ok(metadata)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyRecord {
    item: VaultItem,
    directory: RecordDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordDirectory {
    Items,
    Tombstones,
}

fn load_verified_legacy_records(
    path: &Path,
    vault_key: &SecretBytes,
) -> VaultResult<Vec<LegacyRecord>> {
    let item_records = load_item_records(path)?;
    let tombstone_records = load_tombstone_records(path)?;
    if item_records.rejected_records != 0 || tombstone_records.rejected_records != 0 {
        return Err(invalid_vault(
            "migration source contains unreadable encrypted records",
        ));
    }

    let mut records = Vec::new();
    for loaded in item_records.records {
        let item = decrypt_item_record(vault_key, &loaded.record)?;
        if !matches!(item.status, ItemStatus::Active | ItemStatus::Archived) {
            return Err(invalid_vault(
                "items directory contains an invalid persisted lifecycle",
            ));
        }
        records.push(LegacyRecord {
            item,
            directory: RecordDirectory::Items,
        });
    }
    for loaded in tombstone_records.records {
        let item = decrypt_item_record(vault_key, &loaded.record)?;
        if item.status != ItemStatus::Deleted {
            return Err(invalid_vault(
                "tombstones directory contains a non-deleted record",
            ));
        }
        records.push(LegacyRecord {
            item,
            directory: RecordDirectory::Tombstones,
        });
    }

    records.sort_by(|left, right| {
        left.item
            .id
            .cmp(&right.item.id)
            .then_with(|| left.item.revision.cmp(&right.item.revision))
            .then_with(|| {
                record_directory_order(left.directory).cmp(&record_directory_order(right.directory))
            })
    });
    if records.windows(2).any(|pair| {
        pair[0].item.id == pair[1].item.id && pair[0].item.revision == pair[1].item.revision
    }) {
        return Err(invalid_vault(
            "migration source contains duplicate item revision identities",
        ));
    }
    Ok(records)
}

const fn record_directory_order(directory: RecordDirectory) -> u8 {
    match directory {
        RecordDirectory::Items => 0,
        RecordDirectory::Tombstones => 1,
    }
}

fn migrate_legacy_records(
    legacy_records: Vec<LegacyRecord>,
    vault_id: VaultId,
    device_id: DeviceId,
) -> VaultResult<Vec<CredentialRevision>> {
    let mut credential_ids = BTreeMap::<ItemId, CredentialId>::new();
    let mut revision_ids = BTreeMap::<(ItemId, ItemRevision), RevisionId>::new();
    for legacy in &legacy_records {
        credential_ids
            .entry(legacy.item.id.clone())
            .or_insert_with(CredentialId::generate);
        revision_ids
            .entry((legacy.item.id.clone(), legacy.item.revision.clone()))
            .or_insert_with(RevisionId::generate);
        if let Some(parent_revision) = &legacy.item.parent_revision {
            revision_ids
                .entry((legacy.item.id.clone(), parent_revision.clone()))
                .or_insert_with(RevisionId::generate);
        }
    }

    let mut field_ids = BTreeMap::<(ItemId, String, SecretFieldKind, usize), SecretFieldId>::new();
    let mut migrated = Vec::with_capacity(legacy_records.len());
    for legacy in legacy_records {
        let item_id = legacy.item.id.clone();
        let credential_id = *credential_ids
            .get(&item_id)
            .ok_or_else(|| invalid_vault("missing migrated credential identity"))?;
        let revision_id = *revision_ids
            .get(&(item_id.clone(), legacy.item.revision.clone()))
            .ok_or_else(|| invalid_vault("missing migrated revision identity"))?;
        let parents = legacy
            .item
            .parent_revision
            .as_ref()
            .map(|parent| {
                revision_ids
                    .get(&(item_id.clone(), parent.clone()))
                    .copied()
                    .ok_or_else(|| invalid_vault("missing migrated parent identity"))
            })
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        let lifecycle = match legacy.item.status {
            ItemStatus::Active => CredentialLifecycle::Active,
            ItemStatus::Archived => CredentialLifecycle::Archived,
            ItemStatus::Deleted => CredentialLifecycle::Deleted,
            ItemStatus::Conflicted(_) => {
                return Err(invalid_vault(
                    "migration source persists a derived conflict lifecycle",
                ))
            }
        };

        let mut draft = CredentialDraft::from(legacy.item.draft);
        reuse_migrated_secret_field_ids(&item_id, &mut draft, &mut field_ids);
        let credential = Credential::with_id(vault_id, credential_id, draft)
            .map_err(|error| invalid_vault(error.to_string()))?;
        let digest = ContentDigest::for_credential(&credential);
        let revision = CredentialRevision::with_metadata_and_lifecycle(
            revision_id,
            parents,
            digest,
            device_id,
            lifecycle,
            credential,
        )
        .map_err(|error| invalid_vault(error.to_string()))?;
        migrated.push(revision);
    }
    Ok(migrated)
}

fn reuse_migrated_secret_field_ids(
    item_id: &ItemId,
    draft: &mut CredentialDraft,
    field_ids: &mut BTreeMap<(ItemId, String, SecretFieldKind, usize), SecretFieldId>,
) {
    let mut occurrences = BTreeMap::<(String, SecretFieldKind), usize>::new();
    for field in &mut draft.fields {
        let CredentialFieldValue::Secret {
            secret_field_id,
            kind,
            ..
        } = &mut field.value
        else {
            continue;
        };
        let slot = occurrences.entry((field.role.clone(), *kind)).or_default();
        let key = (item_id.clone(), field.role.clone(), *kind, *slot);
        *secret_field_id = *field_ids.entry(key).or_insert_with(SecretFieldId::generate);
        *slot += 1;
    }
}

fn create_and_verify_backup(
    source: &Path,
    backup_path: &Path,
    vault_key: &SecretBytes,
    expected_manifest: &TreeManifest,
    expected_records: &[LegacyRecord],
) -> VaultResult<()> {
    let copied = backup_vault_directory(source, backup_path);
    if let Err(error) = copied {
        remove_directory_if_present(backup_path);
        return Err(error);
    }

    let verification = verify_encrypted_backup(
        source,
        backup_path,
        vault_key,
        expected_manifest,
        expected_records,
    );
    if let Err(error) = verification {
        remove_directory_if_present(backup_path);
        return Err(error);
    }
    sync_tree(backup_path)
}

fn verify_encrypted_backup(
    source: &Path,
    backup_path: &Path,
    vault_key: &SecretBytes,
    expected_manifest: &TreeManifest,
    expected_records: &[LegacyRecord],
) -> VaultResult<()> {
    if &portable_manifest(source)? != expected_manifest
        || portable_manifest(backup_path)? != *expected_manifest
    {
        return Err(invalid_vault(
            "pre-migration encrypted backup did not verify byte-for-byte",
        ));
    }
    if backup_path.join(LOCAL_UNLOCK_FILE).exists() {
        return Err(invalid_vault(
            "pre-migration backup contains local unlock material",
        ));
    }
    let backup_metadata = validate_migration_source(backup_path)?;
    let source_metadata = validate_migration_source(source)?;
    if backup_metadata != source_metadata {
        return Err(invalid_vault(
            "pre-migration backup metadata differs from the source",
        ));
    }
    let backup_records = load_verified_legacy_records(backup_path, vault_key)?;
    if backup_records != expected_records {
        return Err(invalid_vault(
            "pre-migration backup records differ from the authenticated source",
        ));
    }
    Ok(())
}

fn stage_target_vault(
    source: &Path,
    stage_path: &Path,
    metadata: &VaultMetadata,
    vault_key: &SecretBytes,
    revisions: &[CredentialRevision],
) -> VaultResult<()> {
    copy_tree(source, stage_path)?;
    replace_with_empty_directory(&stage_path.join(ITEMS_DIR))?;
    replace_with_empty_directory(&stage_path.join(TOMBSTONES_DIR))?;
    write_json_new_or_replace(&stage_path.join(METADATA_FILE), metadata)?;

    let mut written = BTreeSet::new();
    for revision in revisions {
        let record = encrypt_target_credential_record(vault_key, revision)?;
        let directory = match revision.lifecycle() {
            CredentialLifecycle::Active | CredentialLifecycle::Archived => ITEMS_DIR,
            CredentialLifecycle::Deleted => TOMBSTONES_DIR,
        };
        let file_name = target_record_file_name(&record, revision.lifecycle());
        if !written.insert((directory, file_name.clone())) {
            return Err(invalid_vault(
                "target migration produced a duplicate record file name",
            ));
        }
        write_json_create_new(&stage_path.join(directory).join(file_name), &record)?;
    }
    Ok(())
}

fn replace_with_empty_directory(path: &Path) -> VaultResult<()> {
    fs::remove_dir_all(path)
        .map_err(|source| VaultError::io("replace record directory", source))?;
    fs::create_dir(path).map_err(|source| VaultError::io("create record directory", source))
}

fn target_record_file_name(
    record: &TargetEncryptedCredentialRecord,
    lifecycle: CredentialLifecycle,
) -> String {
    let stem = format!("{}_{}", record.credential_id, record.revision_id);
    match lifecycle {
        CredentialLifecycle::Active | CredentialLifecycle::Archived => format!("{stem}.enc"),
        CredentialLifecycle::Deleted => format!("tombstone_{stem}.enc"),
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TargetRecordCounts {
    item_records: usize,
    tombstone_records: usize,
}

fn verify_target_vault(
    path: &Path,
    expected_metadata: &VaultMetadata,
    vault_key: &SecretBytes,
    expected_records: usize,
) -> VaultResult<TargetRecordCounts> {
    let metadata: VaultMetadata = read_json(&path.join(METADATA_FILE), "read target metadata")?;
    if &metadata != expected_metadata
        || metadata.vault_format_version != TARGET_VAULT_FORMAT_VERSION
        || metadata.record_format_version != TARGET_RECORD_FORMAT_VERSION
        || metadata.vault_id.is_none()
    {
        return Err(invalid_vault("staged target metadata did not verify"));
    }

    let mut counts = TargetRecordCounts::default();
    let mut identities = BTreeSet::new();
    verify_target_record_directory(
        &path.join(ITEMS_DIR),
        RecordDirectory::Items,
        &metadata,
        vault_key,
        &mut counts,
        &mut identities,
    )?;
    verify_target_record_directory(
        &path.join(TOMBSTONES_DIR),
        RecordDirectory::Tombstones,
        &metadata,
        vault_key,
        &mut counts,
        &mut identities,
    )?;
    if counts.item_records + counts.tombstone_records != expected_records {
        return Err(invalid_vault(
            "staged target record count does not match the migration source",
        ));
    }
    Ok(counts)
}

fn verify_target_record_directory(
    directory: &Path,
    expected_directory: RecordDirectory,
    metadata: &VaultMetadata,
    vault_key: &SecretBytes,
    counts: &mut TargetRecordCounts,
    identities: &mut BTreeSet<(CredentialId, RevisionId)>,
) -> VaultResult<()> {
    for entry in sorted_directory_entries(directory)? {
        let file_type = entry
            .file_type()
            .map_err(|source| VaultError::io("inspect target record", source))?;
        if !file_type.is_file()
            || entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("enc")
        {
            return Err(invalid_vault(
                "target record directory contains an unexpected entry",
            ));
        }
        let bytes = read_regular_file_limited(
            &entry.path(),
            MAX_ENCRYPTED_RECORD_FILE_BYTES,
            "read target record",
        )?;
        let record = parse_target_credential_record(&bytes)?;
        if Some(record.vault_id) != metadata.vault_id {
            return Err(invalid_vault(
                "target record vault identity differs from metadata",
            ));
        }
        let revision = decrypt_target_credential_record(vault_key, &record)?;
        let actual_directory = match revision.lifecycle() {
            CredentialLifecycle::Active | CredentialLifecycle::Archived => RecordDirectory::Items,
            CredentialLifecycle::Deleted => RecordDirectory::Tombstones,
        };
        if actual_directory != expected_directory {
            return Err(invalid_vault(
                "target record lifecycle does not match its directory",
            ));
        }
        if entry.file_name()
            != OsString::from(target_record_file_name(&record, revision.lifecycle()))
        {
            return Err(invalid_vault("target record file name is not canonical"));
        }
        if !identities.insert((record.credential_id, record.revision_id)) {
            return Err(invalid_vault(
                "target vault contains a duplicate revision identity",
            ));
        }
        match expected_directory {
            RecordDirectory::Items => counts.item_records += 1,
            RecordDirectory::Tombstones => counts.tombstone_records += 1,
        }
    }
    Ok(())
}

fn replace_vault_directory(
    source: &Path,
    stage_path: &Path,
    recovery_path: &Path,
    expected_source: &TreeManifest,
) -> VaultResult<bool> {
    let parent = source
        .parent()
        .ok_or_else(|| invalid_vault("vault path has no parent directory"))?;
    fs::rename(source, recovery_path)
        .map_err(|source| VaultError::io("move source vault for migration", source))?;
    sync_directory(parent)?;

    let moved_source_matches =
        matches!(tree_manifest(recovery_path), Ok(actual) if &actual == expected_source);
    if !moved_source_matches {
        restore_original_after_failed_replacement(source, recovery_path)?;
        return Err(invalid_vault(
            "source vault changed before atomic migration replacement",
        ));
    }

    if let Err(install_error) = fs::rename(stage_path, source) {
        restore_original_after_failed_replacement(source, recovery_path)?;
        return Err(VaultError::io(
            "install staged migrated vault",
            install_error,
        ));
    }
    sync_directory(parent)?;

    let cleanup_required = fs::remove_dir_all(recovery_path).is_err();
    if !cleanup_required {
        sync_directory(parent)?;
    }
    Ok(cleanup_required)
}

pub(crate) fn recover_interrupted_migration(source: &Path) -> VaultResult<()> {
    if source.exists() {
        return Ok(());
    }
    let recovery_path = migration_sibling_path(source, "original", None)?;
    match fs::symlink_metadata(&recovery_path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(invalid_vault("migration recovery entry is not a directory")),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(VaultError::io(
                "inspect interrupted vault migration recovery",
                source,
            ))
        }
    }

    let stage_path = migration_sibling_path(source, "stage", None)?;
    match fs::symlink_metadata(&stage_path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(invalid_vault("migration recovery stage is not a directory")),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(VaultError::io(
                "inspect interrupted vault migration stage",
                source,
            ))
        }
    }

    let parent = source
        .parent()
        .ok_or_else(|| invalid_vault("vault path has no parent directory"))?;
    fs::rename(&recovery_path, source)
        .map_err(|source| VaultError::io("recover interrupted vault migration", source))?;
    sync_directory(parent)?;

    remove_directory_if_present(&stage_path);
    sync_directory(parent)
}

fn restore_original_after_failed_replacement(
    source: &Path,
    recovery_path: &Path,
) -> VaultResult<()> {
    fs::rename(recovery_path, source)
        .map_err(|source| VaultError::io("restore source vault after migration failure", source))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeManifest(BTreeMap<PathBuf, TreeEntry>);

#[derive(Clone, Debug, Eq, PartialEq)]
enum TreeEntry {
    Directory,
    File { length: u64, sha256: [u8; 32] },
}

fn tree_manifest(root: &Path) -> VaultResult<TreeManifest> {
    let mut entries = BTreeMap::new();
    collect_manifest(root, root, &mut entries)?;
    Ok(TreeManifest(entries))
}

fn portable_manifest(root: &Path) -> VaultResult<TreeManifest> {
    let mut entries = BTreeMap::new();
    for relative in [
        METADATA_FILE,
        KEYS_FILE,
        ITEMS_DIR,
        ATTACHMENTS_DIR,
        TOMBSTONES_DIR,
    ] {
        collect_manifest(root, &root.join(relative), &mut entries)?;
    }
    Ok(TreeManifest(entries))
}

fn collect_manifest(
    root: &Path,
    path: &Path,
    entries: &mut BTreeMap<PathBuf, TreeEntry>,
) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| VaultError::io("inspect vault snapshot", source))?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_vault("vault migration does not support symlinks"));
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| invalid_vault("vault snapshot path escaped its root"))?
        .to_path_buf();
    if metadata.is_dir() {
        entries.insert(relative, TreeEntry::Directory);
        for entry in sorted_directory_entries(path)? {
            collect_manifest(root, &entry.path(), entries)?;
        }
    } else if metadata.is_file() {
        entries.insert(
            relative,
            TreeEntry::File {
                length: metadata.len(),
                sha256: sha256_file(path)?,
            },
        );
    } else {
        return Err(invalid_vault(
            "vault migration does not support special files",
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> VaultResult<[u8; 32]> {
    let mut file =
        File::open(path).map_err(|source| VaultError::io("hash vault snapshot", source))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| VaultError::io("hash vault snapshot", source))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    buffer.fill(0);
    Ok(digest.finalize().into())
}

fn copy_tree(source: &Path, destination: &Path) -> VaultResult<()> {
    if destination.exists() {
        return Err(invalid_vault(
            "migration staging destination already exists",
        ));
    }
    copy_tree_entry(source, destination)
}

fn copy_tree_entry(source: &Path, destination: &Path) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|source| VaultError::io("inspect migration source", source))?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_vault("vault migration does not support symlinks"));
    }
    if metadata.is_dir() {
        fs::create_dir(destination)
            .map_err(|source| VaultError::io("create migration staging directory", source))?;
        for entry in sorted_directory_entries(source)? {
            copy_tree_entry(&entry.path(), &destination.join(entry.file_name()))?;
        }
        fs::set_permissions(destination, metadata.permissions())
            .map_err(|source| VaultError::io("copy migration directory permissions", source))?;
    } else if metadata.is_file() {
        fs::copy(source, destination)
            .map_err(|source| VaultError::io("copy migration file", source))?;
        fs::set_permissions(destination, metadata.permissions())
            .map_err(|source| VaultError::io("copy migration file permissions", source))?;
    } else {
        return Err(invalid_vault(
            "vault migration does not support special files",
        ));
    }
    Ok(())
}

fn sorted_directory_entries(path: &Path) -> VaultResult<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| VaultError::io("read vault directory", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| VaultError::io("read vault directory entry", source))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn write_json_create_new<T: serde::Serialize>(path: &Path, value: &T) -> VaultResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| invalid_vault(format!("serialize migrated record failed: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| VaultError::io("create migrated record", source))?;
    file.write_all(&bytes)
        .map_err(|source| VaultError::io("write migrated record", source))?;
    file.sync_all()
        .map_err(|source| VaultError::io("sync migrated record", source))
}

fn write_json_new_or_replace<T: serde::Serialize>(path: &Path, value: &T) -> VaultResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| invalid_vault(format!("serialize target metadata failed: {error}")))?;
    let mut file =
        File::create(path).map_err(|source| VaultError::io("create target metadata", source))?;
    file.write_all(&bytes)
        .map_err(|source| VaultError::io("write target metadata", source))?;
    file.sync_all()
        .map_err(|source| VaultError::io("sync target metadata", source))
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    operation: &'static str,
) -> VaultResult<T> {
    let bytes = read_regular_file_limited(path, MAX_VAULT_CONTROL_FILE_BYTES, operation)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_vault(format!("{operation} failed: {error}")))
}

fn sync_tree(path: &Path) -> VaultResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| VaultError::io("inspect sync tree", source))?;
    if metadata.is_dir() {
        for entry in sorted_directory_entries(path)? {
            sync_tree(&entry.path())?;
        }
        sync_directory(path)
    } else if metadata.is_file() {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|source| VaultError::io("sync migration file", source))
    } else {
        Err(invalid_vault(
            "migration sync tree contains an unsupported entry",
        ))
    }
}

fn sync_directory(path: &Path) -> VaultResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| VaultError::io("sync migration directory", source))
}

fn count_files(path: &Path) -> VaultResult<usize> {
    let mut count = 0;
    for entry in sorted_directory_entries(path)? {
        let file_type = entry
            .file_type()
            .map_err(|source| VaultError::io("count attachment files", source))?;
        if file_type.is_dir() {
            count += count_files(&entry.path())?;
        } else if file_type.is_file() {
            count += 1;
        } else {
            return Err(invalid_vault(
                "attachment directory contains an unsupported entry",
            ));
        }
    }
    Ok(count)
}

fn migration_sibling_path(
    source: &Path,
    label: &str,
    suffix: Option<&str>,
) -> VaultResult<PathBuf> {
    let parent = source
        .parent()
        .ok_or_else(|| invalid_vault("vault path has no parent directory"))?;
    let source_name = source
        .file_name()
        .ok_or_else(|| invalid_vault("vault path has no directory name"))?;
    let mut name = OsString::from(".");
    name.push(source_name);
    name.push(format!(".keptnear-migration-{label}"));
    if let Some(suffix) = suffix {
        name.push("-");
        name.push(suffix);
    }
    Ok(parent.join(name))
}

fn paths_resolve_to_same_location(left: &Path, right: &Path) -> VaultResult<bool> {
    Ok(absolute_missing_path(left)? == absolute_missing_path(right)?)
}

fn absolute_missing_path(path: &Path) -> VaultResult<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path)
            .map_err(|source| VaultError::io("resolve migration path", source));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| invalid_vault("migration path has no file name"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|source| VaultError::io("resolve migration parent path", source))?;
    Ok(parent.join(file_name))
}

fn remove_directory_if_present(path: &Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}

fn invalid_vault(reason: impl Into<String>) -> VaultError {
    VaultError::InvalidVault {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::types::{LoginItem, VaultItemContent, VaultItemDraft};
    use crate::{OpenVaultRequest, SecretBytes, UnlockRequest, VaultCore};

    use super::{
        load_verified_legacy_records, migrate_v1_vault_directory, migration_sibling_path,
        parse_target_credential_record, portable_manifest, read_json, tree_manifest,
        verify_encrypted_backup, verify_target_vault, CredentialLifecycle, CredentialRevision,
        VaultMetadata, ITEMS_DIR, LOCAL_UNLOCK_FILE, METADATA_FILE, TOMBSTONES_DIR,
    };

    #[test]
    fn migration_retains_verified_backup_and_replaces_complete_revision_history() {
        let root = unique_temp_dir("migration_complete_history");
        fs::create_dir_all(&root).expect("create test root");
        let vault_path = root.join("Source.pswvault");
        let backup_path = root.join("Source.pre-migration.pswvault");
        let password = SecretBytes::new(b"migration-password".to_vec());
        let core = VaultCore::new();
        crate::storage::create_migration_source_vault_directory(
            &vault_path,
            Some("Migration".to_owned()),
            &password,
        )
        .expect("create source");
        let mut unlocked = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open source")
            .unlock(UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock source");

        let active = unlocked
            .create_item(login_draft("Active", "active-secret-marker"))
            .expect("create active");
        let archived = unlocked
            .create_item(login_draft("Archived", "archived-secret-marker"))
            .expect("create archived");
        unlocked
            .archive_item(&archived.id)
            .expect("archive credential");
        let deleted = unlocked
            .create_item(login_draft("Deleted", "deleted-secret-marker"))
            .expect("create deleted");
        unlocked
            .delete_item(&deleted.id)
            .expect("delete credential");
        unlocked
            .local_unlock_material()
            .expect("create local unlock envelope");

        let vault_key = crate::storage::unlock_vault_key(&vault_path, &password)
            .expect("unlock migration source key");
        let report =
            migrate_v1_vault_directory(&vault_path, &backup_path, &vault_key).expect("migrate");

        assert_eq!(report.backup_path, backup_path);
        assert_eq!(report.migrated_item_records, 4);
        assert_eq!(report.migrated_tombstone_records, 1);
        assert!(!report.cleanup_required);
        assert!(backup_path.is_dir());
        assert!(!backup_path.join(LOCAL_UNLOCK_FILE).exists());
        assert!(vault_path.join(LOCAL_UNLOCK_FILE).is_file());
        assert_eq!(
            verify_target_vault(&vault_path, &report.metadata, &vault_key, 5)
                .expect("verify installed target")
                .tombstone_records,
            1
        );

        let metadata: VaultMetadata =
            read_json(&vault_path.join(METADATA_FILE), "read migrated metadata")
                .expect("read metadata");
        assert_eq!(metadata, report.metadata);
        assert!(metadata.vault_id.is_some());
        let revisions = target_revisions(&vault_path, &vault_key);
        let archived_revisions = revisions
            .iter()
            .filter(|revision| revision.credential().draft().title == "Archived")
            .collect::<Vec<_>>();
        assert_eq!(archived_revisions.len(), 2);
        let archived_initial = archived_revisions
            .iter()
            .find(|revision| revision.parent_revision_ids().is_empty())
            .expect("archived initial revision");
        let archived_descendant = archived_revisions
            .iter()
            .find(|revision| !revision.parent_revision_ids().is_empty())
            .expect("archived descendant revision");
        assert_eq!(
            archived_descendant.parent_revision_ids(),
            &[archived_initial.revision_id()]
        );
        assert_eq!(
            archived_descendant.lifecycle(),
            CredentialLifecycle::Archived
        );
        assert_eq!(
            password_field_id(archived_initial),
            password_field_id(archived_descendant)
        );
        assert!(revisions.iter().all(|revision| {
            revision.credential().vault_id() == metadata.vault_id.expect("target vault ID")
        }));
        let target_text = all_record_text(&vault_path);
        for secret in [
            "active-secret-marker",
            "archived-secret-marker",
            "deleted-secret-marker",
        ] {
            assert!(!target_text.contains(secret));
        }

        let mut migrated_vault = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open migrated target")
            .unlock(UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock migrated target");
        let active_items = migrated_vault.list_items().expect("list migrated target");
        assert_eq!(active_items.len(), 1);
        assert_eq!(active_items[0].title, "Active");
        assert!(active_items[0].id.0.starts_with("credential_"));
        let all_items = migrated_vault
            .search(crate::SearchQuery {
                text: String::new(),
                include_archived: true,
            })
            .expect("list active and archived target items");
        assert_eq!(all_items.len(), 2);
        assert!(all_items.iter().any(|item| item.title == "Archived"));
        let added = migrated_vault
            .create_item(login_draft("Blocked", "blocked-secret"))
            .expect("write released target format");
        assert!(added.id.0.starts_with("credential_"));
        assert_eq!(
            migrated_vault
                .list_items()
                .expect("list target after write")
                .len(),
            2
        );

        let backup = core
            .open_vault(OpenVaultRequest {
                path: backup_path.clone(),
            })
            .expect("open retained v1 backup")
            .unlock(UnlockRequest {
                master_password: password,
            })
            .expect("unlock retained backup");
        assert_eq!(backup.list_items().expect("list backup").len(), 1);
        assert_eq!(
            backup
                .get_item(&active.id)
                .expect("read active backup")
                .draft
                .title,
            "Active"
        );

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn opening_restores_source_after_interrupted_directory_exchange() {
        let root = unique_temp_dir("migration_interrupted_exchange");
        fs::create_dir_all(&root).expect("create test root");
        let vault_path = root.join("Interrupted.pswvault");
        let password = SecretBytes::new(b"migration-password".to_vec());
        let core = VaultCore::new();
        crate::storage::create_migration_source_vault_directory(
            &vault_path,
            Some("Interrupted".to_owned()),
            &password,
        )
        .expect("create source");
        let recovery_path =
            migration_sibling_path(&vault_path, "original", None).expect("recovery path");
        let stage_path = migration_sibling_path(&vault_path, "stage", None).expect("stage path");
        fs::rename(&vault_path, &recovery_path).expect("simulate first exchange rename");
        fs::create_dir(&stage_path).expect("simulate staged target");
        fs::write(stage_path.join("partial"), b"derived migration data")
            .expect("write staged marker");

        let reopened = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("recover and open source");

        assert_eq!(
            reopened.metadata.display_name.as_deref(),
            Some("Interrupted")
        );
        assert!(vault_path.is_dir());
        assert!(!recovery_path.exists());
        assert!(!stage_path.exists());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn opening_does_not_restore_stale_original_without_active_stage() {
        let root = unique_temp_dir("migration_stale_original");
        fs::create_dir_all(&root).expect("create test root");
        let vault_path = root.join("Missing.pswvault");
        let password = SecretBytes::new(b"migration-password".to_vec());
        let core = VaultCore::new();
        crate::storage::create_migration_source_vault_directory(
            &vault_path,
            Some("Stale original".to_owned()),
            &password,
        )
        .expect("create stale original");
        let recovery_path =
            migration_sibling_path(&vault_path, "original", None).expect("recovery path");
        fs::rename(&vault_path, &recovery_path).expect("leave stale original");

        assert!(core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .is_err());
        assert!(!vault_path.exists());
        assert!(recovery_path.is_dir());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn backup_verification_failure_leaves_source_unchanged() {
        let root = unique_temp_dir("migration_backup_verification_failure");
        fs::create_dir_all(&root).expect("create test root");
        let vault_path = root.join("Source.pswvault");
        let backup_path = root.join("Tampered.pswvault");
        let password = SecretBytes::new(b"migration-password".to_vec());
        let core = VaultCore::new();
        crate::storage::create_migration_source_vault_directory(
            &vault_path,
            Some("Source".to_owned()),
            &password,
        )
        .expect("create source");
        let mut unlocked = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open source")
            .unlock(UnlockRequest {
                master_password: password.clone(),
            })
            .expect("unlock source");
        unlocked
            .create_item(login_draft("Source", "source-secret-marker"))
            .expect("create source item");

        let vault_key =
            crate::storage::unlock_vault_key(&vault_path, &password).expect("unlock source key");
        let source_snapshot = tree_manifest(&vault_path).expect("source snapshot");
        let portable_snapshot = portable_manifest(&vault_path).expect("portable snapshot");
        let records =
            load_verified_legacy_records(&vault_path, &vault_key).expect("load source records");
        crate::storage::backup_vault_directory(&vault_path, &backup_path).expect("copy backup");
        let backup_record = first_record_path(&backup_path);
        let mut bytes = fs::read(&backup_record).expect("read backup record");
        bytes.push(b' ');
        fs::write(&backup_record, bytes).expect("tamper backup record");

        assert!(verify_encrypted_backup(
            &vault_path,
            &backup_path,
            &vault_key,
            &portable_snapshot,
            &records,
        )
        .is_err());
        assert_eq!(
            tree_manifest(&vault_path).expect("source after failed verification"),
            source_snapshot
        );
        let metadata: VaultMetadata =
            read_json(&vault_path.join(METADATA_FILE), "read source metadata")
                .expect("source metadata");
        assert_eq!(metadata.vault_format_version, 1);
        assert_eq!(metadata.record_format_version, 1);

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn lifecycle_is_encrypted_and_round_trips_in_target_records() {
        let credential = crate::Credential::new(
            crate::VaultId::generate(),
            crate::CredentialDraft::from(login_draft("Archived", "secret")),
        )
        .expect("create credential");
        let revision = crate::CredentialRevision::initial_with_lifecycle(
            credential,
            crate::DeviceId::generate(),
            CredentialLifecycle::Archived,
        )
        .expect("create archived revision");
        let key = SecretBytes::new(vec![42; 32]);
        let record =
            crate::record::encrypt_target_credential_record(&key, &revision).expect("encrypt");
        let encoded = serde_json::to_string(&record).expect("serialize");
        assert!(!encoded.contains("archived"));
        let decoded =
            crate::record::decrypt_target_credential_record(&key, &record).expect("decrypt");
        assert_eq!(decoded.lifecycle(), CredentialLifecycle::Archived);
    }

    fn login_draft(title: &str, password: &str) -> VaultItemDraft {
        VaultItemDraft {
            title: title.to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some(format!("{}@example.com", title.to_lowercase())),
                password: Some(SecretBytes::new(password.as_bytes().to_vec())),
                urls: vec!["https://example.com".to_owned()],
                notes: None,
                totp_secret: None,
            }),
            tags: vec!["migration".to_owned()],
            favorite: false,
        }
    }

    fn all_record_text(vault_path: &Path) -> String {
        [ITEMS_DIR, TOMBSTONES_DIR]
            .into_iter()
            .flat_map(|directory| {
                fs::read_dir(vault_path.join(directory))
                    .expect("read record directory")
                    .map(|entry| entry.expect("record entry").path())
            })
            .map(|path| fs::read_to_string(path).expect("read encrypted record"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn target_revisions(vault_path: &Path, vault_key: &SecretBytes) -> Vec<CredentialRevision> {
        [ITEMS_DIR, TOMBSTONES_DIR]
            .into_iter()
            .flat_map(|directory| {
                fs::read_dir(vault_path.join(directory))
                    .expect("read target directory")
                    .map(|entry| entry.expect("target entry").path())
            })
            .map(|path| {
                let bytes = fs::read(path).expect("read target record");
                let record = parse_target_credential_record(&bytes).expect("parse target record");
                crate::record::decrypt_target_credential_record(vault_key, &record)
                    .expect("decrypt target record")
            })
            .collect()
    }

    fn first_record_path(vault_path: &Path) -> PathBuf {
        fs::read_dir(vault_path.join(ITEMS_DIR))
            .expect("read item records")
            .next()
            .expect("item record")
            .expect("item record entry")
            .path()
    }

    fn password_field_id(revision: &CredentialRevision) -> crate::SecretFieldId {
        revision
            .credential()
            .draft()
            .fields
            .iter()
            .find(|field| field.role == "password")
            .and_then(crate::CredentialField::secret_field_id)
            .expect("password field identity")
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "psw-core-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }
}
