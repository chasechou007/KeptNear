use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::crypto::{
    create_key_envelope, create_key_envelope_for_vault_key, create_local_unlock_envelope,
    decrypt_key_envelope, decrypt_local_unlock_envelope, rewrap_key_envelope,
    validate_master_password_policy, KeyEnvelope, LocalUnlockEnvelope,
};
use crate::error::{VaultError, VaultResult};
use crate::record::{EncryptedItemRecord, TargetEncryptedCredentialRecord};
use crate::recovery::{
    create_recovery_envelope, decrypt_recovery_envelope, RecoveryEnvelope, RecoveryKey,
};
use crate::revision::CredentialLifecycle;
use crate::safe_fs::{
    read_regular_file_limited, MAX_ENCRYPTED_RECORD_FILE_BYTES, MAX_VAULT_CONTROL_FILE_BYTES,
};
use crate::stable_id::VaultId;
use crate::types::{
    SecretBytes, VaultMetadata, CURRENT_RECORD_FORMAT_VERSION, CURRENT_VAULT_FORMAT_VERSION,
    SOURCE_RECORD_FORMAT_VERSION, SOURCE_VAULT_FORMAT_VERSION, SUPPORTED_VAULT_FORMAT_PAIRS,
    TARGET_RECORD_FORMAT_VERSION, TARGET_VAULT_FORMAT_VERSION, VAULT_FORMAT_NAME,
};

const METADATA_FILE: &str = "vault.json";
const KEYS_FILE: &str = "keys.enc";
const RECOVERY_FILE: &str = "recovery.enc";
const LOCAL_UNLOCK_FILE: &str = "local_unlock.enc";
const ITEMS_DIR: &str = "items";
const ATTACHMENTS_DIR: &str = "attachments";
const TOMBSTONES_DIR: &str = "tombstones";

/// Creates the on-disk vault directory structure.
pub fn create_vault_directory(
    path: &Path,
    display_name: Option<String>,
    master_password: &SecretBytes,
) -> VaultResult<VaultMetadata> {
    validate_master_password_policy(master_password)?;
    validate_new_vault_destination(path)?;

    fs::create_dir_all(path).map_err(|source| VaultError::io("create vault directory", source))?;
    fs::create_dir_all(path.join(ITEMS_DIR))
        .map_err(|source| VaultError::io("create items directory", source))?;
    fs::create_dir_all(path.join(ATTACHMENTS_DIR))
        .map_err(|source| VaultError::io("create attachments directory", source))?;
    fs::create_dir_all(path.join(TOMBSTONES_DIR))
        .map_err(|source| VaultError::io("create tombstones directory", source))?;

    let metadata = VaultMetadata::current(display_name);
    write_json(path.join(METADATA_FILE), &metadata, "write vault metadata")?;

    let key_envelope = create_key_envelope(master_password)?;
    write_json(path.join(KEYS_FILE), &key_envelope, "write key envelope")?;

    Ok(metadata)
}

#[cfg(test)]
pub(crate) fn create_migration_source_vault_directory(
    path: &Path,
    display_name: Option<String>,
    master_password: &SecretBytes,
) -> VaultResult<VaultMetadata> {
    validate_master_password_policy(master_password)?;
    validate_new_vault_destination(path)?;

    fs::create_dir_all(path).map_err(|source| VaultError::io("create vault directory", source))?;
    fs::create_dir_all(path.join(ITEMS_DIR))
        .map_err(|source| VaultError::io("create items directory", source))?;
    fs::create_dir_all(path.join(ATTACHMENTS_DIR))
        .map_err(|source| VaultError::io("create attachments directory", source))?;
    fs::create_dir_all(path.join(TOMBSTONES_DIR))
        .map_err(|source| VaultError::io("create tombstones directory", source))?;

    let metadata = VaultMetadata::migration_source(display_name);
    write_json(path.join(METADATA_FILE), &metadata, "write vault metadata")?;
    let key_envelope = create_key_envelope(master_password)?;
    write_json(path.join(KEYS_FILE), &key_envelope, "write key envelope")?;
    Ok(metadata)
}

/// Opens and validates an existing vault directory.
pub fn open_vault_directory(path: &Path) -> VaultResult<VaultMetadata> {
    crate::migration::recover_interrupted_migration(path)?;
    validate_required_structure(path)?;
    let metadata: VaultMetadata =
        read_control_json(path.join(METADATA_FILE), "read vault metadata")?;
    if metadata.format_name != VAULT_FORMAT_NAME {
        return Err(VaultError::InvalidVault {
            reason: format!(
                "unsupported format name '{}'; expected '{VAULT_FORMAT_NAME}'",
                metadata.format_name
            ),
        });
    }
    if metadata.vault_format_version > CURRENT_VAULT_FORMAT_VERSION {
        return Err(VaultError::UnsupportedFormat {
            found: metadata.vault_format_version,
            supported: CURRENT_VAULT_FORMAT_VERSION,
        });
    }
    if metadata.record_format_version > CURRENT_RECORD_FORMAT_VERSION {
        return Err(VaultError::UnsupportedFormat {
            found: metadata.record_format_version,
            supported: CURRENT_RECORD_FORMAT_VERSION,
        });
    }
    let format_pair = (
        metadata.vault_format_version,
        metadata.record_format_version,
    );
    if !SUPPORTED_VAULT_FORMAT_PAIRS.contains(&format_pair) {
        let supported_pairs = SUPPORTED_VAULT_FORMAT_PAIRS
            .iter()
            .map(|(vault, record)| format!("{vault}/{record}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(VaultError::InvalidVault {
            reason: format!(
                "unsupported vault/record format pair {}/{}; supported pairs: {supported_pairs}",
                metadata.vault_format_version, metadata.record_format_version
            ),
        });
    }
    match format_pair {
        (SOURCE_VAULT_FORMAT_VERSION, SOURCE_RECORD_FORMAT_VERSION)
            if metadata.vault_id.is_some() =>
        {
            return Err(VaultError::InvalidVault {
                reason: "frozen v1/v1 metadata must not contain a target vault identity".to_owned(),
            });
        }
        (TARGET_VAULT_FORMAT_VERSION, TARGET_RECORD_FORMAT_VERSION)
            if metadata.vault_id.is_none() =>
        {
            return Err(VaultError::InvalidVault {
                reason: "target metadata is missing its stable vault identity".to_owned(),
            });
        }
        _ => {}
    }
    Ok(metadata)
}

/// Unlocks the vault key from `keys.enc`.
pub fn unlock_vault_key(path: &Path, master_password: &SecretBytes) -> VaultResult<SecretBytes> {
    validate_required_structure(path)?;
    let envelope: KeyEnvelope = read_control_json(path.join(KEYS_FILE), "read key envelope")?;
    decrypt_key_envelope(&envelope, master_password)
}

/// Changes the master password by rewrapping the existing vault key.
pub fn change_master_password(
    path: &Path,
    current_master_password: &SecretBytes,
    new_master_password: &SecretBytes,
) -> VaultResult<()> {
    validate_required_structure(path)?;
    let key_path = path.join(KEYS_FILE);
    let envelope: KeyEnvelope = read_control_json(key_path.clone(), "read key envelope")?;
    let rewrapped = rewrap_key_envelope(&envelope, current_master_password, new_master_password)?;
    write_json_atomically(key_path, &rewrapped, "write key envelope")
}

/// Installs a new recovery envelope for an unlocked vault.
pub(crate) fn create_and_write_recovery_envelope(
    path: &Path,
    vault_id: VaultId,
    vault_key: &SecretBytes,
) -> VaultResult<(RecoveryKey, RecoveryEnvelope)> {
    let metadata = open_vault_directory(path)?;
    if metadata.vault_id != Some(vault_id) {
        return Err(VaultError::InvalidVault {
            reason: "recovery setup vault identity mismatch".to_owned(),
        });
    }
    let (recovery_key, envelope) = create_recovery_envelope(vault_id, vault_key)?;
    write_recovery_envelope(path, &envelope)?;
    Ok((recovery_key, envelope))
}

/// Creates a recovery-key rotation candidate without changing durable authority.
pub(crate) fn create_recovery_envelope_rotation(
    path: &Path,
    vault_id: VaultId,
    vault_key: &SecretBytes,
) -> VaultResult<(
    RecoveryKey,
    RecoveryEnvelope,
    crate::stable_id::RecoveryKeyId,
)> {
    let metadata = open_vault_directory(path)?;
    if metadata.vault_id != Some(vault_id) {
        return Err(VaultError::InvalidVault {
            reason: "recovery rotation vault identity mismatch".to_owned(),
        });
    }
    let current_envelope = read_recovery_envelope(path)?;
    if current_envelope.vault_id() != vault_id {
        return Err(VaultError::InvalidVault {
            reason: "current recovery envelope vault identity mismatch".to_owned(),
        });
    }

    let previous_recovery_key_id = current_envelope.recovery_key_id();
    let (recovery_key, candidate_envelope) = create_recovery_envelope(vault_id, vault_key)?;
    verify_recovery_rotation_candidate(vault_id, vault_key, &recovery_key, &candidate_envelope)?;
    Ok((recovery_key, candidate_envelope, previous_recovery_key_id))
}

/// Returns the current recovery-key generation without exposing wrapped material.
pub(crate) fn recovery_envelope_key_id(
    path: &Path,
    expected_vault_id: VaultId,
) -> VaultResult<Option<crate::stable_id::RecoveryKeyId>> {
    let metadata = open_vault_directory(path)?;
    if metadata.vault_id != Some(expected_vault_id) {
        return Err(VaultError::InvalidVault {
            reason: "recovery status vault identity mismatch".to_owned(),
        });
    }
    match fs::symlink_metadata(recovery_envelope_path(path)) {
        Ok(_) => {
            let envelope = read_recovery_envelope(path)?;
            if envelope.vault_id() != expected_vault_id {
                return Err(VaultError::InvalidVault {
                    reason: "current recovery envelope vault identity mismatch".to_owned(),
                });
            }
            Ok(Some(envelope.recovery_key_id()))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(VaultError::io("inspect recovery envelope", source)),
    }
}

/// Replaces recovery authority only if the expected prior generation is current.
pub(crate) fn commit_recovery_envelope_rotation(
    path: &Path,
    expected_vault_id: VaultId,
    vault_key: &SecretBytes,
    expected_previous_recovery_key_id: crate::stable_id::RecoveryKeyId,
    candidate_recovery_key: &RecoveryKey,
    candidate_envelope: &RecoveryEnvelope,
) -> VaultResult<()> {
    verify_recovery_rotation_candidate(
        expected_vault_id,
        vault_key,
        candidate_recovery_key,
        candidate_envelope,
    )?;

    let metadata_lock = OpenOptions::new()
        .read(true)
        .open(path.join(METADATA_FILE))
        .map_err(|source| VaultError::io("open recovery rotation lock", source))?;
    FileExt::lock_exclusive(&metadata_lock)
        .map_err(|source| VaultError::io("lock recovery rotation", source))?;

    let metadata = open_vault_directory(path)?;
    if metadata.vault_id != Some(expected_vault_id) {
        return Err(VaultError::InvalidVault {
            reason: "recovery rotation vault identity mismatch".to_owned(),
        });
    }
    let current_envelope = read_recovery_envelope(path)?;
    if current_envelope.vault_id() != expected_vault_id {
        return Err(VaultError::InvalidVault {
            reason: "current recovery envelope vault identity mismatch".to_owned(),
        });
    }
    if current_envelope.recovery_key_id() != expected_previous_recovery_key_id {
        return Err(VaultError::InvalidVault {
            reason: "recovery rotation candidate is stale".to_owned(),
        });
    }

    replace_recovery_envelope(path, candidate_envelope)
}

/// Recovers the existing vault key and atomically wraps it with a new master password.
pub fn recover_vault_key_and_rewrap_master_password(
    path: &Path,
    expected_vault_id: VaultId,
    recovery_key: &RecoveryKey,
    new_master_password: &SecretBytes,
) -> VaultResult<SecretBytes> {
    validate_master_password_policy(new_master_password)?;
    let metadata = open_vault_directory(path)?;
    if metadata.vault_id != Some(expected_vault_id) {
        return Err(VaultError::InvalidVault {
            reason: "recovery request vault identity mismatch".to_owned(),
        });
    }

    let recovery_envelope = read_recovery_envelope(path)?;
    let vault_key = decrypt_recovery_envelope(&recovery_envelope, expected_vault_id, recovery_key)?;
    let key_envelope = create_key_envelope_for_vault_key(new_master_password, &vault_key)?;
    let verified_vault_key = decrypt_key_envelope(&key_envelope, new_master_password)?;
    if verified_vault_key.expose() != vault_key.expose() {
        return Err(VaultError::InvalidVault {
            reason: "recovered master-password envelope did not verify".to_owned(),
        });
    }

    write_json_atomically(
        path.join(KEYS_FILE),
        &key_envelope,
        "write recovered key envelope",
    )?;
    Ok(vault_key)
}

fn write_recovery_envelope(path: &Path, envelope: &RecoveryEnvelope) -> VaultResult<()> {
    let encoded = envelope.to_json()?;
    write_bytes_atomically_create_new(
        recovery_envelope_path(path),
        &encoded,
        "write recovery envelope",
    )
}

fn replace_recovery_envelope(path: &Path, envelope: &RecoveryEnvelope) -> VaultResult<()> {
    let encoded = envelope.to_json()?;
    write_bytes_atomically(
        recovery_envelope_path(path),
        &encoded,
        "replace recovery envelope",
    )
}

fn verify_recovery_rotation_candidate(
    expected_vault_id: VaultId,
    expected_vault_key: &SecretBytes,
    candidate_recovery_key: &RecoveryKey,
    candidate_envelope: &RecoveryEnvelope,
) -> VaultResult<()> {
    if candidate_envelope.vault_id() != expected_vault_id {
        return Err(VaultError::InvalidVault {
            reason: "candidate recovery envelope vault identity mismatch".to_owned(),
        });
    }
    let candidate_vault_key = decrypt_recovery_envelope(
        candidate_envelope,
        expected_vault_id,
        candidate_recovery_key,
    )?;
    if candidate_vault_key.expose() != expected_vault_key.expose() {
        return Err(VaultError::InvalidVault {
            reason: "candidate recovery envelope wraps a different vault key".to_owned(),
        });
    }
    Ok(())
}

fn read_recovery_envelope(path: &Path) -> VaultResult<RecoveryEnvelope> {
    let envelope_path = recovery_envelope_path(path);
    let metadata = match fs::symlink_metadata(&envelope_path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultError::InvalidVault {
                reason: "offline recovery is not configured for this vault".to_owned(),
            });
        }
        Err(source) => return Err(VaultError::io("inspect recovery envelope", source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VaultError::InvalidVault {
            reason: "recovery envelope is not a regular file".to_owned(),
        });
    }
    if metadata.len() > RecoveryEnvelope::MAX_ENCODED_LEN as u64 {
        return Err(VaultError::InvalidVault {
            reason: "recovery envelope exceeds the maximum encoded size".to_owned(),
        });
    }
    let encoded = read_regular_file_limited(
        &envelope_path,
        RecoveryEnvelope::MAX_ENCODED_LEN as u64,
        "read recovery envelope",
    )?;
    RecoveryEnvelope::parse_json(&encoded)
}

/// Writes a local unlock envelope and returns the local unlock material.
pub fn create_local_unlock_material(
    path: &Path,
    vault_key: &SecretBytes,
) -> VaultResult<SecretBytes> {
    validate_required_structure(path)?;
    let (local_unlock_material, envelope) = create_local_unlock_envelope(vault_key)?;
    write_json_atomically(
        local_unlock_envelope_path(path),
        &envelope,
        "write local unlock envelope",
    )?;
    Ok(local_unlock_material)
}

/// Unlocks the vault key from the local unlock envelope.
pub fn unlock_vault_key_with_local_material(
    path: &Path,
    local_unlock_material: &SecretBytes,
) -> VaultResult<SecretBytes> {
    validate_required_structure(path)?;
    let envelope: LocalUnlockEnvelope = read_control_json(
        local_unlock_envelope_path(path),
        "read local unlock envelope",
    )?;
    decrypt_local_unlock_envelope(&envelope, local_unlock_material)
}

/// Loads all encrypted item records from the vault items directory.
pub(crate) fn load_item_records(path: &Path) -> VaultResult<LoadedEncryptedRecords> {
    load_records_from_dir(&path.join(ITEMS_DIR), "read items directory")
}

/// Loads all encrypted tombstone records from the vault tombstones directory.
pub(crate) fn load_tombstone_records(path: &Path) -> VaultResult<LoadedEncryptedRecords> {
    load_records_from_dir(&path.join(TOMBSTONES_DIR), "read tombstones directory")
}

/// Writes one encrypted item record to the vault items directory.
pub(crate) fn write_item_record(path: &Path, record: &EncryptedItemRecord) -> VaultResult<()> {
    let file_name = format!("{}_{}.enc", record.item_id, record.revision);
    write_json(
        path.join(ITEMS_DIR).join(file_name),
        record,
        "write item record",
    )
}

/// Writes one encrypted tombstone record to the vault tombstones directory.
pub(crate) fn write_tombstone_record(path: &Path, record: &EncryptedItemRecord) -> VaultResult<()> {
    let file_name = format!("tombstone_{}_{}.enc", record.item_id, record.revision);
    write_json(
        path.join(TOMBSTONES_DIR).join(file_name),
        record,
        "write tombstone record",
    )
}

/// Writes one current-format credential revision without replacing an existing identity.
pub(crate) fn write_target_credential_record(
    path: &Path,
    record: &TargetEncryptedCredentialRecord,
    lifecycle: CredentialLifecycle,
) -> VaultResult<()> {
    let stem = format!("{}_{}", record.credential_id, record.revision_id);
    let (directory, file_name) = match lifecycle {
        CredentialLifecycle::Active | CredentialLifecycle::Archived => {
            (ITEMS_DIR, format!("{stem}.enc"))
        }
        CredentialLifecycle::Deleted => (TOMBSTONES_DIR, format!("tombstone_{stem}.enc")),
    };
    let target = path.join(directory).join(file_name);
    let encoded = serde_json::to_vec_pretty(record).map_err(|source| VaultError::InvalidVault {
        reason: format!("serialize target credential record failed: {source}"),
    })?;
    let temporary = target.with_extension("enc.tmp");
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| {
                VaultError::io("create temporary target credential record", source)
            })?;
        file.write_all(&encoded)
            .map_err(|source| VaultError::io("write target credential record", source))?;
        file.sync_all()
            .map_err(|source| VaultError::io("sync target credential record", source))?;
        drop(file);
        if target.exists() {
            return Err(VaultError::InvalidVault {
                reason: "target credential record identity already exists".to_owned(),
            });
        }
        fs::rename(&temporary, &target)
            .map_err(|source| VaultError::io("install target credential record", source))
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    write_result
}

/// Successfully parsed encrypted records plus rejected record file count.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct LoadedEncryptedRecords {
    /// Encrypted records that were read and parsed successfully.
    pub(crate) records: Vec<LoadedEncryptedRecord>,
    /// `.enc` files that could not be read or parsed as encrypted records.
    pub(crate) rejected_records: usize,
    /// `.enc` file names that could not be read or parsed as encrypted records.
    pub(crate) rejected_record_files: Vec<String>,
}

/// Successfully parsed encrypted record with the local source file name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoadedEncryptedRecord {
    pub(crate) file_name: String,
    pub(crate) record: EncryptedItemRecord,
}

fn load_records_from_dir(
    records_path: &Path,
    operation: &'static str,
) -> VaultResult<LoadedEncryptedRecords> {
    let mut records = Vec::new();
    let mut rejected_records = 0;
    let mut rejected_record_files = Vec::new();
    for entry in fs::read_dir(records_path).map_err(|source| VaultError::io(operation, source))? {
        let Ok(entry) = entry else {
            rejected_records += 1;
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("enc") {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        match read_record_json(path, "read item record") {
            Ok(record) => records.push(LoadedEncryptedRecord { file_name, record }),
            Err(_) => {
                rejected_records += 1;
                rejected_record_files.push(file_name);
            }
        }
    }
    Ok(LoadedEncryptedRecords {
        records,
        rejected_records,
        rejected_record_files,
    })
}

pub(crate) fn validate_required_structure(path: &Path) -> VaultResult<()> {
    let root_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultError::InvalidVault {
                reason: "vault root does not exist".to_owned(),
            });
        }
        Err(source) => return Err(VaultError::io("inspect vault root", source)),
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(VaultError::InvalidVault {
            reason: "vault root is not a regular directory".to_owned(),
        });
    }

    for (required_path, kind) in required_paths(path) {
        let entry_name = required_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("required entry");
        let metadata = match fs::symlink_metadata(&required_path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(VaultError::InvalidVault {
                    reason: format!("missing required vault entry '{entry_name}'"),
                });
            }
            Err(source) => {
                return Err(VaultError::io("inspect required vault entry", source));
            }
        };
        let valid_kind = match kind {
            RequiredPathKind::File => metadata.is_file(),
            RequiredPathKind::Directory => metadata.is_dir(),
        };
        if metadata.file_type().is_symlink() || !valid_kind {
            return Err(VaultError::InvalidVault {
                reason: format!("invalid required vault entry '{entry_name}'"),
            });
        }
    }

    Ok(())
}

fn validate_new_vault_destination(path: &Path) -> VaultResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(VaultError::io("inspect vault destination", source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(VaultError::InvalidVault {
            reason: "target vault path must be a regular directory".to_owned(),
        });
    }
    if fs::read_dir(path)
        .map_err(|source| VaultError::io("read vault directory", source))?
        .next()
        .is_some()
    {
        return Err(VaultError::InvalidVault {
            reason: "target vault directory already exists and is not empty".to_owned(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct VaultBackupCopyReport {
    pub(crate) copied_item_files: usize,
    pub(crate) copied_attachment_files: usize,
    pub(crate) copied_tombstone_files: usize,
}

pub(crate) fn backup_vault_directory(
    source: &Path,
    destination: &Path,
) -> VaultResult<VaultBackupCopyReport> {
    copy_portable_vault_directory(source, destination)
}

pub(crate) fn restore_vault_backup_directory(
    source: &Path,
    destination: &Path,
) -> VaultResult<VaultBackupCopyReport> {
    copy_portable_vault_directory(source, destination)
}

fn copy_portable_vault_directory(
    source: &Path,
    destination: &Path,
) -> VaultResult<VaultBackupCopyReport> {
    validate_required_structure(source)?;
    validate_backup_destination(source, destination)?;

    fs::create_dir_all(destination)
        .map_err(|source| VaultError::io("create backup directory", source))?;
    copy_required_file(
        &source.join(METADATA_FILE),
        &destination.join(METADATA_FILE),
        "copy backup metadata",
    )?;
    copy_required_file(
        &source.join(KEYS_FILE),
        &destination.join(KEYS_FILE),
        "copy backup key envelope",
    )?;
    copy_optional_file(
        &source.join(RECOVERY_FILE),
        &destination.join(RECOVERY_FILE),
        "copy backup recovery envelope",
    )?;

    let copied_item_files = copy_directory_contents(
        &source.join(ITEMS_DIR),
        &destination.join(ITEMS_DIR),
        "copy backup item records",
    )?;
    let copied_attachment_files = copy_directory_contents(
        &source.join(ATTACHMENTS_DIR),
        &destination.join(ATTACHMENTS_DIR),
        "copy backup attachments",
    )?;
    let copied_tombstone_files = copy_directory_contents(
        &source.join(TOMBSTONES_DIR),
        &destination.join(TOMBSTONES_DIR),
        "copy backup tombstones",
    )?;

    Ok(VaultBackupCopyReport {
        copied_item_files,
        copied_attachment_files,
        copied_tombstone_files,
    })
}

fn validate_backup_destination(source: &Path, destination: &Path) -> VaultResult<()> {
    let source_canonical = fs::canonicalize(source)
        .map_err(|source| VaultError::io("resolve source vault path", source))?;
    let destination_canonical = backup_destination_absolute_path(destination)?;

    if destination_canonical == source_canonical
        || destination_canonical.starts_with(source_canonical)
    {
        return Err(VaultError::InvalidVault {
            reason: "backup destination must be outside the source vault".to_owned(),
        });
    }

    if destination.exists() {
        if !destination.is_dir() {
            return Err(VaultError::InvalidVault {
                reason: "backup destination already exists and is not a directory".to_owned(),
            });
        }
        if fs::read_dir(destination)
            .map_err(|source| VaultError::io("read backup destination", source))?
            .next()
            .is_some()
        {
            return Err(VaultError::InvalidVault {
                reason: "backup destination already exists and is not empty".to_owned(),
            });
        }
    }

    Ok(())
}

fn backup_destination_absolute_path(destination: &Path) -> VaultResult<PathBuf> {
    if destination.exists() {
        return fs::canonicalize(destination)
            .map_err(|source| VaultError::io("resolve backup destination", source));
    }

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .ok_or_else(|| VaultError::InvalidVault {
            reason: "backup destination must name a directory".to_owned(),
        })?;
    let parent = fs::canonicalize(parent)
        .map_err(|source| VaultError::io("resolve backup destination parent", source))?;
    Ok(parent.join(file_name))
}

fn copy_required_file(
    source: &Path,
    destination: &Path,
    operation: &'static str,
) -> VaultResult<()> {
    let metadata =
        fs::symlink_metadata(source).map_err(|source| VaultError::io(operation, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VaultError::InvalidVault {
            reason: "backup source entry is not a regular file".to_owned(),
        });
    }
    fs::copy(source, destination)
        .map_err(|source| VaultError::io(operation, source))
        .map(|_| ())
}

fn copy_optional_file(
    source: &Path,
    destination: &Path,
    operation: &'static str,
) -> VaultResult<()> {
    let metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(VaultError::io(operation, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VaultError::InvalidVault {
            reason: format!(
                "backup optional entry is not a regular file {}",
                source.display()
            ),
        });
    }
    fs::copy(source, destination)
        .map_err(|source| VaultError::io(operation, source))
        .map(|_| ())
}

fn copy_directory_contents(
    source: &Path,
    destination: &Path,
    operation: &'static str,
) -> VaultResult<usize> {
    fs::create_dir_all(destination).map_err(|source| VaultError::io(operation, source))?;
    let mut copied_files = 0;

    for entry in fs::read_dir(source).map_err(|source| VaultError::io(operation, source))? {
        let entry = entry.map_err(|source| VaultError::io(operation, source))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|source| VaultError::io(operation, source))?;

        if file_type.is_symlink() {
            return Err(VaultError::InvalidVault {
                reason: format!("backup does not support symlink {}", source_path.display()),
            });
        }
        if file_type.is_dir() {
            copied_files += copy_directory_contents(&source_path, &destination_path, operation)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)
                .map_err(|source| VaultError::io(operation, source))?;
            copied_files += 1;
        } else {
            return Err(VaultError::InvalidVault {
                reason: format!(
                    "backup does not support special file {}",
                    source_path.display()
                ),
            });
        }
    }

    Ok(copied_files)
}

#[derive(Copy, Clone)]
enum RequiredPathKind {
    File,
    Directory,
}

fn required_paths(path: &Path) -> [(PathBuf, RequiredPathKind); 5] {
    [
        (path.join(METADATA_FILE), RequiredPathKind::File),
        (path.join(KEYS_FILE), RequiredPathKind::File),
        (path.join(ITEMS_DIR), RequiredPathKind::Directory),
        (path.join(ATTACHMENTS_DIR), RequiredPathKind::Directory),
        (path.join(TOMBSTONES_DIR), RequiredPathKind::Directory),
    ]
}

fn local_unlock_envelope_path(path: &Path) -> PathBuf {
    path.join(LOCAL_UNLOCK_FILE)
}

fn recovery_envelope_path(path: &Path) -> PathBuf {
    path.join(RECOVERY_FILE)
}

fn read_control_json<T>(path: PathBuf, operation: &'static str) -> VaultResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = read_regular_file_limited(&path, MAX_VAULT_CONTROL_FILE_BYTES, operation)?;
    serde_json::from_slice(&bytes).map_err(|source| VaultError::InvalidVault {
        reason: format!("{operation} failed: {source}"),
    })
}

fn read_record_json<T>(path: PathBuf, operation: &'static str) -> VaultResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = read_regular_file_limited(&path, MAX_ENCRYPTED_RECORD_FILE_BYTES, operation)?;
    serde_json::from_slice(&bytes).map_err(|source| VaultError::InvalidVault {
        reason: format!("{operation} failed: {source}"),
    })
}

fn write_json<T>(path: PathBuf, value: &T, operation: &'static str) -> VaultResult<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| VaultError::InvalidVault {
        reason: format!("{operation} failed: {source}"),
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| VaultError::io(operation, source))?;
    file.write_all(&bytes)
        .map_err(|source| VaultError::io(operation, source))?;
    file.sync_all()
        .map_err(|source| VaultError::io(operation, source))
}

fn write_json_atomically<T>(path: PathBuf, value: &T, operation: &'static str) -> VaultResult<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| VaultError::InvalidVault {
        reason: format!("{operation} failed: {source}"),
    })?;
    write_bytes_atomically(path, &bytes, operation)
}

fn write_bytes_atomically(path: PathBuf, bytes: &[u8], operation: &'static str) -> VaultResult<()> {
    let temporary_path = path.with_extension("enc.tmp");
    let mut temporary_created = false;
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|source| VaultError::io(operation, source))?;
        temporary_created = true;
        file.write_all(bytes)
            .map_err(|source| VaultError::io(operation, source))?;
        file.sync_all()
            .map_err(|source| VaultError::io(operation, source))?;
        drop(file);
        fs::rename(&temporary_path, &path).map_err(|source| VaultError::io(operation, source))
    })();
    if write_result.is_err() && temporary_created {
        let _ = fs::remove_file(temporary_path);
    }
    write_result
}

fn write_bytes_atomically_create_new(
    path: PathBuf,
    bytes: &[u8],
    operation: &'static str,
) -> VaultResult<()> {
    let temporary_path = path.with_extension("enc.tmp");
    let mut temporary_created = false;
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|source| VaultError::io(operation, source))?;
        temporary_created = true;
        file.write_all(bytes)
            .map_err(|source| VaultError::io(operation, source))?;
        file.sync_all()
            .map_err(|source| VaultError::io(operation, source))?;
        drop(file);
        fs::hard_link(&temporary_path, &path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                VaultError::InvalidVault {
                    reason: "offline recovery is already initialized".to_owned(),
                }
            } else {
                VaultError::io(operation, source)
            }
        })?;
        let _ = fs::remove_file(&temporary_path);
        Ok(())
    })();
    if write_result.is_err() && temporary_created {
        let _ = fs::remove_file(temporary_path);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{CreateVaultRequest, OpenVaultRequest, SecretBytes, VaultCore, VaultError};
    use serde::Deserialize;

    #[test]
    fn create_open_and_unlock_vault_directory() {
        let temp_dir = unique_temp_dir("create_open_and_unlock");
        let vault_path = temp_dir.join("Example.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());

        let locked = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Example".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault");

        assert_eq!(locked.metadata.display_name.as_deref(), Some("Example"));
        assert!(vault_path.join("vault.json").is_file());
        assert!(vault_path.join("keys.enc").is_file());
        assert!(vault_path.join("items").is_dir());
        assert!(vault_path.join("attachments").is_dir());
        assert!(vault_path.join("tombstones").is_dir());

        let reopened = core
            .open_vault(OpenVaultRequest {
                path: vault_path.clone(),
            })
            .expect("open vault");
        assert_eq!(reopened.metadata.display_name.as_deref(), Some("Example"));

        let unlocked = reopened
            .unlock(crate::UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        assert_eq!(unlocked.path, vault_path);

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn create_vault_rejects_empty_master_password_without_partial_vault() {
        let temp_dir = unique_temp_dir("create_empty_master_password");
        let vault_path = temp_dir.join("Empty.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(Vec::new());

        let error = core
            .create_vault(CreateVaultRequest {
                path: vault_path.clone(),
                display_name: Some("Empty".to_owned()),
                master_password: password,
            })
            .expect_err("empty password rejected");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        assert!(!vault_path.exists());
        if temp_dir.exists() {
            fs::remove_dir_all(temp_dir).expect("remove temp dir");
        }
    }

    #[test]
    fn open_rejects_missing_structure() {
        let temp_dir = unique_temp_dir("open_rejects_missing_structure");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let core = VaultCore::new();

        let error = core
            .open_vault(OpenVaultRequest {
                path: temp_dir.clone(),
            })
            .expect_err("invalid vault");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_a_symbolic_link_vault_root() {
        use std::os::unix::fs::symlink;

        let temp_dir = unique_temp_dir("open_rejects_symlink_root");
        let real_vault_path = temp_dir.join("Real.pswvault");
        let linked_vault_path = temp_dir.join("Linked.pswvault");
        let core = VaultCore::new();
        core.create_vault(CreateVaultRequest {
            path: real_vault_path.clone(),
            display_name: Some("Real".to_owned()),
            master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
        })
        .expect("create vault");
        symlink(&real_vault_path, &linked_vault_path).expect("create vault symlink");

        let error = core
            .open_vault(OpenVaultRequest {
                path: linked_vault_path,
            })
            .expect_err("reject vault symlink");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn open_rejects_oversized_control_files_before_json_parsing() {
        let temp_dir = unique_temp_dir("open_rejects_oversized_metadata");
        let vault_path = temp_dir.join("Oversized.pswvault");
        let core = VaultCore::new();
        core.create_vault(CreateVaultRequest {
            path: vault_path.clone(),
            display_name: Some("Oversized".to_owned()),
            master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
        })
        .expect("create vault");
        fs::write(
            vault_path.join("vault.json"),
            vec![b' '; super::MAX_VAULT_CONTROL_FILE_BYTES as usize + 1],
        )
        .expect("write oversized metadata");

        let error = core
            .open_vault(OpenVaultRequest { path: vault_path })
            .expect_err("reject oversized metadata");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn open_rejects_future_format_versions() {
        let temp_dir = unique_temp_dir("open_rejects_future_format_versions");
        let vault_path = temp_dir.join("Future.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        core.create_vault(CreateVaultRequest {
            path: vault_path.clone(),
            display_name: Some("Future".to_owned()),
            master_password: password,
        })
        .expect("create vault");

        let mut metadata = crate::VaultMetadata::current(Some("Future".to_owned()));
        metadata.record_format_version = crate::types::CURRENT_RECORD_FORMAT_VERSION + 1;
        let bytes = serde_json::to_vec_pretty(&metadata).expect("serialize metadata");
        fs::write(vault_path.join("vault.json"), bytes).expect("write metadata");

        let error = core
            .open_vault(OpenVaultRequest { path: vault_path })
            .expect_err("future format");

        assert!(matches!(error, VaultError::UnsupportedFormat { .. }));
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn open_rejects_unlisted_older_format_pairs() {
        let temp_dir = unique_temp_dir("open_rejects_unlisted_older_format_pairs");
        let vault_path = temp_dir.join("Older.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        core.create_vault(CreateVaultRequest {
            path: vault_path.clone(),
            display_name: Some("Older".to_owned()),
            master_password: password,
        })
        .expect("create vault");

        let mut metadata = crate::VaultMetadata::migration_source(Some("Older".to_owned()));
        metadata.vault_format_version = 0;
        let bytes = serde_json::to_vec_pretty(&metadata).expect("serialize metadata");
        fs::write(vault_path.join("vault.json"), bytes).expect("write metadata");

        let error = core
            .open_vault(OpenVaultRequest { path: vault_path })
            .expect_err("unlisted older format");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn open_rejects_unknown_format_name() {
        let temp_dir = unique_temp_dir("open_rejects_unknown_format_name");
        let vault_path = temp_dir.join("Unknown.pswvault");
        let core = VaultCore::new();
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        core.create_vault(CreateVaultRequest {
            path: vault_path.clone(),
            display_name: Some("Unknown".to_owned()),
            master_password: password,
        })
        .expect("create vault");

        let mut metadata = crate::VaultMetadata::migration_source(Some("Unknown".to_owned()));
        metadata.format_name = "another-vault-format".to_owned();
        let bytes = serde_json::to_vec_pretty(&metadata).expect("serialize metadata");
        fs::write(vault_path.join("vault.json"), bytes).expect("write metadata");

        let error = core
            .open_vault(OpenVaultRequest { path: vault_path })
            .expect_err("unknown format name");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn supported_format_pairs_match_fixture_registry() {
        let registry_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/vaults/supported-source-versions.json");
        let registry: SourceVersionRegistry =
            serde_json::from_slice(&fs::read(registry_path).expect("read source-version registry"))
                .expect("parse source-version registry");
        assert_eq!(registry.registry_version, 1);

        let mut declared_pairs = registry
            .source_versions
            .iter()
            .map(|source| (source.vault_format_version, source.record_format_version))
            .collect::<Vec<_>>();
        declared_pairs.sort_unstable();
        let mut supported_pairs = crate::types::MIGRATION_SOURCE_FORMAT_PAIRS.to_vec();
        supported_pairs.sort_unstable();

        assert_eq!(
            declared_pairs, supported_pairs,
            "every accepted format pair must have exactly one sanitized fixture"
        );
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SourceVersionRegistry {
        registry_version: u32,
        source_versions: Vec<SourceVersion>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SourceVersion {
        vault_format_version: u32,
        record_format_version: u32,
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
}
