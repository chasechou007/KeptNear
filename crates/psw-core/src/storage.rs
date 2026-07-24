use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto::{
    create_key_envelope, create_local_unlock_envelope, decrypt_key_envelope,
    decrypt_local_unlock_envelope, rewrap_key_envelope, validate_master_password_policy,
    KeyEnvelope, LocalUnlockEnvelope,
};
use crate::error::{VaultError, VaultResult};
use crate::record::EncryptedItemRecord;
use crate::types::{
    SecretBytes, VaultMetadata, CURRENT_RECORD_FORMAT_VERSION, CURRENT_VAULT_FORMAT_VERSION,
};

const METADATA_FILE: &str = "vault.json";
const KEYS_FILE: &str = "keys.enc";
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

    if path.exists()
        && path
            .read_dir()
            .map_err(|source| VaultError::io("read vault directory", source))?
            .next()
            .is_some()
    {
        return Err(VaultError::InvalidVault {
            reason: "target vault directory already exists and is not empty".to_owned(),
        });
    }

    fs::create_dir_all(path).map_err(|source| VaultError::io("create vault directory", source))?;
    fs::create_dir_all(path.join(ITEMS_DIR))
        .map_err(|source| VaultError::io("create items directory", source))?;
    fs::create_dir_all(path.join(ATTACHMENTS_DIR))
        .map_err(|source| VaultError::io("create attachments directory", source))?;
    fs::create_dir_all(path.join(TOMBSTONES_DIR))
        .map_err(|source| VaultError::io("create tombstones directory", source))?;

    let metadata = VaultMetadata::experimental(display_name);
    write_json(path.join(METADATA_FILE), &metadata, "write vault metadata")?;

    let key_envelope = create_key_envelope(master_password)?;
    write_json(path.join(KEYS_FILE), &key_envelope, "write key envelope")?;

    Ok(metadata)
}

/// Opens and validates an existing vault directory.
pub fn open_vault_directory(path: &Path) -> VaultResult<VaultMetadata> {
    validate_required_structure(path)?;
    let metadata: VaultMetadata = read_json(path.join(METADATA_FILE), "read vault metadata")?;
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
    Ok(metadata)
}

/// Unlocks the vault key from `keys.enc`.
pub fn unlock_vault_key(path: &Path, master_password: &SecretBytes) -> VaultResult<SecretBytes> {
    validate_required_structure(path)?;
    let envelope: KeyEnvelope = read_json(path.join(KEYS_FILE), "read key envelope")?;
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
    let envelope: KeyEnvelope = read_json(key_path.clone(), "read key envelope")?;
    let rewrapped = rewrap_key_envelope(&envelope, current_master_password, new_master_password)?;
    write_json_atomically(key_path, &rewrapped, "write key envelope")
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
    let envelope: LocalUnlockEnvelope = read_json(
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
        match read_json(path, "read item record") {
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
    if !path.is_dir() {
        return Err(VaultError::InvalidVault {
            reason: "vault path is not a directory".to_owned(),
        });
    }

    for (required_path, kind) in required_paths(path) {
        if !required_path.exists() {
            return Err(VaultError::InvalidVault {
                reason: format!("missing required path {}", required_path.display()),
            });
        }
        let valid_kind = match kind {
            RequiredPathKind::File => required_path.is_file(),
            RequiredPathKind::Directory => required_path.is_dir(),
        };
        if !valid_kind {
            return Err(VaultError::InvalidVault {
                reason: format!("invalid required path type {}", required_path.display()),
            });
        }
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
    if fs::symlink_metadata(source)
        .map_err(|source| VaultError::io(operation, source))?
        .file_type()
        .is_symlink()
    {
        return Err(VaultError::InvalidVault {
            reason: format!("backup does not support symlink {}", source.display()),
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

fn read_json<T>(path: PathBuf, operation: &'static str) -> VaultResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(&path).map_err(|source| VaultError::io(operation, source))?;
    serde_json::from_slice(&bytes).map_err(|source| VaultError::InvalidVault {
        reason: format!("{operation} failed for {}: {source}", path.display()),
    })
}

fn write_json<T>(path: PathBuf, value: &T, operation: &'static str) -> VaultResult<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| VaultError::InvalidVault {
        reason: format!("{operation} failed for {}: {source}", path.display()),
    })?;
    fs::write(&path, bytes).map_err(|source| VaultError::io(operation, source))
}

fn write_json_atomically<T>(path: PathBuf, value: &T, operation: &'static str) -> VaultResult<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| VaultError::InvalidVault {
        reason: format!("{operation} failed for {}: {source}", path.display()),
    })?;
    let temporary_path = path.with_extension("enc.tmp");
    let mut file =
        File::create(&temporary_path).map_err(|source| VaultError::io(operation, source))?;
    file.write_all(&bytes)
        .map_err(|source| VaultError::io(operation, source))?;
    file.sync_all()
        .map_err(|source| VaultError::io(operation, source))?;
    drop(file);
    fs::rename(&temporary_path, &path).map_err(|source| VaultError::io(operation, source))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{CreateVaultRequest, OpenVaultRequest, SecretBytes, VaultCore, VaultError};

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

        let mut metadata = crate::VaultMetadata::experimental(Some("Future".to_owned()));
        metadata.record_format_version = crate::types::CURRENT_RECORD_FORMAT_VERSION + 1;
        let bytes = serde_json::to_vec_pretty(&metadata).expect("serialize metadata");
        fs::write(vault_path.join("vault.json"), bytes).expect("write metadata");

        let error = core
            .open_vault(OpenVaultRequest { path: vault_path })
            .expect_err("future format");

        assert!(matches!(error, VaultError::UnsupportedFormat { .. }));
        fs::remove_dir_all(temp_dir).expect("remove temp dir");
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
