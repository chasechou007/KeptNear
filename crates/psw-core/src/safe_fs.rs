use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::error::{VaultError, VaultResult};

pub(crate) const MAX_VAULT_CONTROL_FILE_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_ENCRYPTED_RECORD_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_PLAINTEXT_IMPORT_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn read_regular_file_limited(
    path: &Path,
    max_bytes: u64,
    operation: &'static str,
) -> VaultResult<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| VaultError::io(operation, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VaultError::InvalidVault {
            reason: format!("{operation} requires a regular file"),
        });
    }
    if metadata.len() > max_bytes {
        return Err(VaultError::InvalidVault {
            reason: format!("{operation} exceeds the maximum supported size"),
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);

    let file = options
        .open(path)
        .map_err(|source| VaultError::io(operation, source))?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| VaultError::io(operation, source))?;
    if !opened_metadata.is_file() {
        return Err(VaultError::InvalidVault {
            reason: format!("{operation} requires a regular file"),
        });
    }
    if opened_metadata.len() > max_bytes {
        return Err(VaultError::InvalidVault {
            reason: format!("{operation} exceeds the maximum supported size"),
        });
    }

    let capacity = usize::try_from(opened_metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| VaultError::io(operation, source))?;
    if bytes.len() as u64 > max_bytes {
        return Err(VaultError::InvalidVault {
            reason: format!("{operation} exceeds the maximum supported size"),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::read_regular_file_limited;
    use crate::VaultError;

    fn test_root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "keptnear-safe-fs-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create test root");
        root
    }

    #[test]
    fn bounded_reader_accepts_a_regular_file_within_the_limit() {
        let root = test_root("regular");
        let path = root.join("record.enc");
        fs::write(&path, b"bounded").expect("write fixture");

        let bytes = read_regular_file_limited(&path, 7, "read fixture").expect("read fixture");

        assert_eq!(bytes, b"bounded");
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_file_before_parsing() {
        let root = test_root("oversized");
        let path = root.join("record.enc");
        fs::write(&path, b"too-large").expect("write fixture");

        let error =
            read_regular_file_limited(&path, 8, "read fixture").expect_err("reject oversized");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let root = test_root("symlink");
        let target = root.join("target.enc");
        let link = root.join("record.enc");
        fs::write(&target, b"secret").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let error =
            read_regular_file_limited(&link, 64, "read fixture").expect_err("reject symbolic link");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        fs::remove_dir_all(root).expect("remove test root");
    }
}
