#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Command-line support library for PSW local vault tooling.

use std::fs;
use std::path::Path;

use psw_core::VaultMetadata;
use serde::{Deserialize, Serialize};

const CURRENT_VAULT_FORMAT_VERSION: u32 = 1;
const CURRENT_RECORD_FORMAT_VERSION: u32 = 1;

/// Overall vault doctor status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    /// The vault is locally usable by this client.
    Usable,
    /// The path or required structure is incomplete or malformed.
    Unusable,
    /// The vault or record format is newer than this client supports.
    UnsupportedFormat,
}

/// Required vault path kind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredPathKind {
    /// Required regular file.
    File,
    /// Required directory.
    Directory,
}

/// Status for one required portable vault path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequiredPathReport {
    /// Stable path label without parent directories.
    pub label: String,
    /// Expected local filesystem kind.
    pub expected_kind: RequiredPathKind,
    /// Whether the path exists.
    pub exists: bool,
    /// Whether the existing path has the expected kind.
    pub valid_kind: bool,
}

/// Non-secret aggregate file counts for a vault directory.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultDoctorCounts {
    /// Number of `.enc` files under `items/`.
    pub item_record_files: usize,
    /// Number of files under `attachments/`.
    pub attachment_files: usize,
    /// Number of `.enc` files under `tombstones/`.
    pub tombstone_record_files: usize,
}

/// Non-secret doctor report for a local vault path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultDoctorReport {
    /// Overall status.
    pub status: DoctorStatus,
    /// Whether the supplied path exists.
    pub path_exists: bool,
    /// Whether the supplied path is a directory.
    pub is_directory: bool,
    /// Required portable vault path statuses.
    pub required_paths: Vec<RequiredPathReport>,
    /// Whether all required portable vault paths are present with valid types.
    pub required_structure_complete: bool,
    /// Public vault metadata when readable.
    pub metadata: Option<VaultMetadata>,
    /// Non-secret metadata or structure error label.
    pub problem: Option<String>,
    /// Non-secret aggregate file counts.
    pub counts: VaultDoctorCounts,
    /// Whether `local_unlock.enc` is present.
    pub local_unlock_envelope_present: bool,
}

impl VaultDoctorReport {
    /// Returns true when the report indicates the vault is locally usable.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.status == DoctorStatus::Usable
    }
}

/// Inspects a local vault directory without unlocking or decrypting records.
#[must_use]
pub fn doctor_vault(path: &Path) -> VaultDoctorReport {
    let path_exists = path.exists();
    let is_directory = path.is_dir();
    let required_paths = required_path_reports(path);
    let required_structure_complete = is_directory
        && required_paths
            .iter()
            .all(|report| report.exists && report.valid_kind);
    let local_unlock_envelope_present = path.join("local_unlock.enc").is_file();

    if !path_exists {
        return report(
            DoctorStatus::Unusable,
            path_exists,
            is_directory,
            required_paths,
            None,
            Some("vault path does not exist".to_owned()),
            VaultDoctorCounts::default(),
            local_unlock_envelope_present,
        );
    }
    if !is_directory {
        return report(
            DoctorStatus::Unusable,
            path_exists,
            is_directory,
            required_paths,
            None,
            Some("vault path is not a directory".to_owned()),
            VaultDoctorCounts::default(),
            local_unlock_envelope_present,
        );
    }
    if !required_structure_complete {
        return report(
            DoctorStatus::Unusable,
            path_exists,
            is_directory,
            required_paths,
            None,
            Some("required structure is incomplete".to_owned()),
            VaultDoctorCounts::default(),
            local_unlock_envelope_present,
        );
    }

    let metadata = match read_metadata(path) {
        Ok(metadata) => metadata,
        Err(problem) => {
            return report(
                DoctorStatus::Unusable,
                path_exists,
                is_directory,
                required_paths,
                None,
                Some(problem),
                count_vault_files(path),
                local_unlock_envelope_present,
            )
        }
    };
    if metadata.vault_format_version > CURRENT_VAULT_FORMAT_VERSION
        || metadata.record_format_version > CURRENT_RECORD_FORMAT_VERSION
    {
        return report(
            DoctorStatus::UnsupportedFormat,
            path_exists,
            is_directory,
            required_paths,
            Some(metadata),
            Some("vault format is newer than this client supports".to_owned()),
            count_vault_files(path),
            local_unlock_envelope_present,
        );
    }

    report(
        DoctorStatus::Usable,
        path_exists,
        is_directory,
        required_paths,
        Some(metadata),
        None,
        count_vault_files(path),
        local_unlock_envelope_present,
    )
}

/// Renders a non-secret human-readable doctor report.
#[must_use]
pub fn render_text_report(report: &VaultDoctorReport) -> String {
    let mut output = String::new();
    output.push_str("PSW vault doctor\n");
    output.push_str(&format!("Status: {}\n", status_label(&report.status)));
    output.push_str(&format!(
        "Required structure: {}\n",
        yes_no(report.required_structure_complete)
    ));

    if let Some(metadata) = &report.metadata {
        output.push_str(&format!("Format name: {}\n", metadata.format_name));
        output.push_str(&format!(
            "Vault format version: {}\n",
            metadata.vault_format_version
        ));
        output.push_str(&format!(
            "Record format version: {}\n",
            metadata.record_format_version
        ));
        output.push_str(&format!(
            "Display name: {}\n",
            metadata.display_name.as_deref().unwrap_or("(none)")
        ));
    }

    if let Some(problem) = &report.problem {
        output.push_str(&format!("Problem: {problem}\n"));
    }

    let invalid = invalid_required_labels(report);
    if !invalid.is_empty() {
        output.push_str(&format!("Missing or invalid: {}\n", invalid.join(", ")));
    }

    output.push_str(&format!(
        "Encrypted item records: {}\n",
        report.counts.item_record_files
    ));
    output.push_str(&format!(
        "Attachment files: {}\n",
        report.counts.attachment_files
    ));
    output.push_str(&format!(
        "Encrypted tombstone records: {}\n",
        report.counts.tombstone_record_files
    ));
    output.push_str(&format!(
        "Local unlock envelope: {}\n",
        yes_no(report.local_unlock_envelope_present)
    ));
    output
        .push_str("Provider sync status: not checked; this is local filesystem readiness only.\n");

    output
}

#[allow(clippy::too_many_arguments)]
fn report(
    status: DoctorStatus,
    path_exists: bool,
    is_directory: bool,
    required_paths: Vec<RequiredPathReport>,
    metadata: Option<VaultMetadata>,
    problem: Option<String>,
    counts: VaultDoctorCounts,
    local_unlock_envelope_present: bool,
) -> VaultDoctorReport {
    let required_structure_complete = is_directory
        && required_paths
            .iter()
            .all(|report| report.exists && report.valid_kind);
    VaultDoctorReport {
        status,
        path_exists,
        is_directory,
        required_paths,
        required_structure_complete,
        metadata,
        problem,
        counts,
        local_unlock_envelope_present,
    }
}

fn required_path_reports(path: &Path) -> Vec<RequiredPathReport> {
    [
        ("vault.json", RequiredPathKind::File),
        ("keys.enc", RequiredPathKind::File),
        ("items/", RequiredPathKind::Directory),
        ("attachments/", RequiredPathKind::Directory),
        ("tombstones/", RequiredPathKind::Directory),
    ]
    .into_iter()
    .map(|(label, expected_kind)| {
        let full_path = path.join(label.trim_end_matches('/'));
        let exists = full_path.exists();
        let valid_kind = match expected_kind {
            RequiredPathKind::File => full_path.is_file(),
            RequiredPathKind::Directory => full_path.is_dir(),
        };
        RequiredPathReport {
            label: label.to_owned(),
            expected_kind,
            exists,
            valid_kind,
        }
    })
    .collect()
}

fn invalid_required_labels(report: &VaultDoctorReport) -> Vec<String> {
    report
        .required_paths
        .iter()
        .filter(|path| !path.exists || !path.valid_kind)
        .map(|path| path.label.clone())
        .collect()
}

fn read_metadata(path: &Path) -> Result<VaultMetadata, String> {
    let bytes =
        fs::read(path.join("vault.json")).map_err(|_| "vault metadata is unreadable".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|_| "vault metadata is malformed".to_owned())
}

fn count_vault_files(path: &Path) -> VaultDoctorCounts {
    VaultDoctorCounts {
        item_record_files: count_extension_files(&path.join("items"), "enc"),
        attachment_files: count_files(&path.join("attachments")),
        tombstone_record_files: count_extension_files(&path.join("tombstones"), "enc"),
    }
}

fn count_files(path: &Path) -> usize {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .count()
}

fn count_extension_files(path: &Path, extension: &str) -> usize {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
                && entry.path().extension().and_then(|value| value.to_str()) == Some(extension)
        })
        .count()
}

fn status_label(status: &DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Usable => "usable",
        DoctorStatus::Unusable => "unusable",
        DoctorStatus::UnsupportedFormat => "unsupported_format",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use psw_core::{
        CreateVaultRequest, LoginItem, SecretBytes, UnlockRequest, VaultCore, VaultItemContent,
        VaultItemDraft,
    };

    #[test]
    fn doctor_reports_complete_supported_vault_without_decrypting_items() {
        let temp_dir = unique_temp_dir("doctor_complete");
        let vault_path = temp_dir.join("Complete.pswvault");
        create_sample_vault(&vault_path);
        fs::write(
            vault_path.join("attachments").join("receipt.bin"),
            b"attachment",
        )
        .expect("write attachment");
        fs::write(vault_path.join("local_unlock.enc"), b"local envelope")
            .expect("write local unlock envelope");

        let report = doctor_vault(&vault_path);

        assert_eq!(report.status, DoctorStatus::Usable);
        assert!(report.is_usable());
        assert!(report.required_structure_complete);
        assert_eq!(
            report
                .metadata
                .as_ref()
                .expect("metadata")
                .vault_format_version,
            1
        );
        assert_eq!(report.counts.item_record_files, 1);
        assert_eq!(report.counts.attachment_files, 1);
        assert_eq!(report.counts.tombstone_record_files, 0);
        assert!(report.local_unlock_envelope_present);
        let text = render_text_report(&report);
        assert!(text.contains("Status: usable"));
        assert!(!text.contains("secret-password"));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn doctor_reports_incomplete_vault_with_required_path_labels() {
        let temp_dir = unique_temp_dir("doctor_incomplete");
        let vault_path = temp_dir.join("Incomplete.pswvault");
        fs::create_dir_all(&vault_path).expect("create incomplete vault");
        fs::write(vault_path.join("vault.json"), b"{}").expect("write metadata");
        fs::create_dir(vault_path.join("keys.enc")).expect("wrong key path type");
        fs::create_dir(vault_path.join("items")).expect("create items");

        let report = doctor_vault(&vault_path);

        assert_eq!(report.status, DoctorStatus::Unusable);
        assert!(!report.is_usable());
        assert_eq!(
            invalid_required_labels(&report),
            vec![
                "keys.enc".to_owned(),
                "attachments/".to_owned(),
                "tombstones/".to_owned()
            ]
        );
        assert!(render_text_report(&report).contains("Missing or invalid: keys.enc"));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn doctor_reports_unsupported_future_format() {
        let temp_dir = unique_temp_dir("doctor_future");
        let vault_path = temp_dir.join("Future.pswvault");
        create_sample_vault(&vault_path);
        let mut metadata = VaultMetadata::experimental(Some("Future".to_owned()));
        metadata.vault_format_version = CURRENT_VAULT_FORMAT_VERSION + 1;
        fs::write(
            vault_path.join("vault.json"),
            serde_json::to_vec_pretty(&metadata).expect("serialize metadata"),
        )
        .expect("write future metadata");

        let report = doctor_vault(&vault_path);

        assert_eq!(report.status, DoctorStatus::UnsupportedFormat);
        assert!(!report.is_usable());
        assert!(render_text_report(&report).contains("unsupported_format"));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn doctor_json_output_omits_secret_values() {
        let temp_dir = unique_temp_dir("doctor_json");
        let vault_path = temp_dir.join("Json.pswvault");
        create_sample_vault(&vault_path);
        let report = doctor_vault(&vault_path);

        let json = serde_json::to_string(&report).expect("serialize report");

        assert!(json.contains("\"status\":\"usable\""));
        assert!(!json.contains("secret-password"));
        assert!(!json.contains("alice@example.com"));

        fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    fn create_sample_vault(path: &Path) {
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        let core = VaultCore::new();
        let mut unlocked = core
            .create_vault(CreateVaultRequest {
                path: path.to_path_buf(),
                display_name: Some("Doctor".to_owned()),
                master_password: password.clone(),
            })
            .expect("create vault")
            .unlock(UnlockRequest {
                master_password: password,
            })
            .expect("unlock vault");
        unlocked
            .create_item(VaultItemDraft {
                title: "Email".to_owned(),
                content: VaultItemContent::Login(LoginItem {
                    username: Some("alice@example.com".to_owned()),
                    password: Some(SecretBytes::new(b"secret-password".to_vec())),
                    urls: vec!["https://example.com".to_owned()],
                    notes: Some("private note".to_owned()),
                    totp_secret: None,
                }),
                tags: vec!["personal".to_owned()],
                favorite: false,
            })
            .expect("create item");
    }

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "psw-cli-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }
}
