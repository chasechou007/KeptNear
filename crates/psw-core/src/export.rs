use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use base64ct::{Base64, Encoding};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::credential_model::{CredentialDraft, CredentialFieldValue};
use crate::error::{VaultError, VaultResult};
use crate::import::BITWARDEN_JSON_FORMAT;
use crate::revision::CredentialLifecycle;
use crate::stable_id::{CredentialId, SecretFieldId, VaultId};
use crate::types::{SecretBytes, SoftwareLicenseItem, VaultItemContent, VaultItemDraft};

/// Version-one structured plaintext export for the extensible KeptNear model.
pub(crate) const KEPTNEAR_JSON_FORMAT: &str = "keptnear-json";

/// Export result counts and warnings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExportResult {
    /// Records written to the destination export file.
    pub exported_records: usize,
    /// Credentials or encrypted records skipped for a reported omission reason.
    pub skipped_records: usize,
    /// Structured reasons that data was omitted or transformed.
    pub omissions: Vec<ExportOmission>,
    /// Human-readable warnings for the user.
    pub warnings: Vec<String>,
}

/// Stable category explaining one plaintext-export omission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportOmissionReason {
    /// A credential had multiple authenticated current revisions.
    ConflictedCredential,
    /// An encrypted record could not be authenticated or parsed.
    RejectedRecord,
    /// The selected compatibility format cannot represent the credential template.
    UnsupportedTemplate,
    /// The selected compatibility format cannot represent every credential field.
    UnsupportedField,
    /// The selected compatibility format retained only the first tag.
    AdditionalTags,
}

impl ExportOmissionReason {
    /// Returns the canonical reason used by FFI and plaintext export documents.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConflictedCredential => "conflicted-credential",
            Self::RejectedRecord => "rejected-record",
            Self::UnsupportedTemplate => "unsupported-template",
            Self::UnsupportedField => "unsupported-field",
            Self::AdditionalTags => "additional-tags",
        }
    }

    const fn skips_record(self) -> bool {
        !matches!(self, Self::AdditionalTags)
    }
}

/// Aggregate count for one plaintext-export omission category.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOmission {
    /// Stable omission category.
    pub reason: ExportOmissionReason,
    /// Number of affected credentials or encrypted records.
    pub count: usize,
}

impl ExportOmission {
    pub(crate) const fn new(reason: ExportOmissionReason, count: usize) -> Self {
        Self { reason, count }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ExportCredential {
    pub source_credential_id: Option<CredentialId>,
    pub lifecycle: CredentialLifecycle,
    pub draft: CredentialDraft,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ExportSnapshot {
    pub source_vault_id: Option<VaultId>,
    pub credentials: Vec<ExportCredential>,
    pub omissions: Vec<ExportOmission>,
}

impl ExportSnapshot {
    pub(crate) fn add_omission(&mut self, reason: ExportOmissionReason, count: usize) {
        add_omission(&mut self.omissions, reason, count);
    }
}

pub(crate) fn export_credentials_to_file(
    destination_path: &Path,
    export_format: &str,
    snapshot: ExportSnapshot,
) -> VaultResult<ExportResult> {
    match export_format {
        KEPTNEAR_JSON_FORMAT => export_keptnear_json(destination_path, snapshot),
        BITWARDEN_JSON_FORMAT => export_bitwarden_json(destination_path, snapshot),
        other => Err(VaultError::InvalidVault {
            reason: format!("unsupported export format '{other}'"),
        }),
    }
}

fn export_keptnear_json(
    destination_path: &Path,
    snapshot: ExportSnapshot,
) -> VaultResult<ExportResult> {
    let ExportSnapshot {
        source_vault_id,
        credentials,
        omissions,
    } = snapshot;
    let items = credentials
        .into_iter()
        .map(KeptNearExportItem::from_credential)
        .collect::<Vec<_>>();
    let export = KeptNearPlaintextExport {
        format: "keptnear-plaintext-export",
        version: 1,
        warning: "This file contains plaintext-equivalent secrets. Base64 is reversible encoding, not encryption.",
        source_vault_id,
        items,
        omissions: omissions.clone(),
    };
    write_json_export(destination_path, &export, "KeptNear JSON")?;

    Ok(ExportResult {
        exported_records: export.items.len(),
        skipped_records: skipped_record_count(&omissions),
        warnings: export_warnings(&omissions, false),
        omissions,
    })
}

fn export_bitwarden_json(
    destination_path: &Path,
    snapshot: ExportSnapshot,
) -> VaultResult<ExportResult> {
    let mut omissions = snapshot.omissions;
    let mut drafts = Vec::new();
    for credential in snapshot.credentials {
        let known_template = matches!(
            credential.draft.template_id.as_deref(),
            Some("login" | "secure-note" | "software-license" | "credit-card")
        );
        match VaultItemDraft::try_from(credential.draft) {
            Ok(draft) => drafts.push(draft),
            Err(_) if known_template => {
                add_omission(&mut omissions, ExportOmissionReason::UnsupportedField, 1);
            }
            Err(_) => {
                add_omission(&mut omissions, ExportOmissionReason::UnsupportedTemplate, 1);
            }
        }
    }

    let folders = bitwarden_folders(&drafts);
    let folder_ids = folders
        .iter()
        .map(|folder| (folder.name.to_lowercase(), folder.id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut exported_items = Vec::new();
    let mut exported_software_licenses = false;

    for draft in drafts {
        if draft.tags.len() > 1 {
            add_omission(&mut omissions, ExportOmissionReason::AdditionalTags, 1);
        }
        if matches!(draft.content, VaultItemContent::SoftwareLicense(_)) {
            exported_software_licenses = true;
        }
        exported_items.push(bitwarden_item(&draft, &folder_ids));
    }

    let export = BitwardenExport {
        encrypted: false,
        folders,
        items: exported_items,
    };
    write_json_export(destination_path, &export, "Bitwarden JSON")?;

    let mut warnings = export_warnings(&omissions, true);
    if exported_software_licenses {
        warnings.push(
            "Software license items were exported as secure notes because Bitwarden JSON has no native software-license item type."
                .to_owned(),
        );
    }

    Ok(ExportResult {
        exported_records: export.items.len(),
        skipped_records: skipped_record_count(&omissions),
        omissions,
        warnings,
    })
}

fn write_json_export(
    destination_path: &Path,
    value: &impl Serialize,
    format_name: &str,
) -> VaultResult<()> {
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(value).map_err(|source| {
        VaultError::InvalidVault {
            reason: format!("serialize {format_name} failed: {source}"),
        }
    })?);

    match fs::symlink_metadata(destination_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(VaultError::InvalidVault {
                reason: "export destination must be a regular file".to_owned(),
            });
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(VaultError::io("inspect export destination", source)),
    }

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);

    let mut file = options
        .open(destination_path)
        .map_err(|source| VaultError::io("write export file", source))?;
    if !file
        .metadata()
        .map_err(|source| VaultError::io("inspect export file", source))?
        .is_file()
    {
        return Err(VaultError::InvalidVault {
            reason: "export destination must be a regular file".to_owned(),
        });
    }
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| VaultError::io("secure export file permissions", source))?;

    file.write_all(&bytes)
        .map_err(|source| VaultError::io("write export file", source))?;
    file.sync_all()
        .map_err(|source| VaultError::io("sync export file", source))
}

fn skipped_record_count(omissions: &[ExportOmission]) -> usize {
    omissions
        .iter()
        .filter(|omission| omission.reason.skips_record())
        .map(|omission| omission.count)
        .sum()
}

fn export_warnings(omissions: &[ExportOmission], bitwarden_compatibility: bool) -> Vec<String> {
    let mut warnings =
        vec!["Export file contains plaintext secrets; delete or secure it after use.".to_owned()];
    for omission in omissions {
        let warning = match omission.reason {
            ExportOmissionReason::ConflictedCredential => format!(
                "Skipped {} conflicted credential(s); resolve conflicts before exporting again.",
                omission.count
            ),
            ExportOmissionReason::RejectedRecord => format!(
                "Skipped {} rejected encrypted record(s); repair or quarantine them before exporting again.",
                omission.count
            ),
            ExportOmissionReason::UnsupportedTemplate => format!(
                "Skipped {} typed credential(s) whose templates are unsupported by the selected export format.",
                omission.count
            ),
            ExportOmissionReason::UnsupportedField => format!(
                "Skipped {} typed credential(s) containing fields unsupported by the selected export format.",
                omission.count
            ),
            ExportOmissionReason::AdditionalTags => format!(
                "{} credential(s) had additional tags omitted because Bitwarden folders represent one tag per item.",
                omission.count
            ),
        };
        warnings.push(warning);
    }
    if bitwarden_compatibility
        && omissions.iter().any(|omission| {
            matches!(
                omission.reason,
                ExportOmissionReason::UnsupportedTemplate | ExportOmissionReason::UnsupportedField
            )
        })
    {
        warnings.push(
            "Use keptnear-json to preserve the complete supported typed credential structure."
                .to_owned(),
        );
    }
    warnings
}

fn add_omission(omissions: &mut Vec<ExportOmission>, reason: ExportOmissionReason, count: usize) {
    if count == 0 {
        return;
    }
    if let Some(existing) = omissions
        .iter_mut()
        .find(|omission| omission.reason == reason)
    {
        existing.count = existing.count.saturating_add(count);
    } else {
        omissions.push(ExportOmission::new(reason, count));
    }
}

fn bitwarden_folders(drafts: &[VaultItemDraft]) -> Vec<BitwardenFolder> {
    let mut tags = BTreeMap::<String, String>::new();
    for draft in drafts {
        for tag in draft.tags.iter().take(1) {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                continue;
            }
            tags.entry(trimmed.to_lowercase())
                .or_insert_with(|| trimmed.to_owned());
        }
    }
    tags.into_values()
        .enumerate()
        .map(|(index, name)| BitwardenFolder {
            id: format!("folder_{}", index + 1),
            name,
        })
        .collect()
}

fn bitwarden_item(draft: &VaultItemDraft, folder_ids: &BTreeMap<String, String>) -> BitwardenItem {
    let folder_id = draft
        .tags
        .first()
        .and_then(|tag| folder_ids.get(&tag.trim().to_lowercase()).cloned());
    match &draft.content {
        VaultItemContent::Login(login) => BitwardenItem {
            item_type: 1,
            name: draft.title.clone(),
            notes: login.notes.clone(),
            favorite: draft.favorite,
            folder_id,
            login: Some(BitwardenLogin {
                username: login.username.clone(),
                password: login.password.as_ref().map(secret_to_string),
                totp: login.totp_secret.as_ref().map(secret_to_string),
                uris: login
                    .urls
                    .iter()
                    .map(|uri| BitwardenUri { uri: uri.clone() })
                    .collect(),
            }),
            secure_note: None,
            card: None,
        },
        VaultItemContent::SecureNote(note) => BitwardenItem {
            item_type: 2,
            name: draft.title.clone(),
            notes: Some(note.body.clone()),
            favorite: draft.favorite,
            folder_id,
            login: None,
            secure_note: Some(BitwardenSecureNote { note_type: 0 }),
            card: None,
        },
        VaultItemContent::SoftwareLicense(license) => BitwardenItem {
            item_type: 2,
            name: draft.title.clone(),
            notes: Some(software_license_note(license)),
            favorite: draft.favorite,
            folder_id,
            login: None,
            secure_note: Some(BitwardenSecureNote { note_type: 0 }),
            card: None,
        },
        VaultItemContent::CreditCard(card) => BitwardenItem {
            item_type: 3,
            name: draft.title.clone(),
            notes: card.notes.clone(),
            favorite: draft.favorite,
            folder_id,
            login: None,
            secure_note: None,
            card: Some(BitwardenCard {
                cardholder_name: card.cardholder_name.clone(),
                brand: None,
                number: card.number.as_ref().map(secret_to_string),
                exp_month: card.expiry_month.map(|month| format!("{month:02}")),
                exp_year: card.expiry_year.map(|year| year.to_string()),
                code: card.verification_code.as_ref().map(secret_to_string),
            }),
        },
    }
}

fn software_license_note(license: &SoftwareLicenseItem) -> String {
    let mut lines = Vec::new();
    if let Some(product) = &license.product {
        lines.push(format!("Product: {product}"));
    }
    if let Some(licensed_to) = &license.licensed_to {
        lines.push(format!("Licensed to: {licensed_to}"));
    }
    if let Some(license_key) = &license.license_key {
        lines.push(format!("License key: {}", secret_to_string(license_key)));
    }
    if let Some(notes) = &license.notes {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(notes.clone());
    }
    lines.join("\n")
}

fn secret_to_string(secret: &SecretBytes) -> String {
    String::from_utf8_lossy(secret.expose()).to_string()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KeptNearPlaintextExport {
    format: &'static str,
    version: u32,
    warning: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_vault_id: Option<VaultId>,
    items: Vec<KeptNearExportItem>,
    omissions: Vec<ExportOmission>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KeptNearExportItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    source_credential_id: Option<CredentialId>,
    status: CredentialLifecycle,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template_id: Option<String>,
    fields: Vec<KeptNearExportField>,
    tags: Vec<String>,
    favorite: bool,
}

impl KeptNearExportItem {
    fn from_credential(credential: ExportCredential) -> Self {
        let include_source_identities = credential.source_credential_id.is_some();
        let draft = credential.draft;
        Self {
            source_credential_id: credential.source_credential_id,
            status: credential.lifecycle,
            title: draft.title,
            template_id: draft.template_id,
            fields: draft
                .fields
                .into_iter()
                .map(|field| {
                    KeptNearExportField::from_credential_field(field, include_source_identities)
                })
                .collect(),
            tags: draft.tags,
            favorite: draft.favorite,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KeptNearExportField {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    value: KeptNearExportFieldValue,
}

impl KeptNearExportField {
    fn from_credential_field(
        field: crate::credential_model::CredentialField,
        include_source_identity: bool,
    ) -> Self {
        let value = match field.value {
            CredentialFieldValue::Text { text } => KeptNearExportFieldValue::Text { text },
            CredentialFieldValue::Secret {
                secret_field_id,
                kind,
                secret,
            } => KeptNearExportFieldValue::Secret {
                source_secret_field_id: include_source_identity.then_some(secret_field_id),
                kind,
                encoding: "base64",
                value_base64: Base64::encode_string(secret.expose()),
            },
        };
        Self {
            role: field.role,
            label: field.label,
            value,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum KeptNearExportFieldValue {
    Text {
        text: String,
    },
    Secret {
        #[serde(
            rename = "sourceSecretFieldId",
            skip_serializing_if = "Option::is_none"
        )]
        source_secret_field_id: Option<SecretFieldId>,
        kind: crate::credential_model::SecretFieldKind,
        encoding: &'static str,
        #[serde(rename = "valueBase64")]
        value_base64: String,
    },
}

#[derive(Debug, Serialize)]
struct BitwardenExport {
    encrypted: bool,
    folders: Vec<BitwardenFolder>,
    items: Vec<BitwardenItem>,
}

#[derive(Debug, Serialize)]
struct BitwardenFolder {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct BitwardenItem {
    #[serde(rename = "type")]
    item_type: u8,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    favorite: bool,
    #[serde(rename = "folderId", skip_serializing_if = "Option::is_none")]
    folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<BitwardenLogin>,
    #[serde(rename = "secureNote", skip_serializing_if = "Option::is_none")]
    secure_note: Option<BitwardenSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<BitwardenCard>,
}

#[derive(Debug, Serialize)]
struct BitwardenLogin {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
    uris: Vec<BitwardenUri>,
}

#[derive(Debug, Serialize)]
struct BitwardenUri {
    uri: String,
}

#[derive(Debug, Serialize)]
struct BitwardenSecureNote {
    #[serde(rename = "type")]
    note_type: u8,
}

#[derive(Debug, Serialize)]
struct BitwardenCard {
    #[serde(rename = "cardholderName", skip_serializing_if = "Option::is_none")]
    cardholder_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<String>,
    #[serde(rename = "expMonth", skip_serializing_if = "Option::is_none")]
    exp_month: Option<String>,
    #[serde(rename = "expYear", skip_serializing_if = "Option::is_none")]
    exp_year: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::write_json_export;
    use crate::VaultError;

    fn test_root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "keptnear-export-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create test root");
        root
    }

    #[cfg(unix)]
    #[test]
    fn plaintext_export_is_written_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_root("permissions");
        let destination = root.join("export.json");

        write_json_export(
            &destination,
            &serde_json::json!({"secret": "marker"}),
            "test",
        )
        .expect("write export");

        let mode = fs::metadata(&destination)
            .expect("export metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn plaintext_export_rejects_a_symbolic_link_destination() {
        use std::os::unix::fs::symlink;

        let root = test_root("symlink");
        let target = root.join("target.json");
        let destination = root.join("export.json");
        fs::write(&target, b"unchanged").expect("write target");
        symlink(&target, &destination).expect("create symlink");

        let error = write_json_export(
            &destination,
            &serde_json::json!({"secret": "marker"}),
            "test",
        )
        .expect_err("reject symlink");

        assert!(matches!(error, VaultError::InvalidVault { .. }));
        assert_eq!(fs::read(&target).expect("read target"), b"unchanged");
        fs::remove_dir_all(root).expect("remove test root");
    }
}
