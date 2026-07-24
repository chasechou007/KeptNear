use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::error::{VaultError, VaultResult};
use crate::import::BITWARDEN_JSON_FORMAT;
use crate::types::{SecretBytes, SoftwareLicenseItem, VaultItem, VaultItemContent};

/// Export result counts and warnings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExportResult {
    /// Records written to the destination export file.
    pub exported_records: usize,
    /// Records skipped because the export format does not support them.
    pub skipped_records: usize,
    /// Human-readable warnings for the user.
    pub warnings: Vec<String>,
}

pub(crate) fn export_items_to_file(
    destination_path: &Path,
    export_format: &str,
    items: &[VaultItem],
) -> VaultResult<ExportResult> {
    match export_format {
        BITWARDEN_JSON_FORMAT => export_bitwarden_json(destination_path, items),
        other => Err(VaultError::InvalidVault {
            reason: format!("unsupported export format '{other}'"),
        }),
    }
}

fn export_bitwarden_json(
    destination_path: &Path,
    items: &[VaultItem],
) -> VaultResult<ExportResult> {
    let folders = bitwarden_folders(items);
    let folder_ids = folders
        .iter()
        .map(|folder| (folder.name.to_lowercase(), folder.id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut exported_items = Vec::new();
    let mut skipped_records = 0;
    let mut truncated_tags = false;
    let mut exported_software_licenses = false;

    for item in items {
        match bitwarden_item(item, &folder_ids) {
            Some(exported) => {
                if item.draft.tags.len() > 1 {
                    truncated_tags = true;
                }
                if matches!(item.draft.content, VaultItemContent::SoftwareLicense(_)) {
                    exported_software_licenses = true;
                }
                exported_items.push(exported);
            }
            None => skipped_records += 1,
        }
    }

    let export = BitwardenExport {
        encrypted: false,
        folders,
        items: exported_items,
    };
    let bytes = serde_json::to_vec_pretty(&export).map_err(|source| VaultError::InvalidVault {
        reason: format!("serialize Bitwarden JSON failed: {source}"),
    })?;
    fs::write(destination_path, bytes)
        .map_err(|source| VaultError::io("write export file", source))?;

    let mut warnings =
        vec!["Export file contains plaintext secrets; delete or secure it after use.".to_owned()];
    if skipped_records > 0 {
        warnings.push(format!(
            "Skipped {skipped_records} unsupported item(s); alpha export supports login items, secure notes, credit cards, and software licenses."
        ));
    }
    if truncated_tags {
        warnings.push(
            "Bitwarden folders can represent one tag per item; additional tags were not exported."
                .to_owned(),
        );
    }
    if exported_software_licenses {
        warnings.push(
            "Software license items were exported as secure notes because Bitwarden JSON has no native software-license item type."
                .to_owned(),
        );
    }

    Ok(ExportResult {
        exported_records: export.items.len(),
        skipped_records,
        warnings,
    })
}

fn bitwarden_folders(items: &[VaultItem]) -> Vec<BitwardenFolder> {
    let mut tags = BTreeMap::<String, String>::new();
    for item in items {
        if !is_bitwarden_exportable(&item.draft.content) {
            continue;
        }
        for tag in &item.draft.tags {
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

fn bitwarden_item(
    item: &VaultItem,
    folder_ids: &BTreeMap<String, String>,
) -> Option<BitwardenItem> {
    let folder_id = item
        .draft
        .tags
        .first()
        .and_then(|tag| folder_ids.get(&tag.trim().to_lowercase()).cloned());
    match &item.draft.content {
        VaultItemContent::Login(login) => Some(BitwardenItem {
            item_type: 1,
            name: item.draft.title.clone(),
            notes: login.notes.clone(),
            favorite: item.draft.favorite,
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
        }),
        VaultItemContent::SecureNote(note) => Some(BitwardenItem {
            item_type: 2,
            name: item.draft.title.clone(),
            notes: Some(note.body.clone()),
            favorite: item.draft.favorite,
            folder_id,
            login: None,
            secure_note: Some(BitwardenSecureNote { note_type: 0 }),
            card: None,
        }),
        VaultItemContent::SoftwareLicense(license) => Some(BitwardenItem {
            item_type: 2,
            name: item.draft.title.clone(),
            notes: Some(software_license_note(license)),
            favorite: item.draft.favorite,
            folder_id,
            login: None,
            secure_note: Some(BitwardenSecureNote { note_type: 0 }),
            card: None,
        }),
        VaultItemContent::CreditCard(card) => Some(BitwardenItem {
            item_type: 3,
            name: item.draft.title.clone(),
            notes: card.notes.clone(),
            favorite: item.draft.favorite,
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
        }),
    }
}

fn is_bitwarden_exportable(content: &VaultItemContent) -> bool {
    matches!(
        content,
        VaultItemContent::Login(_)
            | VaultItemContent::SecureNote(_)
            | VaultItemContent::SoftwareLicense(_)
            | VaultItemContent::CreditCard(_)
    )
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
