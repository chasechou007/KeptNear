use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use csv::StringRecord;
use serde::Deserialize;

use crate::error::{VaultError, VaultResult};
use crate::totp::normalize_totp_secret;
use crate::types::{
    CreditCardItem, LoginItem, SecretBytes, SecureNoteItem, VaultItemContent, VaultItemDraft,
};

/// First alpha import format: unencrypted Bitwarden JSON export subset.
pub(crate) const BITWARDEN_JSON_FORMAT: &str = "bitwarden-json";
/// Generic plaintext CSV import format for login records.
pub(crate) const GENERIC_LOGIN_CSV_FORMAT: &str = "generic-login-csv";

/// Parsed import data before duplicate handling or commit.
#[derive(Debug, Default)]
pub(crate) struct ParsedImport {
    /// Drafts that can be imported.
    pub drafts: Vec<VaultItemDraft>,
    /// Records skipped during parsing.
    pub skipped_records: usize,
    /// Warnings to show to the user.
    pub warnings: Vec<String>,
}

/// Parses a supported import file.
pub(crate) fn parse_import_file(path: &Path, source_format: &str) -> VaultResult<ParsedImport> {
    match source_format {
        BITWARDEN_JSON_FORMAT => parse_bitwarden_json(path),
        GENERIC_LOGIN_CSV_FORMAT => parse_generic_login_csv(path),
        other => Err(VaultError::InvalidVault {
            reason: format!("unsupported import format '{other}'"),
        }),
    }
}

fn parse_generic_login_csv(path: &Path) -> VaultResult<ParsedImport> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_path(path)
        .map_err(|source| VaultError::InvalidVault {
            reason: format!("open generic login CSV failed: {source}"),
        })?;
    let headers = reader
        .headers()
        .map_err(|source| VaultError::InvalidVault {
            reason: format!("read generic login CSV headers failed: {source}"),
        })?
        .clone();
    let header_map = GenericLoginCsvHeaders::from_record(&headers)?;

    let mut parsed = ParsedImport::default();
    parsed.warnings.push(
        "Source export files may contain plaintext secrets; delete or secure the source file after import."
            .to_owned(),
    );

    for result in reader.records() {
        let record = result.map_err(|source| VaultError::InvalidVault {
            reason: format!("parse generic login CSV row failed: {source}"),
        })?;
        match generic_csv_record_to_draft(&record, &header_map) {
            Some(converted) => {
                parsed.warnings.extend(converted.warnings);
                parsed.drafts.push(converted.draft);
            }
            None => {
                parsed.skipped_records += 1;
                parsed
                    .warnings
                    .push("Skipped CSV login row without a title".to_owned());
            }
        }
    }

    Ok(parsed)
}

#[derive(Debug)]
struct GenericLoginCsvHeaders {
    title: usize,
    username: Option<usize>,
    password: Option<usize>,
    url: Option<usize>,
    notes: Option<usize>,
    tags: Option<usize>,
    group: Option<usize>,
    folder: Option<usize>,
    favorite: Option<usize>,
    totp: Option<usize>,
}

impl GenericLoginCsvHeaders {
    fn from_record(headers: &StringRecord) -> VaultResult<Self> {
        let mut mapped = Self {
            title: usize::MAX,
            username: None,
            password: None,
            url: None,
            notes: None,
            tags: None,
            group: None,
            folder: None,
            favorite: None,
            totp: None,
        };

        for (index, header) in headers.iter().enumerate() {
            match normalize_header(header).as_str() {
                "title" | "name" | "item" | "account" => {
                    if mapped.title == usize::MAX {
                        mapped.title = index;
                    }
                }
                "username" | "user" | "login" | "loginusername" | "email" => {
                    mapped.username.get_or_insert(index);
                }
                "password" | "pass" => {
                    mapped.password.get_or_insert(index);
                }
                "url" | "uri" | "website" | "websites" | "loginurl" | "loginuri" => {
                    mapped.url.get_or_insert(index);
                }
                "notes" | "note" | "comments" | "comment" => {
                    mapped.notes.get_or_insert(index);
                }
                "tags" | "tag" => {
                    mapped.tags.get_or_insert(index);
                }
                "group" => {
                    mapped.group.get_or_insert(index);
                }
                "folder" => {
                    mapped.folder.get_or_insert(index);
                }
                "favorite" | "favourite" | "starred" => {
                    mapped.favorite.get_or_insert(index);
                }
                "totp" | "otp" | "otpauth" | "onetimepassword" => {
                    mapped.totp.get_or_insert(index);
                }
                _ => {}
            }
        }

        if mapped.title == usize::MAX {
            return Err(VaultError::InvalidVault {
                reason: "generic login CSV requires a title or name header".to_owned(),
            });
        }

        Ok(mapped)
    }
}

fn normalize_header(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn generic_csv_record_to_draft(
    record: &StringRecord,
    headers: &GenericLoginCsvHeaders,
) -> Option<ConvertedDraft> {
    let title = csv_value(record, headers.title)?;
    let mut warnings = Vec::new();
    let totp_secret = headers
        .totp
        .and_then(|index| csv_value(record, index))
        .and_then(|totp| match normalize_totp_secret(&totp) {
            Ok(secret) => Some(secret),
            Err(error) => {
                warnings.push(format!(
                    "Skipped invalid TOTP secret for a CSV login row: {error}"
                ));
                None
            }
        });

    Some(ConvertedDraft {
        draft: VaultItemDraft {
            title,
            content: VaultItemContent::Login(LoginItem {
                username: headers.username.and_then(|index| csv_value(record, index)),
                password: headers
                    .password
                    .and_then(|index| csv_value(record, index))
                    .map(|password| SecretBytes::new(password.into_bytes())),
                urls: headers
                    .url
                    .and_then(|index| csv_value(record, index))
                    .into_iter()
                    .collect(),
                notes: headers.notes.and_then(|index| csv_value(record, index)),
                totp_secret,
            }),
            tags: generic_csv_tags(record, headers),
            favorite: headers
                .favorite
                .and_then(|index| csv_value(record, index))
                .map(|value| csv_truthy(&value))
                .unwrap_or(false),
        },
        warnings,
    })
}

fn csv_value(record: &StringRecord, index: usize) -> Option<String> {
    record.get(index).and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn generic_csv_tags(record: &StringRecord, headers: &GenericLoginCsvHeaders) -> Vec<String> {
    let mut tags = Vec::new();
    if let Some(index) = headers.group {
        if let Some(group) = csv_value(record, index) {
            push_unique_tag(&mut tags, group);
        }
    }
    if let Some(index) = headers.folder {
        if let Some(folder) = csv_value(record, index) {
            push_unique_tag(&mut tags, folder);
        }
    }
    if let Some(index) = headers.tags {
        if let Some(value) = csv_value(record, index) {
            for tag in value.split([',', ';', '|']) {
                let trimmed = tag.trim();
                if !trimmed.is_empty() {
                    push_unique_tag(&mut tags, trimmed.to_owned());
                }
            }
        }
    }
    tags
}

fn push_unique_tag(tags: &mut Vec<String>, tag: String) {
    if !tags
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&tag))
    {
        tags.push(tag);
    }
}

fn csv_truthy(value: &str) -> bool {
    matches!(
        normalize_header(value).as_str(),
        "1" | "true" | "yes" | "y" | "favorite" | "favourite" | "starred"
    )
}

fn parse_bitwarden_json(path: &Path) -> VaultResult<ParsedImport> {
    let bytes = fs::read(path).map_err(|source| VaultError::io("read import file", source))?;
    let export: BitwardenExport =
        serde_json::from_slice(&bytes).map_err(|source| VaultError::InvalidVault {
            reason: format!("parse Bitwarden JSON failed: {source}"),
        })?;
    if export.encrypted.unwrap_or(false) {
        return Err(VaultError::InvalidVault {
            reason: "encrypted Bitwarden exports are not supported for local import".to_owned(),
        });
    }

    let folder_names = bitwarden_folder_names(export.folders);
    let mut parsed = ParsedImport::default();
    parsed.warnings.push(
        "Source export files may contain plaintext secrets; delete or secure the source file after import."
            .to_owned(),
    );
    for item in export.items {
        let tags = bitwarden_item_tags(&item, &folder_names);
        match item.item_type {
            1 => {
                if let Some(converted) = bitwarden_login_to_draft(item, tags) {
                    parsed.warnings.extend(converted.warnings);
                    let draft = converted.draft;
                    parsed.drafts.push(draft);
                } else {
                    parsed.skipped_records += 1;
                    parsed
                        .warnings
                        .push("Skipped login item without a name".to_owned());
                }
            }
            2 => {
                if let Some(draft) = bitwarden_note_to_draft(item, tags) {
                    parsed.drafts.push(draft);
                } else {
                    parsed.skipped_records += 1;
                    parsed
                        .warnings
                        .push("Skipped secure note without a name".to_owned());
                }
            }
            3 => {
                if let Some(draft) = bitwarden_card_to_draft(item, tags) {
                    parsed.drafts.push(draft);
                } else {
                    parsed.skipped_records += 1;
                    parsed
                        .warnings
                        .push("Skipped credit card without a name".to_owned());
                }
            }
            unsupported => {
                parsed.skipped_records += 1;
                parsed.warnings.push(format!(
                    "Skipped unsupported Bitwarden item type {unsupported}"
                ));
            }
        }
    }
    Ok(parsed)
}

struct ConvertedDraft {
    draft: VaultItemDraft,
    warnings: Vec<String>,
}

fn bitwarden_login_to_draft(item: BitwardenItem, tags: Vec<String>) -> Option<ConvertedDraft> {
    let title = non_empty(item.name)?;
    let login = item.login.unwrap_or_default();
    let urls = login
        .uris
        .into_iter()
        .filter_map(|uri| non_empty(uri.uri))
        .collect();
    let mut warnings = Vec::new();
    let totp_secret = non_empty(login.totp).and_then(|totp| match normalize_totp_secret(&totp) {
        Ok(secret) => Some(secret),
        Err(error) => {
            warnings.push(format!(
                "Skipped invalid TOTP secret for a login item: {error}"
            ));
            None
        }
    });
    Some(ConvertedDraft {
        draft: VaultItemDraft {
            title,
            content: VaultItemContent::Login(LoginItem {
                username: non_empty(login.username),
                password: non_empty(login.password)
                    .map(|password| SecretBytes::new(password.into_bytes())),
                urls,
                notes: non_empty(item.notes),
                totp_secret,
            }),
            tags,
            favorite: item.favorite.unwrap_or(false),
        },
        warnings,
    })
}

fn bitwarden_note_to_draft(item: BitwardenItem, tags: Vec<String>) -> Option<VaultItemDraft> {
    let title = non_empty(item.name)?;
    Some(VaultItemDraft {
        title,
        content: VaultItemContent::SecureNote(SecureNoteItem {
            body: item.notes.unwrap_or_default(),
        }),
        tags,
        favorite: item.favorite.unwrap_or(false),
    })
}

fn bitwarden_card_to_draft(item: BitwardenItem, tags: Vec<String>) -> Option<VaultItemDraft> {
    let title = non_empty(item.name)?;
    let card = item.card.unwrap_or_default();
    Some(VaultItemDraft {
        title,
        content: VaultItemContent::CreditCard(CreditCardItem {
            cardholder_name: non_empty(card.cardholder_name),
            number: non_empty(card.number).map(|number| SecretBytes::new(number.into_bytes())),
            expiry_month: parse_expiry_month(card.exp_month),
            expiry_year: parse_expiry_year(card.exp_year),
            verification_code: non_empty(card.code).map(|code| SecretBytes::new(code.into_bytes())),
            notes: non_empty(item.notes),
        }),
        tags,
        favorite: item.favorite.unwrap_or(false),
    })
}

fn bitwarden_folder_names(folders: Vec<BitwardenFolder>) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for folder in folders {
        if let (Some(id), Some(name)) = (non_empty(folder.id), non_empty(folder.name)) {
            names.entry(id).or_insert(name);
        }
    }
    names
}

fn bitwarden_item_tags(
    item: &BitwardenItem,
    folder_names: &BTreeMap<String, String>,
) -> Vec<String> {
    item.folder_id
        .as_deref()
        .and_then(|id| folder_names.get(id.trim()))
        .cloned()
        .into_iter()
        .collect()
}

fn parse_expiry_month(value: Option<String>) -> Option<u8> {
    non_empty(value)
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|month| (1..=12).contains(month))
}

fn parse_expiry_year(value: Option<String>) -> Option<u16> {
    non_empty(value).and_then(|value| value.parse::<u16>().ok())
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

#[derive(Debug, Deserialize)]
struct BitwardenExport {
    encrypted: Option<bool>,
    #[serde(default)]
    folders: Vec<BitwardenFolder>,
    #[serde(default)]
    items: Vec<BitwardenItem>,
}

#[derive(Debug, Deserialize)]
struct BitwardenFolder {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitwardenItem {
    #[serde(rename = "type")]
    item_type: u8,
    name: Option<String>,
    notes: Option<String>,
    favorite: Option<bool>,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    login: Option<BitwardenLogin>,
    card: Option<BitwardenCard>,
}

#[derive(Debug, Default, Deserialize)]
struct BitwardenLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<BitwardenUri>,
}

#[derive(Debug, Deserialize)]
struct BitwardenUri {
    uri: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct BitwardenCard {
    #[serde(rename = "cardholderName")]
    cardholder_name: Option<String>,
    number: Option<String>,
    #[serde(rename = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "expYear")]
    exp_year: Option<String>,
    code: Option<String>,
}
