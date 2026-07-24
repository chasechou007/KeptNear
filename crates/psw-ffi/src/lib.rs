use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use psw_core::{
    normalize_totp_secret, ConflictFieldSelection, ConflictId, ConflictMergeRequest,
    CreateVaultRequest, CreditCardItem, ExportItemsRequest, ImportCommitRequest,
    ImportPreviewRequest, ItemId, ItemRevision, ItemStatus, LoginItem, OpenVaultRequest,
    PasswordHealthIssueKind, RejectedSyncRecordFile, RejectedSyncRecordKind,
    RestoreVaultBackupRequest, SearchQuery, SecretBytes, SecureNoteItem, SoftwareLicenseItem,
    UnlockRequest, UnlockedVault, VaultCore, VaultItemContent, VaultItemDraft,
};
use serde::{Deserialize, Serialize};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static SESSIONS: OnceLock<Mutex<BTreeMap<u64, UnlockedVault>>> = OnceLock::new();

/// Executes one JSON command and returns a JSON response string.
///
/// The returned pointer must be released with `psw_string_free`.
///
/// # Safety
///
/// `input_json` must point to a valid NUL-terminated UTF-8 C string for the
/// duration of this call.
#[no_mangle]
pub unsafe extern "C" fn psw_command(input_json: *const c_char) -> *mut c_char {
    let response = command_from_ptr(input_json).and_then(handle_command);
    response_to_ptr(response)
}

/// Frees a string returned by `psw_command`.
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by `psw_command` that
/// has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn psw_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: callers must pass pointers returned by CString::into_raw from this crate.
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

fn command_from_ptr(input_json: *const c_char) -> Result<Command, String> {
    if input_json.is_null() {
        return Err("input JSON pointer is null".to_owned());
    }
    // SAFETY: callers must pass a valid NUL-terminated UTF-8 C string.
    let input = unsafe { CStr::from_ptr(input_json) }
        .to_str()
        .map_err(|error| format!("input JSON is not UTF-8: {error}"))?;
    serde_json::from_str(input).map_err(|error| format!("invalid command JSON: {error}"))
}

fn response_to_ptr(result: Result<ResponsePayload, String>) -> *mut c_char {
    let response = match result {
        Ok(payload) => Response {
            ok: true,
            error: None,
            payload: Some(payload),
        },
        Err(error) => Response {
            ok: false,
            error: Some(error),
            payload: None,
        },
    };
    let json = serde_json::to_string(&response).unwrap_or_else(|error| {
        format!(r#"{{"ok":false,"error":"failed to serialize response: {error}"}}"#)
    });
    CString::new(json)
        .expect("JSON response cannot contain NUL")
        .into_raw()
}

fn handle_command(command: Command) -> Result<ResponsePayload, String> {
    match command {
        Command::Version => Ok(ResponsePayload::Version {
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }),
        Command::CreateVault {
            path,
            display_name,
            password,
        } => {
            let locked = VaultCore::new()
                .create_vault(CreateVaultRequest {
                    path: PathBuf::from(path),
                    display_name,
                    master_password: SecretBytes::new(password.into_bytes()),
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Vault {
                display_name: locked.metadata.display_name,
                vault_format_version: locked.metadata.vault_format_version,
                record_format_version: locked.metadata.record_format_version,
            })
        }
        Command::OpenVault { path } => {
            let locked = VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: PathBuf::from(path),
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Vault {
                display_name: locked.metadata.display_name,
                vault_format_version: locked.metadata.vault_format_version,
                record_format_version: locked.metadata.record_format_version,
            })
        }
        Command::Unlock { path, password } => {
            let unlocked = VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: PathBuf::from(path),
                })
                .map_err(|error| error.to_string())?
                .unlock(UnlockRequest {
                    master_password: SecretBytes::new(password.into_bytes()),
                })
                .map_err(|error| error.to_string())?;
            let items = item_views(&unlocked)?;
            let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
            sessions()
                .lock()
                .expect("session lock")
                .insert(session_id, unlocked);
            Ok(ResponsePayload::Unlocked { session_id, items })
        }
        Command::UnlockWithLocalMaterial {
            path,
            local_material,
        } => {
            let unlocked = VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: PathBuf::from(path),
                })
                .map_err(|error| error.to_string())?
                .unlock_with_local_material(SecretBytes::new(decode_hex(&local_material)?))
                .map_err(|error| error.to_string())?;
            let items = item_views(&unlocked)?;
            let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
            sessions()
                .lock()
                .expect("session lock")
                .insert(session_id, unlocked);
            Ok(ResponsePayload::Unlocked { session_id, items })
        }
        Command::Lock { session_id } => {
            sessions().lock().expect("session lock").remove(&session_id);
            Ok(ResponsePayload::Unit)
        }
        Command::ListItems { session_id } => with_session(session_id, |vault| {
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::PasswordHealth { session_id } => with_session(session_id, |vault| {
            let audit = vault
                .password_health_audit()
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::PasswordHealth {
                checked_login_passwords: audit.checked_login_passwords,
                weak_passwords: audit.weak_passwords,
                reused_passwords: audit.reused_passwords,
                issues: audit
                    .issues
                    .into_iter()
                    .map(PasswordHealthIssueView::from_issue)
                    .collect(),
            })
        }),
        Command::LocalUnlockMaterial { session_id } => with_session(session_id, |vault| {
            let material = vault
                .local_unlock_material()
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Secret {
                value: encode_hex(material.expose()),
            })
        }),
        Command::ChangeMasterPassword {
            session_id,
            current_password,
            new_password,
        } => with_session(session_id, |vault| {
            vault
                .change_master_password(
                    SecretBytes::new(current_password.into_bytes()),
                    SecretBytes::new(new_password.into_bytes()),
                )
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Unit)
        }),
        Command::BackupVault {
            session_id,
            destination_path,
        } => with_session(session_id, |vault| {
            let result = vault
                .backup_to(PathBuf::from(destination_path))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::BackupResult {
                copied_item_files: result.copied_item_files,
                copied_attachment_files: result.copied_attachment_files,
                copied_tombstone_files: result.copied_tombstone_files,
            })
        }),
        Command::RestoreVaultBackup {
            source_path,
            destination_path,
        } => {
            let result = VaultCore::new()
                .restore_vault_backup(RestoreVaultBackupRequest {
                    source_path: PathBuf::from(source_path),
                    destination_path: PathBuf::from(destination_path),
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::RestoreBackupResult {
                copied_item_files: result.copied_item_files,
                copied_attachment_files: result.copied_attachment_files,
                copied_tombstone_files: result.copied_tombstone_files,
            })
        }
        Command::RefreshFromDisk { session_id } => with_session_mut(session_id, |vault| {
            let report = vault
                .refresh_from_disk()
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::SyncRefreshReport {
                loaded_items: report.loaded_items,
                applied_tombstones: report.applied_tombstones,
                detected_conflicts: report.detected_conflicts,
                rejected_records: report.rejected_records,
                rejected_item_records: report.rejected_item_records,
                rejected_tombstone_records: report.rejected_tombstone_records,
                rejected_record_files: rejected_record_file_views(report.rejected_record_files),
                items: item_views(vault)?,
            })
        }),
        Command::QuarantineRejectedRecords { session_id } => {
            with_session_mut(session_id, |vault| {
                let report = vault
                    .quarantine_rejected_records()
                    .map_err(|error| error.to_string())?;
                Ok(ResponsePayload::SyncQuarantineReport {
                    moved_records: report.moved_records,
                    moved_item_records: report.moved_item_records,
                    moved_tombstone_records: report.moved_tombstone_records,
                })
            })
        }
        Command::Search {
            session_id,
            text,
            include_archived,
        } => with_session(session_id, |vault| {
            let items = vault
                .search(SearchQuery {
                    text,
                    include_archived,
                })
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(ItemView::from_summary)
                .collect();
            Ok(ResponsePayload::Items { items })
        }),
        Command::CreateLogin {
            session_id,
            title,
            username,
            password,
            url,
            urls,
            notes,
            totp_secret,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            vault
                .create_item(login_draft(
                    title,
                    username,
                    password.map(|password| SecretBytes::new(password.into_bytes())),
                    login_urls(urls, url),
                    notes,
                    secret_from_optional_string(totp_secret)?,
                    tags,
                    favorite,
                ))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::CreateSecureNote {
            session_id,
            title,
            body,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            vault
                .create_item(secure_note_draft(title, body, tags, favorite))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetSecureNote {
            session_id,
            item_id,
        } => with_session(session_id, |vault| {
            let item = vault
                .get_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            let VaultItemContent::SecureNote(note) = item.draft.content else {
                return Err("item is not a secure note".to_owned());
            };
            Ok(ResponsePayload::SecureNoteDetail {
                id: item.id.0,
                revision: item.revision.0,
                title: item.draft.title,
                body: note.body,
                favorite: item.draft.favorite,
                tags: item.draft.tags,
                status: item_status_label(item.status),
            })
        }),
        Command::UpdateSecureNote {
            session_id,
            item_id,
            expected_revision,
            title,
            body,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            let item_id = ItemId(item_id);
            let existing = vault
                .get_item(&item_id)
                .map_err(|error| error.to_string())?;
            if !matches!(&existing.draft.content, VaultItemContent::SecureNote(_)) {
                return Err("item is not a secure note".to_owned());
            }
            let draft = secure_note_draft(
                title,
                body,
                tags,
                favorite.unwrap_or(existing.draft.favorite),
            );
            update_item_with_optional_expected_revision(vault, &item_id, expected_revision, draft)?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::CreateCreditCard {
            session_id,
            title,
            cardholder_name,
            number,
            expiry_month,
            expiry_year,
            verification_code,
            notes,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            vault
                .create_item(credit_card_draft(
                    title,
                    cardholder_name,
                    secret_bytes_from_optional_string(number),
                    expiry_month,
                    expiry_year,
                    secret_bytes_from_optional_string(verification_code),
                    notes,
                    tags,
                    favorite,
                ))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetCreditCard {
            session_id,
            item_id,
        } => with_session(session_id, |vault| {
            let item = vault
                .get_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            let VaultItemContent::CreditCard(card) = item.draft.content else {
                return Err("item is not a credit card".to_owned());
            };
            Ok(ResponsePayload::CreditCardDetail {
                id: item.id.0,
                revision: item.revision.0,
                title: item.draft.title,
                cardholder_name: card.cardholder_name,
                expiry_month: card.expiry_month,
                expiry_year: card.expiry_year,
                notes: card.notes,
                favorite: item.draft.favorite,
                tags: item.draft.tags,
                status: item_status_label(item.status),
            })
        }),
        Command::UpdateCreditCard {
            session_id,
            item_id,
            expected_revision,
            title,
            cardholder_name,
            number,
            expiry_month,
            expiry_year,
            verification_code,
            notes,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            let item_id = ItemId(item_id);
            let existing = vault
                .get_item(&item_id)
                .map_err(|error| error.to_string())?;
            let VaultItemContent::CreditCard(existing_card) = existing.draft.content else {
                return Err("item is not a credit card".to_owned());
            };
            let number = match number {
                Some(value) => secret_bytes_from_string(value),
                None => existing_card.number,
            };
            let verification_code = match verification_code {
                Some(value) => secret_bytes_from_string(value),
                None => existing_card.verification_code,
            };
            let draft = credit_card_draft(
                title,
                cardholder_name,
                number,
                expiry_month,
                expiry_year,
                verification_code,
                notes,
                tags,
                favorite.unwrap_or(existing.draft.favorite),
            );
            update_item_with_optional_expected_revision(vault, &item_id, expected_revision, draft)?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetCreditCardField {
            session_id,
            item_id,
            field,
        } => with_session(session_id, |vault| {
            let item = vault
                .get_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            let VaultItemContent::CreditCard(card) = item.draft.content else {
                return Err("item is not a credit card".to_owned());
            };
            let value = match field.as_str() {
                "number" => card.number.map(secret_to_string).unwrap_or_default(),
                "verification_code" | "verificationCode" => card
                    .verification_code
                    .map(secret_to_string)
                    .unwrap_or_default(),
                other => return Err(format!("unsupported credit card field '{other}'")),
            };
            Ok(ResponsePayload::Secret { value })
        }),
        Command::CreateSoftwareLicense {
            session_id,
            title,
            product,
            license_key,
            licensed_to,
            notes,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            vault
                .create_item(software_license_draft(
                    title,
                    product,
                    secret_bytes_from_optional_string(license_key),
                    licensed_to,
                    notes,
                    tags,
                    favorite,
                ))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetSoftwareLicense {
            session_id,
            item_id,
        } => with_session(session_id, |vault| {
            let item = vault
                .get_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            let VaultItemContent::SoftwareLicense(license) = item.draft.content else {
                return Err("item is not a software license".to_owned());
            };
            Ok(ResponsePayload::SoftwareLicenseDetail {
                id: item.id.0,
                revision: item.revision.0,
                title: item.draft.title,
                product: license.product,
                licensed_to: license.licensed_to,
                notes: license.notes,
                favorite: item.draft.favorite,
                tags: item.draft.tags,
                status: item_status_label(item.status),
            })
        }),
        Command::UpdateSoftwareLicense {
            session_id,
            item_id,
            expected_revision,
            title,
            product,
            license_key,
            licensed_to,
            notes,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            let item_id = ItemId(item_id);
            let existing = vault
                .get_item(&item_id)
                .map_err(|error| error.to_string())?;
            let VaultItemContent::SoftwareLicense(existing_license) = existing.draft.content else {
                return Err("item is not a software license".to_owned());
            };
            let license_key = match license_key {
                Some(value) => secret_bytes_from_string(value),
                None => existing_license.license_key,
            };
            let draft = software_license_draft(
                title,
                product,
                license_key,
                licensed_to,
                notes,
                tags,
                favorite.unwrap_or(existing.draft.favorite),
            );
            update_item_with_optional_expected_revision(vault, &item_id, expected_revision, draft)?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetSoftwareLicenseField {
            session_id,
            item_id,
            field,
        } => with_session(session_id, |vault| {
            let item = vault
                .get_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            let VaultItemContent::SoftwareLicense(license) = item.draft.content else {
                return Err("item is not a software license".to_owned());
            };
            let value = match field.as_str() {
                "license_key" | "licenseKey" => license
                    .license_key
                    .map(secret_to_string)
                    .unwrap_or_default(),
                other => return Err(format!("unsupported software license field '{other}'")),
            };
            Ok(ResponsePayload::Secret { value })
        }),
        Command::GetLogin {
            session_id,
            item_id,
        } => with_session(session_id, |vault| {
            let item = vault
                .get_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            let VaultItemContent::Login(login) = item.draft.content else {
                return Err("item is not a login".to_owned());
            };
            let urls = login.urls;
            Ok(ResponsePayload::LoginDetail {
                id: item.id.0,
                revision: item.revision.0,
                title: item.draft.title,
                username: login.username,
                url: urls.first().cloned(),
                urls,
                notes: login.notes,
                totp_secret: login.totp_secret.map(secret_to_string),
                favorite: item.draft.favorite,
                tags: item.draft.tags,
                status: item_status_label(item.status),
            })
        }),
        Command::UpdateLogin {
            session_id,
            item_id,
            expected_revision,
            title,
            username,
            password,
            url,
            urls,
            notes,
            totp_secret,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            let item_id = ItemId(item_id);
            let existing = vault
                .get_item(&item_id)
                .map_err(|error| error.to_string())?;
            let VaultItemContent::Login(existing_login) = existing.draft.content else {
                return Err("item is not a login".to_owned());
            };
            let password = match password {
                Some(password) => secret_bytes_from_string(password),
                None => existing_login.password,
            };
            let totp_secret = match totp_secret {
                Some(value) => secret_from_string(value)?,
                None => existing_login.totp_secret,
            };
            let draft = login_draft(
                title,
                username,
                password,
                login_urls(urls, url),
                notes,
                totp_secret,
                tags,
                favorite.unwrap_or(existing.draft.favorite),
            );
            update_item_with_optional_expected_revision(vault, &item_id, expected_revision, draft)?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetLoginField {
            session_id,
            item_id,
            field,
        } => with_session(session_id, |vault| {
            let item = vault
                .get_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            let VaultItemContent::Login(login) = item.draft.content else {
                return Err("item is not a login".to_owned());
            };
            let value = match field.as_str() {
                "username" => login.username.unwrap_or_default(),
                "password" => login
                    .password
                    .map(|secret| String::from_utf8_lossy(secret.expose()).to_string())
                    .unwrap_or_default(),
                other => return Err(format!("unsupported login field '{other}'")),
            };
            Ok(ResponsePayload::Secret { value })
        }),
        Command::ArchiveItem {
            session_id,
            item_id,
            expected_revision,
        } => with_session_mut(session_id, |vault| {
            let item_id = ItemId(item_id);
            match expected_revision {
                Some(expected_revision) => vault
                    .archive_item_with_expected_revision(&item_id, &ItemRevision(expected_revision))
                    .map_err(|error| error.to_string())?,
                None => vault
                    .archive_item(&item_id)
                    .map_err(|error| error.to_string())?,
            };
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::RestoreItem {
            session_id,
            item_id,
        } => with_session_mut(session_id, |vault| {
            vault
                .restore_item(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::DeleteItem {
            session_id,
            item_id,
            expected_revision,
        } => with_session_mut(session_id, |vault| {
            let item_id = ItemId(item_id);
            match expected_revision {
                Some(expected_revision) => vault
                    .delete_item_with_expected_revision(&item_id, &ItemRevision(expected_revision))
                    .map_err(|error| error.to_string())?,
                None => vault
                    .delete_item(&item_id)
                    .map_err(|error| error.to_string())?,
            };
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::ResolveConflict {
            session_id,
            conflict_id,
        } => with_session_mut(session_id, |vault| {
            vault
                .resolve_conflict(&ConflictId(conflict_id))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetConflictCandidates {
            session_id,
            conflict_id,
        } => with_session(session_id, |vault| {
            let candidates = vault
                .conflict_candidates(&ConflictId(conflict_id))
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(ConflictCandidateView::from_summary)
                .collect();
            Ok(ResponsePayload::ConflictCandidates { candidates })
        }),
        Command::ResolveConflictCandidate {
            session_id,
            conflict_id,
            revision,
        } => with_session_mut(session_id, |vault| {
            vault
                .resolve_conflict_candidate(&ConflictId(conflict_id), &ItemRevision(revision))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::ResolveConflictMerge {
            session_id,
            conflict_id,
            base_revision,
            field_selections,
        } => with_session_mut(session_id, |vault| {
            vault
                .resolve_conflict_merge(ConflictMergeRequest {
                    conflict_id: ConflictId(conflict_id),
                    base_revision: ItemRevision(base_revision),
                    field_selections: field_selections
                        .into_iter()
                        .map(|selection| ConflictFieldSelection {
                            field_label: selection.field_label,
                            revision: ItemRevision(selection.revision),
                        })
                        .collect(),
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::SetFavorite {
            session_id,
            item_id,
            expected_revision,
            favorite,
        } => with_session_mut(session_id, |vault| {
            let item_id = ItemId(item_id);
            match expected_revision {
                Some(expected_revision) => vault
                    .set_favorite_with_expected_revision(
                        &item_id,
                        &ItemRevision(expected_revision),
                        favorite,
                    )
                    .map_err(|error| error.to_string())?,
                None => vault
                    .set_favorite(&item_id, favorite)
                    .map_err(|error| error.to_string())?,
            };
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::TotpCode {
            session_id,
            item_id,
        } => with_session(session_id, |vault| {
            let code = vault
                .totp_code(&ItemId(item_id))
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Totp {
                code: code.code,
                remaining_seconds: code.remaining_seconds,
            })
        }),
        Command::PreviewImport {
            session_id,
            source_path,
            source_format,
        } => with_session(session_id, |vault| {
            let preview = vault
                .preview_import(ImportPreviewRequest {
                    source_path: PathBuf::from(source_path),
                    source_format,
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::ImportPreview {
                importable_records: preview.importable_records,
                skipped_records: preview.skipped_records,
                duplicate_records: preview.duplicate_records,
                warnings: preview.warnings,
            })
        }),
        Command::CommitImport {
            session_id,
            source_path,
            source_format,
            keep_duplicates,
        } => with_session_mut(session_id, |vault| {
            let preview = vault
                .commit_import(ImportCommitRequest {
                    source_path: PathBuf::from(source_path),
                    source_format,
                    keep_duplicates,
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::ImportPreview {
                importable_records: preview.importable_records,
                skipped_records: preview.skipped_records,
                duplicate_records: preview.duplicate_records,
                warnings: preview.warnings,
            })
        }),
        Command::ExportItems {
            session_id,
            destination_path,
            export_format,
        } => with_session(session_id, |vault| {
            let result = vault
                .export_items(ExportItemsRequest {
                    destination_path: PathBuf::from(destination_path),
                    export_format,
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::ExportResult {
                exported_records: result.exported_records,
                skipped_records: result.skipped_records,
                warnings: result.warnings,
            })
        }),
    }
}

fn sessions() -> &'static Mutex<BTreeMap<u64, UnlockedVault>> {
    SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn with_session<F>(session_id: u64, f: F) -> Result<ResponsePayload, String>
where
    F: FnOnce(&UnlockedVault) -> Result<ResponsePayload, String>,
{
    let sessions = sessions().lock().expect("session lock");
    let vault = sessions
        .get(&session_id)
        .ok_or_else(|| format!("unknown vault session {session_id}"))?;
    f(vault)
}

fn with_session_mut<F>(session_id: u64, f: F) -> Result<ResponsePayload, String>
where
    F: FnOnce(&mut UnlockedVault) -> Result<ResponsePayload, String>,
{
    let mut sessions = sessions().lock().expect("session lock");
    let vault = sessions
        .get_mut(&session_id)
        .ok_or_else(|| format!("unknown vault session {session_id}"))?;
    f(vault)
}

#[allow(clippy::too_many_arguments)]
fn login_draft(
    title: String,
    username: Option<String>,
    password: Option<SecretBytes>,
    urls: Vec<String>,
    notes: Option<String>,
    totp_secret: Option<SecretBytes>,
    tags: Vec<String>,
    favorite: bool,
) -> VaultItemDraft {
    VaultItemDraft {
        title,
        content: VaultItemContent::Login(LoginItem {
            username,
            password,
            urls,
            notes,
            totp_secret,
        }),
        tags,
        favorite,
    }
}

fn login_urls(urls: Option<Vec<String>>, legacy_url: Option<String>) -> Vec<String> {
    urls.unwrap_or_else(|| legacy_url.into_iter().collect())
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn secure_note_draft(
    title: String,
    body: String,
    tags: Vec<String>,
    favorite: bool,
) -> VaultItemDraft {
    VaultItemDraft {
        title,
        content: VaultItemContent::SecureNote(SecureNoteItem { body }),
        tags,
        favorite,
    }
}

#[allow(clippy::too_many_arguments)]
fn credit_card_draft(
    title: String,
    cardholder_name: Option<String>,
    number: Option<SecretBytes>,
    expiry_month: Option<u8>,
    expiry_year: Option<u16>,
    verification_code: Option<SecretBytes>,
    notes: Option<String>,
    tags: Vec<String>,
    favorite: bool,
) -> VaultItemDraft {
    VaultItemDraft {
        title,
        content: VaultItemContent::CreditCard(CreditCardItem {
            cardholder_name,
            number,
            expiry_month,
            expiry_year,
            verification_code,
            notes,
        }),
        tags,
        favorite,
    }
}

fn software_license_draft(
    title: String,
    product: Option<String>,
    license_key: Option<SecretBytes>,
    licensed_to: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    favorite: bool,
) -> VaultItemDraft {
    VaultItemDraft {
        title,
        content: VaultItemContent::SoftwareLicense(SoftwareLicenseItem {
            product,
            license_key,
            licensed_to,
            notes,
        }),
        tags,
        favorite,
    }
}

fn secret_bytes_from_optional_string(value: Option<String>) -> Option<SecretBytes> {
    value.and_then(secret_bytes_from_string)
}

fn secret_bytes_from_string(value: String) -> Option<SecretBytes> {
    (!value.trim().is_empty()).then(|| SecretBytes::new(value.into_bytes()))
}

fn secret_from_optional_string(value: Option<String>) -> Result<Option<SecretBytes>, String> {
    match value {
        Some(value) => secret_from_string(value),
        None => Ok(None),
    }
}

fn secret_from_string(value: String) -> Result<Option<SecretBytes>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    normalize_totp_secret(&value)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn secret_to_string(secret: SecretBytes) -> String {
    String::from_utf8_lossy(secret.expose()).to_string()
}

fn item_views(vault: &UnlockedVault) -> Result<Vec<ItemView>, String> {
    vault
        .list_items()
        .map_err(|error| error.to_string())
        .map(|items| items.into_iter().map(ItemView::from_summary).collect())
}

fn rejected_record_file_views(files: Vec<RejectedSyncRecordFile>) -> Vec<RejectedRecordFileView> {
    files
        .into_iter()
        .map(|file| RejectedRecordFileView {
            kind: match file.kind {
                RejectedSyncRecordKind::Item => "item",
                RejectedSyncRecordKind::Tombstone => "tombstone",
            },
            file_name: file.file_name,
        })
        .collect()
}

fn update_item_with_optional_expected_revision(
    vault: &mut UnlockedVault,
    item_id: &ItemId,
    expected_revision: Option<String>,
    draft: VaultItemDraft,
) -> Result<(), String> {
    match expected_revision {
        Some(expected_revision) => vault
            .update_item_with_expected_revision(item_id, &ItemRevision(expected_revision), draft)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        None => vault
            .update_item(item_id, draft)
            .map(|_| ())
            .map_err(|error| error.to_string()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
enum Command {
    Version,
    CreateVault {
        path: String,
        display_name: Option<String>,
        password: String,
    },
    OpenVault {
        path: String,
    },
    Unlock {
        path: String,
        password: String,
    },
    UnlockWithLocalMaterial {
        path: String,
        local_material: String,
    },
    Lock {
        session_id: u64,
    },
    ListItems {
        session_id: u64,
    },
    PasswordHealth {
        session_id: u64,
    },
    LocalUnlockMaterial {
        session_id: u64,
    },
    ChangeMasterPassword {
        session_id: u64,
        current_password: String,
        new_password: String,
    },
    BackupVault {
        session_id: u64,
        destination_path: String,
    },
    RestoreVaultBackup {
        source_path: String,
        destination_path: String,
    },
    RefreshFromDisk {
        session_id: u64,
    },
    QuarantineRejectedRecords {
        session_id: u64,
    },
    Search {
        session_id: u64,
        text: String,
        include_archived: bool,
    },
    CreateLogin {
        session_id: u64,
        title: String,
        username: Option<String>,
        password: Option<String>,
        url: Option<String>,
        #[serde(default)]
        urls: Option<Vec<String>>,
        notes: Option<String>,
        totp_secret: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        favorite: bool,
    },
    CreateSecureNote {
        session_id: u64,
        title: String,
        body: String,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        favorite: bool,
    },
    GetSecureNote {
        session_id: u64,
        item_id: String,
    },
    UpdateSecureNote {
        session_id: u64,
        item_id: String,
        #[serde(default)]
        expected_revision: Option<String>,
        title: String,
        body: String,
        #[serde(default)]
        tags: Vec<String>,
        favorite: Option<bool>,
    },
    CreateCreditCard {
        session_id: u64,
        title: String,
        cardholder_name: Option<String>,
        number: Option<String>,
        expiry_month: Option<u8>,
        expiry_year: Option<u16>,
        verification_code: Option<String>,
        notes: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        favorite: bool,
    },
    GetCreditCard {
        session_id: u64,
        item_id: String,
    },
    UpdateCreditCard {
        session_id: u64,
        item_id: String,
        #[serde(default)]
        expected_revision: Option<String>,
        title: String,
        cardholder_name: Option<String>,
        number: Option<String>,
        expiry_month: Option<u8>,
        expiry_year: Option<u16>,
        verification_code: Option<String>,
        notes: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        favorite: Option<bool>,
    },
    GetCreditCardField {
        session_id: u64,
        item_id: String,
        field: String,
    },
    CreateSoftwareLicense {
        session_id: u64,
        title: String,
        product: Option<String>,
        license_key: Option<String>,
        licensed_to: Option<String>,
        notes: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        favorite: bool,
    },
    GetSoftwareLicense {
        session_id: u64,
        item_id: String,
    },
    UpdateSoftwareLicense {
        session_id: u64,
        item_id: String,
        #[serde(default)]
        expected_revision: Option<String>,
        title: String,
        product: Option<String>,
        license_key: Option<String>,
        licensed_to: Option<String>,
        notes: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        favorite: Option<bool>,
    },
    GetSoftwareLicenseField {
        session_id: u64,
        item_id: String,
        field: String,
    },
    GetLogin {
        session_id: u64,
        item_id: String,
    },
    UpdateLogin {
        session_id: u64,
        item_id: String,
        #[serde(default)]
        expected_revision: Option<String>,
        title: String,
        username: Option<String>,
        password: Option<String>,
        url: Option<String>,
        #[serde(default)]
        urls: Option<Vec<String>>,
        notes: Option<String>,
        totp_secret: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        favorite: Option<bool>,
    },
    GetLoginField {
        session_id: u64,
        item_id: String,
        field: String,
    },
    ArchiveItem {
        session_id: u64,
        item_id: String,
        #[serde(default)]
        expected_revision: Option<String>,
    },
    RestoreItem {
        session_id: u64,
        item_id: String,
    },
    DeleteItem {
        session_id: u64,
        item_id: String,
        #[serde(default)]
        expected_revision: Option<String>,
    },
    ResolveConflict {
        session_id: u64,
        conflict_id: String,
    },
    GetConflictCandidates {
        session_id: u64,
        conflict_id: String,
    },
    ResolveConflictCandidate {
        session_id: u64,
        conflict_id: String,
        revision: String,
    },
    ResolveConflictMerge {
        session_id: u64,
        conflict_id: String,
        base_revision: String,
        #[serde(default)]
        field_selections: Vec<ConflictMergeFieldSelectionCommand>,
    },
    SetFavorite {
        session_id: u64,
        item_id: String,
        #[serde(default)]
        expected_revision: Option<String>,
        favorite: bool,
    },
    TotpCode {
        session_id: u64,
        item_id: String,
    },
    PreviewImport {
        session_id: u64,
        source_path: String,
        source_format: String,
    },
    CommitImport {
        session_id: u64,
        source_path: String,
        source_format: String,
        keep_duplicates: bool,
    },
    ExportItems {
        session_id: u64,
        destination_path: String,
        export_format: String,
    },
}

#[derive(Debug, Deserialize)]
struct ConflictMergeFieldSelectionCommand {
    field_label: String,
    revision: String,
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    error: Option<String>,
    payload: Option<ResponsePayload>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ResponsePayload {
    Unit,
    Version {
        version: String,
    },
    Vault {
        display_name: Option<String>,
        vault_format_version: u32,
        record_format_version: u32,
    },
    Unlocked {
        session_id: u64,
        items: Vec<ItemView>,
    },
    Items {
        items: Vec<ItemView>,
    },
    SyncRefreshReport {
        loaded_items: usize,
        applied_tombstones: usize,
        detected_conflicts: usize,
        rejected_records: usize,
        rejected_item_records: usize,
        rejected_tombstone_records: usize,
        rejected_record_files: Vec<RejectedRecordFileView>,
        items: Vec<ItemView>,
    },
    SyncQuarantineReport {
        moved_records: usize,
        moved_item_records: usize,
        moved_tombstone_records: usize,
    },
    PasswordHealth {
        checked_login_passwords: usize,
        weak_passwords: usize,
        reused_passwords: usize,
        issues: Vec<PasswordHealthIssueView>,
    },
    BackupResult {
        copied_item_files: usize,
        copied_attachment_files: usize,
        copied_tombstone_files: usize,
    },
    RestoreBackupResult {
        copied_item_files: usize,
        copied_attachment_files: usize,
        copied_tombstone_files: usize,
    },
    LoginDetail {
        id: String,
        revision: String,
        title: String,
        username: Option<String>,
        url: Option<String>,
        urls: Vec<String>,
        notes: Option<String>,
        totp_secret: Option<String>,
        favorite: bool,
        tags: Vec<String>,
        status: String,
    },
    SecureNoteDetail {
        id: String,
        revision: String,
        title: String,
        body: String,
        favorite: bool,
        tags: Vec<String>,
        status: String,
    },
    CreditCardDetail {
        id: String,
        revision: String,
        title: String,
        cardholder_name: Option<String>,
        expiry_month: Option<u8>,
        expiry_year: Option<u16>,
        notes: Option<String>,
        favorite: bool,
        tags: Vec<String>,
        status: String,
    },
    SoftwareLicenseDetail {
        id: String,
        revision: String,
        title: String,
        product: Option<String>,
        licensed_to: Option<String>,
        notes: Option<String>,
        favorite: bool,
        tags: Vec<String>,
        status: String,
    },
    Secret {
        value: String,
    },
    Totp {
        code: String,
        remaining_seconds: u64,
    },
    ImportPreview {
        importable_records: usize,
        skipped_records: usize,
        duplicate_records: usize,
        warnings: Vec<String>,
    },
    ExportResult {
        exported_records: usize,
        skipped_records: usize,
        warnings: Vec<String>,
    },
    ConflictCandidates {
        candidates: Vec<ConflictCandidateView>,
    },
}

#[derive(Debug, Serialize)]
struct PasswordHealthIssueView {
    item_id: String,
    title: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reuse_group_size: Option<usize>,
}

impl PasswordHealthIssueView {
    fn from_issue(issue: psw_core::PasswordHealthIssue) -> Self {
        Self {
            item_id: issue.item_id.0,
            title: issue.title,
            kind: match issue.kind {
                PasswordHealthIssueKind::WeakPassword => "weakPassword",
                PasswordHealthIssueKind::ReusedPassword => "reusedPassword",
            },
            reuse_group_size: issue.reuse_group_size,
        }
    }
}

#[derive(Debug, Serialize)]
struct RejectedRecordFileView {
    kind: &'static str,
    file_name: String,
}

#[derive(Debug, Serialize)]
struct ItemView {
    id: String,
    revision: String,
    title: String,
    item_type: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflict_id: Option<String>,
    favorite: bool,
    tags: Vec<String>,
}

impl ItemView {
    fn from_summary(summary: psw_core::ItemSummary) -> Self {
        let conflict_id = match &summary.status {
            ItemStatus::Conflicted(conflict_id) => Some(conflict_id.0.clone()),
            _ => None,
        };
        Self {
            id: summary.id.0,
            revision: summary.revision.0,
            title: summary.title,
            item_type: summary.item_type.as_search_label().to_owned(),
            status: item_status_label(summary.status),
            conflict_id,
            favorite: summary.favorite,
            tags: summary.tags,
        }
    }
}

#[derive(Debug, Serialize)]
struct ConflictCandidateView {
    item_id: String,
    revision: String,
    title: String,
    item_type: String,
    status: String,
    favorite: bool,
    tags: Vec<String>,
    comparison_fields: Vec<ConflictCandidateFieldView>,
    changed_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConflictCandidateFieldView {
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    redacted: bool,
}

impl ConflictCandidateView {
    fn from_summary(summary: psw_core::ConflictCandidateSummary) -> Self {
        Self {
            item_id: summary.item_id.0,
            revision: summary.revision.0,
            title: summary.title,
            item_type: summary.item_type,
            status: summary.status,
            favorite: summary.favorite,
            tags: summary.tags,
            comparison_fields: summary
                .comparison_fields
                .into_iter()
                .map(ConflictCandidateFieldView::from_field)
                .collect(),
            changed_fields: summary.changed_fields,
            preview: summary.preview,
        }
    }
}

impl ConflictCandidateFieldView {
    fn from_field(field: psw_core::ConflictCandidateField) -> Self {
        Self {
            label: field.label,
            value: field.value,
            redacted: field.redacted,
        }
    }
}

fn item_status_label(status: ItemStatus) -> String {
    match status {
        ItemStatus::Active => "active".to_owned(),
        ItemStatus::Archived => "archived".to_owned(),
        ItemStatus::Deleted => "deleted".to_owned(),
        ItemStatus::Conflicted(_) => "conflicted".to_owned(),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return Err("local unlock material must have even-length hex encoding".to_owned());
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("local unlock material must be hex encoded".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::{json, Value};

    #[test]
    fn ffi_version_command_returns_json() {
        let input = CString::new(r#"{"command":"version"}"#).expect("cstring");
        let response_ptr = unsafe { crate::psw_command(input.as_ptr()) };
        assert!(!response_ptr.is_null());
        let response = unsafe { CStr::from_ptr(response_ptr) }
            .to_string_lossy()
            .to_string();
        unsafe { crate::psw_string_free(response_ptr) };

        assert!(response.contains(r#""ok":true"#));
        assert!(response.contains(r#""version""#));
    }

    #[test]
    fn ffi_item_view_includes_conflict_identifier_for_conflicted_items() {
        let view = super::ItemView::from_summary(psw_core::ItemSummary {
            id: psw_core::ItemId("item_1".to_owned()),
            revision: psw_core::ItemRevision("rev_1".to_owned()),
            title: "Example".to_owned(),
            item_type: psw_core::ItemType::Login,
            status: psw_core::ItemStatus::Conflicted(psw_core::ConflictId(
                "conflict_item_1".to_owned(),
            )),
            tags: vec!["sync".to_owned()],
            favorite: false,
        });

        let serialized = serde_json::to_value(view).expect("serialize item view");

        assert_eq!(serialized["status"], "conflicted");
        assert_eq!(serialized["revision"], "rev_1");
        assert_eq!(serialized["conflict_id"], "conflict_item_1");
    }

    #[test]
    fn ffi_conflict_candidate_view_serializes_revision_and_preview() {
        let view = super::ConflictCandidateView::from_summary(psw_core::ConflictCandidateSummary {
            item_id: psw_core::ItemId("item_1".to_owned()),
            revision: psw_core::ItemRevision("rev_left".to_owned()),
            title: "Left".to_owned(),
            item_type: "login".to_owned(),
            status: "active".to_owned(),
            favorite: true,
            tags: vec!["sync".to_owned()],
            comparison_fields: vec![
                psw_core::ConflictCandidateField {
                    label: "username".to_owned(),
                    value: Some("alice".to_owned()),
                    redacted: false,
                },
                psw_core::ConflictCandidateField {
                    label: "password".to_owned(),
                    value: None,
                    redacted: true,
                },
            ],
            changed_fields: vec!["username".to_owned(), "password".to_owned()],
            preview: Some("username: alice".to_owned()),
        });

        let serialized = serde_json::to_value(view).expect("serialize candidate view");

        assert_eq!(serialized["item_id"], "item_1");
        assert_eq!(serialized["revision"], "rev_left");
        assert_eq!(serialized["title"], "Left");
        assert_eq!(serialized["comparison_fields"][0]["label"], "username");
        assert_eq!(serialized["comparison_fields"][0]["value"], "alice");
        assert_eq!(serialized["comparison_fields"][0]["redacted"], false);
        assert_eq!(serialized["comparison_fields"][1]["label"], "password");
        assert!(serialized["comparison_fields"][1]["value"].is_null());
        assert_eq!(serialized["comparison_fields"][1]["redacted"], true);
        assert_eq!(serialized["changed_fields"][0], "username");
        assert_eq!(serialized["changed_fields"][1], "password");
        assert_eq!(serialized["preview"], "username: alice");
    }

    #[test]
    fn ffi_login_workflow_preserves_password_and_tags() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let created = command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "tags": ["work", "finance"],
            "favorite": true
        }));
        let item_id = created["payload"]["items"][0]["id"]
            .as_str()
            .expect("item id")
            .to_owned();

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Edited",
            "tags": ["finance"],
            "favorite": true
        }));

        let detail = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(detail["payload"]["tags"], json!(["finance"]));
        assert_eq!(detail["payload"]["favorite"], true);

        let secret = command(json!({
            "command": "getLoginField",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "field": "password"
        }));
        assert_eq!(secret["payload"]["value"], "secret");

        let search = command(json!({
            "command": "search",
            "session_id": session_id,
            "text": "finance",
            "include_archived": false
        }));
        assert_eq!(search["payload"]["items"][0]["title"], "Example Edited");

        let active_restore = command_result(json!({
            "command": "restoreItem",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(active_restore["ok"], false);
        assert!(active_restore["error"]
            .as_str()
            .expect("error")
            .contains("only archived items can be restored"));

        let archived = command(json!({
            "command": "archiveItem",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert!(archived["payload"]["items"]
            .as_array()
            .expect("items")
            .is_empty());

        let restored = command(json!({
            "command": "restoreItem",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(restored["payload"]["items"][0]["title"], "Example Edited");
        assert_eq!(restored["payload"]["items"][0]["status"], "active");
        assert_eq!(restored["payload"]["items"][0]["tags"], json!(["finance"]));

        let refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": session_id
        }));
        assert_eq!(refresh["payload"]["type"], "syncRefreshReport");
        assert!(
            refresh["payload"]["loaded_items"]
                .as_u64()
                .expect("loaded items")
                >= 2
        );
        assert_eq!(refresh["payload"]["rejected_records"], 0);
        assert_eq!(refresh["payload"]["rejected_item_records"], 0);
        assert_eq!(refresh["payload"]["rejected_tombstone_records"], 0);
        assert_eq!(refresh["payload"]["rejected_record_files"], json!([]));
        assert_eq!(refresh["payload"]["items"][0]["title"], "Example Edited");

        fs::write(
            vault_path.join("items").join("bad_sync_record.enc"),
            b"not json",
        )
        .expect("write bad synced record");
        let rejected_refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": session_id
        }));
        assert_eq!(rejected_refresh["payload"]["type"], "syncRefreshReport");
        assert_eq!(rejected_refresh["payload"]["rejected_records"], 1);
        assert_eq!(rejected_refresh["payload"]["rejected_item_records"], 1);
        assert_eq!(rejected_refresh["payload"]["rejected_tombstone_records"], 0);
        assert_eq!(
            rejected_refresh["payload"]["rejected_record_files"],
            json!([{ "kind": "item", "file_name": "bad_sync_record.enc" }])
        );
        assert_eq!(
            rejected_refresh["payload"]["items"][0]["title"],
            "Example Edited"
        );

        let material = command(json!({
            "command": "localUnlockMaterial",
            "session_id": session_id
        }));
        let local_material = material["payload"]["value"]
            .as_str()
            .expect("local unlock material")
            .to_owned();
        assert_eq!(local_material.len(), 64);
        assert_ne!(local_material, "correct horse");
        assert!(vault_path.join("local_unlock.enc").is_file());

        command(json!({
            "command": "lock",
            "session_id": session_id
        }));
        let local_unlocked = command(json!({
            "command": "unlockWithLocalMaterial",
            "path": path,
            "local_material": local_material
        }));
        assert_eq!(
            local_unlocked["payload"]["items"][0]["title"],
            "Example Edited"
        );

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_login_workflow_preserves_multiple_urls_and_legacy_url() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-url-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI URL Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let legacy_created = command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Legacy URL",
            "username": "legacy",
            "password": "legacy-secret",
            "url": "https://legacy.example.com"
        }));
        let legacy_item_id = legacy_created["payload"]["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["title"] == "Legacy URL")
            .and_then(|item| item["id"].as_str())
            .expect("legacy item id")
            .to_owned();

        let legacy_detail = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": legacy_item_id.clone()
        }));
        assert_eq!(
            legacy_detail["payload"]["url"],
            "https://legacy.example.com"
        );
        assert_eq!(
            legacy_detail["payload"]["urls"],
            json!(["https://legacy.example.com"])
        );

        let modern_created = command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Modern URLs",
            "username": "modern",
            "password": "modern-secret",
            "url": "https://ignored.example.com",
            "urls": [
                "ftp://not-opened.example.com",
                " https://app.example.com/login ",
                "",
                "https://backup.example.com"
            ]
        }));
        let modern_item_id = modern_created["payload"]["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["title"] == "Modern URLs")
            .and_then(|item| item["id"].as_str())
            .expect("modern item id")
            .to_owned();

        let modern_detail = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": modern_item_id.clone()
        }));
        assert_eq!(
            modern_detail["payload"]["url"],
            "ftp://not-opened.example.com"
        );
        assert_eq!(
            modern_detail["payload"]["urls"],
            json!([
                "ftp://not-opened.example.com",
                "https://app.example.com/login",
                "https://backup.example.com"
            ])
        );

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": modern_item_id.clone(),
            "title": "Modern URLs",
            "username": "modern",
            "url": "https://ignored-update.example.com",
            "urls": [
                "https://primary.example.com",
                "https://secondary.example.com"
            ],
            "notes": "Edited"
        }));
        let updated_modern_detail = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": modern_item_id.clone()
        }));
        assert_eq!(
            updated_modern_detail["payload"]["urls"],
            json!([
                "https://primary.example.com",
                "https://secondary.example.com"
            ])
        );
        let modern_secret = command(json!({
            "command": "getLoginField",
            "session_id": session_id,
            "item_id": modern_item_id,
            "field": "password"
        }));
        assert_eq!(modern_secret["payload"]["value"], "modern-secret");

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": legacy_item_id.clone(),
            "title": "Legacy URL Edited",
            "username": "legacy",
            "url": "https://legacy-edited.example.com"
        }));
        let updated_legacy_detail = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": legacy_item_id
        }));
        assert_eq!(
            updated_legacy_detail["payload"]["urls"],
            json!(["https://legacy-edited.example.com"])
        );

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_backup_vault_copies_encrypted_portable_structure() {
        let root_path = std::env::temp_dir().join(format!(
            "psw-ffi-backup-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let vault_path = root_path.join("Source.pswvault");
        let backup_path = root_path.join("Backup.pswvault");
        let path = vault_path.to_string_lossy().to_string();
        let backup = backup_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Backup Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "tags": ["work"],
            "favorite": false
        }));
        fs::write(
            vault_path.join("attachments").join("receipt.bin"),
            b"attachment",
        )
        .expect("write attachment");
        command(json!({
            "command": "localUnlockMaterial",
            "session_id": session_id
        }));
        assert!(vault_path.join("local_unlock.enc").is_file());

        let result = command(json!({
            "command": "backupVault",
            "session_id": session_id,
            "destination_path": backup
        }));

        assert_eq!(result["payload"]["type"], "backupResult");
        assert_eq!(result["payload"]["copied_item_files"], 1);
        assert_eq!(result["payload"]["copied_attachment_files"], 1);
        assert_eq!(result["payload"]["copied_tombstone_files"], 0);
        assert!(backup_path.join("vault.json").is_file());
        assert!(backup_path.join("keys.enc").is_file());
        assert!(backup_path.join("items").is_dir());
        assert!(backup_path
            .join("attachments")
            .join("receipt.bin")
            .is_file());
        assert!(backup_path.join("tombstones").is_dir());
        assert!(!backup_path.join("local_unlock.enc").exists());

        command(json!({
            "command": "openVault",
            "path": backup_path.to_string_lossy().to_string()
        }));
        let backup_unlocked = command(json!({
            "command": "unlock",
            "path": backup_path.to_string_lossy().to_string(),
            "password": "correct horse"
        }));
        assert_eq!(backup_unlocked["payload"]["items"][0]["title"], "Example");

        let duplicate_destination = command_result(json!({
            "command": "backupVault",
            "session_id": session_id,
            "destination_path": backup_path.to_string_lossy().to_string()
        }));
        assert_eq!(duplicate_destination["ok"], false);
        assert!(duplicate_destination["error"]
            .as_str()
            .expect("error")
            .contains("not empty"));

        let _ = fs::remove_dir_all(root_path);
    }

    #[test]
    fn ffi_restore_vault_backup_copies_encrypted_portable_structure() {
        let root_path = std::env::temp_dir().join(format!(
            "psw-ffi-restore-backup-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let source_path = root_path.join("Backup.pswvault");
        let restored_path = root_path.join("Restored.pswvault");
        let source = source_path.to_string_lossy().to_string();
        let restored = restored_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": source,
            "display_name": "FFI Restore Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": source,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "tags": ["work"],
            "favorite": false
        }));
        fs::write(
            source_path.join("attachments").join("receipt.bin"),
            b"attachment",
        )
        .expect("write attachment");
        command(json!({
            "command": "localUnlockMaterial",
            "session_id": session_id
        }));
        assert!(source_path.join("local_unlock.enc").is_file());

        let result = command(json!({
            "command": "restoreVaultBackup",
            "source_path": source,
            "destination_path": restored
        }));

        assert_eq!(result["payload"]["type"], "restoreBackupResult");
        assert_eq!(result["payload"]["copied_item_files"], 1);
        assert_eq!(result["payload"]["copied_attachment_files"], 1);
        assert_eq!(result["payload"]["copied_tombstone_files"], 0);
        assert!(restored_path.join("vault.json").is_file());
        assert!(restored_path.join("keys.enc").is_file());
        assert!(restored_path.join("items").is_dir());
        assert!(restored_path
            .join("attachments")
            .join("receipt.bin")
            .is_file());
        assert!(restored_path.join("tombstones").is_dir());
        assert!(!restored_path.join("local_unlock.enc").exists());

        command(json!({
            "command": "openVault",
            "path": restored_path.to_string_lossy().to_string()
        }));
        let restored_unlocked = command(json!({
            "command": "unlock",
            "path": restored_path.to_string_lossy().to_string(),
            "password": "correct horse"
        }));
        assert_eq!(restored_unlocked["payload"]["items"][0]["title"], "Example");

        let duplicate_destination = command_result(json!({
            "command": "restoreVaultBackup",
            "source_path": source_path.to_string_lossy().to_string(),
            "destination_path": restored_path.to_string_lossy().to_string()
        }));
        assert_eq!(duplicate_destination["ok"], false);
        assert!(duplicate_destination["error"]
            .as_str()
            .expect("error")
            .contains("not empty"));

        let _ = fs::remove_dir_all(root_path);
    }

    #[test]
    fn ffi_update_login_can_clear_and_replace_password() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-password-clear-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Password Clear Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let created = command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "initial-secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "tags": ["work"],
            "favorite": false
        }));
        let item_id = created["payload"]["items"][0]["id"]
            .as_str()
            .expect("item id")
            .to_owned();

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Edited",
            "tags": ["work"],
            "favorite": false
        }));
        let preserved = command(json!({
            "command": "getLoginField",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "field": "password"
        }));
        assert_eq!(preserved["payload"]["value"], "initial-secret");

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "password": "",
            "url": "https://example.com",
            "notes": "Edited",
            "tags": ["work"],
            "favorite": false
        }));
        let cleared = command(json!({
            "command": "getLoginField",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "field": "password"
        }));
        assert_eq!(cleared["payload"]["value"], "");

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "password": "replacement-secret",
            "url": "https://example.com",
            "notes": "Edited",
            "tags": ["work"],
            "favorite": false
        }));
        let replaced = command(json!({
            "command": "getLoginField",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "field": "password"
        }));
        assert_eq!(replaced["payload"]["value"], "replacement-secret");

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_update_login_rejects_stale_expected_revision() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-stale-update-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Stale Update",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let created = command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "tags": ["work"],
            "favorite": false
        }));
        let item_id = created["payload"]["items"][0]["id"]
            .as_str()
            .expect("item id")
            .to_owned();
        let stale_revision = created["payload"]["items"][0]["revision"]
            .as_str()
            .expect("created revision")
            .to_owned();

        let remote = command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Remote Edit",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Remote",
            "tags": ["work"],
            "favorite": false
        }));
        let current_revision = remote["payload"]["items"][0]["revision"]
            .as_str()
            .expect("current revision")
            .to_owned();

        let stale = command_result(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "expected_revision": stale_revision,
            "title": "Stale Edit",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Stale",
            "tags": ["personal"],
            "favorite": true
        }));
        assert_eq!(stale["ok"], false);
        assert!(stale["error"]
            .as_str()
            .expect("error")
            .contains("item changed on disk"));

        let detail = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(detail["payload"]["revision"], current_revision);
        assert_eq!(detail["payload"]["title"], "Remote Edit");
        assert_eq!(detail["payload"]["tags"], json!(["work"]));
        assert_eq!(detail["payload"]["favorite"], false);

        let current = command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "expected_revision": current_revision,
            "title": "Current Edit",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Current",
            "tags": ["personal"],
            "favorite": true
        }));
        assert_eq!(current["payload"]["items"][0]["title"], "Current Edit");
        assert_eq!(current["payload"]["items"][0]["tags"], json!(["personal"]));
        assert_eq!(current["payload"]["items"][0]["favorite"], true);

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_login_totp_secret_can_be_saved_updated_and_cleared() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-totp-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI TOTP Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let invalid_create = command_result(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Invalid TOTP",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "totp_secret": "otpauth://totp/Example?issuer=Example"
        }));
        assert_eq!(invalid_create["ok"], false);
        assert!(invalid_create["error"]
            .as_str()
            .expect("error")
            .contains("missing a TOTP secret"));
        let empty_items = command(json!({
            "command": "listItems",
            "session_id": session_id
        }));
        assert!(empty_items["payload"]["items"]
            .as_array()
            .expect("items")
            .is_empty());

        let created = command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "totp_secret": "otpauth://totp/Example:alice?secret=GEZD%20GNBV-GY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example",
            "tags": ["work"],
            "favorite": true
        }));
        assert!(created["payload"]["items"][0]["totp_secret"].is_null());
        let item_id = created["payload"]["items"][0]["id"]
            .as_str()
            .expect("item id")
            .to_owned();

        let detail = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(
            detail["payload"]["totp_secret"],
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );

        let code = command(json!({
            "command": "totpCode",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(code["payload"]["code"].as_str().expect("code").len(), 6);

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Edited",
            "tags": ["work"],
            "favorite": true
        }));
        let preserved = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(
            preserved["payload"]["totp_secret"],
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Edited",
            "totp_secret": "otpauth://totp/Example:alice?issuer=Example&secret=JBSWY3DPEHPK3PXP",
            "tags": ["work"],
            "favorite": true
        }));
        let updated = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(updated["payload"]["totp_secret"], "JBSWY3DPEHPK3PXP");

        let invalid_update = command_result(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Edited",
            "totp_secret": "otpauth://totp/Example?secret=JBSW%ZZDPEHPK3PXP",
            "tags": ["work"],
            "favorite": true
        }));
        assert_eq!(invalid_update["ok"], false);
        assert!(invalid_update["error"]
            .as_str()
            .expect("error")
            .contains("invalid percent encoding"));
        let still_updated = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(still_updated["payload"]["totp_secret"], "JBSWY3DPEHPK3PXP");

        command(json!({
            "command": "updateLogin",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Example Edited",
            "username": "alice",
            "url": "https://example.com",
            "notes": "Edited",
            "totp_secret": "",
            "tags": ["work"],
            "favorite": true
        }));
        let cleared = command(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert!(cleared["payload"]["totp_secret"].is_null());

        let missing_code = command_result(json!({
            "command": "totpCode",
            "session_id": session_id,
            "item_id": item_id
        }));
        assert_eq!(missing_code["ok"], false);
        assert!(missing_code["error"]
            .as_str()
            .expect("error")
            .contains("login item has no TOTP secret"));

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_quarantine_rejected_records_moves_bad_records_and_refreshes_clean() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-quarantine-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Quarantine",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Trusted",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login"
        }));

        fs::write(vault_path.join("items").join("bad_item.enc"), b"not json")
            .expect("write bad item record");
        fs::write(
            vault_path.join("tombstones").join("bad_tombstone.enc"),
            b"not json",
        )
        .expect("write bad tombstone record");

        let rejected_refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": session_id
        }));
        assert_eq!(rejected_refresh["payload"]["rejected_records"], 2);
        assert_eq!(rejected_refresh["payload"]["rejected_item_records"], 1);
        assert_eq!(rejected_refresh["payload"]["rejected_tombstone_records"], 1);
        assert_eq!(
            rejected_refresh["payload"]["rejected_record_files"],
            json!([
                { "kind": "item", "file_name": "bad_item.enc" },
                { "kind": "tombstone", "file_name": "bad_tombstone.enc" }
            ])
        );

        let quarantined = command(json!({
            "command": "quarantineRejectedRecords",
            "session_id": session_id
        }));
        assert_eq!(quarantined["payload"]["type"], "syncQuarantineReport");
        assert_eq!(quarantined["payload"]["moved_records"], 2);
        assert_eq!(quarantined["payload"]["moved_item_records"], 1);
        assert_eq!(quarantined["payload"]["moved_tombstone_records"], 1);

        let clean_refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": session_id
        }));
        assert_eq!(clean_refresh["payload"]["rejected_records"], 0);
        assert_eq!(clean_refresh["payload"]["rejected_item_records"], 0);
        assert_eq!(clean_refresh["payload"]["rejected_tombstone_records"], 0);
        assert_eq!(clean_refresh["payload"]["rejected_record_files"], json!([]));
        assert_eq!(clean_refresh["payload"]["items"][0]["title"], "Trusted");

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_secure_note_workflow_round_trips_body_and_tags() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-note-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Note Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let created = command(json!({
            "command": "createSecureNote",
            "session_id": session_id,
            "title": "Recovery Notes",
            "body": "offline backup codes",
            "tags": ["recovery", "personal"],
            "favorite": true
        }));
        assert_eq!(created["payload"]["items"][0]["item_type"], "secure note");
        let item_id = created["payload"]["items"][0]["id"]
            .as_str()
            .expect("item id")
            .to_owned();

        let detail = command(json!({
            "command": "getSecureNote",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(detail["payload"]["type"], "secureNoteDetail");
        assert_eq!(detail["payload"]["title"], "Recovery Notes");
        assert_eq!(detail["payload"]["body"], "offline backup codes");
        assert_eq!(detail["payload"]["tags"], json!(["recovery", "personal"]));
        assert_eq!(detail["payload"]["favorite"], true);

        let login_detail = command_result(json!({
            "command": "getLogin",
            "session_id": session_id,
            "item_id": item_id.clone()
        }));
        assert_eq!(login_detail["ok"], false);
        assert!(login_detail["error"]
            .as_str()
            .expect("error")
            .contains("item is not a login"));

        command(json!({
            "command": "updateSecureNote",
            "session_id": session_id,
            "item_id": item_id.clone(),
            "title": "Recovery Notes Edited",
            "body": "rotated backup codes",
            "tags": ["recovery"],
            "favorite": false
        }));

        let updated = command(json!({
            "command": "getSecureNote",
            "session_id": session_id,
            "item_id": item_id
        }));
        assert_eq!(updated["payload"]["title"], "Recovery Notes Edited");
        assert_eq!(updated["payload"]["body"], "rotated backup codes");
        assert_eq!(updated["payload"]["tags"], json!(["recovery"]));
        assert_eq!(updated["payload"]["favorite"], false);

        let search = command(json!({
            "command": "search",
            "session_id": session_id,
            "text": "rotated backup",
            "include_archived": false
        }));
        assert_eq!(
            search["payload"]["items"][0]["title"],
            "Recovery Notes Edited"
        );

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_credit_card_and_software_license_workflows_round_trip_and_export() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-structured-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();
        let destination_path = vault_path.with_extension("json");
        let destination = destination_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Structured Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let created_card = command(json!({
            "command": "createCreditCard",
            "session_id": session_id,
            "title": "Travel Card",
            "cardholder_name": "Alice Example",
            "number": "4111111111111111",
            "expiry_month": 4,
            "expiry_year": 2030,
            "verification_code": "123",
            "notes": "Travel rewards card",
            "tags": ["finance"],
            "favorite": true
        }));
        assert_eq!(
            created_card["payload"]["items"][0]["item_type"],
            "credit card"
        );
        let card_id = created_card["payload"]["items"][0]["id"]
            .as_str()
            .expect("card id")
            .to_owned();

        let card_detail = command(json!({
            "command": "getCreditCard",
            "session_id": session_id,
            "item_id": card_id.clone()
        }));
        assert_eq!(card_detail["payload"]["type"], "creditCardDetail");
        assert_eq!(card_detail["payload"]["title"], "Travel Card");
        assert_eq!(card_detail["payload"]["cardholder_name"], "Alice Example");
        assert!(card_detail["payload"]["number"].is_null());
        assert_eq!(card_detail["payload"]["expiry_month"], 4);
        assert_eq!(card_detail["payload"]["expiry_year"], 2030);

        let card_number = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "number"
        }));
        assert_eq!(card_number["payload"]["value"], "4111111111111111");
        let card_code = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "verification_code"
        }));
        assert_eq!(card_code["payload"]["value"], "123");

        command(json!({
            "command": "updateCreditCard",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "title": "Travel Card Edited",
            "cardholder_name": "Alice B. Example",
            "expiry_month": 5,
            "expiry_year": 2031,
            "notes": "Updated card notes",
            "tags": ["finance", "travel"],
            "favorite": false
        }));
        let updated_card = command(json!({
            "command": "getCreditCard",
            "session_id": session_id,
            "item_id": card_id.clone()
        }));
        assert_eq!(updated_card["payload"]["title"], "Travel Card Edited");
        assert_eq!(updated_card["payload"]["favorite"], false);
        let preserved_card_number = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "number"
        }));
        assert_eq!(
            preserved_card_number["payload"]["value"],
            "4111111111111111"
        );
        let preserved_card_code = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "verification_code"
        }));
        assert_eq!(preserved_card_code["payload"]["value"], "123");

        command(json!({
            "command": "updateCreditCard",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "title": "Travel Card Cleared",
            "cardholder_name": "Alice B. Example",
            "number": "",
            "expiry_month": 5,
            "expiry_year": 2031,
            "verification_code": "",
            "notes": "Cleared card secrets",
            "tags": ["finance", "travel"],
            "favorite": false
        }));
        let cleared_card_number = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "number"
        }));
        assert_eq!(cleared_card_number["payload"]["value"], "");
        let cleared_card_code = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "verification_code"
        }));
        assert_eq!(cleared_card_code["payload"]["value"], "");

        command(json!({
            "command": "updateCreditCard",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "title": "Travel Card Replaced",
            "cardholder_name": "Alice B. Example",
            "number": "5555555555554444",
            "expiry_month": 5,
            "expiry_year": 2031,
            "verification_code": "987",
            "notes": "Replaced card secrets",
            "tags": ["finance", "travel"],
            "favorite": false
        }));
        let replaced_card_number = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "number"
        }));
        assert_eq!(replaced_card_number["payload"]["value"], "5555555555554444");
        let replaced_card_code = command(json!({
            "command": "getCreditCardField",
            "session_id": session_id,
            "item_id": card_id.clone(),
            "field": "verificationCode"
        }));
        assert_eq!(replaced_card_code["payload"]["value"], "987");

        let created_license = command(json!({
            "command": "createSoftwareLicense",
            "session_id": session_id,
            "title": "Editor License",
            "product": "TextPro",
            "license_key": "AAAA-BBBB-CCCC",
            "licensed_to": "alice@example.com",
            "notes": "Renewal due Q4",
            "tags": ["software"],
            "favorite": true
        }));
        let license_id = created_license["payload"]["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["item_type"] == "software license")
            .expect("license item")["id"]
            .as_str()
            .expect("license id")
            .to_owned();

        let license_detail = command(json!({
            "command": "getSoftwareLicense",
            "session_id": session_id,
            "item_id": license_id.clone()
        }));
        assert_eq!(license_detail["payload"]["type"], "softwareLicenseDetail");
        assert_eq!(license_detail["payload"]["title"], "Editor License");
        assert_eq!(license_detail["payload"]["product"], "TextPro");
        assert!(license_detail["payload"]["license_key"].is_null());

        let license_key = command(json!({
            "command": "getSoftwareLicenseField",
            "session_id": session_id,
            "item_id": license_id.clone(),
            "field": "license_key"
        }));
        assert_eq!(license_key["payload"]["value"], "AAAA-BBBB-CCCC");

        command(json!({
            "command": "updateSoftwareLicense",
            "session_id": session_id,
            "item_id": license_id.clone(),
            "title": "Editor License Edited",
            "product": "TextPro",
            "licensed_to": "alice@example.com",
            "notes": "Updated renewal note",
            "tags": ["software", "tools"],
            "favorite": false
        }));
        let preserved_license_key = command(json!({
            "command": "getSoftwareLicenseField",
            "session_id": session_id,
            "item_id": license_id.clone(),
            "field": "licenseKey"
        }));
        assert_eq!(preserved_license_key["payload"]["value"], "AAAA-BBBB-CCCC");

        command(json!({
            "command": "updateSoftwareLicense",
            "session_id": session_id,
            "item_id": license_id.clone(),
            "title": "Editor License Cleared",
            "product": "TextPro",
            "license_key": "",
            "licensed_to": "alice@example.com",
            "notes": "Cleared license key",
            "tags": ["software", "tools"],
            "favorite": false
        }));
        let cleared_license_key = command(json!({
            "command": "getSoftwareLicenseField",
            "session_id": session_id,
            "item_id": license_id.clone(),
            "field": "license_key"
        }));
        assert_eq!(cleared_license_key["payload"]["value"], "");

        command(json!({
            "command": "updateSoftwareLicense",
            "session_id": session_id,
            "item_id": license_id.clone(),
            "title": "Editor License Replaced",
            "product": "TextPro",
            "license_key": "DDDD-EEEE-FFFF",
            "licensed_to": "alice@example.com",
            "notes": "Replaced license key",
            "tags": ["software", "tools"],
            "favorite": false
        }));
        let replaced_license_key = command(json!({
            "command": "getSoftwareLicenseField",
            "session_id": session_id,
            "item_id": license_id.clone(),
            "field": "licenseKey"
        }));
        assert_eq!(replaced_license_key["payload"]["value"], "DDDD-EEEE-FFFF");

        let exported = command(json!({
            "command": "exportItems",
            "session_id": session_id,
            "destination_path": destination,
            "export_format": "bitwarden-json"
        }));
        assert_eq!(exported["payload"]["exported_records"], 2);
        assert_eq!(exported["payload"]["skipped_records"], 0);
        assert!(exported["payload"]["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|warning| warning
                .as_str()
                .expect("warning")
                .contains("Software license items were exported as secure notes")));
        let exported_json: Value =
            serde_json::from_slice(&fs::read(&destination_path).expect("read export"))
                .expect("parse export");
        assert!(exported_json["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|item| item["type"] == 3
                && item["card"]["number"] == "5555555555554444"
                && item["card"]["code"] == "987"));
        assert!(exported_json["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|item| item["type"] == 2
                && item["notes"]
                    .as_str()
                    .expect("notes")
                    .contains("License key: DDDD-EEEE-FFFF")));

        let _ = fs::remove_dir_all(vault_path);
        let _ = fs::remove_file(destination_path);
    }

    #[test]
    fn ffi_export_items_writes_bitwarden_json_and_warnings() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-export-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();
        let destination_path = vault_path.with_extension("json");
        let destination = destination_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Export Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login",
            "tags": ["work"],
            "favorite": true
        }));
        command(json!({
            "command": "createSecureNote",
            "session_id": session_id,
            "title": "Recovery Notes",
            "body": "offline backup codes",
            "tags": ["personal"],
            "favorite": false
        }));

        let exported = command(json!({
            "command": "exportItems",
            "session_id": session_id,
            "destination_path": destination,
            "export_format": "bitwarden-json"
        }));

        assert_eq!(exported["payload"]["type"], "exportResult");
        assert_eq!(exported["payload"]["exported_records"], 2);
        assert_eq!(exported["payload"]["skipped_records"], 0);
        assert!(exported["payload"]["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|warning| warning
                .as_str()
                .expect("warning")
                .contains("plaintext secrets")));

        let export_json: Value =
            serde_json::from_slice(&fs::read(&destination_path).expect("read exported JSON"))
                .expect("parse exported JSON");
        assert_eq!(export_json["encrypted"], false);
        assert_eq!(export_json["items"].as_array().expect("items").len(), 2);
        assert!(export_json["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|item| item["name"] == "Example" && item["type"] == 1));
        assert!(export_json["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|item| item["name"] == "Recovery Notes" && item["type"] == 2));

        let _ = fs::remove_file(destination_path);
        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_password_health_returns_non_secret_metadata() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-health-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Health Test",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Email",
            "username": "alice@example.com",
            "password": "EmailPassword2026!",
            "url": "https://email.example.com",
            "notes": "Primary mailbox",
            "tags": [],
            "favorite": false
        }));
        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Bank",
            "username": "alice",
            "password": "alice-Strong-2026!",
            "url": "https://bank.example.com",
            "notes": "Checking account",
            "tags": [],
            "favorite": false
        }));
        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Work",
            "username": "work@example.com",
            "password": "Shared-Password-123!",
            "url": "https://work.example.com",
            "notes": "Work login",
            "tags": [],
            "favorite": false
        }));
        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Forum",
            "username": "forum@example.com",
            "password": "Shared-Password-123!",
            "url": "https://forum.example.com",
            "notes": "Forum login",
            "tags": [],
            "favorite": false
        }));
        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Unique",
            "username": "unique@example.com",
            "password": "Distinct-Strong-987!",
            "url": "https://unique.example.com",
            "notes": "Unique login",
            "tags": [],
            "favorite": false
        }));
        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "No Password",
            "username": "nopassword@example.com",
            "url": "https://nopassword.example.com",
            "notes": "Missing password",
            "tags": [],
            "favorite": false
        }));
        command(json!({
            "command": "createSecureNote",
            "session_id": session_id,
            "title": "Recovery Notes",
            "body": "offline backup codes",
            "tags": [],
            "favorite": false
        }));

        let health = command(json!({
            "command": "passwordHealth",
            "session_id": session_id
        }));

        assert_eq!(health["payload"]["type"], "passwordHealth");
        assert_eq!(health["payload"]["checked_login_passwords"], 5);
        assert_eq!(health["payload"]["weak_passwords"], 2);
        assert_eq!(health["payload"]["reused_passwords"], 2);
        let issues = health["payload"]["issues"].as_array().expect("issues");
        assert_eq!(issues.len(), 4);
        assert!(issues
            .iter()
            .any(|issue| issue["title"] == "Email" && issue["kind"] == "weakPassword"));
        assert!(issues
            .iter()
            .any(|issue| issue["title"] == "Bank" && issue["kind"] == "weakPassword"));
        assert!(issues.iter().any(|issue| issue["title"] == "Work"
            && issue["kind"] == "reusedPassword"
            && issue["reuse_group_size"] == 2));
        assert!(issues.iter().any(|issue| issue["title"] == "Forum"
            && issue["kind"] == "reusedPassword"
            && issue["reuse_group_size"] == 2));
        assert!(!issues.iter().any(|issue| issue["title"] == "Unique"));
        assert!(!issues.iter().any(|issue| issue["title"] == "No Password"));
        assert!(!issues
            .iter()
            .any(|issue| issue["title"] == "Recovery Notes"));

        let response_text = serde_json::to_string(&health).expect("serialize health response");
        for forbidden in [
            "EmailPassword2026!",
            "alice-Strong-2026!",
            "Shared-Password-123!",
            "Distinct-Strong-987!",
            "alice@example.com",
            "work@example.com",
            "https://email.example.com",
            "Primary mailbox",
            "offline backup codes",
        ] {
            assert!(
                !response_text.contains(forbidden),
                "FFI password health response leaked secret or non-result metadata: {forbidden}"
            );
        }

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_resolve_conflict_rejects_unknown_conflict_id() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-resolve-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Resolve",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        let resolved = command_result(json!({
            "command": "resolveConflict",
            "session_id": session_id,
            "conflict_id": "conflict_missing"
        }));

        assert_eq!(resolved["ok"], false);
        assert!(resolved["error"]
            .as_str()
            .expect("error")
            .contains("item 'conflict_missing' was not found"));

        let candidates = command_result(json!({
            "command": "getConflictCandidates",
            "session_id": session_id,
            "conflict_id": "conflict_missing"
        }));
        assert_eq!(candidates["ok"], false);
        assert!(candidates["error"]
            .as_str()
            .expect("error")
            .contains("item 'conflict_missing' was not found"));

        let selected = command_result(json!({
            "command": "resolveConflictCandidate",
            "session_id": session_id,
            "conflict_id": "conflict_missing",
            "revision": "rev_missing"
        }));
        assert_eq!(selected["ok"], false);
        assert!(selected["error"]
            .as_str()
            .expect("error")
            .contains("item 'conflict_missing' was not found"));

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_resolve_conflict_merge_combines_safe_fields() {
        let root = std::env::temp_dir().join(format!(
            "psw-ffi-merge-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let vault_path = root.join("Primary.pswvault");
        let clone_path = root.join("Clone.pswvault");
        let path = vault_path.to_string_lossy().to_string();
        let clone = clone_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Merge",
            "password": "correct horse"
        }));
        let primary = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let primary_session = primary["payload"]["session_id"]
            .as_u64()
            .expect("primary session id");

        let created = command(json!({
            "command": "createLogin",
            "session_id": primary_session,
            "title": "Base",
            "username": "base@example.com",
            "password": "base-secret",
            "url": "https://base.example.com",
            "notes": "base notes",
            "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "tags": ["base"],
            "favorite": false
        }));
        let item = &created["payload"]["items"][0];
        let item_id = item["id"].as_str().expect("item id").to_owned();
        let base_revision = item["revision"].as_str().expect("base revision").to_owned();

        copy_dir_all(&vault_path, &clone_path);
        let clone_unlocked = command(json!({
            "command": "unlock",
            "path": clone,
            "password": "correct horse"
        }));
        let clone_session = clone_unlocked["payload"]["session_id"]
            .as_u64()
            .expect("clone session id");

        let left = command(json!({
            "command": "updateLogin",
            "session_id": primary_session,
            "item_id": item_id,
            "expected_revision": base_revision,
            "title": "Left",
            "username": "left@example.com",
            "password": "left-secret",
            "url": "https://left.example.com",
            "notes": "left notes",
            "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "tags": ["left"],
            "favorite": false
        }));
        let left_revision = left["payload"]["items"][0]["revision"]
            .as_str()
            .expect("left revision")
            .to_owned();

        let right = command(json!({
            "command": "updateLogin",
            "session_id": clone_session,
            "item_id": item_id,
            "expected_revision": base_revision,
            "title": "Right",
            "username": "right@example.com",
            "password": "right-secret",
            "url": "https://right.example.com",
            "notes": "right notes",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "tags": ["right", "merged"],
            "favorite": true
        }));
        let right_revision = right["payload"]["items"][0]["revision"]
            .as_str()
            .expect("right revision")
            .to_owned();

        copy_item_records(&clone_path, &vault_path);
        let refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": primary_session
        }));
        assert_eq!(refresh["payload"]["detected_conflicts"], 1);
        let conflict_id = refresh["payload"]["items"][0]["conflict_id"]
            .as_str()
            .expect("conflict id")
            .to_owned();

        let merged = command(json!({
            "command": "resolveConflictMerge",
            "session_id": primary_session,
            "conflict_id": conflict_id,
            "base_revision": left_revision,
            "field_selections": [
                { "field_label": "title", "revision": right_revision },
                { "field_label": "favorite", "revision": right_revision },
                { "field_label": "tags", "revision": right_revision },
                { "field_label": "username", "revision": right_revision },
                { "field_label": "URLs", "revision": right_revision }
            ]
        }));
        assert_eq!(merged["payload"]["items"][0]["title"], "Right");
        assert_eq!(merged["payload"]["items"][0]["favorite"], true);
        assert_eq!(
            merged["payload"]["items"][0]["tags"],
            json!(["right", "merged"])
        );

        let detail = command(json!({
            "command": "getLogin",
            "session_id": primary_session,
            "item_id": item_id
        }));
        assert_eq!(detail["payload"]["title"], "Right");
        assert_eq!(detail["payload"]["username"], "right@example.com");
        assert_eq!(detail["payload"]["url"], "https://right.example.com");
        let password = command(json!({
            "command": "getLoginField",
            "session_id": primary_session,
            "item_id": item_id,
            "field": "password"
        }));
        assert_eq!(password["payload"]["value"], "left-secret");

        let refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": primary_session
        }));
        assert_eq!(refresh["payload"]["detected_conflicts"], 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ffi_change_master_password_rotates_unlock_password() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-rotate-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Rotate",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        command(json!({
            "command": "createLogin",
            "session_id": session_id,
            "title": "Example",
            "username": "alice",
            "password": "secret",
            "url": "https://example.com",
            "notes": "Primary login"
        }));
        command(json!({
            "command": "changeMasterPassword",
            "session_id": session_id,
            "current_password": "correct horse",
            "new_password": "new correct horse"
        }));

        let old_unlock = command_result(json!({
            "command": "unlock",
            "path": path,
            "password": "correct horse"
        }));
        assert_eq!(old_unlock["ok"], false);
        assert!(old_unlock["error"]
            .as_str()
            .expect("error")
            .contains("invalid vault credentials"));

        let new_unlock = command(json!({
            "command": "unlock",
            "path": path,
            "password": "new correct horse"
        }));
        assert_eq!(new_unlock["payload"]["items"][0]["title"], "Example");

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_accepts_short_non_empty_master_password_policy_inputs() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-short-password-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        let empty_create = command_result(json!({
            "command": "createVault",
            "path": path,
            "display_name": "Empty Password",
            "password": ""
        }));
        assert_eq!(empty_create["ok"], false);
        assert!(empty_create["error"]
            .as_str()
            .expect("error")
            .contains("master password is required"));
        assert!(!vault_path.exists());

        command(json!({
            "command": "createVault",
            "path": path.clone(),
            "display_name": "Short Password",
            "password": "short"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path.clone(),
            "password": "short"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");

        command(json!({
            "command": "changeMasterPassword",
            "session_id": session_id,
            "current_password": "short",
            "new_password": "x"
        }));
        command(json!({
            "command": "unlock",
            "path": path,
            "password": "x"
        }));

        let _ = fs::remove_dir_all(vault_path);
    }

    fn command(input: Value) -> Value {
        let decoded = command_result(input);
        assert_eq!(decoded["ok"], true, "{decoded}");
        decoded
    }

    fn command_result(input: Value) -> Value {
        let input = CString::new(input.to_string()).expect("cstring");
        let response_ptr = unsafe { crate::psw_command(input.as_ptr()) };
        assert!(!response_ptr.is_null());
        let response = unsafe { CStr::from_ptr(response_ptr) }
            .to_string_lossy()
            .to_string();
        unsafe { crate::psw_string_free(response_ptr) };

        serde_json::from_str(&response).expect("json response")
    }

    fn copy_dir_all(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create destination");
        for entry in fs::read_dir(source).expect("read source") {
            let entry = entry.expect("source entry");
            let file_type = entry.file_type().expect("entry type");
            let destination_path = destination.join(entry.file_name());
            if file_type.is_dir() {
                copy_dir_all(&entry.path(), &destination_path);
            } else {
                fs::copy(entry.path(), destination_path).expect("copy file");
            }
        }
    }

    fn copy_item_records(source_vault: &Path, destination_vault: &Path) {
        let source_items = source_vault.join("items");
        let destination_items = destination_vault.join("items");
        for entry in fs::read_dir(source_items).expect("read source items") {
            let entry = entry.expect("source item entry");
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("enc")
            {
                fs::copy(entry.path(), destination_items.join(entry.file_name()))
                    .expect("copy item record");
            }
        }
    }
}
