use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use psw_broker::{
    bundled_usage_profile_template, bundled_usage_profile_templates,
    recommend_bundled_usage_profile, BrokerAppsToolsSnapshot, BrokerConsumerAuditSummary,
    BrokerConsumerDetail, BrokerConsumerIdentityEvidence, BrokerConsumerSummary,
    BrokerFieldGrantSummary, BrokerPendingRequest, BrokerPendingRequestId,
    BrokerPendingRequestKind, BrokerPendingRequestQueue, BrokerUsageProfileSummary,
    BundledUsageProfileRecommendation, BundledUsageProfileTemplate, BundledUsageProfileTemplateId,
    ConsumerCodeSigningEvidence, ConsumerId, CredentialFieldScope, RuleLifetime, UsagePlacement,
    UsageProfile, UsageProfileId,
};
#[cfg(target_os = "macos")]
use psw_broker::{
    ApprovalRequestId, BrokerCredentialCandidateSelection, BrokerHumanCredentialReview,
    BrokerPairingUserApproval, BrokerRuntime, BrokerRuntimeError, BrokerVaultLockState,
    BrokerVaultSessionError, Capability, ConfirmationPolicy, DeviceKeyError, DeviceKeyManager,
    DevicePaths, DeviceStateStore, MacOsDeviceKeyStore, PairingRequestId, StateTimestamp,
    DEVICE_STATE_DATABASE_FILENAME,
};
use psw_core::{
    built_in_credential_template, normalize_totp_secret, ConflictFieldSelection, ConflictId,
    ConflictMergeRequest, CreateVaultRequest, CredentialDraft, CredentialEdit, CredentialField,
    CredentialFieldEdit, CredentialFieldValue, CredentialId, CredentialListItem,
    CredentialRevision, CreditCardItem, ExportItemsRequest, ImportCommitRequest,
    ImportPreviewRequest, ItemId, ItemRevision, ItemStatus, LoginItem, OpenVaultRequest,
    PasswordHealthIssueKind, PendingRecoveryRotation, PendingRecoverySetup, RecoverVaultRequest,
    RecoveryKey, RejectedSyncRecordFile, RejectedSyncRecordKind, RestoreVaultBackupRequest,
    RevisionId, SearchQuery, SecretBytes, SecretFieldId, SecretFieldKind, SecureNoteItem,
    SoftwareLicenseItem, UnlockRequest, UnlockedVault, VaultCore, VaultError, VaultId,
    VaultItemContent, VaultItemDraft, CURRENT_RECORD_FORMAT_VERSION, CURRENT_VAULT_FORMAT_VERSION,
};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroize;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static SESSIONS: OnceLock<Mutex<BTreeMap<u64, UnlockedVault>>> = OnceLock::new();
static NEXT_RECOVERY_WORKFLOW_ID: AtomicU64 = AtomicU64::new(1);
static RECOVERY_WORKFLOWS: OnceLock<Mutex<BTreeMap<u64, PendingRecoveryWorkflow>>> =
    OnceLock::new();
#[cfg(target_os = "macos")]
static BROKER_RUNTIME: OnceLock<Mutex<Option<BrokerRuntime>>> = OnceLock::new();

enum PendingRecoveryWorkflow {
    Setup {
        session_id: u64,
        pending: PendingRecoverySetup,
    },
    Rotation {
        session_id: u64,
        pending: PendingRecoveryRotation,
    },
}

impl PendingRecoveryWorkflow {
    fn session_id(&self) -> u64 {
        match self {
            Self::Setup { session_id, .. } | Self::Rotation { session_id, .. } => *session_id,
        }
    }

    fn recovery_key(&self) -> &RecoveryKey {
        match self {
            Self::Setup { pending, .. } => &pending.recovery_key,
            Self::Rotation { pending, .. } => pending.recovery_key(),
        }
    }

    fn recovery_key_id(&self) -> psw_core::RecoveryKeyId {
        match self {
            Self::Setup { pending, .. } => pending.recovery_key_id,
            Self::Rotation { pending, .. } => pending.recovery_key_id(),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Setup { .. } => "setup",
            Self::Rotation { .. } => "rotation",
        }
    }
}

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
        let mut bytes = CString::from_raw(ptr).into_bytes_with_nul();
        bytes.zeroize();
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
        Command::Version {} => Ok(ResponsePayload::Version {
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
        Command::LockedRecoveryStatus { path } => {
            let locked = VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: PathBuf::from(path),
                })
                .map_err(|error| error.to_string())?;
            let recovery_key_id = locked
                .recovery_key_id()
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::RecoveryStatus {
                has_recovery_envelope: recovery_key_id.is_some(),
                recovery_key_id,
            })
        }
        Command::Unlock { path, password } => {
            let broker_password = SecretBytes::new(password.as_bytes().to_vec());
            let unlocked = VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: PathBuf::from(&path),
                })
                .map_err(|error| error.to_string())?
                .unlock(UnlockRequest {
                    master_password: SecretBytes::new(password.into_bytes()),
                })
                .map_err(|error| error.to_string())?;
            let apps_tools_vault_path_conflict = sync_apps_tools_broker_unlock(
                &path,
                unlocked.metadata.vault_id,
                AppsToolsBrokerUnlockCredential::MasterPassword(broker_password),
            );
            register_unlocked_session(unlocked, apps_tools_vault_path_conflict)
        }
        Command::UnlockWithLocalMaterial {
            path,
            local_material,
        } => {
            let decoded_material = decode_hex(&local_material)?;
            let broker_material = SecretBytes::new(decoded_material.clone());
            let unlocked = VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: PathBuf::from(&path),
                })
                .map_err(|error| error.to_string())?
                .unlock_with_local_material(SecretBytes::new(decoded_material))
                .map_err(|error| error.to_string())?;
            let apps_tools_vault_path_conflict = sync_apps_tools_broker_unlock(
                &path,
                unlocked.metadata.vault_id,
                AppsToolsBrokerUnlockCredential::LocalMaterial(broker_material),
            );
            register_unlocked_session(unlocked, apps_tools_vault_path_conflict)
        }
        Command::RecoverVault {
            path,
            mut recovery_code,
            new_password,
        } => {
            let parsed_recovery_key = RecoveryKey::from_str(&recovery_code)
                .map_err(|_| "invalid KeptNear recovery key".to_owned());
            recovery_code.zeroize();
            let broker_password = SecretBytes::new(new_password.as_bytes().to_vec());
            let unlocked = VaultCore::new()
                .open_vault(OpenVaultRequest {
                    path: PathBuf::from(&path),
                })
                .map_err(|error| error.to_string())?
                .recover(RecoverVaultRequest {
                    recovery_key: parsed_recovery_key?,
                    new_master_password: SecretBytes::new(new_password.into_bytes()),
                })
                .map_err(|error| error.to_string())?;
            let apps_tools_vault_path_conflict = sync_apps_tools_broker_unlock(
                &path,
                unlocked.metadata.vault_id,
                AppsToolsBrokerUnlockCredential::MasterPassword(broker_password),
            );
            register_unlocked_session(unlocked, apps_tools_vault_path_conflict)
        }
        Command::Lock { session_id } => {
            let vault_id = sessions()
                .lock()
                .expect("session lock")
                .remove(&session_id)
                .and_then(|vault| vault.metadata.vault_id);
            recovery_workflows()
                .lock()
                .expect("recovery workflow lock")
                .retain(|_, workflow| workflow.session_id() != session_id);
            if let Some(vault_id) = vault_id {
                lock_apps_tools_broker_vault(vault_id);
            }
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
        Command::RecoveryStatus { session_id } => with_session(session_id, |vault| {
            let recovery_key_id = vault.recovery_key_id().map_err(|error| error.to_string())?;
            Ok(ResponsePayload::RecoveryStatus {
                has_recovery_envelope: recovery_key_id.is_some(),
                recovery_key_id,
            })
        }),
        Command::BeginRecoverySetup { session_id } => {
            let pending = {
                let sessions = sessions().lock().expect("session lock");
                let vault = sessions
                    .get(&session_id)
                    .ok_or_else(|| format!("unknown vault session {session_id}"))?;
                vault
                    .begin_recovery_setup()
                    .map_err(|error| error.to_string())?
            };
            begin_recovery_workflow(PendingRecoveryWorkflow::Setup {
                session_id,
                pending,
            })
        }
        Command::BeginRecoveryRotation { session_id } => {
            let pending = {
                let sessions = sessions().lock().expect("session lock");
                let vault = sessions
                    .get(&session_id)
                    .ok_or_else(|| format!("unknown vault session {session_id}"))?;
                vault
                    .begin_recovery_rotation()
                    .map_err(|error| error.to_string())?
            };
            begin_recovery_workflow(PendingRecoveryWorkflow::Rotation {
                session_id,
                pending,
            })
        }
        Command::ConfirmRecoveryWorkflow {
            session_id,
            workflow_id,
            mut recovery_code,
        } => {
            let result = confirm_recovery_workflow(session_id, workflow_id, &recovery_code);
            recovery_code.zeroize();
            result
        }
        Command::CancelRecoveryWorkflow {
            session_id,
            workflow_id,
        } => {
            cancel_recovery_workflow(session_id, workflow_id)?;
            Ok(ResponsePayload::Unit)
        }
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
            Ok(ResponsePayload::Items {
                items: search_item_views(
                    vault,
                    SearchQuery {
                        text,
                        include_archived,
                    },
                )?,
            })
        }),
        Command::ListAuthorizedCredentialIds { session_id } => with_session(session_id, |vault| {
            Ok(ResponsePayload::AuthorizedCredentialIds {
                credential_ids: active_authorized_credential_ids(vault)?,
            })
        }),
        Command::AppsToolsPendingRequests => Ok(ResponsePayload::AppsToolsPendingRequests {
            queue: apps_tools_pending_requests()?,
        }),
        Command::AppsToolsDenyPendingRequest {
            request_source,
            request_id,
        } => Ok(ResponsePayload::AppsToolsPendingRequestDecision {
            decision: deny_apps_tools_pending_request(&request_source, &request_id)?,
        }),
        Command::AppsToolsApprovePairing { request_id, label } => {
            Ok(ResponsePayload::AppsToolsPendingRequestDecision {
                decision: approve_apps_tools_pairing(&request_id, label)?,
            })
        }
        Command::AppsToolsApprovePendingUnlock {
            session_id,
            request_id,
        } => with_session(session_id, |vault| {
            Ok(ResponsePayload::AppsToolsPendingRequestDecision {
                decision: approve_apps_tools_pending_unlock(vault, &request_id)?,
            })
        }),
        Command::AppsToolsReviewPendingCredential {
            session_id,
            request_id,
        } => with_session(session_id, |vault| {
            Ok(ResponsePayload::AppsToolsCredentialReview {
                review: review_apps_tools_pending_credential(vault, &request_id)?,
            })
        }),
        Command::AppsToolsAllowOnce {
            session_id,
            request_id,
            credential_id,
            secret_field_id,
        } => with_session(session_id, |vault| {
            Ok(ResponsePayload::AppsToolsPendingRequestDecision {
                decision: allow_apps_tools_pending_request_once(
                    vault,
                    &request_id,
                    credential_id.as_deref(),
                    secret_field_id.as_deref(),
                )?,
            })
        }),
        Command::AppsToolsConfigureLongTermAccess {
            session_id,
            request_id,
            credential_id,
            secret_field_id,
            confirmation_policy,
        } => with_session(session_id, |vault| {
            Ok(ResponsePayload::AppsToolsPendingRequestDecision {
                decision: configure_apps_tools_long_term_access(
                    vault,
                    &request_id,
                    credential_id.as_deref(),
                    secret_field_id.as_deref(),
                    &confirmation_policy,
                )?,
            })
        }),
        Command::AppsToolsSnapshot { session_id } => with_session(session_id, |vault| {
            Ok(ResponsePayload::AppsToolsSnapshot {
                snapshot: apps_tools_snapshot(vault)?,
            })
        }),
        Command::AppsToolsConsumerDetail {
            session_id,
            consumer_id,
        } => with_session(session_id, |vault| {
            let consumer_id = consumer_id
                .parse::<ConsumerId>()
                .map_err(|_| "invalid Apps & Tools Consumer identity".to_owned())?;
            Ok(ResponsePayload::AppsToolsConsumerDetail {
                detail: apps_tools_consumer_detail(vault, consumer_id)?,
            })
        }),
        Command::AppsToolsUsageProfileSetup {
            session_id,
            consumer_id,
        } => with_session(session_id, |_vault| {
            let consumer_id = consumer_id
                .parse::<ConsumerId>()
                .map_err(|_| "invalid Apps & Tools Consumer identity".to_owned())?;
            Ok(ResponsePayload::AppsToolsUsageProfileSetup {
                setup: apps_tools_usage_profile_setup(consumer_id)?,
            })
        }),
        Command::CreateAppsToolsUsageProfile {
            session_id,
            consumer_id,
            label,
            template_id,
            technical_name,
        } => with_session(session_id, |_vault| {
            let consumer_id = consumer_id
                .parse::<ConsumerId>()
                .map_err(|_| "invalid Apps & Tools Consumer identity".to_owned())?;
            Ok(ResponsePayload::AppsToolsUsageProfileCreated {
                consumer_id: consumer_id.to_string(),
                profile: create_apps_tools_usage_profile(
                    consumer_id,
                    label,
                    &template_id,
                    technical_name.as_deref(),
                )?,
            })
        }),
        Command::RemoveAppsToolsUsageProfile {
            session_id,
            consumer_id,
            usage_profile_id,
        } => with_session(session_id, |_vault| {
            let consumer_id = consumer_id
                .parse::<ConsumerId>()
                .map_err(|_| "invalid Apps & Tools Consumer identity".to_owned())?;
            let usage_profile_id = usage_profile_id
                .parse::<UsageProfileId>()
                .map_err(|_| "invalid Apps & Tools Usage Profile identity".to_owned())?;
            Ok(ResponsePayload::AppsToolsUsageProfileRemoved {
                consumer_id: consumer_id.to_string(),
                usage_profile_id: usage_profile_id.to_string(),
                removed: remove_apps_tools_usage_profile(consumer_id, usage_profile_id)?,
            })
        }),
        Command::SetAppsToolsPaused { session_id, paused } => with_session(session_id, |vault| {
            let snapshot = set_apps_tools_paused(vault, paused)?;
            Ok(ResponsePayload::AppsToolsSnapshot { snapshot })
        }),
        Command::RevokeAppsToolsField {
            session_id,
            consumer_id,
            vault_id,
            credential_id,
            secret_field_id,
        } => with_session(session_id, |vault| {
            let consumer_id = consumer_id
                .parse::<ConsumerId>()
                .map_err(|_| "invalid Apps & Tools Consumer identity".to_owned())?;
            let vault_id = vault_id
                .parse::<VaultId>()
                .map_err(|_| "invalid Apps & Tools Vault identity".to_owned())?;
            let credential_id = credential_id
                .parse::<CredentialId>()
                .map_err(|_| "invalid Apps & Tools Credential identity".to_owned())?;
            let secret_field_id = secret_field_id
                .parse::<SecretFieldId>()
                .map_err(|_| "invalid Apps & Tools Secret Field identity".to_owned())?;
            let snapshot = revoke_apps_tools_field(
                vault,
                consumer_id,
                CredentialFieldScope::new(vault_id, credential_id, secret_field_id),
            )?;
            Ok(ResponsePayload::AppsToolsSnapshot { snapshot })
        }),
        Command::RevokeAppsToolsConsumer {
            session_id,
            consumer_id,
        } => with_session(session_id, |vault| {
            let consumer_id = consumer_id
                .parse::<ConsumerId>()
                .map_err(|_| "invalid Apps & Tools Consumer identity".to_owned())?;
            let snapshot = revoke_apps_tools_consumer(vault, consumer_id)?;
            Ok(ResponsePayload::AppsToolsSnapshot { snapshot })
        }),
        Command::CreateCredentialFromTemplate {
            session_id,
            template_id,
            title,
            secret,
            expiry,
            notes,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            let draft = credential_draft_from_template(
                template_id,
                title,
                secret,
                expiry,
                notes,
                tags,
                favorite,
            )?;
            vault
                .create_credential(draft)
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::UpdateCredential {
            session_id,
            credential_id,
            expected_revision,
            title,
            template_id,
            fields,
            tags,
            favorite,
        } => with_session_mut(session_id, |vault| {
            let credential_id = credential_id
                .parse()
                .map_err(|_| "invalid credential identity".to_owned())?;
            let expected_revision = expected_revision
                .parse::<RevisionId>()
                .map_err(|_| "invalid credential revision identity".to_owned())?;
            let edit = credential_edit(title, template_id, fields, tags, favorite)?;
            let prepared = vault
                .prepare_credential_update(credential_id, expected_revision, edit)
                .map_err(|error| error.to_string())?;
            revoke_removed_field_authorizations(
                prepared.vault_id(),
                prepared.credential_id(),
                prepared.removed_secret_field_ids(),
            )?;
            vault
                .commit_credential_update(prepared)
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::DuplicateCredential {
            session_id,
            credential_id,
            expected_revision,
            title,
        } => with_session_mut(session_id, |vault| {
            let credential_id = credential_id
                .parse::<CredentialId>()
                .map_err(|_| "invalid credential identity".to_owned())?;
            let expected_revision = expected_revision
                .parse::<RevisionId>()
                .map_err(|_| "invalid credential revision identity".to_owned())?;
            vault
                .duplicate_credential_with_expected_revision(
                    credential_id,
                    expected_revision,
                    title,
                )
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::GetCredential {
            session_id,
            credential_id,
        } => with_session(session_id, |vault| {
            let credential_id = credential_id
                .parse()
                .map_err(|_| "invalid credential identity".to_owned())?;
            let revision = vault
                .credential_revision(credential_id)
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::CredentialDetail {
                detail: CredentialDetailView::from_revision(revision),
            })
        }),
        Command::GetCredentialSecretField {
            session_id,
            credential_id,
            secret_field_id,
        } => with_session(session_id, |vault| {
            let credential_id = credential_id
                .parse()
                .map_err(|_| "invalid credential identity".to_owned())?;
            let secret_field_id = secret_field_id
                .parse::<SecretFieldId>()
                .map_err(|_| "invalid secret-field identity".to_owned())?;
            let revision = vault
                .credential_revision(credential_id)
                .map_err(|error| error.to_string())?;
            let secret = revision
                .credential()
                .draft()
                .fields
                .iter()
                .find_map(|field| match &field.value {
                    CredentialFieldValue::Secret {
                        secret_field_id: candidate_id,
                        secret,
                        ..
                    } if *candidate_id == secret_field_id => Some(secret.clone()),
                    CredentialFieldValue::Text { .. } | CredentialFieldValue::Secret { .. } => None,
                })
                .ok_or_else(|| "credential secret field was not found".to_owned())?;
            Ok(ResponsePayload::Secret {
                value: secret_to_string(secret),
            })
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
            if let Some(current) = current_credential_revision(vault, &item_id)? {
                let expected_revision =
                    parse_or_current_credential_revision(expected_revision, &current)?;
                vault
                    .archive_credential_with_expected_revision(
                        current.credential().credential_id(),
                        expected_revision,
                    )
                    .map_err(|error| error.to_string())?;
            } else {
                let item_id = ItemId(item_id);
                match expected_revision {
                    Some(expected_revision) => vault
                        .archive_item_with_expected_revision(
                            &item_id,
                            &ItemRevision(expected_revision),
                        )
                        .map_err(|error| error.to_string())?,
                    None => vault
                        .archive_item(&item_id)
                        .map_err(|error| error.to_string())?,
                };
            }
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::RestoreItem {
            session_id,
            item_id,
        } => with_session_mut(session_id, |vault| {
            if let Some(current) = current_credential_revision(vault, &item_id)? {
                vault
                    .restore_credential(current.credential().credential_id())
                    .map_err(|error| error.to_string())?;
            } else {
                vault
                    .restore_item(&ItemId(item_id))
                    .map_err(|error| error.to_string())?;
            }
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::DeleteItem {
            session_id,
            item_id,
            expected_revision,
        } => with_session_mut(session_id, |vault| {
            if let Some(current) = current_credential_revision(vault, &item_id)? {
                let credential_id = current.credential().credential_id();
                let expected_revision =
                    parse_or_current_credential_revision(expected_revision, &current)?;
                let removed_secret_field_ids = current
                    .credential()
                    .draft()
                    .secret_fields()
                    .filter_map(|field| field.secret_field_id())
                    .collect::<Vec<_>>();
                revoke_removed_field_authorizations(
                    current.credential().vault_id(),
                    credential_id,
                    &removed_secret_field_ids,
                )?;
                vault
                    .delete_credential_with_expected_revision(credential_id, expected_revision)
                    .map_err(|error| error.to_string())?;
            } else {
                let item_id = ItemId(item_id);
                match expected_revision {
                    Some(expected_revision) => vault
                        .delete_item_with_expected_revision(
                            &item_id,
                            &ItemRevision(expected_revision),
                        )
                        .map_err(|error| error.to_string())?,
                    None => vault
                        .delete_item(&item_id)
                        .map_err(|error| error.to_string())?,
                };
            }
            Ok(ResponsePayload::Items {
                items: item_views(vault)?,
            })
        }),
        Command::ResolveConflict {
            session_id,
            conflict_id,
        } => with_session_mut(session_id, |vault| {
            let conflict_id = ConflictId(conflict_id);
            let candidates = vault
                .conflict_candidates(&conflict_id)
                .map_err(|error| error.to_string())?;
            let selected_revision = candidates
                .iter()
                .filter(|candidate| candidate.status != "deleted")
                .map(|candidate| candidate.revision.clone())
                .max()
                .or_else(|| {
                    candidates
                        .iter()
                        .map(|candidate| candidate.revision.clone())
                        .max()
                })
                .ok_or_else(|| format!("item '{}' was not found", conflict_id.0))?;
            resolve_selected_conflict_candidate(vault, &conflict_id, &selected_revision)?;
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
            resolve_selected_conflict_candidate(
                vault,
                &ConflictId(conflict_id),
                &ItemRevision(revision),
            )?;
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
            if let Some(current) = current_credential_revision(vault, &item_id)? {
                let expected_revision =
                    parse_or_current_credential_revision(expected_revision, &current)?;
                vault
                    .set_credential_favorite_with_expected_revision(
                        current.credential().credential_id(),
                        expected_revision,
                        favorite,
                    )
                    .map_err(|error| error.to_string())?;
            } else {
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
            }
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
            current_password,
        } => with_session(session_id, |vault| {
            let result = vault
                .export_items(ExportItemsRequest {
                    destination_path: PathBuf::from(destination_path),
                    export_format,
                    current_master_password: SecretBytes::new(current_password.into_bytes()),
                })
                .map_err(|error| error.to_string())?;
            Ok(ResponsePayload::ExportResult {
                exported_records: result.exported_records,
                skipped_records: result.skipped_records,
                omissions: result
                    .omissions
                    .into_iter()
                    .map(|omission| ExportOmissionView {
                        reason: omission.reason.as_str(),
                        count: omission.count,
                    })
                    .collect(),
                warnings: result.warnings,
            })
        }),
    }
}

fn sessions() -> &'static Mutex<BTreeMap<u64, UnlockedVault>> {
    SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn register_unlocked_session(
    unlocked: UnlockedVault,
    apps_tools_vault_path_conflict: bool,
) -> Result<ResponsePayload, String> {
    let items = item_views(&unlocked)?;
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    sessions()
        .lock()
        .expect("session lock")
        .insert(session_id, unlocked);
    Ok(ResponsePayload::Unlocked {
        session_id,
        items,
        apps_tools_vault_path_conflict,
    })
}

fn recovery_workflows() -> &'static Mutex<BTreeMap<u64, PendingRecoveryWorkflow>> {
    RECOVERY_WORKFLOWS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn begin_recovery_workflow(workflow: PendingRecoveryWorkflow) -> Result<ResponsePayload, String> {
    let generated_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_secs();
    let kit = match &workflow {
        PendingRecoveryWorkflow::Setup { pending, .. } => {
            pending.recovery_kit(generated_at_unix_seconds)
        }
        PendingRecoveryWorkflow::Rotation { pending, .. } => {
            pending.recovery_kit(generated_at_unix_seconds)
        }
    };
    let workflow_id = NEXT_RECOVERY_WORKFLOW_ID.fetch_add(1, Ordering::Relaxed);
    let response = ResponsePayload::RecoveryKit {
        workflow_id,
        workflow_kind: workflow.kind(),
        vault_id: kit.vault_id().to_string(),
        recovery_key_id: kit.recovery_key_id().to_string(),
        generated_at_unix_seconds: kit.generated_at_unix_seconds(),
        canonical_code: SecretResponseString::new(kit.canonical_code().to_owned()),
        grouped_code: SecretResponseString::new(kit.grouped_code().to_owned()),
        qr_payload: SecretResponseString::new(kit.qr_payload().to_owned()),
        verification_groups: kit
            .verification_groups()
            .iter()
            .cloned()
            .map(SecretResponseString::new)
            .collect(),
    };
    recovery_workflows()
        .lock()
        .expect("recovery workflow lock")
        .insert(workflow_id, workflow);
    Ok(response)
}

fn confirm_recovery_workflow(
    session_id: u64,
    workflow_id: u64,
    recovery_code: &str,
) -> Result<ResponsePayload, String> {
    if !sessions()
        .lock()
        .expect("session lock")
        .contains_key(&session_id)
    {
        return Err(format!("unknown vault session {session_id}"));
    }
    let parsed = RecoveryKey::from_str(recovery_code)
        .map_err(|_| "recovery confirmation did not match".to_owned())?;
    let workflow = {
        let mut workflows = recovery_workflows().lock().expect("recovery workflow lock");
        let workflow = workflows
            .get(&workflow_id)
            .ok_or_else(|| format!("unknown recovery workflow {workflow_id}"))?;
        if workflow.session_id() != session_id || workflow.recovery_key() != &parsed {
            return Err("recovery confirmation did not match".to_owned());
        }
        workflows
            .remove(&workflow_id)
            .expect("validated recovery workflow exists")
    };
    let recovery_key_id = workflow.recovery_key_id().to_string();
    let workflow_kind = workflow.kind();

    match workflow {
        PendingRecoveryWorkflow::Setup { .. } => Ok(ResponsePayload::RecoveryConfirmed {
            workflow_kind,
            recovery_key_id,
        }),
        PendingRecoveryWorkflow::Rotation { pending, .. } => {
            with_session(session_id, move |vault| {
                vault.commit_recovery_rotation(pending).map_err(|error| {
                    format!("recovery rotation commit failed; start again: {error}")
                })?;
                Ok(ResponsePayload::RecoveryConfirmed {
                    workflow_kind,
                    recovery_key_id,
                })
            })
        }
    }
}

fn cancel_recovery_workflow(session_id: u64, workflow_id: u64) -> Result<(), String> {
    if !sessions()
        .lock()
        .expect("session lock")
        .contains_key(&session_id)
    {
        return Err(format!("unknown vault session {session_id}"));
    }
    let mut workflows = recovery_workflows().lock().expect("recovery workflow lock");
    let workflow = workflows
        .get(&workflow_id)
        .ok_or_else(|| format!("unknown recovery workflow {workflow_id}"))?;
    if workflow.session_id() != session_id {
        return Err(format!("unknown recovery workflow {workflow_id}"));
    }
    workflows
        .remove(&workflow_id)
        .expect("validated recovery workflow exists");
    Ok(())
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

fn current_credential_revision(
    vault: &UnlockedVault,
    item_id: &str,
) -> Result<Option<CredentialRevision>, String> {
    let Ok(credential_id) = item_id.parse::<CredentialId>() else {
        return Ok(None);
    };
    match vault.credential_revision(credential_id) {
        Ok(revision) => Ok(Some(revision)),
        Err(VaultError::NotImplemented { .. }) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn parse_or_current_credential_revision(
    expected_revision: Option<String>,
    current: &CredentialRevision,
) -> Result<RevisionId, String> {
    expected_revision
        .map(|revision| {
            revision
                .parse::<RevisionId>()
                .map_err(|_| "invalid credential revision identity".to_owned())
        })
        .transpose()
        .map(|revision| revision.unwrap_or_else(|| current.revision_id()))
}

fn resolve_selected_conflict_candidate(
    vault: &mut UnlockedVault,
    conflict_id: &ConflictId,
    selected_revision: &ItemRevision,
) -> Result<(), String> {
    let uses_current_format = (
        vault.metadata.vault_format_version,
        vault.metadata.record_format_version,
    ) == (CURRENT_VAULT_FORMAT_VERSION, CURRENT_RECORD_FORMAT_VERSION);
    if !uses_current_format {
        vault
            .resolve_conflict_candidate(conflict_id, selected_revision)
            .map_err(|error| error.to_string())?;
        return Ok(());
    }

    let candidates = vault
        .conflict_candidates(conflict_id)
        .map_err(|error| error.to_string())?;
    let selected = candidates
        .iter()
        .find(|candidate| candidate.revision == *selected_revision)
        .ok_or_else(|| format!("item '{}' was not found", selected_revision.0))?;
    let all_secret_field_ids = candidates
        .iter()
        .flat_map(|candidate| &candidate.credential_fields)
        .filter_map(|field| match field {
            psw_core::ConflictCandidateCredentialField::Secret {
                secret_field_id, ..
            } => Some(*secret_field_id),
            psw_core::ConflictCandidateCredentialField::Text { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let retained_secret_field_ids = if selected.status == "deleted" {
        BTreeSet::new()
    } else {
        selected
            .credential_fields
            .iter()
            .filter_map(|field| match field {
                psw_core::ConflictCandidateCredentialField::Secret {
                    secret_field_id, ..
                } => Some(*secret_field_id),
                psw_core::ConflictCandidateCredentialField::Text { .. } => None,
            })
            .collect()
    };
    let removed_secret_field_ids = all_secret_field_ids
        .difference(&retained_secret_field_ids)
        .copied()
        .collect::<Vec<_>>();
    let vault_id = vault
        .metadata
        .vault_id
        .ok_or_else(|| "current vault metadata is missing its stable identity".to_owned())?;
    let credential_id = selected
        .item_id
        .0
        .parse::<CredentialId>()
        .map_err(|_| "conflict candidate has an invalid credential identity".to_owned())?;
    revoke_removed_field_authorizations(vault_id, credential_id, &removed_secret_field_ids)?;
    vault
        .resolve_credential_conflict_candidate(conflict_id, selected_revision)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn item_views(vault: &UnlockedVault) -> Result<Vec<ItemView>, String> {
    match vault.list_credential_items(false) {
        Ok(items) => Ok(items.into_iter().map(ItemView::from_credential).collect()),
        Err(VaultError::NotImplemented { .. }) => vault
            .list_items()
            .map_err(|error| error.to_string())
            .map(|items| items.into_iter().map(ItemView::from_summary).collect()),
        Err(error) => Err(error.to_string()),
    }
}

fn search_item_views(vault: &UnlockedVault, query: SearchQuery) -> Result<Vec<ItemView>, String> {
    match vault.search_credential_items(query.clone()) {
        Ok(items) => Ok(items.into_iter().map(ItemView::from_credential).collect()),
        Err(VaultError::NotImplemented { .. }) => vault
            .search(query)
            .map_err(|error| error.to_string())
            .map(|items| items.into_iter().map(ItemView::from_summary).collect()),
        Err(error) => Err(error.to_string()),
    }
}

enum AppsToolsBrokerUnlockCredential {
    MasterPassword(SecretBytes),
    LocalMaterial(SecretBytes),
}

#[cfg(target_os = "macos")]
fn sync_apps_tools_broker_unlock(
    path: &str,
    vault_id: Option<VaultId>,
    credential: AppsToolsBrokerUnlockCredential,
) -> bool {
    let Some(vault_id) = vault_id else {
        return false;
    };
    if !matches!(broker_state_exists(), Ok(true)) {
        return false;
    }
    matches!(
        with_broker_runtime(|runtime| {
            let snapshot = match runtime
                .process()
                .vault_sessions()
                .open_vault_with_expected_identity(path, vault_id)
            {
                Ok(snapshot) => snapshot,
                Err(
                    BrokerVaultSessionError::VaultIdentityAlreadyOpen
                    | BrokerVaultSessionError::VaultPathIdentityChanged,
                ) => {
                    let _ = runtime.lock_vault_for_human(vault_id);
                    return Ok(true);
                }
                Err(error) => {
                    return Err(format!("Apps & Tools Vault open failed: {error}"));
                }
            };
            match snapshot.lock_state() {
                BrokerVaultLockState::Unlocked => Ok(false),
                BrokerVaultLockState::Locked => {
                    let result = match credential {
                        AppsToolsBrokerUnlockCredential::MasterPassword(password) => runtime
                            .process()
                            .vault_sessions()
                            .unlock_with_master_password(vault_id, password),
                        AppsToolsBrokerUnlockCredential::LocalMaterial(material) => runtime
                            .process()
                            .vault_sessions()
                            .unlock_with_local_material(vault_id, material),
                    };
                    result
                        .map(|_| false)
                        .map_err(|error| format!("Apps & Tools Vault unlock failed: {error}"))
                }
                BrokerVaultLockState::Unlocking => {
                    Err("Apps & Tools Vault unlock is already in progress".to_owned())
                }
            }
        }),
        Ok(true)
    )
}

#[cfg(not(target_os = "macos"))]
fn sync_apps_tools_broker_unlock(
    _path: &str,
    _vault_id: Option<VaultId>,
    _credential: AppsToolsBrokerUnlockCredential,
) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn lock_apps_tools_broker_vault(vault_id: VaultId) {
    if !matches!(broker_state_exists(), Ok(true)) {
        return;
    }
    let _ = with_broker_runtime(|runtime| match runtime.lock_vault_for_human(vault_id) {
        Ok(_) | Err(BrokerRuntimeError::VaultSession(BrokerVaultSessionError::VaultNotOpen)) => {
            Ok(())
        }
        Err(error) => Err(format!("Apps & Tools Vault lock failed: {error}")),
    });
}

#[cfg(not(target_os = "macos"))]
fn lock_apps_tools_broker_vault(_vault_id: VaultId) {}

#[cfg(target_os = "macos")]
fn active_authorized_credential_ids(vault: &UnlockedVault) -> Result<Vec<String>, String> {
    apps_tools_snapshot(vault).map(|snapshot| snapshot.authorized_credential_ids)
}

#[cfg(target_os = "macos")]
fn with_broker_runtime<T>(
    operation: impl FnOnce(&mut BrokerRuntime) -> Result<T, String>,
) -> Result<T, String> {
    let runtime = BROKER_RUNTIME.get_or_init(|| Mutex::new(None));
    let mut runtime = runtime
        .lock()
        .map_err(|_| "Apps & Tools runtime unavailable".to_owned())?;
    if runtime.is_none() {
        *runtime = Some(open_or_initialize_broker_runtime()?);
    }
    operation(
        runtime
            .as_mut()
            .ok_or_else(|| "Apps & Tools runtime unavailable".to_owned())?,
    )
}

#[cfg(target_os = "macos")]
fn open_or_initialize_broker_runtime() -> Result<BrokerRuntime, String> {
    BrokerRuntime::open_or_initialize_for_current_user(MacOsDeviceKeyStore::new())
        .map_err(|error| format!("Apps & Tools runtime unavailable: {error}"))
}

#[cfg(target_os = "macos")]
fn current_state_timestamp() -> Result<StateTimestamp, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Apps & Tools clock unavailable".to_owned())?;
    let millis = i64::try_from(elapsed.as_millis())
        .map_err(|_| "Apps & Tools clock unavailable".to_owned())?;
    StateTimestamp::from_unix_millis(millis)
        .map_err(|_| "Apps & Tools clock unavailable".to_owned())
}

#[cfg(target_os = "macos")]
fn apps_tools_pending_requests() -> Result<AppsToolsPendingRequestQueueView, String> {
    if !broker_state_exists()? {
        return Ok(AppsToolsPendingRequestQueueView::empty());
    }
    with_broker_runtime(|runtime| {
        runtime
            .pending_requests_for_human()
            .map(AppsToolsPendingRequestQueueView::from_broker)
            .map_err(|error| format!("Apps & Tools pending requests unavailable: {error}"))
    })
}

#[cfg(target_os = "macos")]
fn deny_apps_tools_pending_request(
    request_source: &str,
    request_id: &str,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    let request_id = parse_apps_tools_pending_request_id(request_source, request_id)?;
    let denied_at = current_state_timestamp()?;
    with_broker_runtime(|runtime| {
        runtime
            .deny_pending_request(request_id, denied_at)
            .map_err(|error| format!("Apps & Tools request denial failed: {error}"))
    })?;
    Ok(AppsToolsPendingRequestDecisionView::new("deny", "denied"))
}

#[cfg(target_os = "macos")]
fn approve_apps_tools_pairing(
    request_id: &str,
    label: String,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    let request_id = request_id
        .parse::<PairingRequestId>()
        .map_err(|_| "invalid Apps & Tools pairing request identity".to_owned())?;
    let approved_at = current_state_timestamp()?;
    with_broker_runtime(|runtime| {
        runtime
            .approve_pairing(
                request_id,
                BrokerPairingUserApproval::after_user_approval(label, approved_at),
            )
            .map_err(|error| format!("Apps & Tools pairing approval failed: {error}"))
    })?;
    Ok(AppsToolsPendingRequestDecisionView::new(
        "pair",
        "awaiting-proof",
    ))
}

#[cfg(target_os = "macos")]
fn approve_apps_tools_pending_unlock(
    vault: &UnlockedVault,
    request_id: &str,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    let request_id = parse_approval_request_id(request_id)?;
    let approved_at = current_state_timestamp()?;
    let vault_id = vault
        .metadata
        .vault_id
        .ok_or_else(|| "Apps & Tools request requires a current Vault identity".to_owned())?;
    with_broker_runtime(|runtime| {
        ensure_pending_request_matches_vault(runtime, request_id, vault)?;
        runtime
            .approve_pending_unlock(request_id, vault_id, approved_at)
            .map_err(|error| format!("Apps & Tools unlock approval failed: {error}"))
    })?;
    Ok(AppsToolsPendingRequestDecisionView::new(
        "approve-unlock",
        "approved",
    ))
}

#[cfg(target_os = "macos")]
fn review_apps_tools_pending_credential(
    vault: &UnlockedVault,
    request_id: &str,
) -> Result<AppsToolsCredentialReviewView, String> {
    let request_id = parse_approval_request_id(request_id)?;
    let observed_at = current_state_timestamp()?;
    with_broker_runtime(|runtime| {
        ensure_pending_request_matches_vault(runtime, request_id, vault)?;
        runtime
            .review_pending_new_credential_for_current_session(request_id, observed_at)
            .map(|review| AppsToolsCredentialReviewView::from_broker(request_id, &review))
            .map_err(|error| format!("Apps & Tools credential review failed: {error}"))
    })
}

#[cfg(target_os = "macos")]
fn allow_apps_tools_pending_request_once(
    vault: &UnlockedVault,
    request_id: &str,
    credential_id: Option<&str>,
    secret_field_id: Option<&str>,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    let request_id = parse_approval_request_id(request_id)?;
    let selection = parse_apps_tools_credential_selection(credential_id, secret_field_id)?;
    let approved_at = current_state_timestamp()?;
    let use_grant_id = with_broker_runtime(|runtime| {
        ensure_pending_request_matches_vault(runtime, request_id, vault)?;
        runtime
            .allow_once_pending_request(request_id, selection, approved_at)
            .map(|issuance| issuance.grant().use_grant_id().to_string())
            .map_err(|error| format!("Apps & Tools Allow Once failed: {error}"))
    })?;
    Ok(
        AppsToolsPendingRequestDecisionView::new("allow-once", "approved")
            .with_use_grant_id(use_grant_id),
    )
}

#[cfg(target_os = "macos")]
fn configure_apps_tools_long_term_access(
    vault: &UnlockedVault,
    request_id: &str,
    credential_id: Option<&str>,
    secret_field_id: Option<&str>,
    confirmation_policy: &str,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    let request_id = parse_approval_request_id(request_id)?;
    let selection = parse_apps_tools_credential_selection(credential_id, secret_field_id)?;
    let confirmation_policy = ConfirmationPolicy::from_str(confirmation_policy)
        .map_err(|_| "invalid Apps & Tools confirmation policy".to_owned())?;
    let approved_at = current_state_timestamp()?;
    let access_rule_id = with_broker_runtime(|runtime| {
        ensure_pending_request_matches_vault(runtime, request_id, vault)?;
        let capability = pending_request_capability_for_vault(runtime, request_id, vault)?;
        runtime
            .configure_pending_request_access_rule(
                request_id,
                selection,
                capability,
                confirmation_policy,
                RuleLifetime::Persistent,
                approved_at,
            )
            .map(|creation| creation.rule().access_rule_id().to_string())
            .map_err(|error| format!("Apps & Tools long-term access configuration failed: {error}"))
    })?;
    Ok(
        AppsToolsPendingRequestDecisionView::new("configure-long-term-access", "approved")
            .with_access_rule_id(access_rule_id),
    )
}

#[cfg(target_os = "macos")]
fn parse_apps_tools_credential_selection(
    credential_id: Option<&str>,
    secret_field_id: Option<&str>,
) -> Result<Option<BrokerCredentialCandidateSelection>, String> {
    match (credential_id, secret_field_id) {
        (None, None) => Ok(None),
        (Some(credential_id), Some(secret_field_id)) => {
            Ok(Some(BrokerCredentialCandidateSelection::new(
                credential_id
                    .parse::<CredentialId>()
                    .map_err(|_| "invalid Apps & Tools Credential identity".to_owned())?,
                secret_field_id
                    .parse::<SecretFieldId>()
                    .map_err(|_| "invalid Apps & Tools Secret Field identity".to_owned())?,
            )))
        }
        _ => Err(
            "Apps & Tools candidate selection requires Credential and Secret Field identities"
                .to_owned(),
        ),
    }
}

#[cfg(target_os = "macos")]
fn parse_apps_tools_pending_request_id(
    request_source: &str,
    request_id: &str,
) -> Result<BrokerPendingRequestId, String> {
    match request_source {
        "pairing" => request_id
            .parse::<PairingRequestId>()
            .map(BrokerPendingRequestId::Pairing)
            .map_err(|_| "invalid Apps & Tools pairing request identity".to_owned()),
        "approval" => parse_approval_request_id(request_id).map(BrokerPendingRequestId::Approval),
        _ => Err("invalid Apps & Tools pending request source".to_owned()),
    }
}

#[cfg(target_os = "macos")]
fn parse_approval_request_id(request_id: &str) -> Result<ApprovalRequestId, String> {
    request_id
        .parse::<ApprovalRequestId>()
        .map_err(|_| "invalid Apps & Tools approval request identity".to_owned())
}

#[cfg(target_os = "macos")]
fn ensure_pending_request_matches_vault(
    runtime: &BrokerRuntime,
    approval_request_id: ApprovalRequestId,
    vault: &UnlockedVault,
) -> Result<(), String> {
    let current_vault_id = vault
        .metadata
        .vault_id
        .ok_or_else(|| "Apps & Tools request requires a current Vault identity".to_owned())?;
    let matches_current_vault = runtime
        .pending_requests_for_human()
        .map_err(|error| format!("Apps & Tools pending request unavailable: {error}"))?
        .requests()
        .iter()
        .any(|request| {
            request.request_id() == BrokerPendingRequestId::Approval(approval_request_id)
                && request.vault_id() == Some(current_vault_id)
        });
    if !matches_current_vault {
        return Err("Apps & Tools request is unavailable for the current Vault".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn pending_request_capability_for_vault(
    runtime: &BrokerRuntime,
    approval_request_id: ApprovalRequestId,
    vault: &UnlockedVault,
) -> Result<Capability, String> {
    let current_vault_id = vault
        .metadata
        .vault_id
        .ok_or_else(|| "Apps & Tools request requires a current Vault identity".to_owned())?;
    runtime
        .pending_requests_for_human()
        .map_err(|error| format!("Apps & Tools pending request unavailable: {error}"))?
        .requests()
        .iter()
        .find(|request| {
            request.request_id() == BrokerPendingRequestId::Approval(approval_request_id)
                && request.vault_id() == Some(current_vault_id)
        })
        .and_then(|request| request.capability())
        .ok_or_else(|| "Apps & Tools capability is unavailable for this request".to_owned())
}

#[cfg(target_os = "macos")]
fn apps_tools_snapshot(vault: &UnlockedVault) -> Result<AppsToolsSnapshotView, String> {
    if !broker_state_exists()? {
        return Ok(AppsToolsSnapshotView::empty());
    }
    with_broker_runtime(|runtime| apps_tools_snapshot_with_runtime(vault, runtime))
}

#[cfg(target_os = "macos")]
fn broker_state_exists() -> Result<bool, String> {
    let paths = DevicePaths::prepare_for_current_user()
        .map_err(|error| format!("Apps & Tools paths unavailable: {error}"))?;
    let database_exists = paths
        .state()
        .join(DEVICE_STATE_DATABASE_FILENAME)
        .try_exists()
        .map_err(|_| "Apps & Tools state availability could not be checked".to_owned())?;
    match (
        database_exists,
        DeviceKeyManager::new(MacOsDeviceKeyStore::new()).load_existing(),
    ) {
        (true, Ok(_)) => Ok(true),
        (false, Err(DeviceKeyError::Missing)) => Ok(false),
        (false, Ok(_)) => {
            Err("Apps & Tools encrypted state is missing while its device key remains".to_owned())
        }
        (true, Err(DeviceKeyError::Missing)) => {
            Err("Apps & Tools device key is missing while encrypted state remains".to_owned())
        }
        (_, Err(error)) => Err(format!("Apps & Tools device key unavailable: {error}")),
    }
}

#[cfg(target_os = "macos")]
fn apps_tools_snapshot_with_runtime(
    vault: &UnlockedVault,
    runtime: &BrokerRuntime,
) -> Result<AppsToolsSnapshotView, String> {
    let vault_id = vault
        .metadata
        .vault_id
        .ok_or_else(|| "Apps & Tools authorization requires a current vault identity".to_owned())?;
    runtime
        .apps_tools_snapshot(vault_id)
        .map(AppsToolsSnapshotView::from_broker)
        .map_err(|error| format!("Apps & Tools authorization unavailable: {error}"))
}

#[cfg(target_os = "macos")]
fn apps_tools_consumer_detail(
    vault: &UnlockedVault,
    consumer_id: ConsumerId,
) -> Result<AppsToolsConsumerDetailView, String> {
    with_broker_runtime(|runtime| {
        runtime
            .apps_tools_consumer_detail(consumer_id)
            .map(|detail| AppsToolsConsumerDetailView::from_broker(vault, detail))
            .map_err(|error| format!("Apps & Tools Consumer detail unavailable: {error}"))
    })
}

#[cfg(target_os = "macos")]
fn apps_tools_usage_profile_setup(
    consumer_id: ConsumerId,
) -> Result<AppsToolsUsageProfileSetupView, String> {
    with_broker_runtime(|runtime| {
        let detail = runtime
            .apps_tools_consumer_detail(consumer_id)
            .map_err(|error| format!("Apps & Tools Consumer detail unavailable: {error}"))?;
        Ok(AppsToolsUsageProfileSetupView::new(
            consumer_id,
            detail.consumer().identity_evidence().executable_name(),
        ))
    })
}

#[cfg(target_os = "macos")]
fn create_apps_tools_usage_profile(
    consumer_id: ConsumerId,
    label: String,
    template_id: &str,
    technical_name: Option<&str>,
) -> Result<AppsToolsUsageProfileView, String> {
    let template_id = template_id
        .parse::<BundledUsageProfileTemplateId>()
        .map_err(|_| "unknown Apps & Tools Usage Profile template".to_owned())?;
    let template = bundled_usage_profile_template(template_id)
        .ok_or_else(|| "Apps & Tools Usage Profile template unavailable".to_owned())?;
    let technical_name = technical_name
        .map(str::trim)
        .filter(|technical_name| !technical_name.is_empty());
    let definition = template
        .instantiate(technical_name)
        .map_err(|_| "Apps & Tools Usage Profile configuration is invalid".to_owned())?;
    with_broker_runtime(|runtime| {
        runtime
            .create_usage_profile(consumer_id, label.trim().to_owned(), definition)
            .map(|profile| AppsToolsUsageProfileView::from_profile(&profile))
            .map_err(|error| format!("Apps & Tools Usage Profile creation failed: {error}"))
    })
}

#[cfg(target_os = "macos")]
fn remove_apps_tools_usage_profile(
    consumer_id: ConsumerId,
    usage_profile_id: UsageProfileId,
) -> Result<bool, String> {
    with_broker_runtime(|runtime| {
        runtime
            .remove_usage_profile(consumer_id, usage_profile_id)
            .map_err(|error| format!("Apps & Tools Usage Profile removal failed: {error}"))
    })
}

#[cfg(target_os = "macos")]
fn set_apps_tools_paused(
    vault: &UnlockedVault,
    paused: bool,
) -> Result<AppsToolsSnapshotView, String> {
    let updated_at = current_state_timestamp()?;
    with_broker_runtime(|runtime| {
        runtime
            .set_machine_access_paused(paused, updated_at)
            .map_err(|error| format!("Apps & Tools pause unavailable: {error}"))?;
        apps_tools_snapshot_with_runtime(vault, runtime)
    })
}

#[cfg(target_os = "macos")]
fn revoke_apps_tools_field(
    vault: &UnlockedVault,
    consumer_id: ConsumerId,
    field_scope: CredentialFieldScope,
) -> Result<AppsToolsSnapshotView, String> {
    with_broker_runtime(|runtime| {
        runtime
            .revoke_consumer_field_access(consumer_id, field_scope)
            .map_err(|error| format!("Apps & Tools field revocation failed: {error}"))?;
        apps_tools_snapshot_with_runtime(vault, runtime)
    })
}

#[cfg(target_os = "macos")]
fn revoke_apps_tools_consumer(
    vault: &UnlockedVault,
    consumer_id: ConsumerId,
) -> Result<AppsToolsSnapshotView, String> {
    with_broker_runtime(|runtime| {
        runtime
            .revoke_consumer_access(consumer_id)
            .map_err(|error| format!("Apps & Tools Consumer revocation failed: {error}"))?;
        apps_tools_snapshot_with_runtime(vault, runtime)
    })
}

#[cfg(not(target_os = "macos"))]
fn active_authorized_credential_ids(_vault: &UnlockedVault) -> Result<Vec<String>, String> {
    Err("Apps & Tools authorization is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn apps_tools_pending_requests() -> Result<AppsToolsPendingRequestQueueView, String> {
    Err("Apps & Tools pending requests are unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn deny_apps_tools_pending_request(
    _request_source: &str,
    _request_id: &str,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    Err("Apps & Tools pending request decisions are unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn approve_apps_tools_pairing(
    _request_id: &str,
    _label: String,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    Err("Apps & Tools pairing approval is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn approve_apps_tools_pending_unlock(
    _vault: &UnlockedVault,
    _request_id: &str,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    Err("Apps & Tools unlock approval is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn review_apps_tools_pending_credential(
    _vault: &UnlockedVault,
    _request_id: &str,
) -> Result<AppsToolsCredentialReviewView, String> {
    Err("Apps & Tools credential review is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn allow_apps_tools_pending_request_once(
    _vault: &UnlockedVault,
    _request_id: &str,
    _credential_id: Option<&str>,
    _secret_field_id: Option<&str>,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    Err("Apps & Tools Allow Once is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn configure_apps_tools_long_term_access(
    _vault: &UnlockedVault,
    _request_id: &str,
    _credential_id: Option<&str>,
    _secret_field_id: Option<&str>,
    _confirmation_policy: &str,
) -> Result<AppsToolsPendingRequestDecisionView, String> {
    Err("Apps & Tools long-term access is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn apps_tools_snapshot(_vault: &UnlockedVault) -> Result<AppsToolsSnapshotView, String> {
    Err("Apps & Tools management is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn apps_tools_consumer_detail(
    _vault: &UnlockedVault,
    _consumer_id: ConsumerId,
) -> Result<AppsToolsConsumerDetailView, String> {
    Err("Apps & Tools management is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn apps_tools_usage_profile_setup(
    _consumer_id: ConsumerId,
) -> Result<AppsToolsUsageProfileSetupView, String> {
    Err("Apps & Tools Usage Profiles are unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn create_apps_tools_usage_profile(
    _consumer_id: ConsumerId,
    _label: String,
    _template_id: &str,
    _technical_name: Option<&str>,
) -> Result<AppsToolsUsageProfileView, String> {
    Err("Apps & Tools Usage Profiles are unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn remove_apps_tools_usage_profile(
    _consumer_id: ConsumerId,
    _usage_profile_id: UsageProfileId,
) -> Result<bool, String> {
    Err("Apps & Tools Usage Profiles are unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn set_apps_tools_paused(
    _vault: &UnlockedVault,
    _paused: bool,
) -> Result<AppsToolsSnapshotView, String> {
    Err("Apps & Tools management is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn revoke_apps_tools_field(
    _vault: &UnlockedVault,
    _consumer_id: ConsumerId,
    _field_scope: CredentialFieldScope,
) -> Result<AppsToolsSnapshotView, String> {
    Err("Apps & Tools management is unsupported on this platform".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn revoke_apps_tools_consumer(
    _vault: &UnlockedVault,
    _consumer_id: ConsumerId,
) -> Result<AppsToolsSnapshotView, String> {
    Err("Apps & Tools management is unsupported on this platform".to_owned())
}

fn credential_draft_from_template(
    template_id: String,
    title: String,
    secret: String,
    expiry: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    favorite: bool,
) -> Result<CredentialDraft, String> {
    let template = built_in_credential_template(&template_id)
        .ok_or_else(|| "unknown built-in credential template".to_owned())?;
    if !matches!(
        template.id,
        "api-token" | "api-key" | "ssh-key" | "certificate" | "custom"
    ) {
        return Err("credential template uses a dedicated human editor".to_owned());
    }
    if title.trim().is_empty() {
        return Err("credential title is required".to_owned());
    }
    if template.primary_secret_required && secret.is_empty() {
        return Err("credential secret is required".to_owned());
    }

    let mut fields = vec![CredentialField::secret(
        template.primary_secret_role,
        template.primary_secret_kind,
        SecretBytes::new(secret.into_bytes()),
    )];
    push_template_text_field(&mut fields, template.optional_text_roles, "expiry", expiry)?;
    push_template_text_field(&mut fields, template.optional_text_roles, "notes", notes)?;
    Ok(CredentialDraft {
        title: title.trim().to_owned(),
        template_id: Some(template.id.to_owned()),
        fields,
        tags,
        favorite,
    })
}

fn credential_edit(
    title: String,
    template_id: Option<String>,
    fields: Vec<CredentialFieldEditCommand>,
    tags: Vec<String>,
    favorite: bool,
) -> Result<CredentialEdit, String> {
    let fields = fields
        .into_iter()
        .map(|field| match field {
            CredentialFieldEditCommand::Text { role, label, text } => {
                Ok(CredentialFieldEdit::Text {
                    role,
                    label: normalized_optional_label(label),
                    text,
                })
            }
            CredentialFieldEditCommand::ExistingSecret {
                role,
                label,
                secret_field_id,
                replacement,
            } => Ok(CredentialFieldEdit::ExistingSecret {
                role,
                label: normalized_optional_label(label),
                secret_field_id: secret_field_id
                    .parse()
                    .map_err(|_| "invalid secret-field identity".to_owned())?,
                replacement: replacement.map(|value| SecretBytes::new(value.into_bytes())),
            }),
            CredentialFieldEditCommand::NewSecret {
                role,
                label,
                secret_kind,
                secret,
            } => {
                if secret.is_empty() {
                    return Err("new credential secret is required".to_owned());
                }
                Ok(CredentialFieldEdit::NewSecret {
                    role,
                    label: normalized_optional_label(label),
                    kind: secret_kind
                        .parse::<SecretFieldKind>()
                        .map_err(|_| "invalid secret-field kind".to_owned())?,
                    secret: SecretBytes::new(secret.into_bytes()),
                })
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(CredentialEdit {
        title: title.trim().to_owned(),
        template_id: normalized_optional_label(template_id),
        fields,
        tags,
        favorite,
    })
}

fn normalized_optional_label(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

#[cfg(target_os = "macos")]
fn revoke_removed_field_authorizations(
    vault_id: psw_core::VaultId,
    credential_id: psw_core::CredentialId,
    removed_secret_field_ids: &[SecretFieldId],
) -> Result<(), String> {
    if removed_secret_field_ids.is_empty() {
        return Ok(());
    }
    let paths = DevicePaths::prepare_for_current_user()
        .map_err(|error| format!("Apps & Tools paths unavailable: {error}"))?;
    let database_exists = paths
        .state()
        .join(DEVICE_STATE_DATABASE_FILENAME)
        .try_exists()
        .map_err(|_| "Apps & Tools state availability could not be checked".to_owned())?;
    if !database_exists {
        return Ok(());
    }
    let root_key = DeviceKeyManager::new(MacOsDeviceKeyStore::new())
        .load_existing()
        .map_err(|error| format!("Apps & Tools device key unavailable: {error}"))?;
    let mut store = DeviceStateStore::open_existing(&paths, &root_key)
        .map_err(|error| format!("Apps & Tools state unavailable: {error}"))?;
    for secret_field_id in removed_secret_field_ids {
        store
            .remove_field_authorization(CredentialFieldScope::new(
                vault_id,
                credential_id,
                *secret_field_id,
            ))
            .map_err(|error| format!("Apps & Tools authorization cleanup unavailable: {error}"))?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn revoke_removed_field_authorizations(
    _vault_id: psw_core::VaultId,
    _credential_id: psw_core::CredentialId,
    removed_secret_field_ids: &[SecretFieldId],
) -> Result<(), String> {
    if removed_secret_field_ids.is_empty() {
        Ok(())
    } else {
        Err("Apps & Tools authorization cleanup is unsupported on this platform".to_owned())
    }
}

fn push_template_text_field(
    fields: &mut Vec<CredentialField>,
    supported_roles: &[&str],
    role: &'static str,
    value: Option<String>,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() {
        return Ok(());
    }
    if !supported_roles.contains(&role) {
        return Err(format!(
            "credential template does not support the '{role}' field"
        ));
    }
    fields.push(CredentialField::text(role, value.trim().to_owned()));
    Ok(())
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

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "camelCase", deny_unknown_fields)]
enum Command {
    Version {},
    CreateVault {
        path: String,
        display_name: Option<String>,
        password: String,
    },
    OpenVault {
        path: String,
    },
    LockedRecoveryStatus {
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
    RecoverVault {
        path: String,
        recovery_code: String,
        new_password: String,
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
    RecoveryStatus {
        session_id: u64,
    },
    BeginRecoverySetup {
        session_id: u64,
    },
    BeginRecoveryRotation {
        session_id: u64,
    },
    ConfirmRecoveryWorkflow {
        session_id: u64,
        workflow_id: u64,
        recovery_code: String,
    },
    CancelRecoveryWorkflow {
        session_id: u64,
        workflow_id: u64,
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
    ListAuthorizedCredentialIds {
        session_id: u64,
    },
    AppsToolsPendingRequests,
    AppsToolsDenyPendingRequest {
        request_source: String,
        request_id: String,
    },
    AppsToolsApprovePairing {
        request_id: String,
        label: String,
    },
    AppsToolsApprovePendingUnlock {
        session_id: u64,
        request_id: String,
    },
    AppsToolsReviewPendingCredential {
        session_id: u64,
        request_id: String,
    },
    AppsToolsAllowOnce {
        session_id: u64,
        request_id: String,
        credential_id: Option<String>,
        secret_field_id: Option<String>,
    },
    AppsToolsConfigureLongTermAccess {
        session_id: u64,
        request_id: String,
        credential_id: Option<String>,
        secret_field_id: Option<String>,
        confirmation_policy: String,
    },
    AppsToolsSnapshot {
        session_id: u64,
    },
    AppsToolsConsumerDetail {
        session_id: u64,
        consumer_id: String,
    },
    AppsToolsUsageProfileSetup {
        session_id: u64,
        consumer_id: String,
    },
    CreateAppsToolsUsageProfile {
        session_id: u64,
        consumer_id: String,
        label: String,
        template_id: String,
        technical_name: Option<String>,
    },
    RemoveAppsToolsUsageProfile {
        session_id: u64,
        consumer_id: String,
        usage_profile_id: String,
    },
    SetAppsToolsPaused {
        session_id: u64,
        paused: bool,
    },
    RevokeAppsToolsField {
        session_id: u64,
        consumer_id: String,
        vault_id: String,
        credential_id: String,
        secret_field_id: String,
    },
    RevokeAppsToolsConsumer {
        session_id: u64,
        consumer_id: String,
    },
    CreateCredentialFromTemplate {
        session_id: u64,
        template_id: String,
        title: String,
        secret: String,
        expiry: Option<String>,
        notes: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        favorite: bool,
    },
    UpdateCredential {
        session_id: u64,
        credential_id: String,
        expected_revision: String,
        title: String,
        template_id: Option<String>,
        fields: Vec<CredentialFieldEditCommand>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        favorite: bool,
    },
    DuplicateCredential {
        session_id: u64,
        credential_id: String,
        expected_revision: String,
        title: String,
    },
    GetCredential {
        session_id: u64,
        credential_id: String,
    },
    GetCredentialSecretField {
        session_id: u64,
        credential_id: String,
        secret_field_id: String,
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
        current_password: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "value_type", rename_all = "camelCase")]
enum CredentialFieldEditCommand {
    Text {
        role: String,
        label: Option<String>,
        text: String,
    },
    ExistingSecret {
        role: String,
        label: Option<String>,
        secret_field_id: String,
        replacement: Option<String>,
    },
    NewSecret {
        role: String,
        label: Option<String>,
        secret_kind: String,
        secret: String,
    },
}

#[derive(Debug, Deserialize)]
struct ConflictMergeFieldSelectionCommand {
    field_label: String,
    revision: String,
}

struct SecretResponseString(String);

impl SecretResponseString {
    fn new(value: String) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for SecretResponseString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretResponseString([REDACTED])")
    }
}

impl Serialize for SecretResponseString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl Drop for SecretResponseString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
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
        apps_tools_vault_path_conflict: bool,
    },
    Items {
        items: Vec<ItemView>,
    },
    AuthorizedCredentialIds {
        credential_ids: Vec<String>,
    },
    AppsToolsPendingRequests {
        queue: AppsToolsPendingRequestQueueView,
    },
    AppsToolsPendingRequestDecision {
        decision: AppsToolsPendingRequestDecisionView,
    },
    AppsToolsCredentialReview {
        review: AppsToolsCredentialReviewView,
    },
    AppsToolsSnapshot {
        snapshot: AppsToolsSnapshotView,
    },
    AppsToolsConsumerDetail {
        detail: AppsToolsConsumerDetailView,
    },
    AppsToolsUsageProfileSetup {
        setup: AppsToolsUsageProfileSetupView,
    },
    AppsToolsUsageProfileCreated {
        consumer_id: String,
        profile: AppsToolsUsageProfileView,
    },
    AppsToolsUsageProfileRemoved {
        consumer_id: String,
        usage_profile_id: String,
        removed: bool,
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
    RecoveryStatus {
        has_recovery_envelope: bool,
        recovery_key_id: Option<psw_core::RecoveryKeyId>,
    },
    RecoveryKit {
        workflow_id: u64,
        workflow_kind: &'static str,
        vault_id: String,
        recovery_key_id: String,
        generated_at_unix_seconds: u64,
        canonical_code: SecretResponseString,
        grouped_code: SecretResponseString,
        qr_payload: SecretResponseString,
        verification_groups: Vec<SecretResponseString>,
    },
    RecoveryConfirmed {
        workflow_kind: &'static str,
        recovery_key_id: String,
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
    CredentialDetail {
        detail: CredentialDetailView,
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
        omissions: Vec<ExportOmissionView>,
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

#[derive(Debug, Serialize)]
struct ExportOmissionView {
    reason: &'static str,
    count: usize,
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
struct AppsToolsSnapshotView {
    paused: bool,
    authorized_credential_ids: Vec<String>,
    consumers: Vec<AppsToolsConsumerSummaryView>,
}

impl AppsToolsSnapshotView {
    fn empty() -> Self {
        Self {
            paused: false,
            authorized_credential_ids: Vec::new(),
            consumers: Vec::new(),
        }
    }

    fn from_broker(snapshot: BrokerAppsToolsSnapshot) -> Self {
        Self {
            paused: snapshot.paused(),
            authorized_credential_ids: snapshot
                .authorized_credential_ids()
                .iter()
                .map(ToString::to_string)
                .collect(),
            consumers: snapshot
                .consumers()
                .iter()
                .map(AppsToolsConsumerSummaryView::from_broker)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsConsumerIdentityView {
    executable_name: Option<String>,
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    code_signing_evidence: &'static str,
    code_signature_fingerprint: Option<String>,
}

impl AppsToolsConsumerIdentityView {
    fn from_broker(evidence: &BrokerConsumerIdentityEvidence) -> Self {
        Self {
            executable_name: evidence.executable_name().map(str::to_owned),
            bundle_identifier: evidence.bundle_identifier().map(str::to_owned),
            team_identifier: evidence.team_identifier().map(str::to_owned),
            code_signing_evidence: match evidence.code_signing_evidence() {
                ConsumerCodeSigningEvidence::NoVerifiedSignature => "no-verified-signature",
                ConsumerCodeSigningEvidence::VerifiedWithoutTeamIdentifier => {
                    "verified-without-team-identifier"
                }
                ConsumerCodeSigningEvidence::VerifiedWithTeamIdentifier => {
                    "verified-with-team-identifier"
                }
            },
            code_signature_fingerprint: evidence
                .code_signature_fingerprint()
                .map(|fingerprint| fingerprint.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsConsumerSummaryView {
    consumer_id: String,
    label: String,
    identity: AppsToolsConsumerIdentityView,
    access_rule_count: usize,
    usage_profile_count: usize,
    created_at_ms: i64,
}

impl AppsToolsConsumerSummaryView {
    fn from_broker(summary: &BrokerConsumerSummary) -> Self {
        let evidence = summary.identity_evidence();
        Self {
            consumer_id: summary.consumer_id().to_string(),
            label: summary.label().to_owned(),
            identity: AppsToolsConsumerIdentityView::from_broker(evidence),
            access_rule_count: summary.access_rule_count(),
            usage_profile_count: summary.usage_profile_count(),
            created_at_ms: summary.created_at().unix_millis(),
        }
    }
}

#[derive(Serialize)]
struct AppsToolsPendingRequestQueueView {
    pending_count: usize,
    requests: Vec<AppsToolsPendingRequestView>,
}

impl AppsToolsPendingRequestQueueView {
    fn empty() -> Self {
        Self {
            pending_count: 0,
            requests: Vec::new(),
        }
    }

    fn from_broker(queue: BrokerPendingRequestQueue) -> Self {
        Self {
            pending_count: queue.pending_count(),
            requests: queue
                .requests()
                .iter()
                .map(AppsToolsPendingRequestView::from_broker)
                .collect(),
        }
    }
}

impl std::fmt::Debug for AppsToolsPendingRequestQueueView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppsToolsPendingRequestQueueView")
            .field("pending_count", &self.pending_count)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsPendingRequestDecisionView {
    action: &'static str,
    status: &'static str,
    use_grant_id: Option<String>,
    access_rule_id: Option<String>,
}

impl AppsToolsPendingRequestDecisionView {
    fn new(action: &'static str, status: &'static str) -> Self {
        Self {
            action,
            status,
            use_grant_id: None,
            access_rule_id: None,
        }
    }

    fn with_use_grant_id(mut self, use_grant_id: String) -> Self {
        self.use_grant_id = Some(use_grant_id);
        self
    }

    fn with_access_rule_id(mut self, access_rule_id: String) -> Self {
        self.access_rule_id = Some(access_rule_id);
        self
    }
}

#[derive(Serialize)]
struct AppsToolsCredentialReviewView {
    request_id: String,
    request_description: String,
    capability: String,
    capability_version: u16,
    truncated: bool,
    candidates: Vec<AppsToolsCredentialCandidateView>,
}

impl AppsToolsCredentialReviewView {
    #[cfg(target_os = "macos")]
    fn from_broker(request_id: ApprovalRequestId, review: &BrokerHumanCredentialReview) -> Self {
        Self {
            request_id: request_id.to_string(),
            request_description: review.description().to_owned(),
            capability: review.capability().name().as_str().to_owned(),
            capability_version: review.capability().version(),
            truncated: review.truncated(),
            candidates: review
                .candidates()
                .iter()
                .map(|candidate| AppsToolsCredentialCandidateView {
                    credential_id: candidate.credential_id().to_string(),
                    title: candidate.title().to_owned(),
                    template_id: candidate.template_id().map(str::to_owned),
                    tags: candidate.tags().to_vec(),
                    favorite: candidate.favorite(),
                    secret_fields: candidate
                        .secret_fields()
                        .iter()
                        .map(|field| AppsToolsCredentialFieldCandidateView {
                            secret_field_id: field.secret_field_id().to_string(),
                            role: field.role().to_owned(),
                            label: field.label().map(str::to_owned),
                            kind: field.kind().as_str().to_owned(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

impl std::fmt::Debug for AppsToolsCredentialReviewView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppsToolsCredentialReviewView")
            .field("capability", &self.capability)
            .field("capability_version", &self.capability_version)
            .field("truncated", &self.truncated)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AppsToolsCredentialCandidateView {
    credential_id: String,
    title: String,
    template_id: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    secret_fields: Vec<AppsToolsCredentialFieldCandidateView>,
}

#[derive(Serialize)]
struct AppsToolsCredentialFieldCandidateView {
    secret_field_id: String,
    role: String,
    label: Option<String>,
    kind: String,
}

#[derive(Serialize)]
struct AppsToolsPendingRequestView {
    request_source: &'static str,
    request_id: String,
    kind: &'static str,
    consumer_id: Option<String>,
    consumer_label: Option<String>,
    identity: Option<AppsToolsConsumerIdentityView>,
    pairing_comparison_code: Option<String>,
    pairing_key_fingerprint: Option<String>,
    vault_id: Option<String>,
    credential_id: Option<String>,
    secret_field_id: Option<String>,
    capability: Option<String>,
    capability_version: Option<u16>,
    request_description: Option<String>,
    created_at_ms: Option<i64>,
    expires_at_ms: Option<i64>,
    remaining_ms: Option<u64>,
}

impl AppsToolsPendingRequestView {
    fn from_broker(request: &BrokerPendingRequest) -> Self {
        let (request_source, request_id) = match request.request_id() {
            BrokerPendingRequestId::Pairing(request_id) => ("pairing", request_id.to_string()),
            BrokerPendingRequestId::Approval(request_id) => ("approval", request_id.to_string()),
        };
        let field_scope = request.field_scope();
        let capability = request.capability();
        Self {
            request_source,
            request_id,
            kind: match request.kind() {
                BrokerPendingRequestKind::Pairing => "pairing",
                BrokerPendingRequestKind::Unlock => "unlock",
                BrokerPendingRequestKind::Access => "access",
                BrokerPendingRequestKind::CredentialAccess => "credential-access",
            },
            consumer_id: request.consumer_id().map(|value| value.to_string()),
            consumer_label: request.consumer_label().map(str::to_owned),
            identity: request
                .identity_evidence()
                .map(AppsToolsConsumerIdentityView::from_broker),
            pairing_comparison_code: request
                .pairing_comparison_code()
                .map(|value| value.to_string()),
            pairing_key_fingerprint: request
                .pairing_key_fingerprint()
                .map(|value| value.to_string()),
            vault_id: request.vault_id().map(|value| value.to_string()),
            credential_id: field_scope.map(|value| value.credential_id().to_string()),
            secret_field_id: field_scope.map(|value| value.secret_field_id().to_string()),
            capability: capability.map(|value| value.name().as_str().to_owned()),
            capability_version: capability.map(|value| value.version()),
            request_description: request.request_description().map(str::to_owned),
            created_at_ms: request.created_at().map(StateTimestamp::unix_millis),
            expires_at_ms: request.expires_at().map(StateTimestamp::unix_millis),
            remaining_ms: request
                .remaining()
                .map(|remaining| u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
        }
    }
}

impl std::fmt::Debug for AppsToolsPendingRequestView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppsToolsPendingRequestView")
            .field("request_source", &self.request_source)
            .field("kind", &self.kind)
            .field("has_consumer_label", &self.consumer_label.is_some())
            .field("identity", &self.identity)
            .field(
                "has_request_description",
                &self.request_description.is_some(),
            )
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("remaining_ms", &self.remaining_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsFieldReferenceView {
    vault_id: String,
    credential_id: String,
    secret_field_id: String,
    current_vault: bool,
    credential_title: Option<String>,
    field_label: Option<String>,
    secret_kind: Option<String>,
}

impl AppsToolsFieldReferenceView {
    fn from_scope(vault: &UnlockedVault, scope: CredentialFieldScope) -> Self {
        let current_vault = vault.metadata.vault_id == Some(scope.vault_id());
        let mut credential_title = None;
        let mut field_label = None;
        let mut secret_kind = None;
        if current_vault {
            if let Ok(revision) = vault.credential_revision(scope.credential_id()) {
                credential_title = Some(revision.credential().draft().title.clone());
                if let Some(field) = revision.credential().draft().fields.iter().find(|field| {
                    matches!(
                        &field.value,
                        CredentialFieldValue::Secret {
                            secret_field_id,
                            ..
                        } if *secret_field_id == scope.secret_field_id()
                    )
                }) {
                    field_label = Some(field.label.clone().unwrap_or_else(|| field.role.clone()));
                    secret_kind = match &field.value {
                        CredentialFieldValue::Secret { kind, .. } => Some(kind.to_string()),
                        CredentialFieldValue::Text { .. } => None,
                    };
                }
            }
        }
        Self {
            vault_id: scope.vault_id().to_string(),
            credential_id: scope.credential_id().to_string(),
            secret_field_id: scope.secret_field_id().to_string(),
            current_vault,
            credential_title,
            field_label,
            secret_kind,
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsFieldGrantView {
    access_rule_id: String,
    field: AppsToolsFieldReferenceView,
    capability: String,
    capability_version: u16,
    confirmation_policy: &'static str,
    lifetime: &'static str,
    expires_at_ms: Option<i64>,
    created_at_ms: i64,
    active: bool,
}

impl AppsToolsFieldGrantView {
    fn from_broker(vault: &UnlockedVault, grant: &BrokerFieldGrantSummary) -> Self {
        let (lifetime, expires_at_ms) = match grant.lifetime() {
            RuleLifetime::Persistent => ("persistent", None),
            RuleLifetime::Until(expires_at) => ("until", Some(expires_at.unix_millis())),
        };
        Self {
            access_rule_id: grant.access_rule_id().to_string(),
            field: AppsToolsFieldReferenceView::from_scope(vault, grant.field_scope()),
            capability: grant.capability().name().as_str().to_owned(),
            capability_version: grant.capability().version(),
            confirmation_policy: grant.confirmation_policy().as_str(),
            lifetime,
            expires_at_ms,
            created_at_ms: grant.created_at().unix_millis(),
            active: grant.active(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsUsagePlacementView {
    kind: &'static str,
    variable_name: Option<String>,
    append_newline: Option<bool>,
    reference_variable_name: Option<String>,
    render_dev_fd_path: Option<bool>,
    header_name: Option<String>,
}

impl AppsToolsUsagePlacementView {
    fn from_broker(placement: &UsagePlacement) -> Self {
        match placement {
            UsagePlacement::ProcessEnvironment { variable_name } => Self {
                kind: "process-environment",
                variable_name: Some(variable_name.clone()),
                append_newline: None,
                reference_variable_name: None,
                render_dev_fd_path: None,
                header_name: None,
            },
            UsagePlacement::ProcessStdin { append_newline } => Self {
                kind: "process-stdin",
                variable_name: None,
                append_newline: Some(*append_newline),
                reference_variable_name: None,
                render_dev_fd_path: None,
                header_name: None,
            },
            UsagePlacement::ProcessFileDescriptor {
                reference_variable_name,
                render_dev_fd_path,
            } => Self {
                kind: "process-file-descriptor",
                variable_name: None,
                append_newline: None,
                reference_variable_name: reference_variable_name.clone(),
                render_dev_fd_path: Some(*render_dev_fd_path),
                header_name: None,
            },
            UsagePlacement::HttpBearerAuthorization {} => Self {
                kind: "http-bearer-authorization",
                variable_name: None,
                append_newline: None,
                reference_variable_name: None,
                render_dev_fd_path: None,
                header_name: None,
            },
            UsagePlacement::HttpHeader { header_name } => Self {
                kind: "http-header",
                variable_name: None,
                append_newline: None,
                reference_variable_name: None,
                render_dev_fd_path: None,
                header_name: Some(header_name.clone()),
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsUsageProfileView {
    usage_profile_id: String,
    label: String,
    capability: String,
    capability_version: u16,
    placement: AppsToolsUsagePlacementView,
    created_at_ms: i64,
}

impl AppsToolsUsageProfileView {
    fn from_broker(profile: &BrokerUsageProfileSummary) -> Self {
        Self {
            usage_profile_id: profile.usage_profile_id().to_string(),
            label: profile.label().to_owned(),
            capability: profile.capability().name().as_str().to_owned(),
            capability_version: profile.capability().version(),
            placement: AppsToolsUsagePlacementView::from_broker(profile.placement()),
            created_at_ms: profile.created_at().unix_millis(),
        }
    }

    fn from_profile(profile: &UsageProfile) -> Self {
        Self {
            usage_profile_id: profile.usage_profile_id().to_string(),
            label: profile.label().to_owned(),
            capability: profile.capability().name().as_str().to_owned(),
            capability_version: profile.capability().version(),
            placement: AppsToolsUsagePlacementView::from_broker(profile.placement()),
            created_at_ms: profile.created_at().unix_millis(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsUsageProfileTemplateView {
    template_id: &'static str,
    capability: &'static str,
    capability_version: u16,
    technical_field: &'static str,
    suggested_value: Option<&'static str>,
}

impl AppsToolsUsageProfileTemplateView {
    fn from_broker(template: &BundledUsageProfileTemplate) -> Self {
        let (technical_field, suggested_value) = match template.technical_field() {
            psw_broker::UsageProfileTemplateTechnicalField::None => ("none", None),
            psw_broker::UsageProfileTemplateTechnicalField::HttpHeaderName { suggested_value } => {
                ("http-header-name", Some(suggested_value))
            }
            psw_broker::UsageProfileTemplateTechnicalField::EnvironmentVariableName => {
                ("environment-variable-name", None)
            }
        };
        Self {
            template_id: template.id().as_str(),
            capability: template.capability().name().as_str(),
            capability_version: template.capability().version(),
            technical_field,
            suggested_value,
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsUsageProfileRecommendationView {
    recommendation_id: &'static str,
    template_id: &'static str,
    technical_name: &'static str,
}

impl AppsToolsUsageProfileRecommendationView {
    fn from_broker(recommendation: BundledUsageProfileRecommendation) -> Self {
        Self {
            recommendation_id: recommendation.id().as_str(),
            template_id: recommendation.template_id().as_str(),
            technical_name: recommendation.technical_name(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsUsageProfileSetupView {
    consumer_id: String,
    templates: Vec<AppsToolsUsageProfileTemplateView>,
    recommendation: Option<AppsToolsUsageProfileRecommendationView>,
}

impl AppsToolsUsageProfileSetupView {
    fn new(consumer_id: ConsumerId, executable_name: Option<&str>) -> Self {
        Self {
            consumer_id: consumer_id.to_string(),
            templates: bundled_usage_profile_templates()
                .iter()
                .map(AppsToolsUsageProfileTemplateView::from_broker)
                .collect(),
            recommendation: recommend_bundled_usage_profile(executable_name)
                .map(AppsToolsUsageProfileRecommendationView::from_broker),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsAuditEventView {
    audit_event_id: String,
    occurred_at_ms: i64,
    kind: &'static str,
    field: Option<AppsToolsFieldReferenceView>,
    capability: Option<String>,
    capability_version: Option<u16>,
    decision: &'static str,
    confirmation_method: &'static str,
}

impl AppsToolsAuditEventView {
    fn from_broker(vault: &UnlockedVault, event: &BrokerConsumerAuditSummary) -> Self {
        Self {
            audit_event_id: event.audit_event_id().to_string(),
            occurred_at_ms: event.occurred_at().unix_millis(),
            kind: event.kind().as_str(),
            field: event
                .field_scope()
                .map(|scope| AppsToolsFieldReferenceView::from_scope(vault, scope)),
            capability: event
                .capability()
                .map(|capability| capability.name().as_str().to_owned()),
            capability_version: event.capability().map(|capability| capability.version()),
            decision: event.decision().as_str(),
            confirmation_method: event.confirmation_method().as_str(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppsToolsConsumerDetailView {
    consumer: AppsToolsConsumerSummaryView,
    field_grants: Vec<AppsToolsFieldGrantView>,
    usage_profiles: Vec<AppsToolsUsageProfileView>,
    recent_audit_events: Vec<AppsToolsAuditEventView>,
}

impl AppsToolsConsumerDetailView {
    fn from_broker(vault: &UnlockedVault, detail: BrokerConsumerDetail) -> Self {
        Self {
            consumer: AppsToolsConsumerSummaryView::from_broker(detail.consumer()),
            field_grants: detail
                .field_grants()
                .iter()
                .map(|grant| AppsToolsFieldGrantView::from_broker(vault, grant))
                .collect(),
            usage_profiles: detail
                .usage_profiles()
                .iter()
                .map(AppsToolsUsageProfileView::from_broker)
                .collect(),
            recent_audit_events: detail
                .recent_audit_events()
                .iter()
                .map(|event| AppsToolsAuditEventView::from_broker(vault, event))
                .collect(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    template_id: Option<String>,
    secret_kinds: Vec<String>,
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
        let template_id = match summary.item_type {
            psw_core::ItemType::Login => "login",
            psw_core::ItemType::SecureNote => "secure-note",
            psw_core::ItemType::SoftwareLicense => "software-license",
            psw_core::ItemType::CreditCard => "credit-card",
        };
        Self {
            id: summary.id.0,
            revision: summary.revision.0,
            title: summary.title,
            item_type: summary.item_type.as_search_label().to_owned(),
            template_id: Some(template_id.to_owned()),
            secret_kinds: Vec::new(),
            status: item_status_label(summary.status),
            conflict_id,
            favorite: summary.favorite,
            tags: summary.tags,
        }
    }

    fn from_credential(item: CredentialListItem) -> Self {
        let conflict_id = match &item.status {
            ItemStatus::Conflicted(conflict_id) => Some(conflict_id.0.clone()),
            _ => None,
        };
        let template_id = item.credential.template_id.clone();
        let item_type = template_id
            .as_deref()
            .map(template_item_type_label)
            .unwrap_or_else(|| "custom".to_owned());
        Self {
            id: item.credential.credential_id.to_string(),
            revision: item.revision_id.to_string(),
            title: item.credential.title,
            item_type,
            template_id,
            secret_kinds: item
                .credential
                .secret_fields
                .into_iter()
                .map(|field| field.kind.to_string())
                .collect(),
            status: item_status_label(item.status),
            conflict_id,
            favorite: item.credential.favorite,
            tags: item.credential.tags,
        }
    }
}

fn template_item_type_label(template_id: &str) -> String {
    template_id.replace('-', " ")
}

#[derive(Debug, Serialize)]
struct CredentialDetailView {
    id: String,
    revision: String,
    title: String,
    template_id: Option<String>,
    fields: Vec<CredentialFieldView>,
    favorite: bool,
    tags: Vec<String>,
    status: &'static str,
}

impl CredentialDetailView {
    fn from_revision(revision: psw_core::CredentialRevision) -> Self {
        let credential = revision.credential();
        Self {
            id: credential.credential_id().to_string(),
            revision: revision.revision_id().to_string(),
            title: credential.draft().title.clone(),
            template_id: credential.draft().template_id.clone(),
            fields: credential
                .draft()
                .fields
                .iter()
                .map(CredentialFieldView::from_field)
                .collect(),
            favorite: credential.draft().favorite,
            tags: credential.draft().tags.clone(),
            status: match revision.lifecycle() {
                psw_core::CredentialLifecycle::Active => "active",
                psw_core::CredentialLifecycle::Archived => "archived",
                psw_core::CredentialLifecycle::Deleted => "deleted",
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "value_type", rename_all = "camelCase")]
enum CredentialFieldView {
    Text {
        role: String,
        label: Option<String>,
        text: String,
    },
    Secret {
        role: String,
        label: Option<String>,
        secret_field_id: String,
        secret_kind: String,
        has_value: bool,
    },
}

impl CredentialFieldView {
    fn from_field(field: &CredentialField) -> Self {
        match &field.value {
            CredentialFieldValue::Text { text } => Self::Text {
                role: field.role.clone(),
                label: field.label.clone(),
                text: text.clone(),
            },
            CredentialFieldValue::Secret {
                secret_field_id,
                kind,
                secret,
            } => Self::Secret {
                role: field.role.clone(),
                label: field.label.clone(),
                secret_field_id: secret_field_id.to_string(),
                secret_kind: kind.to_string(),
                has_value: !secret.expose().is_empty(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct ConflictCandidateView {
    item_id: String,
    revision: String,
    title: String,
    item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template_id: Option<String>,
    status: String,
    favorite: bool,
    tags: Vec<String>,
    comparison_fields: Vec<ConflictCandidateFieldView>,
    changed_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
    credential_fields: Vec<ConflictCandidateCredentialFieldView>,
    field_shape_changed: bool,
    supports_safe_field_merge: bool,
}

#[derive(Debug, Serialize)]
struct ConflictCandidateFieldView {
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    redacted: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "value_type", rename_all = "camelCase")]
enum ConflictCandidateCredentialFieldView {
    Text {
        index: usize,
        role: String,
        label: Option<String>,
        text: String,
        changed: bool,
    },
    Secret {
        index: usize,
        role: String,
        label: Option<String>,
        secret_field_id: String,
        secret_kind: String,
        has_value: bool,
        changed: bool,
    },
}

impl ConflictCandidateView {
    fn from_summary(summary: psw_core::ConflictCandidateSummary) -> Self {
        Self {
            item_id: summary.item_id.0,
            revision: summary.revision.0,
            title: summary.title,
            item_type: summary.item_type,
            template_id: summary.template_id,
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
            credential_fields: summary
                .credential_fields
                .into_iter()
                .map(ConflictCandidateCredentialFieldView::from_field)
                .collect(),
            field_shape_changed: summary.field_shape_changed,
            supports_safe_field_merge: summary.supports_safe_field_merge,
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

impl ConflictCandidateCredentialFieldView {
    fn from_field(field: psw_core::ConflictCandidateCredentialField) -> Self {
        match field {
            psw_core::ConflictCandidateCredentialField::Text {
                index,
                role,
                label,
                text,
                changed,
            } => Self::Text {
                index,
                role,
                label,
                text,
                changed,
            },
            psw_core::ConflictCandidateCredentialField::Secret {
                index,
                role,
                label,
                secret_field_id,
                secret_kind,
                has_value,
                changed,
            } => Self::Secret {
                index,
                role,
                label,
                secret_field_id: secret_field_id.to_string(),
                secret_kind: secret_kind.to_string(),
                has_value,
                changed,
            },
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
    if !input.len().is_multiple_of(2) {
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
    use std::collections::BTreeSet;
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
    fn ffi_command_parser_rejects_unknown_fields_without_echoing_values() {
        let marker = "KN_FFI_UNKNOWN_PRIVATE_MARKER";
        let input = CString::new(format!(
            r#"{{"command":"version","private_marker":"{marker}"}}"#
        ))
        .expect("cstring");

        let response_ptr = unsafe { crate::psw_command(input.as_ptr()) };
        assert!(!response_ptr.is_null());
        let response = unsafe { CStr::from_ptr(response_ptr) }
            .to_string_lossy()
            .to_string();
        unsafe { crate::psw_string_free(response_ptr) };

        assert!(response.contains(r#""ok":false"#));
        assert!(!response.contains(marker));
    }

    #[test]
    fn ffi_authorized_credential_projection_serializes_stable_ids_only() {
        let serialized = serde_json::to_value(super::ResponsePayload::AuthorizedCredentialIds {
            credential_ids: vec![
                "credential_01J_AUTHORIZED".to_owned(),
                "credential_01J_SECOND".to_owned(),
            ],
        })
        .expect("serialize authorized credential projection");

        assert_eq!(serialized["type"], "authorizedCredentialIds");
        assert_eq!(
            serialized["credential_ids"],
            json!(["credential_01J_AUTHORIZED", "credential_01J_SECOND"])
        );
        let object = serialized.as_object().expect("projection object");
        assert_eq!(object.len(), 2);
        assert!(object.contains_key("type"));
        assert!(object.contains_key("credential_ids"));
    }

    #[test]
    fn ffi_unlocked_projection_exposes_only_a_path_free_conflict_signal() {
        let path_marker = "/Users/private/Personal.pswvault";
        let serialized = serde_json::to_value(super::ResponsePayload::Unlocked {
            session_id: 7,
            items: Vec::new(),
            apps_tools_vault_path_conflict: true,
        })
        .expect("serialize unlocked projection");

        assert_eq!(serialized["type"], "unlocked");
        assert_eq!(serialized["session_id"], 7);
        assert_eq!(serialized["items"], json!([]));
        assert_eq!(serialized["apps_tools_vault_path_conflict"], true);
        let object = serialized.as_object().expect("unlocked object");
        assert_eq!(object.len(), 4);
        assert!(!object.contains_key("path"));
        assert!(!object.contains_key("vault_path"));
        assert!(!serialized.to_string().contains(path_marker));
    }

    #[test]
    fn ffi_apps_tools_detail_projection_excludes_secret_and_path_material() {
        let detail = super::AppsToolsConsumerDetailView {
            consumer: super::AppsToolsConsumerSummaryView {
                consumer_id: "consumer_000102030405060708090a0b0c0d0e0f".to_owned(),
                label: "Local adapter".to_owned(),
                identity: super::AppsToolsConsumerIdentityView {
                    executable_name: Some("adapter".to_owned()),
                    bundle_identifier: Some("com.example.adapter".to_owned()),
                    team_identifier: Some("EXAMPLE".to_owned()),
                    code_signing_evidence: "verified-with-team-identifier",
                    code_signature_fingerprint: Some("0102-0304-0506-0708".to_owned()),
                },
                access_rule_count: 1,
                usage_profile_count: 1,
                created_at_ms: 100,
            },
            field_grants: vec![super::AppsToolsFieldGrantView {
                access_rule_id: "access_rule_000102030405060708090a0b0c0d0e0f".to_owned(),
                field: super::AppsToolsFieldReferenceView {
                    vault_id: "vault_000102030405060708090a0b0c0d0e0f".to_owned(),
                    credential_id: "credential_000102030405060708090a0b0c0d0e0f".to_owned(),
                    secret_field_id: "secret_field_000102030405060708090a0b0c0d0e0f".to_owned(),
                    current_vault: true,
                    credential_title: Some("Deployment token".to_owned()),
                    field_label: Some("Token".to_owned()),
                    secret_kind: Some("api-token".to_owned()),
                },
                capability: "process.run".to_owned(),
                capability_version: 1,
                confirmation_policy: "every-use",
                lifetime: "persistent",
                expires_at_ms: None,
                created_at_ms: 110,
                active: true,
            }],
            usage_profiles: vec![super::AppsToolsUsageProfileView {
                usage_profile_id: "usage_profile_000102030405060708090a0b0c0d0e0f".to_owned(),
                label: "Child environment".to_owned(),
                capability: "process.run".to_owned(),
                capability_version: 1,
                placement: super::AppsToolsUsagePlacementView {
                    kind: "process-environment",
                    variable_name: Some("SERVICE_TOKEN".to_owned()),
                    append_newline: None,
                    reference_variable_name: None,
                    render_dev_fd_path: None,
                    header_name: None,
                },
                created_at_ms: 120,
            }],
            recent_audit_events: vec![],
        };

        let json =
            serde_json::to_string(&super::ResponsePayload::AppsToolsConsumerDetail { detail })
                .expect("serialize Apps & Tools detail");

        assert!(json.contains("\"type\":\"appsToolsConsumerDetail\""));
        assert!(json.contains("\"confirmation_policy\":\"every-use\""));
        assert!(json.contains("\"variable_name\":\"SERVICE_TOKEN\""));
        assert!(!json.contains("seeded-secret-marker"));
        assert!(!json.contains("/Users/chase"));
        assert!(!json.contains("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"));
    }

    #[test]
    fn ffi_usage_profile_setup_is_offline_bounded_and_exactly_recommended() {
        let consumer_id = "consumer_000102030405060708090a0b0c0d0e0f"
            .parse::<psw_broker::ConsumerId>()
            .expect("Consumer identity");
        let setup = super::AppsToolsUsageProfileSetupView::new(consumer_id, Some("gh"));
        let serialized =
            serde_json::to_value(super::ResponsePayload::AppsToolsUsageProfileSetup { setup })
                .expect("serialize Usage Profile setup");

        assert_eq!(serialized["type"], "appsToolsUsageProfileSetup");
        assert_eq!(
            serialized["setup"]["consumer_id"],
            "consumer_000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            serialized["setup"]["templates"]
                .as_array()
                .expect("template catalog")
                .iter()
                .map(|template| template["template_id"].as_str().expect("template identity"))
                .collect::<Vec<_>>(),
            vec![
                "http-bearer-authorization",
                "http-api-key-header",
                "cli-environment-variable",
            ]
        );
        assert_eq!(
            serialized["setup"]["recommendation"]["recommendation_id"],
            "github-cli"
        );
        assert_eq!(
            serialized["setup"]["recommendation"]["template_id"],
            "cli-environment-variable"
        );
        assert_eq!(
            serialized["setup"]["recommendation"]["technical_name"],
            "GH_TOKEN"
        );

        let encoded = serialized.to_string();
        for forbidden in [
            "seeded-secret-marker",
            "/Users/chase",
            "\"script\"",
            "\"command\"",
            "\"arguments\"",
            "\"url\"",
            "\"request_body\"",
        ] {
            assert!(!encoded.contains(forbidden));
        }

        let unknown = super::AppsToolsUsageProfileSetupView::new(consumer_id, Some("github"));
        assert!(unknown.recommendation.is_none());
    }

    #[test]
    fn ffi_usage_profile_commands_and_receipts_bind_stable_identities() {
        let command = serde_json::from_value::<super::Command>(json!({
            "command": "createAppsToolsUsageProfile",
            "session_id": 7,
            "consumer_id": "consumer_000102030405060708090a0b0c0d0e0f",
            "label": "GitHub CLI",
            "template_id": "cli-environment-variable",
            "technical_name": "GH_TOKEN"
        }))
        .expect("decode create command");
        match command {
            super::Command::CreateAppsToolsUsageProfile {
                session_id,
                consumer_id,
                label,
                template_id,
                technical_name,
            } => {
                assert_eq!(session_id, 7);
                assert_eq!(consumer_id, "consumer_000102030405060708090a0b0c0d0e0f");
                assert_eq!(label, "GitHub CLI");
                assert_eq!(template_id, "cli-environment-variable");
                assert_eq!(technical_name.as_deref(), Some("GH_TOKEN"));
            }
            _ => panic!("unexpected command"),
        }

        let consumer_id = "consumer_000102030405060708090a0b0c0d0e0f"
            .parse::<psw_broker::ConsumerId>()
            .expect("Consumer identity");
        let template = psw_broker::bundled_usage_profile_template(
            psw_broker::BundledUsageProfileTemplateId::CliEnvironmentVariable,
        )
        .expect("CLI template");
        let profile = psw_broker::UsageProfile::from_definition(
            consumer_id,
            "GitHub CLI".to_owned(),
            template.instantiate(Some("GH_TOKEN")).expect("definition"),
            psw_broker::StateTimestamp::from_unix_millis(100).expect("timestamp"),
        )
        .expect("Usage Profile");
        let profile_id = profile.usage_profile_id().to_string();
        let created = serde_json::to_value(super::ResponsePayload::AppsToolsUsageProfileCreated {
            consumer_id: consumer_id.to_string(),
            profile: super::AppsToolsUsageProfileView::from_profile(&profile),
        })
        .expect("serialize created profile");
        assert_eq!(created["type"], "appsToolsUsageProfileCreated");
        assert_eq!(created["consumer_id"], consumer_id.to_string());
        assert_eq!(created["profile"]["usage_profile_id"], profile_id);
        assert_eq!(created["profile"]["placement"]["variable_name"], "GH_TOKEN");
        assert!(created.get("secret").is_none());

        let removed = serde_json::to_value(super::ResponsePayload::AppsToolsUsageProfileRemoved {
            consumer_id: consumer_id.to_string(),
            usage_profile_id: profile_id.clone(),
            removed: true,
        })
        .expect("serialize removal receipt");
        assert_eq!(removed["type"], "appsToolsUsageProfileRemoved");
        assert_eq!(removed["usage_profile_id"], profile_id);
        assert_eq!(removed["removed"], true);
        assert!(!removed.to_string().contains("seeded-secret-marker"));
    }

    #[test]
    fn ffi_pending_request_queue_contains_only_bounded_human_metadata() {
        let queue = super::AppsToolsPendingRequestQueueView {
            pending_count: 1,
            requests: vec![super::AppsToolsPendingRequestView {
                request_source: "approval",
                request_id: "approval_request_000102030405060708090a0b0c0d0e0f".to_owned(),
                kind: "credential-access",
                consumer_id: Some("consumer_000102030405060708090a0b0c0d0e0f".to_owned()),
                consumer_label: Some("Local adapter".to_owned()),
                identity: Some(super::AppsToolsConsumerIdentityView {
                    executable_name: Some("adapter".to_owned()),
                    bundle_identifier: Some("com.example.adapter".to_owned()),
                    team_identifier: None,
                    code_signing_evidence: "verified-without-team-identifier",
                    code_signature_fingerprint: Some("0102-0304-0506-0708".to_owned()),
                }),
                pairing_comparison_code: None,
                pairing_key_fingerprint: None,
                vault_id: Some("vault_000102030405060708090a0b0c0d0e0f".to_owned()),
                credential_id: None,
                secret_field_id: None,
                capability: Some("http.request".to_owned()),
                capability_version: Some(1),
                request_description: Some("release credential".to_owned()),
                created_at_ms: Some(100),
                expires_at_ms: Some(200),
                remaining_ms: None,
            }],
        };
        let debug = format!("{queue:?}");
        assert!(!debug.contains("release credential"));
        assert!(!debug.contains("Local adapter"));

        let json =
            serde_json::to_string(&super::ResponsePayload::AppsToolsPendingRequests { queue })
                .expect("serialize pending request queue");

        assert!(json.contains("\"type\":\"appsToolsPendingRequests\""));
        assert!(json.contains("\"pending_count\":1"));
        assert!(json.contains("\"kind\":\"credential-access\""));
        assert!(json.contains("\"request_description\":\"release credential\""));
        assert!(!json.contains("seeded-secret-marker"));
        assert!(!json.contains("/Users/chase"));
        assert!(!json.contains("pairing_public_key"));
        assert!(!json.contains("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"));
    }

    #[test]
    fn ffi_credential_review_and_allow_once_receipt_exclude_secret_and_path_material() {
        let review = super::AppsToolsCredentialReviewView {
            request_id: "approval_request_000102030405060708090a0b0c0d0e0f".to_owned(),
            request_description: "release credential".to_owned(),
            capability: "process.run".to_owned(),
            capability_version: 1,
            truncated: false,
            candidates: vec![super::AppsToolsCredentialCandidateView {
                credential_id: "credential_000102030405060708090a0b0c0d0e0f".to_owned(),
                title: "GitHub release token".to_owned(),
                template_id: Some("api-token".to_owned()),
                tags: vec!["production".to_owned()],
                favorite: true,
                secret_fields: vec![super::AppsToolsCredentialFieldCandidateView {
                    secret_field_id: "secret_field_000102030405060708090a0b0c0d0e0f".to_owned(),
                    role: "token".to_owned(),
                    label: Some("Release token".to_owned()),
                    kind: "api-token".to_owned(),
                }],
            }],
        };
        let debug = format!("{review:?}");
        assert!(!debug.contains("release credential"));
        assert!(!debug.contains("GitHub release token"));
        assert!(!debug.contains("production"));
        assert!(!debug.contains("Release token"));

        let json =
            serde_json::to_string(&super::ResponsePayload::AppsToolsCredentialReview { review })
                .expect("serialize credential review");
        assert!(json.contains("\"type\":\"appsToolsCredentialReview\""));
        assert!(json.contains("\"title\":\"GitHub release token\""));
        assert!(json.contains("\"kind\":\"api-token\""));
        assert!(!json.contains("seeded-secret-marker"));
        assert!(!json.contains("/Users/chase"));
        assert!(!json.contains("pairing_public_key"));

        let decision = super::AppsToolsPendingRequestDecisionView::new("allow-once", "approved")
            .with_use_grant_id("use_grant_000102030405060708090a0b0c0d0e0f".to_owned());
        let decision_json =
            serde_json::to_string(&super::ResponsePayload::AppsToolsPendingRequestDecision {
                decision,
            })
            .expect("serialize Allow Once receipt");
        assert!(decision_json.contains("\"action\":\"allow-once\""));
        assert!(decision_json.contains("\"status\":\"approved\""));
        assert!(decision_json.contains("\"use_grant_id\":\"use_grant_"));
        assert!(!decision_json.contains("seeded-secret-marker"));

        let persistent_decision = super::AppsToolsPendingRequestDecisionView::new(
            "configure-long-term-access",
            "approved",
        )
        .with_access_rule_id("access_rule_000102030405060708090a0b0c0d0e0f".to_owned());
        let persistent_json =
            serde_json::to_string(&super::ResponsePayload::AppsToolsPendingRequestDecision {
                decision: persistent_decision,
            })
            .expect("serialize persistent rule receipt");
        assert!(persistent_json.contains("\"action\":\"configure-long-term-access\""));
        assert!(persistent_json.contains("\"access_rule_id\":\"access_rule_"));
        assert!(persistent_json.contains("\"use_grant_id\":null"));
        assert!(!persistent_json.contains("seeded-secret-marker"));
        assert!(!persistent_json.contains("/Users/chase"));
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
            template_id: Some("login".to_owned()),
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
            credential_fields: vec![
                psw_core::ConflictCandidateCredentialField::Text {
                    index: 0,
                    role: "username".to_owned(),
                    label: None,
                    text: "alice".to_owned(),
                    changed: false,
                },
                psw_core::ConflictCandidateCredentialField::Secret {
                    index: 1,
                    role: "password".to_owned(),
                    label: None,
                    secret_field_id: psw_core::SecretFieldId::generate(),
                    secret_kind: psw_core::SecretFieldKind::Password,
                    has_value: true,
                    changed: true,
                },
            ],
            field_shape_changed: false,
            supports_safe_field_merge: true,
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
        assert_eq!(serialized["template_id"], "login");
        assert_eq!(serialized["credential_fields"][0]["value_type"], "text");
        assert_eq!(serialized["credential_fields"][0]["text"], "alice");
        assert_eq!(serialized["credential_fields"][1]["value_type"], "secret");
        assert_eq!(
            serialized["credential_fields"][1]["secret_kind"],
            "password"
        );
        assert_eq!(serialized["credential_fields"][1]["has_value"], true);
        assert_eq!(serialized["credential_fields"][1]["changed"], true);
        assert_eq!(serialized["field_shape_changed"], false);
        assert_eq!(serialized["supports_safe_field_merge"], true);
        assert!(!serialized.to_string().contains("secret-value-marker"));
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
        assert_eq!(
            updated["payload"]["title"], "Recovery Notes Edited",
            "{updated}"
        );
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
            "export_format": "bitwarden-json",
            "current_password": "correct horse"
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

        let missing_password = command_result(json!({
            "command": "exportItems",
            "session_id": session_id,
            "destination_path": destination.clone(),
            "export_format": "bitwarden-json"
        }));
        assert_eq!(missing_password["ok"], false);
        assert!(!destination_path.exists());

        let wrong_password_marker = "KN_FFI_EXPORT_WRONG_PASSWORD_11_3";
        let wrong_password = command_result(json!({
            "command": "exportItems",
            "session_id": session_id,
            "destination_path": destination.clone(),
            "export_format": "bitwarden-json",
            "current_password": wrong_password_marker
        }));
        assert_eq!(wrong_password["ok"], false);
        assert!(wrong_password["error"]
            .as_str()
            .expect("wrong-password error")
            .contains("invalid vault credentials"));
        assert!(!wrong_password.to_string().contains(wrong_password_marker));
        assert!(!destination_path.exists());

        let exported = command(json!({
            "command": "exportItems",
            "session_id": session_id,
            "destination_path": destination,
            "export_format": "bitwarden-json",
            "current_password": "correct horse"
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
    fn ffi_typed_export_preserves_tokens_and_reports_compatibility_omissions() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-typed-export-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();
        let typed_destination_path = vault_path.with_extension("keptnear.json");
        let compatibility_destination_path = vault_path.with_extension("bitwarden.json");

        command(json!({
            "command": "createVault",
            "path": path,
            "display_name": "FFI Typed Export",
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
            "command": "createCredentialFromTemplate",
            "session_id": session_id,
            "template_id": "api-token",
            "title": "Build API",
            "secret": "ffi-token-marker",
            "expiry": "2030-01-02",
            "notes": "automation",
            "tags": ["development"],
            "favorite": true
        }));
        let credential_id = created["payload"]["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["title"] == "Build API")
            .expect("created token")["id"]
            .as_str()
            .expect("credential id")
            .to_owned();

        let typed = command(json!({
            "command": "exportItems",
            "session_id": session_id,
            "destination_path": typed_destination_path.to_string_lossy(),
            "export_format": "keptnear-json",
            "current_password": "correct horse"
        }));
        assert_eq!(typed["payload"]["type"], "exportResult");
        assert_eq!(typed["payload"]["exported_records"], 1);
        assert_eq!(typed["payload"]["skipped_records"], 0);
        assert_eq!(typed["payload"]["omissions"], json!([]));
        let typed_json: Value =
            serde_json::from_slice(&fs::read(&typed_destination_path).expect("read typed export"))
                .expect("parse typed export");
        assert_eq!(typed_json["format"], "keptnear-plaintext-export");
        assert_eq!(typed_json["items"][0]["sourceCredentialId"], credential_id);
        assert_eq!(typed_json["items"][0]["templateId"], "api-token");
        assert_eq!(
            typed_json["items"][0]["fields"][0]["value"]["valueBase64"],
            "ZmZpLXRva2VuLW1hcmtlcg=="
        );

        let compatibility = command(json!({
            "command": "exportItems",
            "session_id": session_id,
            "destination_path": compatibility_destination_path.to_string_lossy(),
            "export_format": "bitwarden-json",
            "current_password": "correct horse"
        }));
        assert_eq!(compatibility["payload"]["exported_records"], 0);
        assert_eq!(compatibility["payload"]["skipped_records"], 1);
        assert_eq!(
            compatibility["payload"]["omissions"],
            json!([{
                "reason": "unsupported-template",
                "count": 1
            }])
        );

        let _ = fs::remove_file(typed_destination_path);
        let _ = fs::remove_file(compatibility_destination_path);
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
    fn ffi_typed_conflict_candidates_redact_and_resolve_custom_token() {
        let root = std::env::temp_dir().join(format!(
            "psw-ffi-typed-conflict-test-{}-{}",
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
            "display_name": "Typed Conflict",
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
            "command": "createCredentialFromTemplate",
            "session_id": primary_session,
            "template_id": "api-token",
            "title": "Deployment token",
            "secret": "base-private-token",
            "notes": "Production deploy",
            "tags": ["automation"]
        }));
        let item = &created["payload"]["items"][0];
        let credential_id = item["id"].as_str().expect("credential identity").to_owned();
        let base_revision = item["revision"].as_str().expect("base revision").to_owned();
        let detail = command(json!({
            "command": "getCredential",
            "session_id": primary_session,
            "credential_id": credential_id
        }));
        let fields = detail["payload"]["detail"]["fields"]
            .as_array()
            .expect("credential fields");
        let secret_field_id = fields
            .iter()
            .find(|field| field["value_type"] == "secret")
            .expect("secret field")["secret_field_id"]
            .as_str()
            .expect("secret field identity")
            .to_owned();
        let notes = fields
            .iter()
            .find(|field| field["value_type"] == "text")
            .expect("text field");
        let notes_role = notes["role"].as_str().expect("notes role").to_owned();
        let notes_text = notes["text"].as_str().expect("notes text").to_owned();

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
            "command": "updateCredential",
            "session_id": primary_session,
            "credential_id": credential_id,
            "expected_revision": base_revision,
            "title": "Left deployment token",
            "template_id": "api-token",
            "fields": [
                {
                    "value_type": "existingSecret",
                    "role": "token",
                    "secret_field_id": secret_field_id,
                    "replacement": "left-private-token"
                },
                {
                    "value_type": "text",
                    "role": notes_role,
                    "text": notes_text
                }
            ],
            "tags": ["automation"],
            "favorite": false
        }));
        let left_revision = left["payload"]["items"][0]["revision"]
            .as_str()
            .expect("left revision")
            .to_owned();
        let right = command(json!({
            "command": "updateCredential",
            "session_id": clone_session,
            "credential_id": credential_id,
            "expected_revision": base_revision,
            "title": "Right deployment token",
            "template_id": "api-token",
            "fields": [
                {
                    "value_type": "existingSecret",
                    "role": "token",
                    "secret_field_id": secret_field_id,
                    "replacement": "right-private-token"
                },
                {
                    "value_type": "text",
                    "role": notes_role,
                    "text": notes_text
                }
            ],
            "tags": ["automation"],
            "favorite": false
        }));
        let right_revision = right["payload"]["items"][0]["revision"]
            .as_str()
            .expect("right revision")
            .to_owned();
        assert_ne!(left_revision, right_revision);

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
        let candidates = command(json!({
            "command": "getConflictCandidates",
            "session_id": primary_session,
            "conflict_id": conflict_id
        }));
        let serialized = candidates.to_string();
        assert!(!serialized.contains("left-private-token"));
        assert!(!serialized.contains("right-private-token"));
        let candidates = candidates["payload"]["candidates"]
            .as_array()
            .expect("conflict candidates");
        assert_eq!(candidates.len(), 2);
        for candidate in candidates {
            assert_eq!(candidate["template_id"], "api-token");
            assert_eq!(candidate["supports_safe_field_merge"], false);
            let secret = candidate["credential_fields"]
                .as_array()
                .expect("typed fields")
                .iter()
                .find(|field| field["value_type"] == "secret")
                .expect("typed secret");
            assert_eq!(secret["secret_field_id"], secret_field_id);
            assert_eq!(secret["secret_kind"], "api-token");
            assert_eq!(secret["has_value"], true);
            assert_eq!(secret["changed"], true);
            assert!(secret.get("text").is_none());
        }

        command(json!({
            "command": "resolveConflictCandidate",
            "session_id": primary_session,
            "conflict_id": conflict_id,
            "revision": right_revision
        }));
        let refreshed = command(json!({
            "command": "refreshFromDisk",
            "session_id": primary_session
        }));
        assert_eq!(refreshed["payload"]["detected_conflicts"], 0);
        let revealed = command(json!({
            "command": "getCredentialSecretField",
            "session_id": primary_session,
            "credential_id": credential_id,
            "secret_field_id": secret_field_id
        }));
        assert_eq!(revealed["payload"]["value"], "right-private-token");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ffi_quick_resolver_never_selects_deleted_candidate_implicitly() {
        let root = std::env::temp_dir().join(format!(
            "psw-ffi-delete-edit-quick-resolve-test-{}-{}",
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
            "display_name": "Delete Edit Conflict",
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
            "title": "Base login",
            "username": "alice",
            "password": "base-private-password",
            "url": "https://example.test",
            "notes": "Primary login",
            "tags": [],
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
        command(json!({
            "command": "updateLogin",
            "session_id": primary_session,
            "item_id": item_id,
            "expected_revision": base_revision,
            "title": "Edited login",
            "username": "alice",
            "url": "https://example.test",
            "notes": "Primary login",
            "tags": [],
            "favorite": false
        }));
        command(json!({
            "command": "deleteItem",
            "session_id": clone_session,
            "item_id": item_id,
            "expected_revision": base_revision
        }));
        copy_tombstone_records(&clone_path, &vault_path);

        let refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": primary_session
        }));
        assert_eq!(refresh["payload"]["detected_conflicts"], 1);
        let conflict_id = refresh["payload"]["items"][0]["conflict_id"]
            .as_str()
            .expect("conflict id")
            .to_owned();
        let candidates = command(json!({
            "command": "getConflictCandidates",
            "session_id": primary_session,
            "conflict_id": conflict_id
        }));
        let statuses = candidates["payload"]["candidates"]
            .as_array()
            .expect("candidates")
            .iter()
            .map(|candidate| candidate["status"].as_str().expect("candidate status"))
            .collect::<BTreeSet<_>>();
        assert_eq!(statuses, BTreeSet::from(["active", "deleted"]));

        command(json!({
            "command": "resolveConflict",
            "session_id": primary_session,
            "conflict_id": conflict_id
        }));
        let refreshed = command(json!({
            "command": "refreshFromDisk",
            "session_id": primary_session
        }));
        assert_eq!(refreshed["payload"]["detected_conflicts"], 0);
        assert_eq!(refreshed["payload"]["items"][0]["title"], "Edited login");
        let password = command(json!({
            "command": "getLoginField",
            "session_id": primary_session,
            "item_id": item_id,
            "field": "password"
        }));
        assert_eq!(password["payload"]["value"], "base-private-password");

        let _ = fs::remove_dir_all(root);
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
    fn ffi_recovery_setup_renders_minimal_material_and_requires_matching_confirmation() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-recovery-kit-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path.clone(),
            "display_name": "Private Recovery Marker",
            "password": "correct horse"
        }));
        let initial_locked_status = command(json!({
            "command": "lockedRecoveryStatus",
            "path": path.clone()
        }));
        assert_eq!(
            initial_locked_status["payload"]["has_recovery_envelope"],
            false
        );
        let unlocked = command(json!({
            "command": "unlock",
            "path": path.clone(),
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");
        let status = command(json!({
            "command": "recoveryStatus",
            "session_id": session_id
        }));
        assert_eq!(status["payload"]["has_recovery_envelope"], false);

        let kit = command(json!({
            "command": "beginRecoverySetup",
            "session_id": session_id
        }));
        let payload = &kit["payload"];
        let workflow_id = payload["workflow_id"].as_u64().expect("workflow id");
        let canonical = payload["canonical_code"]
            .as_str()
            .expect("canonical recovery code");
        assert_eq!(payload["type"], "recoveryKit");
        assert_eq!(payload["workflow_kind"], "setup");
        assert!(canonical.starts_with("knr1"));
        assert_eq!(canonical.len(), 63);
        assert!(payload["grouped_code"]
            .as_str()
            .expect("grouped recovery code")
            .starts_with("KNR1 "));
        assert_eq!(payload["qr_payload"], canonical);
        assert_eq!(
            payload["verification_groups"]
                .as_array()
                .expect("verification groups")
                .len(),
            14
        );
        assert!(payload["vault_id"]
            .as_str()
            .expect("vault id")
            .starts_with("vault_"));
        assert!(payload["recovery_key_id"]
            .as_str()
            .expect("recovery key id")
            .starts_with("recovery_key_"));
        let serialized = kit.to_string();
        assert!(!serialized.contains(&path));
        assert!(!serialized.contains("Private Recovery Marker"));
        assert!(!serialized.contains("clipboard"));

        let wrong = command_result(json!({
            "command": "confirmRecoveryWorkflow",
            "session_id": session_id,
            "workflow_id": workflow_id,
            "recovery_code": psw_core::RecoveryKey::generate().expose_canonical()
        }));
        assert_eq!(wrong["ok"], false);
        assert_eq!(wrong["error"], "recovery confirmation did not match");

        let confirmed = command(json!({
            "command": "confirmRecoveryWorkflow",
            "session_id": session_id,
            "workflow_id": workflow_id,
            "recovery_code": canonical
        }));
        assert_eq!(confirmed["payload"]["type"], "recoveryConfirmed");
        assert_eq!(confirmed["payload"]["workflow_kind"], "setup");
        let status = command(json!({
            "command": "recoveryStatus",
            "session_id": session_id
        }));
        assert_eq!(status["payload"]["has_recovery_envelope"], true);
        assert_eq!(
            status["payload"]["recovery_key_id"],
            confirmed["payload"]["recovery_key_id"]
        );

        command(json!({
            "command": "lock",
            "session_id": session_id
        }));
        let locked_status = command(json!({
            "command": "lockedRecoveryStatus",
            "path": path.clone()
        }));
        assert_eq!(locked_status["payload"]["has_recovery_envelope"], true);
        assert_eq!(
            locked_status["payload"]["recovery_key_id"],
            confirmed["payload"]["recovery_key_id"]
        );

        let wrong_recovery = command_result(json!({
            "command": "recoverVault",
            "path": path.clone(),
            "recovery_code": psw_core::RecoveryKey::generate().expose_canonical(),
            "new_password": "wrong recovery replacement"
        }));
        assert_eq!(wrong_recovery["ok"], false);
        let old_unlock = command(json!({
            "command": "unlock",
            "path": path.clone(),
            "password": "correct horse"
        }));
        command(json!({
            "command": "lock",
            "session_id": old_unlock["payload"]["session_id"]
        }));

        let recovered = command(json!({
            "command": "recoverVault",
            "path": path.clone(),
            "recovery_code": canonical,
            "new_password": "recovered correct horse"
        }));
        assert_eq!(recovered["payload"]["type"], "unlocked");
        let recovered_serialized = recovered.to_string();
        assert!(!recovered_serialized.contains(canonical));
        assert!(!recovered_serialized.contains(&path));
        let old_password = command_result(json!({
            "command": "unlock",
            "path": path.clone(),
            "password": "correct horse"
        }));
        assert_eq!(old_password["ok"], false);
        let new_password = command(json!({
            "command": "unlock",
            "path": path.clone(),
            "password": "recovered correct horse"
        }));
        assert_eq!(new_password["payload"]["type"], "unlocked");

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_recovery_rotation_commit_and_lock_discard_pending_material() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-recovery-rotation-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = vault_path.to_string_lossy().to_string();

        command(json!({
            "command": "createVault",
            "path": path.clone(),
            "display_name": "FFI Recovery Rotation",
            "password": "correct horse"
        }));
        let unlocked = command(json!({
            "command": "unlock",
            "path": path.clone(),
            "password": "correct horse"
        }));
        let session_id = unlocked["payload"]["session_id"]
            .as_u64()
            .expect("session id");
        let setup = command(json!({
            "command": "beginRecoverySetup",
            "session_id": session_id
        }));
        command(json!({
            "command": "confirmRecoveryWorkflow",
            "session_id": session_id,
            "workflow_id": setup["payload"]["workflow_id"],
            "recovery_code": setup["payload"]["canonical_code"]
        }));

        let rotation = command(json!({
            "command": "beginRecoveryRotation",
            "session_id": session_id
        }));
        let old_status = command(json!({
            "command": "recoveryStatus",
            "session_id": session_id
        }));
        assert_ne!(
            old_status["payload"]["recovery_key_id"],
            rotation["payload"]["recovery_key_id"]
        );
        let confirmed = command(json!({
            "command": "confirmRecoveryWorkflow",
            "session_id": session_id,
            "workflow_id": rotation["payload"]["workflow_id"],
            "recovery_code": rotation["payload"]["grouped_code"]
        }));
        assert_eq!(confirmed["payload"]["workflow_kind"], "rotation");
        let new_status = command(json!({
            "command": "recoveryStatus",
            "session_id": session_id
        }));
        assert_eq!(
            new_status["payload"]["recovery_key_id"],
            rotation["payload"]["recovery_key_id"]
        );

        let cancellable = command(json!({
            "command": "beginRecoveryRotation",
            "session_id": session_id
        }));
        let second_unlock = command(json!({
            "command": "unlock",
            "path": path.clone(),
            "password": "correct horse"
        }));
        let second_session_id = second_unlock["payload"]["session_id"]
            .as_u64()
            .expect("second session id");
        let cross_session_cancel = command_result(json!({
            "command": "cancelRecoveryWorkflow",
            "session_id": second_session_id,
            "workflow_id": cancellable["payload"]["workflow_id"]
        }));
        assert_eq!(cross_session_cancel["ok"], false);
        assert!(cross_session_cancel["error"]
            .as_str()
            .expect("cross-session cancellation error")
            .contains("unknown recovery workflow"));
        command(json!({
            "command": "cancelRecoveryWorkflow",
            "session_id": session_id,
            "workflow_id": cancellable["payload"]["workflow_id"]
        }));

        let abandoned = command(json!({
            "command": "beginRecoveryRotation",
            "session_id": session_id
        }));
        command(json!({
            "command": "lock",
            "session_id": session_id
        }));
        let discarded = command_result(json!({
            "command": "confirmRecoveryWorkflow",
            "session_id": session_id,
            "workflow_id": abandoned["payload"]["workflow_id"],
            "recovery_code": abandoned["payload"]["canonical_code"]
        }));
        assert_eq!(discarded["ok"], false);
        assert!(discarded["error"]
            .as_str()
            .expect("discard error")
            .contains("unknown vault session"));

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_template_credentials_create_list_search_and_reveal_by_stable_field_id() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-template-credential-test-{}-{}",
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
            "display_name": "Template Credentials",
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

        let templates = [
            ("api-token", "API Token", "api-token", true),
            ("api-key", "API Key", "api-key", true),
            ("ssh-key", "SSH Key", "private-key", false),
            ("certificate", "Certificate", "certificate", true),
            ("custom", "Custom Secret", "generic-secret", false),
        ];
        for (index, (template_id, title, secret_kind, supports_expiry)) in
            templates.iter().enumerate()
        {
            let secret = format!("template-secret-marker-{index}");
            let response = command(json!({
                "command": "createCredentialFromTemplate",
                "session_id": session_id,
                "template_id": template_id,
                "title": title,
                "secret": secret,
                "expiry": supports_expiry.then_some("2028-06-30"),
                "notes": format!("notes for {template_id}"),
                "tags": ["development"],
                "favorite": index == 0
            }));
            let serialized = response.to_string();
            assert!(!serialized.contains(&secret));
            let item = response["payload"]["items"]
                .as_array()
                .expect("items")
                .iter()
                .find(|item| item["title"] == *title)
                .expect("created item");
            assert_eq!(item["template_id"], *template_id);
            assert_eq!(item["secret_kinds"], json!([secret_kind]));
        }

        let listed = command(json!({
            "command": "listItems",
            "session_id": session_id
        }));
        assert_eq!(
            listed["payload"]["items"]
                .as_array()
                .expect("listed items")
                .len(),
            templates.len()
        );
        for index in 0..templates.len() {
            assert!(!listed
                .to_string()
                .contains(&format!("template-secret-marker-{index}")));
        }

        let token_item = listed["payload"]["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["template_id"] == "api-token")
            .expect("API token item");
        let credential_id = token_item["id"]
            .as_str()
            .expect("credential identity")
            .to_owned();
        let detail = command(json!({
            "command": "getCredential",
            "session_id": session_id,
            "credential_id": credential_id
        }));
        assert_eq!(detail["payload"]["type"], "credentialDetail");
        assert_eq!(detail["payload"]["detail"]["template_id"], "api-token");
        assert_eq!(detail["payload"]["detail"]["title"], "API Token");
        assert!(!detail.to_string().contains("template-secret-marker-0"));
        let secret_field = detail["payload"]["detail"]["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .find(|field| field["value_type"] == "secret")
            .expect("secret field");
        assert_eq!(secret_field["secret_kind"], "api-token");
        assert_eq!(secret_field["has_value"], true);
        let secret_field_id = secret_field["secret_field_id"]
            .as_str()
            .expect("secret field identity");
        let revealed = command(json!({
            "command": "getCredentialSecretField",
            "session_id": session_id,
            "credential_id": credential_id,
            "secret_field_id": secret_field_id
        }));
        assert_eq!(revealed["payload"]["value"], "template-secret-marker-0");

        let searched = command(json!({
            "command": "search",
            "session_id": session_id,
            "text": "notes for api-token",
            "include_archived": false
        }));
        assert_eq!(
            searched["payload"]["items"]
                .as_array()
                .expect("search results")
                .len(),
            1
        );
        let secret_search = command(json!({
            "command": "search",
            "session_id": session_id,
            "text": "template-secret-marker-0",
            "include_archived": false
        }));
        assert!(secret_search["payload"]["items"]
            .as_array()
            .expect("secret search results")
            .is_empty());
        let refresh = command(json!({
            "command": "refreshFromDisk",
            "session_id": session_id
        }));
        assert_eq!(refresh["payload"]["loaded_items"], templates.len());
        assert_eq!(
            refresh["payload"]["items"]
                .as_array()
                .expect("refresh items")
                .len(),
            templates.len()
        );

        let unknown = command_result(json!({
            "command": "createCredentialFromTemplate",
            "session_id": session_id,
            "template_id": "github-token",
            "title": "Provider-specific",
            "secret": "must-not-persist"
        }));
        assert_eq!(unknown["ok"], false);
        let empty_secret = command_result(json!({
            "command": "createCredentialFromTemplate",
            "session_id": session_id,
            "template_id": "api-token",
            "title": "Missing secret",
            "secret": ""
        }));
        assert_eq!(empty_secret["ok"], false);

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn ffi_field_aware_edit_preserves_saved_secrets_and_stable_field_ids() {
        let vault_path = std::env::temp_dir().join(format!(
            "psw-ffi-field-aware-edit-test-{}-{}",
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
            "display_name": "Field Aware Edit",
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
            "command": "createCredentialFromTemplate",
            "session_id": session_id,
            "template_id": "api-token",
            "title": "Build API",
            "secret": "saved-secret-marker",
            "notes": "Initial notes",
            "tags": ["development"]
        }));
        let created_item = created["payload"]["items"]
            .as_array()
            .expect("created items")
            .iter()
            .find(|item| item["title"] == "Build API")
            .expect("created item");
        let credential_id = created_item["id"]
            .as_str()
            .expect("credential identity")
            .to_owned();
        let created_revision = created_item["revision"]
            .as_str()
            .expect("created revision")
            .to_owned();
        let detail = command(json!({
            "command": "getCredential",
            "session_id": session_id,
            "credential_id": credential_id
        }));
        let original_secret_field_id = detail["payload"]["detail"]["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .find(|field| field["value_type"] == "secret")
            .expect("secret field")["secret_field_id"]
            .as_str()
            .expect("secret field identity")
            .to_owned();

        let updated = command(json!({
            "command": "updateCredential",
            "session_id": session_id,
            "credential_id": credential_id,
            "expected_revision": created_revision,
            "title": "Build API Renamed",
            "template_id": "api-token",
            "fields": [
                {
                    "value_type": "existingSecret",
                    "role": "access-token",
                    "label": "Build token",
                    "secret_field_id": original_secret_field_id
                },
                {
                    "value_type": "text",
                    "role": "account",
                    "label": "Account",
                    "text": "chasechou007"
                },
                {
                    "value_type": "newSecret",
                    "role": "fallback",
                    "label": "Fallback",
                    "secret_kind": "generic-secret",
                    "secret": "new-secret-marker"
                }
            ],
            "tags": ["development", "automation"],
            "favorite": true
        }));
        assert!(!updated.to_string().contains("saved-secret-marker"));
        assert!(!updated.to_string().contains("new-secret-marker"));
        let updated_item = updated["payload"]["items"]
            .as_array()
            .expect("updated items")
            .iter()
            .find(|item| item["id"] == credential_id)
            .expect("updated item");
        let updated_revision = updated_item["revision"]
            .as_str()
            .expect("updated revision")
            .to_owned();
        assert_ne!(updated_revision, created_revision);
        assert_eq!(
            updated_item["secret_kinds"],
            json!(["api-token", "generic-secret"])
        );

        let detail = command(json!({
            "command": "getCredential",
            "session_id": session_id,
            "credential_id": credential_id
        }));
        let fields = detail["payload"]["detail"]["fields"]
            .as_array()
            .expect("updated fields");
        assert_eq!(
            fields
                .iter()
                .map(|field| field["role"].as_str().expect("field role"))
                .collect::<Vec<_>>(),
            vec!["access-token", "account", "fallback"]
        );
        let secret_fields = fields
            .iter()
            .filter(|field| field["value_type"] == "secret")
            .collect::<Vec<_>>();
        assert_eq!(secret_fields.len(), 2);
        assert_eq!(
            secret_fields[0]["secret_field_id"],
            original_secret_field_id
        );
        let new_secret_field_id = secret_fields[1]["secret_field_id"]
            .as_str()
            .expect("new secret field identity")
            .to_owned();
        assert_ne!(new_secret_field_id, original_secret_field_id);
        for (secret_field_id, expected_value) in [
            (original_secret_field_id.as_str(), "saved-secret-marker"),
            (new_secret_field_id.as_str(), "new-secret-marker"),
        ] {
            let revealed = command(json!({
                "command": "getCredentialSecretField",
                "session_id": session_id,
                "credential_id": credential_id,
                "secret_field_id": secret_field_id
            }));
            assert_eq!(revealed["payload"]["value"], expected_value);
        }

        let replaced = command(json!({
            "command": "updateCredential",
            "session_id": session_id,
            "credential_id": credential_id,
            "expected_revision": updated_revision,
            "title": "Build API Renamed",
            "template_id": "api-token",
            "fields": [
                {
                    "value_type": "existingSecret",
                    "role": "access-token",
                    "label": "Build token",
                    "secret_field_id": original_secret_field_id,
                    "replacement": "replacement-secret-marker"
                },
                {
                    "value_type": "text",
                    "role": "account",
                    "label": "Account",
                    "text": "chasechou007"
                },
                {
                    "value_type": "existingSecret",
                    "role": "fallback",
                    "label": "Fallback",
                    "secret_field_id": new_secret_field_id
                }
            ],
            "tags": ["automation"],
            "favorite": false
        }));
        assert!(!replaced.to_string().contains("replacement-secret-marker"));
        let replaced_revision = replaced["payload"]["items"]
            .as_array()
            .expect("replaced items")
            .iter()
            .find(|item| item["id"] == credential_id)
            .expect("replaced item")["revision"]
            .as_str()
            .expect("replaced revision")
            .to_owned();
        let revealed = command(json!({
            "command": "getCredentialSecretField",
            "session_id": session_id,
            "credential_id": credential_id,
            "secret_field_id": original_secret_field_id
        }));
        assert_eq!(revealed["payload"]["value"], "replacement-secret-marker");

        let stale = command_result(json!({
            "command": "updateCredential",
            "session_id": session_id,
            "credential_id": credential_id,
            "expected_revision": created_revision,
            "title": "Stale",
            "template_id": "api-token",
            "fields": [],
            "tags": [],
            "favorite": false
        }));
        assert_eq!(stale["ok"], false);
        assert!(stale["error"]
            .as_str()
            .expect("stale error")
            .contains("item changed on disk"));

        let favorited = command(json!({
            "command": "setFavorite",
            "session_id": session_id,
            "item_id": credential_id,
            "expected_revision": replaced_revision,
            "favorite": true
        }));
        let favorited_item = favorited["payload"]["items"]
            .as_array()
            .expect("favorited items")
            .iter()
            .find(|item| item["id"] == credential_id)
            .expect("favorited item");
        assert_eq!(favorited_item["favorite"], true);
        let favorited_revision = favorited_item["revision"]
            .as_str()
            .expect("favorited revision")
            .to_owned();

        let duplicated = command(json!({
            "command": "duplicateCredential",
            "session_id": session_id,
            "credential_id": credential_id,
            "expected_revision": favorited_revision,
            "title": "Build API Copy"
        }));
        assert!(!duplicated.to_string().contains("replacement-secret-marker"));
        assert!(!duplicated.to_string().contains("new-secret-marker"));
        let duplicate = duplicated["payload"]["items"]
            .as_array()
            .expect("duplicated items")
            .iter()
            .find(|item| item["title"] == "Build API Copy")
            .expect("duplicate item");
        let duplicate_credential_id = duplicate["id"]
            .as_str()
            .expect("duplicate credential identity")
            .to_owned();
        assert_ne!(duplicate_credential_id, credential_id);
        let duplicate_detail = command(json!({
            "command": "getCredential",
            "session_id": session_id,
            "credential_id": duplicate_credential_id
        }));
        let duplicate_secret_field_ids = duplicate_detail["payload"]["detail"]["fields"]
            .as_array()
            .expect("duplicate fields")
            .iter()
            .filter(|field| field["value_type"] == "secret")
            .map(|field| {
                field["secret_field_id"]
                    .as_str()
                    .expect("duplicate secret-field identity")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(duplicate_secret_field_ids.len(), 2);
        assert!(!duplicate_secret_field_ids.contains(&original_secret_field_id));
        assert!(!duplicate_secret_field_ids.contains(&new_secret_field_id));
        for (secret_field_id, expected_value) in duplicate_secret_field_ids
            .iter()
            .zip(["replacement-secret-marker", "new-secret-marker"])
        {
            let revealed = command(json!({
                "command": "getCredentialSecretField",
                "session_id": session_id,
                "credential_id": duplicate_credential_id,
                "secret_field_id": secret_field_id
            }));
            assert_eq!(revealed["payload"]["value"], expected_value);
        }

        let archived = command(json!({
            "command": "archiveItem",
            "session_id": session_id,
            "item_id": credential_id,
            "expected_revision": favorited_revision
        }));
        assert!(archived["payload"]["items"]
            .as_array()
            .expect("active items")
            .iter()
            .all(|item| item["id"] != credential_id));
        let restored = command(json!({
            "command": "restoreItem",
            "session_id": session_id,
            "item_id": credential_id
        }));
        assert_eq!(
            restored["payload"]["items"]
                .as_array()
                .expect("restored items")
                .iter()
                .find(|item| item["id"] == credential_id)
                .expect("restored item")["status"],
            "active"
        );

        let _ = fs::remove_dir_all(vault_path);
    }

    #[test]
    fn recovery_response_debug_redacts_secret_text() {
        let marker = "knr1secret-response-marker";
        let payload = super::ResponsePayload::RecoveryKit {
            workflow_id: 1,
            workflow_kind: "setup",
            vault_id: "vault_000102030405060708090a0b0c0d0e0f".to_owned(),
            recovery_key_id: "recovery_key_202122232425262728292a2b2c2d2e2f".to_owned(),
            generated_at_unix_seconds: 1_800_000_000,
            canonical_code: super::SecretResponseString::new(marker.to_owned()),
            grouped_code: super::SecretResponseString::new(marker.to_owned()),
            qr_payload: super::SecretResponseString::new(marker.to_owned()),
            verification_groups: vec![super::SecretResponseString::new(marker.to_owned())],
        };
        let debug = format!("{payload:?}");

        assert!(!debug.contains(marker));
        assert!(debug.contains("[REDACTED]"));
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

    fn copy_tombstone_records(source_vault: &Path, destination_vault: &Path) {
        let source_tombstones = source_vault.join("tombstones");
        let destination_tombstones = destination_vault.join("tombstones");
        for entry in fs::read_dir(source_tombstones).expect("read source tombstones") {
            let entry = entry.expect("source tombstone entry");
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("enc")
            {
                fs::copy(entry.path(), destination_tombstones.join(entry.file_name()))
                    .expect("copy tombstone record");
            }
        }
    }
}
