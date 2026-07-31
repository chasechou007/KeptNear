use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use psw_core::{
    ConflictCandidateCredentialField, ConflictCandidateSummary, ConflictId, CreateVaultRequest,
    CredentialDraft, CredentialEdit, CredentialField, CredentialFieldEdit, CredentialFieldValue,
    CredentialId, CredentialLifecycle, CredentialRevision, ItemRevision, OpenVaultRequest,
    RestoreVaultBackupRequest, SecretBytes, SecretFieldId, SecretFieldKind, UnlockRequest,
    UnlockedVault, VaultCore,
};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TEST_PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
fn migrated_vault_copy_preserves_two_device_identity_and_accepts_synced_descendants() {
    let root = TempRoot::new("migrated-copy");
    let device_a_path = root.path.join("Device-A.pswvault");
    let device_b_path = root.path.join("Device-B.pswvault");
    let retained_backup_path = root.path.join("Device-A.pre-v2.pswvault");
    let core = VaultCore::new();

    core.restore_vault_backup(RestoreVaultBackupRequest {
        source_path: vault_fixture_path("golden-vault-v1.pswvault"),
        destination_path: device_a_path.clone(),
    })
    .expect("copy frozen migration source");
    let source = unlock_vault(&core, &device_a_path);
    let migration = source
        .migrate_to_target_format(retained_backup_path.clone())
        .expect("migrate device A to current format");
    let migrated_vault_id = migration.metadata.vault_id.expect("migrated vault ID");
    assert_eq!(migration.metadata.vault_format_version, 2);
    assert_eq!(migration.metadata.record_format_version, 2);
    assert_eq!(migration.backup_path, retained_backup_path);

    let mut device_a = unlock_vault(&core, &device_a_path);
    let typed = device_a
        .create_credential(token_draft("Deployment token", b"migration-token"))
        .expect("create typed credential after migration");
    let typed_id = typed.credential.credential_id;
    let copied = device_a
        .backup_to(device_b_path.clone())
        .expect("create portable device B copy");
    assert_eq!(copied.copied_item_files, 2);
    assert_eq!(copied.copied_tombstone_files, 0);

    let locked_b = core
        .open_vault(OpenVaultRequest {
            path: device_b_path.clone(),
        })
        .expect("open device B copy");
    assert_ne!(device_a.path, locked_b.path);
    assert_eq!(locked_b.metadata.vault_id, Some(migrated_vault_id));
    let mut device_b = locked_b
        .unlock(UnlockRequest {
            master_password: test_password(),
        })
        .expect("unlock device B copy");

    let ids_a = sorted_credential_ids(&device_a);
    let ids_b = sorted_credential_ids(&device_b);
    assert_eq!(ids_a, ids_b);
    assert_eq!(ids_a.len(), 2);
    for credential_id in ids_a {
        let revision_a = device_a
            .credential_revision(credential_id)
            .expect("device A revision");
        let revision_b = device_b
            .credential_revision(credential_id)
            .expect("device B revision");
        assert_eq!(revision_a, revision_b);
        assert_eq!(secret_field_ids(&revision_a), secret_field_ids(&revision_b));
    }

    let updated = update_credential(&mut device_a, typed_id, |draft| {
        draft.title = "Deployment token from device A".to_owned();
    });
    copy_revision_record(&device_a.path, &device_b.path, &updated);
    let refresh = device_b
        .refresh_from_disk()
        .expect("refresh migrated device B copy");
    assert_eq!(refresh.detected_conflicts, 0);
    assert_eq!(
        device_b
            .credential_revision(typed_id)
            .expect("synced migrated credential")
            .credential()
            .draft()
            .title,
        "Deployment token from device A"
    );

    let retained = core
        .open_vault(OpenVaultRequest {
            path: retained_backup_path,
        })
        .expect("open retained migration source");
    assert_eq!(retained.metadata.vault_format_version, 1);
    assert_eq!(retained.metadata.record_format_version, 1);
}

#[test]
fn two_devices_converge_independent_credential_edits_without_conflict() {
    let root = TempRoot::new("independent-edits");
    let (mut device_a, mut device_b, credential_ids) = create_current_pair(
        &root.path,
        vec![
            token_draft("First token", b"first-token"),
            token_draft("Second token", b"second-token"),
        ],
    );
    let first_id = credential_ids[0];
    let second_id = credential_ids[1];
    let first_base = device_a.credential_revision(first_id).expect("first base");
    let second_base = device_b
        .credential_revision(second_id)
        .expect("second base");

    let first_edit = update_credential(&mut device_a, first_id, |draft| {
        draft.title = "First token edited on A".to_owned();
    });
    let second_edit = update_credential(&mut device_b, second_id, |draft| {
        draft.tags.push("edited-on-b".to_owned());
    });
    exchange_record_files(&device_a.path, &device_b.path);

    assert_eq!(
        device_a
            .refresh_from_disk()
            .expect("refresh device A")
            .detected_conflicts,
        0
    );
    assert_eq!(
        device_b
            .refresh_from_disk()
            .expect("refresh device B")
            .detected_conflicts,
        0
    );
    for device in [&device_a, &device_b] {
        let first = device
            .credential_revision(first_id)
            .expect("synced first edit");
        let second = device
            .credential_revision(second_id)
            .expect("synced second edit");
        assert_eq!(first.revision_id(), first_edit.revision_id());
        assert_eq!(second.revision_id(), second_edit.revision_id());
        assert_eq!(first.parent_revision_ids(), &[first_base.revision_id()]);
        assert_eq!(second.parent_revision_ids(), &[second_base.revision_id()]);
        assert_eq!(first.credential().draft().title, "First token edited on A");
        assert!(second
            .credential()
            .draft()
            .tags
            .contains(&"edited-on-b".to_owned()));
    }
}

#[test]
fn two_devices_preserve_and_resolve_same_secret_field_edits() {
    let root = TempRoot::new("same-secret-field");
    let (mut device_a, mut device_b, credential_ids) =
        create_current_pair(&root.path, vec![token_draft("Shared token", b"base-token")]);
    let credential_id = credential_ids[0];
    let base = device_a
        .credential_revision(credential_id)
        .expect("shared base");
    let token_id = secret_field_id(&base, "token");

    let edit_a = update_credential(&mut device_a, credential_id, |draft| {
        replace_secret(draft, "token", b"token-from-device-a");
    });
    let edit_b = update_credential(&mut device_b, credential_id, |draft| {
        replace_secret(draft, "token", b"token-from-device-b");
    });
    exchange_record_files(&device_a.path, &device_b.path);
    let synced_a = encrypted_record_snapshot(&device_a.path);
    let synced_b = encrypted_record_snapshot(&device_b.path);

    assert_eq!(
        device_a
            .refresh_from_disk()
            .expect("refresh same-field conflict on A")
            .detected_conflicts,
        1
    );
    assert_eq!(
        device_b
            .refresh_from_disk()
            .expect("refresh same-field conflict on B")
            .detected_conflicts,
        1
    );
    assert_eq!(encrypted_record_snapshot(&device_a.path), synced_a);
    assert_eq!(encrypted_record_snapshot(&device_b.path), synced_b);

    let conflict_id = ConflictId(format!("conflict_{credential_id}"));
    for device in [&device_a, &device_b] {
        let candidates = device
            .conflict_candidates(&conflict_id)
            .expect("same-field candidates");
        assert_eq!(
            candidate_revision_ids(&candidates),
            revision_set(&[&edit_a, &edit_b])
        );
        assert!(candidates
            .iter()
            .all(|candidate| !candidate.supports_safe_field_merge));
        assert_secret_metadata(&candidates, token_id);
        let debug = format!("{candidates:?}");
        assert!(!debug.contains("token-from-device-a"));
        assert!(!debug.contains("token-from-device-b"));
    }

    device_a
        .resolve_credential_conflict_candidate(
            &conflict_id,
            &ItemRevision(edit_a.revision_id().to_string()),
        )
        .expect("keep device A value");
    device_b
        .resolve_credential_conflict_candidate(
            &conflict_id,
            &ItemRevision(edit_b.revision_id().to_string()),
        )
        .expect("keep device B value");

    let resolved_a = device_a
        .credential_revision(credential_id)
        .expect("device A resolution");
    let resolved_b = device_b
        .credential_revision(credential_id)
        .expect("device B resolution");
    assert_eq!(secret_value(&resolved_a, "token"), b"token-from-device-a");
    assert_eq!(secret_value(&resolved_b, "token"), b"token-from-device-b");
    let expected_parents = revision_set(&[&edit_a, &edit_b]);
    assert_eq!(
        resolved_a
            .parent_revision_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        expected_parents
    );
    assert_snapshot_is_preserved(&synced_a, &encrypted_record_snapshot(&device_a.path));
    assert_snapshot_is_preserved(&synced_b, &encrypted_record_snapshot(&device_b.path));
}

#[test]
fn two_devices_preserve_delete_edit_conflict_and_both_explicit_outcomes() {
    let root = TempRoot::new("delete-edit");
    let (mut device_a, mut device_b, credential_ids) = create_current_pair(
        &root.path,
        vec![token_draft("Delete or edit", b"base-delete-token")],
    );
    let credential_id = credential_ids[0];
    let base = device_a
        .credential_revision(credential_id)
        .expect("delete-edit base");

    let edited = update_credential(&mut device_a, credential_id, |draft| {
        draft.title = "Edited on device A".to_owned();
        replace_secret(draft, "token", b"edited-before-delete");
    });
    device_b
        .delete_credential_with_expected_revision(credential_id, base.revision_id())
        .expect("delete on device B");
    exchange_record_files(&device_a.path, &device_b.path);
    let synced_a = encrypted_record_snapshot(&device_a.path);
    let synced_b = encrypted_record_snapshot(&device_b.path);

    assert_eq!(
        device_a
            .refresh_from_disk()
            .expect("refresh delete-edit on A")
            .detected_conflicts,
        1
    );
    assert_eq!(
        device_b
            .refresh_from_disk()
            .expect("refresh delete-edit on B")
            .detected_conflicts,
        1
    );
    assert_eq!(encrypted_record_snapshot(&device_a.path), synced_a);
    assert_eq!(encrypted_record_snapshot(&device_b.path), synced_b);

    let conflict_id = ConflictId(format!("conflict_{credential_id}"));
    let candidates_a = device_a
        .conflict_candidates(&conflict_id)
        .expect("delete-edit candidates on A");
    let candidates_b = device_b
        .conflict_candidates(&conflict_id)
        .expect("delete-edit candidates on B");
    for candidates in [&candidates_a, &candidates_b] {
        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .any(|candidate| candidate.status == "active"));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.status == "deleted"));
    }
    let deleted_revision = candidates_b
        .iter()
        .find(|candidate| candidate.status == "deleted")
        .expect("deleted candidate")
        .revision
        .clone();

    device_a
        .resolve_credential_conflict_candidate(
            &conflict_id,
            &ItemRevision(edited.revision_id().to_string()),
        )
        .expect("keep edited candidate");
    device_b
        .resolve_credential_conflict_candidate(&conflict_id, &deleted_revision)
        .expect("keep deletion candidate");

    let kept = device_a
        .credential_revision(credential_id)
        .expect("kept active revision");
    assert_eq!(kept.credential().draft().title, "Edited on device A");
    assert_eq!(secret_value(&kept, "token"), b"edited-before-delete");
    assert!(device_b
        .list_credential_items(true)
        .expect("list after keeping deletion")
        .is_empty());
    assert_snapshot_is_preserved(&synced_a, &encrypted_record_snapshot(&device_a.path));
    assert_snapshot_is_preserved(&synced_b, &encrypted_record_snapshot(&device_b.path));
}

#[test]
fn delayed_parent_arrival_clears_temporary_conflict_without_writing_resolution() {
    let root = TempRoot::new("delayed-parent");
    let (mut device_a, mut device_b, credential_ids) = create_current_pair(
        &root.path,
        vec![token_draft("Delayed sync", b"delayed-base-token")],
    );
    let credential_id = credential_ids[0];

    let left = update_credential(&mut device_a, credential_id, |draft| {
        draft.title = "Title from device A".to_owned();
    });
    let right = update_credential(&mut device_b, credential_id, |draft| {
        draft.tags.push("tag-from-device-b".to_owned());
    });
    copy_revision_record(&device_b.path, &device_a.path, &right);
    assert_eq!(
        device_a
            .refresh_from_disk()
            .expect("create safe merge on device A")
            .detected_conflicts,
        0
    );
    let merged = device_a
        .credential_revision(credential_id)
        .expect("merged revision");
    assert_eq!(
        merged
            .parent_revision_ids()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        revision_set(&[&left, &right])
    );
    let child = update_credential(&mut device_a, credential_id, |draft| {
        draft.favorite = true;
    });
    assert_eq!(child.parent_revision_ids(), &[merged.revision_id()]);

    copy_revision_record(&device_a.path, &device_b.path, &child);
    let before_temporary_conflict = encrypted_record_snapshot(&device_b.path);
    assert_eq!(
        device_b
            .refresh_from_disk()
            .expect("refresh child before parent")
            .detected_conflicts,
        1
    );
    assert_eq!(
        encrypted_record_snapshot(&device_b.path),
        before_temporary_conflict
    );
    let conflict_id = ConflictId(format!("conflict_{credential_id}"));
    assert_eq!(
        candidate_revision_ids(
            &device_b
                .conflict_candidates(&conflict_id)
                .expect("temporary delayed-sync candidates")
        ),
        revision_set(&[&right, &child])
    );

    copy_revision_record(&device_a.path, &device_b.path, &merged);
    assert_eq!(
        device_b
            .refresh_from_disk()
            .expect("refresh after merge parent arrives")
            .detected_conflicts,
        0
    );
    let after_merge_parent = device_b
        .credential_revision(credential_id)
        .expect("child becomes sole head");
    assert_eq!(after_merge_parent.revision_id(), child.revision_id());

    copy_revision_record(&device_a.path, &device_b.path, &left);
    assert_eq!(
        device_b
            .refresh_from_disk()
            .expect("refresh after final delayed ancestor")
            .detected_conflicts,
        0
    );
    let converged = device_b
        .credential_revision(credential_id)
        .expect("converged delayed-sync revision");
    assert_eq!(converged.revision_id(), child.revision_id());
    assert_eq!(converged.credential().draft().title, "Title from device A");
    assert_eq!(
        converged.credential().draft().tags,
        vec!["sync".to_owned(), "tag-from-device-b".to_owned()]
    );
    assert!(converged.credential().draft().favorite);
    assert_eq!(encrypted_record_snapshot(&device_b.path).len(), 5);
}

fn create_current_pair(
    root: &Path,
    drafts: Vec<CredentialDraft>,
) -> (UnlockedVault, UnlockedVault, Vec<CredentialId>) {
    let core = VaultCore::new();
    let device_a_path = root.join("Device-A.pswvault");
    let device_b_path = root.join("Device-B.pswvault");
    let mut device_a = core
        .create_vault(CreateVaultRequest {
            path: device_a_path,
            display_name: Some("Two-device sync".to_owned()),
            master_password: test_password(),
        })
        .expect("create device A vault")
        .unlock(UnlockRequest {
            master_password: test_password(),
        })
        .expect("unlock device A vault");
    let credential_ids = drafts
        .into_iter()
        .map(|draft| {
            device_a
                .create_credential(draft)
                .expect("create shared credential")
                .credential
                .credential_id
        })
        .collect::<Vec<_>>();
    device_a
        .backup_to(device_b_path.clone())
        .expect("create portable device B copy");
    let device_b = unlock_vault(&core, &device_b_path);
    assert_eq!(device_a.metadata.vault_id, device_b.metadata.vault_id);
    (device_a, device_b, credential_ids)
}

fn update_credential(
    vault: &mut UnlockedVault,
    credential_id: CredentialId,
    change: impl FnOnce(&mut CredentialDraft),
) -> CredentialRevision {
    let current = vault
        .credential_revision(credential_id)
        .expect("load current credential");
    let mut draft = current.credential().draft().clone();
    change(&mut draft);
    let prepared = vault
        .prepare_credential_update(credential_id, current.revision_id(), credential_edit(draft))
        .expect("prepare credential update");
    vault
        .commit_credential_update(prepared)
        .expect("commit credential update");
    vault
        .credential_revision(credential_id)
        .expect("load committed credential")
}

fn credential_edit(draft: CredentialDraft) -> CredentialEdit {
    CredentialEdit {
        title: draft.title,
        template_id: draft.template_id,
        fields: draft
            .fields
            .into_iter()
            .map(|field| match field.value {
                CredentialFieldValue::Text { text } => CredentialFieldEdit::Text {
                    role: field.role,
                    label: field.label,
                    text,
                },
                CredentialFieldValue::Secret {
                    secret_field_id,
                    secret,
                    ..
                } => CredentialFieldEdit::ExistingSecret {
                    role: field.role,
                    label: field.label,
                    secret_field_id,
                    replacement: Some(secret),
                },
            })
            .collect(),
        tags: draft.tags,
        favorite: draft.favorite,
    }
}

fn token_draft(title: &str, token: &[u8]) -> CredentialDraft {
    CredentialDraft {
        title: title.to_owned(),
        template_id: Some("api-token".to_owned()),
        fields: vec![
            CredentialField::text("account", "alice"),
            CredentialField::secret(
                "token",
                SecretFieldKind::ApiToken,
                SecretBytes::new(token.to_vec()),
            ),
        ],
        tags: vec!["sync".to_owned()],
        favorite: false,
    }
}

fn replace_secret(draft: &mut CredentialDraft, role: &str, replacement: &[u8]) {
    let field = draft
        .fields
        .iter_mut()
        .find(|field| field.role == role)
        .unwrap_or_else(|| panic!("missing Secret Field {role}"));
    let CredentialFieldValue::Secret { secret, .. } = &mut field.value else {
        panic!("field {role} is not secret");
    };
    *secret = SecretBytes::new(replacement.to_vec());
}

fn secret_field_id(revision: &CredentialRevision, role: &str) -> SecretFieldId {
    revision
        .credential()
        .draft()
        .fields
        .iter()
        .find_map(|field| match &field.value {
            CredentialFieldValue::Secret {
                secret_field_id, ..
            } if field.role == role => Some(*secret_field_id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing Secret Field {role}"))
}

fn secret_field_ids(revision: &CredentialRevision) -> Vec<SecretFieldId> {
    revision
        .credential()
        .draft()
        .secret_fields()
        .map(|field| field.secret_field_id().expect("stable Secret Field ID"))
        .collect()
}

fn secret_value<'a>(revision: &'a CredentialRevision, role: &str) -> &'a [u8] {
    revision
        .credential()
        .draft()
        .fields
        .iter()
        .find_map(|field| match &field.value {
            CredentialFieldValue::Secret { secret, .. } if field.role == role => {
                Some(secret.expose())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing Secret Field {role}"))
}

fn assert_secret_metadata(candidates: &[ConflictCandidateSummary], expected_id: SecretFieldId) {
    for candidate in candidates {
        let field = candidate
            .credential_fields
            .iter()
            .find(|field| {
                matches!(
                    field,
                    ConflictCandidateCredentialField::Secret { role, .. } if role == "token"
                )
            })
            .expect("token metadata");
        assert!(matches!(
            field,
            ConflictCandidateCredentialField::Secret {
                secret_field_id,
                secret_kind: SecretFieldKind::ApiToken,
                has_value: true,
                changed: true,
                ..
            } if *secret_field_id == expected_id
        ));
    }
}

fn sorted_credential_ids(vault: &UnlockedVault) -> Vec<CredentialId> {
    let mut ids = vault
        .list_credential_items(true)
        .expect("list credentials")
        .into_iter()
        .map(|item| item.credential.credential_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

fn candidate_revision_ids(
    candidates: &[ConflictCandidateSummary],
) -> BTreeSet<psw_core::RevisionId> {
    candidates
        .iter()
        .map(|candidate| {
            candidate
                .revision
                .0
                .parse()
                .expect("canonical candidate revision")
        })
        .collect()
}

fn revision_set(revisions: &[&CredentialRevision]) -> BTreeSet<psw_core::RevisionId> {
    revisions
        .iter()
        .map(|revision| revision.revision_id())
        .collect()
}

fn exchange_record_files(left: &Path, right: &Path) {
    for directory in ["items", "tombstones"] {
        merge_record_directory(&left.join(directory), &right.join(directory));
        merge_record_directory(&right.join(directory), &left.join(directory));
    }
}

fn merge_record_directory(source: &Path, destination: &Path) {
    let mut entries = fs::read_dir(source)
        .expect("read source record directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("read source record entries");
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        if entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("enc")
        {
            continue;
        }
        copy_record_file(&entry.path(), &destination.join(entry.file_name()));
    }
}

fn copy_revision_record(source: &Path, destination: &Path, revision: &CredentialRevision) {
    let directory = match revision.lifecycle() {
        CredentialLifecycle::Active | CredentialLifecycle::Archived => "items",
        CredentialLifecycle::Deleted => "tombstones",
    };
    let file_name = match revision.lifecycle() {
        CredentialLifecycle::Active | CredentialLifecycle::Archived => format!(
            "{}_{}.enc",
            revision.credential().credential_id(),
            revision.revision_id()
        ),
        CredentialLifecycle::Deleted => format!(
            "tombstone_{}_{}.enc",
            revision.credential().credential_id(),
            revision.revision_id()
        ),
    };
    copy_record_file(
        &source.join(directory).join(&file_name),
        &destination.join(directory).join(file_name),
    );
}

fn copy_record_file(source: &Path, destination: &Path) {
    if destination.exists() {
        assert_eq!(
            fs::read(destination).expect("read existing destination record"),
            fs::read(source).expect("read existing source record"),
            "same revision file name must have identical encrypted bytes"
        );
        return;
    }
    fs::copy(source, destination).expect("copy encrypted revision");
}

fn encrypted_record_snapshot(vault_path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut snapshot = BTreeMap::new();
    for directory in ["items", "tombstones"] {
        for entry in fs::read_dir(vault_path.join(directory)).expect("read record directory") {
            let entry = entry.expect("read record entry");
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("enc")
            {
                continue;
            }
            snapshot.insert(
                format!("{directory}/{}", entry.file_name().to_string_lossy()),
                fs::read(entry.path()).expect("read encrypted record"),
            );
        }
    }
    snapshot
}

fn assert_snapshot_is_preserved(
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
) {
    for (path, bytes) in before {
        assert_eq!(
            after.get(path),
            Some(bytes),
            "source encrypted record changed or disappeared: {path}"
        );
    }
}

fn unlock_vault(core: &VaultCore, path: &Path) -> UnlockedVault {
    core.open_vault(OpenVaultRequest {
        path: path.to_path_buf(),
    })
    .expect("open vault")
    .unlock(UnlockRequest {
        master_password: test_password(),
    })
    .expect("unlock vault")
}

fn test_password() -> SecretBytes {
    SecretBytes::new(TEST_PASSWORD.to_vec())
}

fn vault_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/vaults")
        .join(name)
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(label: &str) -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "keptnear-two-device-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test root");
        Self { path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
