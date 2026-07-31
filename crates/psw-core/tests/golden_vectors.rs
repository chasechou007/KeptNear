use std::fs;
use std::path::{Path, PathBuf};

use psw_core::{
    CreateVaultRequest, LoginItem, OpenVaultRequest, SecretBytes, VaultCore, VaultItemContent,
    VaultItemDraft, VaultMetadata,
};
use serde::Deserialize;

#[test]
fn golden_vault_creation_unlock_and_item_encryption() {
    let manifest = read_current_manifest();
    let temp_dir = unique_temp_dir("golden_vault_creation_unlock");
    let vault_path = temp_dir.join("Golden.pswvault");
    let password = SecretBytes::new(b"correct horse battery staple".to_vec());
    let core = VaultCore::new();

    core.create_vault(CreateVaultRequest {
        path: vault_path.clone(),
        display_name: Some(manifest.display_name.clone()),
        master_password: password.clone(),
    })
    .expect("create vault");

    assert_required_paths(&vault_path, &manifest.required_paths);
    let metadata: VaultMetadata = read_json(&vault_path.join("vault.json"));
    assert_eq!(metadata.format_name, manifest.format_name);
    assert_eq!(metadata.vault_format_version, manifest.vault_format_version);
    assert_eq!(
        metadata.record_format_version,
        manifest.record_format_version
    );
    assert_eq!(metadata.display_name.as_deref(), Some("Golden"));

    let mut unlocked = core
        .open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open vault")
        .unlock(psw_core::UnlockRequest {
            master_password: password,
        })
        .expect("unlock vault");
    let summary = unlocked
        .create_item(golden_login_draft())
        .expect("create encrypted item");
    assert_eq!(summary.title, "Golden Login");

    let item_file = first_enc_file(&vault_path.join("items"));
    let item_bytes = fs::read(item_file).expect("read encrypted item");
    let item_text = String::from_utf8_lossy(&item_bytes);
    for needle in &manifest.plaintext_needles {
        assert!(
            !item_text.contains(needle),
            "encrypted item leaked plaintext needle {needle}"
        );
    }

    let reopened = core
        .open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("reopen vault")
        .unlock(psw_core::UnlockRequest {
            master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
        })
        .expect("unlock reopened vault");
    assert_eq!(
        reopened
            .get_item(&summary.id)
            .expect("get item")
            .draft
            .title,
        "Golden Login"
    );

    fs::remove_dir_all(temp_dir).expect("remove temp dir");
}

#[test]
fn checked_in_golden_vault_fixture_opens_and_keeps_plaintext_encrypted() {
    let manifest = read_source_manifest();
    let fixture_path = vault_fixtures_dir().join(&manifest.fixture_path);
    let core = VaultCore::new();

    assert_required_paths(&fixture_path, &manifest.required_paths);
    let metadata: VaultMetadata = read_json(&fixture_path.join("vault.json"));
    assert_eq!(metadata.format_name, manifest.format_name);
    assert_eq!(metadata.vault_format_version, manifest.vault_format_version);
    assert_eq!(
        metadata.record_format_version,
        manifest.record_format_version
    );
    assert_eq!(
        metadata.display_name.as_deref(),
        Some(manifest.fixture_display_name.as_str())
    );

    assert_plaintext_needles_absent_from_fixture(&fixture_path, &manifest.plaintext_needles);

    let unlocked = core
        .open_vault(OpenVaultRequest {
            path: fixture_path.clone(),
        })
        .expect("open checked-in fixture")
        .unlock(psw_core::UnlockRequest {
            master_password: golden_fixture_password(),
        })
        .expect("unlock checked-in fixture");
    let items = unlocked.list_items().expect("list fixture items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title, manifest.fixture_item_title);
    assert_eq!(items[0].tags, vec![manifest.fixture_item_tag.clone()]);
    assert!(items[0].favorite);

    let item = unlocked
        .get_item(&items[0].id)
        .expect("read checked-in fixture item");
    assert_eq!(item.draft.title, manifest.fixture_item_title);
    assert_eq!(item.draft.tags, vec![manifest.fixture_item_tag]);
    assert!(item.draft.favorite);
    let VaultItemContent::Login(login) = item.draft.content else {
        panic!("checked-in fixture item should be a login");
    };
    assert_eq!(
        login.username.as_deref(),
        Some(manifest.fixture_item_username.as_str())
    );
    assert_eq!(login.urls, vec![manifest.fixture_item_url]);
    assert_eq!(
        login.password.expect("fixture password").expose(),
        b"golden-password"
    );
    assert_eq!(
        login.totp_secret.expect("fixture TOTP").expose(),
        b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    );
}

#[test]
fn migrated_v1_fixture_round_trips_and_accepts_current_writes() {
    let manifest = read_source_manifest();
    let root = unique_temp_dir("golden_migration_round_trip");
    fs::create_dir_all(&root).expect("create migration root");
    let source_path = root.join("Migrating.pswvault");
    let backup_path = root.join("Migrating.pre-v2.pswvault");
    let core = VaultCore::new();
    core.restore_vault_backup(psw_core::RestoreVaultBackupRequest {
        source_path: vault_fixtures_dir().join(manifest.fixture_path.as_str()),
        destination_path: source_path.clone(),
    })
    .expect("copy v1 fixture");

    let source = core
        .open_vault(OpenVaultRequest {
            path: source_path.clone(),
        })
        .expect("open v1 fixture copy")
        .unlock(psw_core::UnlockRequest {
            master_password: golden_fixture_password(),
        })
        .expect("unlock v1 fixture copy");
    let source_item = source
        .get_item(&source.list_items().expect("list v1 source")[0].id)
        .expect("read v1 source item");
    let migration = source
        .migrate_to_target_format(backup_path.clone())
        .expect("migrate fixture to v2");
    assert_eq!(migration.metadata.vault_format_version, 2);
    assert_eq!(migration.metadata.record_format_version, 2);
    assert!(migration.metadata.vault_id.is_some());
    assert_eq!(migration.backup_path, backup_path);
    assert!(!migration.cleanup_required);

    let mut target = core
        .open_vault(OpenVaultRequest {
            path: source_path.clone(),
        })
        .expect("open migrated v2 target")
        .unlock(psw_core::UnlockRequest {
            master_password: golden_fixture_password(),
        })
        .expect("unlock migrated v2 target");
    let target_items = target.list_items().expect("list migrated target");
    assert_eq!(target_items.len(), 1);
    assert!(target_items[0].id.0.starts_with("credential_"));
    let target_item = target
        .get_item(&target_items[0].id)
        .expect("read migrated target item");
    assert_eq!(target_item.draft, source_item.draft);
    let added = target
        .create_item(golden_login_draft())
        .expect("write migrated current vault");
    assert!(added.id.0.starts_with("credential_"));
    assert_eq!(target.list_items().expect("list written target").len(), 2);

    let retained_backup = core
        .open_vault(OpenVaultRequest { path: backup_path })
        .expect("open retained v1 backup");
    assert_eq!(retained_backup.metadata.vault_format_version, 1);
    assert_eq!(retained_backup.metadata.record_format_version, 1);
    fs::remove_dir_all(root).expect("remove migration root");
}

#[test]
fn checked_in_current_fixture_opens_round_trips_and_keeps_plaintext_encrypted() {
    let manifest = read_current_manifest();
    let fixture_path = vault_fixtures_dir().join(&manifest.fixture_path);
    let core = VaultCore::new();

    assert_required_paths(&fixture_path, &manifest.required_paths);
    assert_plaintext_needles_absent_from_fixture(&fixture_path, &manifest.plaintext_needles);
    let metadata: VaultMetadata = read_json(&fixture_path.join("vault.json"));
    assert_eq!(metadata.vault_format_version, 2);
    assert_eq!(metadata.record_format_version, 2);
    assert!(metadata.vault_id.is_some());

    let unlocked = core
        .open_vault(OpenVaultRequest { path: fixture_path })
        .expect("open checked-in target fixture")
        .unlock(psw_core::UnlockRequest {
            master_password: golden_fixture_password(),
        })
        .expect("unlock checked-in target fixture");
    let summaries = unlocked.list_items().expect("list target fixture");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].title, manifest.fixture_item_title);
    assert!(summaries[0].id.0.starts_with("credential_"));
    let item = unlocked
        .get_item(&summaries[0].id)
        .expect("read target fixture");
    assert_eq!(item.draft.tags, vec![manifest.fixture_item_tag]);
    assert!(item.draft.favorite);
    let VaultItemContent::Login(login) = item.draft.content else {
        panic!("target fixture item should be a login");
    };
    assert_eq!(
        login.username.as_deref(),
        Some(manifest.fixture_item_username.as_str())
    );
    assert_eq!(login.urls, vec![manifest.fixture_item_url]);
    assert_eq!(
        login.password.expect("target fixture password").expose(),
        b"golden-password"
    );
}

#[test]
fn current_fixture_rejects_future_vault_and_record_versions() {
    let manifest = read_current_manifest();
    let root = unique_temp_dir("target_fixture_future_version");
    fs::create_dir_all(&root).expect("create future-version root");
    let target_path = root.join("Future.pswvault");
    let core = VaultCore::new();
    core.restore_vault_backup(psw_core::RestoreVaultBackupRequest {
        source_path: vault_fixtures_dir().join(manifest.fixture_path.as_str()),
        destination_path: target_path.clone(),
    })
    .expect("copy target fixture");
    let mut metadata: VaultMetadata = read_json(&target_path.join("vault.json"));
    metadata.vault_format_version = 3;
    metadata.record_format_version = 3;
    fs::write(
        target_path.join("vault.json"),
        serde_json::to_vec_pretty(&metadata).expect("serialize future target metadata"),
    )
    .expect("write future target metadata");

    assert!(matches!(
        core.open_vault(OpenVaultRequest { path: target_path }),
        Err(psw_core::VaultError::UnsupportedFormat { .. })
    ));
    fs::remove_dir_all(root).expect("remove future-version root");
}

#[test]
fn released_format_registry_tracks_the_current_golden_fixture() {
    let registry: ReleasedFormatRegistry =
        read_json(&vault_fixtures_dir().join("released-format-fixtures.json"));
    let manifest = read_current_manifest();
    assert_eq!(registry.registry_version, 1);
    assert_eq!(registry.released_formats.len(), 1);
    let released = &registry.released_formats[0];
    assert_eq!(released.format_id, "vault-v2-record-v2");
    assert_eq!(released.release_status, "prealpha");
    assert_eq!(released.vault_format_version, manifest.vault_format_version);
    assert_eq!(
        released.record_format_version,
        manifest.record_format_version
    );
    assert_eq!(released.manifest_path, "golden-vault-v2-manifest.json");
    assert_eq!(released.fixture_path, manifest.fixture_path);
}

#[test]
fn supported_source_versions_have_sanitized_openable_fixtures() {
    let registry: SourceVersionRegistry =
        read_json(&vault_fixtures_dir().join("supported-source-versions.json"));
    assert_eq!(registry.registry_version, 1);

    let declared_pair_count = registry.source_versions.len();
    let mut declared_pairs = registry
        .source_versions
        .iter()
        .map(|source| (source.vault_format_version, source.record_format_version))
        .collect::<Vec<_>>();
    declared_pairs.sort_unstable();
    declared_pairs.dedup();
    assert_eq!(
        declared_pairs.len(),
        declared_pair_count,
        "source format pairs must not be duplicated"
    );

    let core = VaultCore::new();
    for source in registry.source_versions {
        assert!(
            !source.source_id.trim().is_empty(),
            "source version ID must not be empty"
        );
        let manifest: GoldenManifest = read_json(&vault_fixtures_dir().join(&source.manifest_path));
        assert_eq!(
            source.vault_format_version, manifest.vault_format_version,
            "{} vault version differs from its manifest",
            source.source_id
        );
        assert_eq!(
            source.record_format_version, manifest.record_format_version,
            "{} record version differs from its manifest",
            source.source_id
        );
        assert_eq!(
            source.fixture_path, manifest.fixture_path,
            "{} fixture path differs from its manifest",
            source.source_id
        );

        let fixture_path = vault_fixtures_dir().join(&source.fixture_path);
        assert_required_paths(&fixture_path, &manifest.required_paths);
        assert_plaintext_needles_absent_from_fixture(&fixture_path, &manifest.plaintext_needles);

        let unlocked = core
            .open_vault(OpenVaultRequest { path: fixture_path })
            .unwrap_or_else(|error| panic!("open {}: {error}", source.source_id))
            .unlock(psw_core::UnlockRequest {
                master_password: golden_fixture_password(),
            })
            .unwrap_or_else(|error| panic!("unlock {}: {error}", source.source_id));
        assert!(
            !unlocked
                .list_items()
                .unwrap_or_else(|error| panic!("list {}: {error}", source.source_id))
                .is_empty(),
            "{} must contain synthetic encrypted test content",
            source.source_id
        );
    }
}

#[test]
fn golden_vectors_reject_tampered_item_and_future_format() {
    let temp_dir = unique_temp_dir("golden_rejects_tamper_future");
    let vault_path = temp_dir.join("Golden.pswvault");
    let password = SecretBytes::new(b"correct horse battery staple".to_vec());
    let core = VaultCore::new();
    let mut unlocked = core
        .create_vault(CreateVaultRequest {
            path: vault_path.clone(),
            display_name: Some("Golden".to_owned()),
            master_password: password.clone(),
        })
        .expect("create vault")
        .unlock(psw_core::UnlockRequest {
            master_password: password.clone(),
        })
        .expect("unlock vault");
    let summary = unlocked
        .create_item(golden_login_draft())
        .expect("create encrypted item");
    tamper_first_item_ciphertext(&vault_path.join("items"));

    let mut tampered_vault = core
        .open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        })
        .expect("open tampered vault")
        .unlock(psw_core::UnlockRequest {
            master_password: password.clone(),
        })
        .expect("unlock tampered vault");
    let refresh = tampered_vault
        .refresh_from_disk()
        .expect("refresh tampered vault");
    assert_eq!(refresh.rejected_records, 1);
    assert_eq!(refresh.rejected_item_records, 1);
    assert_eq!(refresh.rejected_tombstone_records, 0);
    assert!(tampered_vault
        .list_items()
        .expect("list trusted items")
        .is_empty());
    let tampered = tampered_vault.get_item(&summary.id);
    assert!(matches!(
        tampered,
        Err(psw_core::VaultError::ItemNotFound { .. })
    ));

    let mut metadata: VaultMetadata = read_json(&vault_path.join("vault.json"));
    metadata.vault_format_version = 3;
    metadata.record_format_version = 3;
    fs::write(
        vault_path.join("vault.json"),
        serde_json::to_vec_pretty(&metadata).expect("serialize future metadata"),
    )
    .expect("write future metadata");
    let future = core.open_vault(OpenVaultRequest { path: vault_path });
    assert!(matches!(
        future,
        Err(psw_core::VaultError::UnsupportedFormat { .. })
    ));

    fs::remove_dir_all(temp_dir).expect("remove temp dir");
}

#[test]
#[ignore = "explicit fixture regeneration writes checked-in encrypted test data"]
fn regenerate_checked_in_current_fixture() {
    let fixtures = vault_fixtures_dir();
    let source_manifest = read_source_manifest();
    let target_manifest = read_current_manifest();
    let target_fixture = fixtures.join(&target_manifest.fixture_path);
    assert!(
        !target_fixture.exists(),
        "remove the existing target fixture before explicit regeneration"
    );

    let root = unique_temp_dir("regenerate_target_fixture");
    fs::create_dir_all(&root).expect("create fixture-generation root");
    let source_path = root.join("FixtureSource.pswvault");
    let backup_path = root.join("FixtureSource.pre-v2.pswvault");
    let core = VaultCore::new();
    core.restore_vault_backup(psw_core::RestoreVaultBackupRequest {
        source_path: fixtures.join(source_manifest.fixture_path),
        destination_path: source_path.clone(),
    })
    .expect("copy source fixture");
    let mut metadata: VaultMetadata = read_json(&source_path.join("vault.json"));
    metadata.display_name = Some(target_manifest.fixture_display_name);
    fs::write(
        source_path.join("vault.json"),
        serde_json::to_vec_pretty(&metadata).expect("serialize target fixture source metadata"),
    )
    .expect("write target fixture source metadata");
    core.open_vault(OpenVaultRequest {
        path: source_path.clone(),
    })
    .expect("open target fixture source")
    .unlock(psw_core::UnlockRequest {
        master_password: golden_fixture_password(),
    })
    .expect("unlock target fixture source")
    .migrate_to_target_format(backup_path)
    .expect("migrate target fixture source");
    core.restore_vault_backup(psw_core::RestoreVaultBackupRequest {
        source_path,
        destination_path: target_fixture.clone(),
    })
    .expect("write checked-in target fixture");
    fs::write(target_fixture.join("tombstones/.gitkeep"), [])
        .expect("retain empty target tombstones directory");
    fs::remove_dir_all(root).expect("remove fixture-generation root");
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenManifest {
    display_name: String,
    fixture_path: String,
    fixture_display_name: String,
    fixture_item_title: String,
    fixture_item_username: String,
    fixture_item_url: String,
    fixture_item_tag: String,
    format_name: String,
    vault_format_version: u32,
    record_format_version: u32,
    required_paths: Vec<String>,
    plaintext_needles: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceVersionRegistry {
    registry_version: u32,
    source_versions: Vec<SourceVersionFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceVersionFixture {
    source_id: String,
    vault_format_version: u32,
    record_format_version: u32,
    manifest_path: String,
    fixture_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleasedFormatRegistry {
    registry_version: u32,
    released_formats: Vec<ReleasedFormatFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleasedFormatFixture {
    format_id: String,
    release_status: String,
    vault_format_version: u32,
    record_format_version: u32,
    manifest_path: String,
    fixture_path: String,
}

fn golden_login_draft() -> VaultItemDraft {
    VaultItemDraft {
        title: "Golden Login".to_owned(),
        content: VaultItemContent::Login(LoginItem {
            username: Some("golden-user".to_owned()),
            password: Some(SecretBytes::new(b"golden-password".to_vec())),
            urls: vec!["https://golden.example".to_owned()],
            notes: Some("golden-note".to_owned()),
            totp_secret: Some(SecretBytes::new(
                b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_vec(),
            )),
        }),
        tags: vec!["golden".to_owned()],
        favorite: true,
    }
}

fn assert_required_paths(vault_path: &Path, required_paths: &[String]) {
    for required_path in required_paths {
        assert!(
            vault_path.join(required_path).exists(),
            "missing required vault path {required_path}"
        );
    }
}

fn first_enc_file(dir: &Path) -> PathBuf {
    fs::read_dir(dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("enc"))
        .expect("find encrypted file")
}

fn tamper_first_item_ciphertext(items_dir: &Path) {
    let item_file = first_enc_file(items_dir);
    let mut value: serde_json::Value = read_json(&item_file);
    let ciphertext = value
        .get("ciphertext_hex")
        .and_then(serde_json::Value::as_str)
        .expect("ciphertext_hex")
        .to_owned();
    let replacement = if let Some(stripped) = ciphertext.strip_prefix('0') {
        format!("1{stripped}")
    } else {
        format!("0{}", &ciphertext[1..])
    };
    value["ciphertext_hex"] = serde_json::Value::String(replacement);
    fs::write(
        item_file,
        serde_json::to_vec_pretty(&value).expect("serialize tampered item"),
    )
    .expect("write tampered item");
}

fn read_source_manifest() -> GoldenManifest {
    read_json(&vault_fixtures_dir().join("golden-vault-manifest.json"))
}

fn read_current_manifest() -> GoldenManifest {
    read_json(&vault_fixtures_dir().join("golden-vault-v2-manifest.json"))
}

fn vault_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vaults")
}

fn read_json<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_slice(&fs::read(path).expect("read json")).expect("parse json")
}

fn unique_temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "psw-core-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

fn golden_fixture_password() -> SecretBytes {
    SecretBytes::new(b"correct horse battery staple".to_vec())
}

fn assert_plaintext_needles_absent_from_fixture(vault_path: &Path, needles: &[String]) {
    for file_path in fixture_files(vault_path) {
        let bytes = fs::read(&file_path).expect("read fixture file");
        let text = String::from_utf8_lossy(&bytes);
        for needle in needles {
            assert!(
                !text.contains(needle),
                "fixture file {} leaked plaintext needle {needle}",
                file_path.display()
            );
        }
    }
}

fn fixture_files(path: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_fixture_files(path, &mut files);
    files
}

fn collect_fixture_files(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("read fixture directory") {
        let entry = entry.expect("read fixture entry");
        let path = entry.path();
        let file_type = entry.file_type().expect("read fixture file type");
        if file_type.is_dir() {
            collect_fixture_files(&path, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}
