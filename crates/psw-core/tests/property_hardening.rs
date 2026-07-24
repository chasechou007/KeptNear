use std::fs;
use std::path::{Path, PathBuf};

use psw_core::{
    CreateVaultRequest, ImportPreviewRequest, LoginItem, OpenVaultRequest, SecretBytes, VaultCore,
    VaultItemContent, VaultItemDraft,
};

#[test]
fn vault_metadata_parser_rejects_malformed_inputs() {
    let temp_dir = unique_temp_dir("vault_metadata_parser_rejects_malformed_inputs");
    let vault_path = temp_dir.join("Malformed.pswvault");
    let core = VaultCore::new();
    core.create_vault(CreateVaultRequest {
        path: vault_path.clone(),
        display_name: Some("Malformed".to_owned()),
        master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
    })
    .expect("create vault");

    for malformed in [
        b"".as_slice(),
        b"not json".as_slice(),
        br#"{"format_name":42}"#.as_slice(),
        br#"{"format_name":"psw-local-vault","vault_format_version":"bad"}"#.as_slice(),
    ] {
        fs::write(vault_path.join("vault.json"), malformed).expect("write malformed metadata");
        let result = core.open_vault(OpenVaultRequest {
            path: vault_path.clone(),
        });
        assert!(
            matches!(result, Err(psw_core::VaultError::InvalidVault { .. })),
            "malformed metadata should be rejected: {:?}",
            String::from_utf8_lossy(malformed)
        );
    }

    fs::remove_dir_all(temp_dir).expect("remove temp dir");
}

#[test]
fn import_parser_rejects_malformed_inputs_without_writing_items() {
    let temp_dir = unique_temp_dir("import_parser_rejects_malformed_inputs");
    let vault_path = temp_dir.join("Imports.pswvault");
    let import_path = temp_dir.join("bad-import.json");
    let core = VaultCore::new();
    let unlocked = core
        .create_vault(CreateVaultRequest {
            path: vault_path,
            display_name: Some("Imports".to_owned()),
            master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
        })
        .expect("create vault")
        .unlock(psw_core::UnlockRequest {
            master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
        })
        .expect("unlock vault");

    for malformed in [
        b"".as_slice(),
        b"not json".as_slice(),
        br#"{"encrypted":true,"items":[]}"#.as_slice(),
        br#"{"encrypted":false,"items":"bad"}"#.as_slice(),
    ] {
        fs::write(&import_path, malformed).expect("write malformed import");
        let result = unlocked.preview_import(ImportPreviewRequest {
            source_path: import_path.clone(),
            source_format: "bitwarden-json".to_owned(),
        });
        assert!(result.is_err(), "malformed import should be rejected");
        assert!(unlocked.list_items().expect("list items").is_empty());
    }

    fs::remove_dir_all(temp_dir).expect("remove temp dir");
}

#[test]
fn item_record_decoder_rejects_malformed_record_variants() {
    let temp_dir = unique_temp_dir("item_record_decoder_rejects_malformed_record_variants");
    let vault_path = temp_dir.join("Records.pswvault");
    let core = VaultCore::new();
    let mut unlocked = core
        .create_vault(CreateVaultRequest {
            path: vault_path.clone(),
            display_name: Some("Records".to_owned()),
            master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
        })
        .expect("create vault")
        .unlock(psw_core::UnlockRequest {
            master_password: SecretBytes::new(b"correct horse battery staple".to_vec()),
        })
        .expect("unlock vault");
    unlocked
        .create_item(login_draft())
        .expect("create encrypted item");
    let item_file = first_enc_file(&vault_path.join("items"));

    let original = fs::read_to_string(&item_file).expect("read item file");
    let mut variants = Vec::new();
    variants.push("not json".to_owned());
    variants.push(r#"{"format":"bad"}"#.to_owned());
    let mut value: serde_json::Value = serde_json::from_str(&original).expect("parse item json");
    value["nonce_hex"] = serde_json::Value::String("bad nonce".to_owned());
    variants.push(serde_json::to_string_pretty(&value).expect("serialize bad nonce"));
    let mut value: serde_json::Value = serde_json::from_str(&original).expect("parse item json");
    value["ciphertext_hex"] = serde_json::Value::String("00".to_owned());
    variants.push(serde_json::to_string_pretty(&value).expect("serialize bad ciphertext"));

    for variant in variants {
        fs::write(&item_file, variant).expect("write malformed item record");
        let refresh = unlocked
            .refresh_from_disk()
            .expect("refresh malformed item record");
        assert_eq!(refresh.rejected_records, 1);
        assert_eq!(refresh.rejected_item_records, 1);
        assert_eq!(refresh.rejected_tombstone_records, 0);
        let items = unlocked
            .list_items()
            .expect("list trusted items after rejecting malformed record");
        assert!(
            items.is_empty(),
            "malformed item record should not be trusted"
        );
    }

    fs::remove_dir_all(temp_dir).expect("remove temp dir");
}

fn login_draft() -> VaultItemDraft {
    VaultItemDraft {
        title: "Property Login".to_owned(),
        content: VaultItemContent::Login(LoginItem {
            username: Some("property-user".to_owned()),
            password: Some(SecretBytes::new(b"property-password".to_vec())),
            urls: vec!["https://property.example".to_owned()],
            notes: None,
            totp_secret: None,
        }),
        tags: Vec::new(),
        favorite: false,
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

fn unique_temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "psw-core-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}
